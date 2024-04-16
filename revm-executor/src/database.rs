use crate::utils::{collect_account_proofs, collect_storage_proofs};
use bus_mapping::{
    circuit_input_builder::l2::update_codedb,
    state_db,
    state_db::{CodeDB, StateDB},
};
use eth_types::{l2_types::BlockTrace, ToWord, H160, H256, U256};
use log::{trace, Level};
use mpt_zktrie::state::ZktrieState;
use revm::{db::DatabaseRef, AccountInfo, Bytecode, DatabaseCommit};
use revm_precompile::{Bytes, HashMap};
use std::{collections::BTreeMap, convert::Infallible};
use zkevm_circuits::witness::{MptKey, MptUpdate};

#[derive(Debug)]
pub struct EvmDatabase {
    tx_id: usize,
    code_db: CodeDB,
    pub(crate) sdb: StateDB,
    pub updates: BTreeMap<MptKey, MptUpdate>,
}

impl EvmDatabase {
    pub fn new(l2_trace: &BlockTrace) -> Self {
        let mut sdb = StateDB::new();
        for parsed in
            ZktrieState::parse_account_from_proofs(collect_account_proofs(&l2_trace.storage_trace))
        {
            let (addr, acc) = parsed.unwrap();
            trace!("insert account {:?} {:?}", addr, acc);
            sdb.set_account(&addr, state_db::Account::from(&acc));
        }

        for parsed in
            ZktrieState::parse_storage_from_proofs(collect_storage_proofs(&l2_trace.storage_trace))
        {
            let ((addr, key), val) = parsed.unwrap();
            *sdb.get_storage_mut(&addr, &key).1 = val.into();
        }

        let mut code_db = CodeDB::new();
        code_db.insert(Vec::new());
        update_codedb(&mut code_db, &sdb, &l2_trace).unwrap();

        EvmDatabase {
            tx_id: 1,
            code_db,
            sdb,
            updates: BTreeMap::new(),
        }
    }
}

impl DatabaseRef for EvmDatabase {
    type Error = Infallible;

    fn basic(&self, addr: H160) -> Result<Option<AccountInfo>, Self::Error> {
        let (exist, acc) = self.sdb.get_account(&addr);
        log::trace!("loaded account: {addr:?}, exist: {exist}, acc: {acc:?}");
        if exist {
            let mut acc = AccountInfo {
                balance: acc.balance,
                nonce: acc.nonce.as_u64(),
                code_hash: acc.code_hash,
                keccak_code_hash: acc.keccak_code_hash,
                // if None, code_by_hash will be used to fetch it if code needs to be loaded from
                // inside revm.
                code: None,
            };
            let code = self
                .code_db
                .0
                .get(&acc.code_hash)
                .cloned()
                .unwrap_or_default();
            let bytecode = unsafe {
                Bytecode::new_raw_with_hash(
                    Bytes::from(code.to_vec()),
                    acc.code_hash,
                    acc.keccak_code_hash,
                )
            };
            acc.code = Some(bytecode);
            Ok(Some(acc))
        } else {
            Ok(None)
        }
    }

    fn code_by_hash(&self, _code_hash: H256) -> Result<Bytecode, Self::Error> {
        panic!("Should not be called. Code is already loaded");
    }

    fn storage(&self, address: H160, index: U256) -> Result<U256, Self::Error> {
        let (_, val) = self.sdb.get_storage(&address, &index);
        Ok(*val)
    }

    fn block_hash(&self, _: U256) -> Result<H256, Self::Error> {
        unimplemented!("BLOCKHASH is disabled")
    }
}

impl revm::Database for EvmDatabase {
    type Error = Infallible;

    fn basic(&mut self, address: H160) -> Result<Option<AccountInfo>, Self::Error> {
        DatabaseRef::basic(self, address)
    }

    fn code_by_hash(&mut self, _code_hash: H256) -> Result<Bytecode, Self::Error> {
        panic!("Should not be called. Code is already loaded");
    }

    fn storage(&mut self, address: H160, index: U256) -> Result<U256, Self::Error> {
        DatabaseRef::storage(self, address, index)
    }

    fn block_hash(&mut self, number: U256) -> Result<H256, Self::Error> {
        DatabaseRef::block_hash(self, number)
    }
}

impl DatabaseCommit for EvmDatabase {
    fn commit(&mut self, changes: HashMap<H160, revm::Account>) {
        for (addr, incoming) in changes {
            if log::log_enabled!(Level::Trace) {
                let mut acc = incoming.clone();
                acc.info.code = None;
                trace!("commit: addr: {:?}, acc: {:?}", addr, acc);
            }
            let (_, acc) = self.sdb.get_account_mut(&addr);
            let acc_is_empty = acc.is_empty();

            if acc.balance != incoming.info.balance {
                let key = MptKey::new_balance(addr);
                self.updates
                    .entry(key)
                    .or_insert_with(|| MptUpdate::new(key, acc.balance, incoming.info.balance))
                    .new_value = incoming.info.balance;
                acc.balance = incoming.info.balance;
            }
            if acc.nonce.as_u64() != incoming.info.nonce {
                let key = MptKey::new_nonce(addr);
                self.updates
                    .entry(key)
                    .or_insert_with(|| MptUpdate::new(key, acc.nonce, incoming.info.nonce.into()))
                    .new_value = incoming.info.nonce.into();
                acc.nonce = U256::from(incoming.info.nonce);
            }
            if acc_is_empty && !incoming.is_empty() {
                let key = MptKey::new_code_hash(addr);
                debug_assert!(!self.updates.contains_key(&key));
                self.updates.insert(
                    key,
                    MptUpdate::new(key, U256::zero(), incoming.info.code_hash.to_word()),
                );
                acc.code_hash = incoming.info.code_hash;

                let key = MptKey::new_keccak_code_hash(addr);
                debug_assert!(!self.updates.contains_key(&key));
                self.updates.insert(
                    key,
                    MptUpdate::new(key, U256::zero(), incoming.info.keccak_code_hash.to_word()),
                );
                acc.keccak_code_hash = incoming.info.keccak_code_hash;

                let key = MptKey::new_code_size(addr);
                debug_assert!(!self.updates.contains_key(&key));
                let code_size = incoming
                    .info
                    .code
                    .as_ref()
                    .map(|c| c.len())
                    .unwrap_or_default();
                self.updates
                    .insert(key, MptUpdate::new(key, acc.code_size, code_size.into()));
                acc.code_size = U256::from(code_size);
            }

            for (storage_key, slot) in incoming.storage.iter() {
                let is_cleared = slot.present_value().is_zero();
                let key = MptKey::new_storage(self.tx_id, addr, *storage_key, !is_cleared);
                let old = acc.storage.insert(*storage_key, slot.present_value());
                debug_assert_eq!(old.unwrap_or_default(), slot.original_value());
                debug_assert!(!self.updates.contains_key(&key));
                self.updates.insert(
                    key,
                    MptUpdate::new(key, slot.original_value(), slot.present_value()),
                );
            }
        }

        self.tx_id += 1;
    }
}
