use crate::utils::{collect_account_proofs, collect_storage_proofs};
use bus_mapping::{
    circuit_input_builder::l2::update_codedb,
    state_db,
    state_db::{CodeDB, StateDB},
};
use eth_types::{l2_types::BlockTrace, ToBigEndian, ToWord, H160, H256};
use log::{trace, Level};
use mpt_zktrie::state::ZktrieState;
use revm::{
    db::DatabaseRef,
    primitives::{AccountInfo, Bytecode, B160, B256, U256},
    DatabaseCommit,
};
use revm_precompile::Bytes;
use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
};
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

    fn basic(&self, addr: B160) -> Result<Option<AccountInfo>, Self::Error> {
        let (exist, acc) = self.sdb.get_account(&H160::from(addr.to_fixed_bytes()));
        log::trace!("loaded account: {addr:?}, exist: {exist}, acc: {acc:?}");
        if exist {
            let mut acc = AccountInfo {
                balance: U256::from_be_bytes(acc.balance.to_be_bytes()),
                nonce: acc.nonce.as_u64(),
                code_hash: B256::from(acc.code_hash.to_fixed_bytes()),
                keccak_code_hash: B256::from(acc.keccak_code_hash.to_fixed_bytes()),
                // if None, code_by_hash will be used to fetch it if code needs to be loaded from
                // inside revm.
                code: None,
            };
            let code = self
                .code_db
                .0
                .get(&H256(acc.code_hash.to_fixed_bytes()))
                .cloned()
                .unwrap_or_default();
            let bytecode = Bytecode::new_raw(Bytes::from(code.to_vec()));
            acc.code = Some(bytecode);
            Ok(Some(acc))
        } else {
            Ok(None)
        }
    }

    fn code_by_hash(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        panic!("Should not be called. Code is already loaded");
    }

    fn storage(&self, address: B160, index: U256) -> Result<U256, Self::Error> {
        let (_, val) = self.sdb.get_storage(
            &H160::from(address.to_fixed_bytes()),
            &eth_types::U256::from_little_endian(index.as_le_slice()),
        );
        Ok(U256::from_be_bytes(val.to_be_bytes()))
    }

    fn block_hash(&self, _: U256) -> Result<B256, Self::Error> {
        unimplemented!("BLOCKHASH is disabled")
    }
}

impl revm::Database for EvmDatabase {
    type Error = Infallible;

    fn basic(&mut self, address: B160) -> Result<Option<AccountInfo>, Self::Error> {
        DatabaseRef::basic(self, address)
    }

    fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        panic!("Should not be called. Code is already loaded");
    }

    fn storage(&mut self, address: B160, index: U256) -> Result<U256, Self::Error> {
        DatabaseRef::storage(self, address, index)
    }

    fn block_hash(&mut self, _: U256) -> Result<B256, Self::Error> {
        unimplemented!("BLOCKHASH is disabled")
    }
}

impl DatabaseCommit for EvmDatabase {
    fn commit(&mut self, changes: revm::precompile::HashMap<B160, revm::primitives::Account>) {
        for (addr, incoming) in changes {
            let addr = H160::from(addr.to_fixed_bytes());
            if log::log_enabled!(Level::Trace) {
                let mut acc = incoming.clone();
                acc.info.code = None;
                trace!("commit: addr: {:?}, acc: {:?}", addr, acc);
            }
            let (_, acc) = self.sdb.get_account_mut(&addr);
            let acc_is_empty = acc.is_empty();

            let new_balance =
                eth_types::U256::from_little_endian(incoming.info.balance.as_le_slice());
            if acc.balance != new_balance {
                let key = MptKey::new_balance(addr);
                self.updates
                    .entry(key)
                    .or_insert_with(|| MptUpdate::new(key, acc.balance, new_balance))
                    .new_value = new_balance;
                acc.balance = new_balance;
            }
            if acc.nonce.as_u64() != incoming.info.nonce {
                let key = MptKey::new_nonce(addr);
                self.updates
                    .entry(key)
                    .or_insert_with(|| MptUpdate::new(key, acc.nonce, incoming.info.nonce.into()))
                    .new_value = incoming.info.nonce.into();
                acc.nonce = eth_types::U256::from(incoming.info.nonce);
            }
            if acc_is_empty && !incoming.is_empty() {
                let key = MptKey::new_code_hash(addr);
                debug_assert!(!self.updates.contains_key(&key));
                self.updates.insert(
                    key,
                    MptUpdate::new(
                        key,
                        eth_types::U256::zero(),
                        eth_types::U256::from_big_endian(incoming.info.code_hash.as_ref()),
                    ),
                );
                acc.code_hash = H256::from(incoming.info.code_hash.to_fixed_bytes());

                let key = MptKey::new_keccak_code_hash(addr);
                debug_assert!(!self.updates.contains_key(&key));
                self.updates.insert(
                    key,
                    MptUpdate::new(
                        key,
                        eth_types::U256::zero(),
                        eth_types::U256::from_big_endian(incoming.info.keccak_code_hash.as_ref()),
                    ),
                );
                acc.keccak_code_hash = H256::from(incoming.info.keccak_code_hash.to_fixed_bytes());

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
                acc.code_size = eth_types::U256::from(code_size);
            }

            for (storage_key, slot) in incoming.storage.iter() {
                let storage_key = eth_types::U256::from_little_endian(storage_key.as_le_slice());
                let is_cleared = slot.present_value().is_zero();
                let key = MptKey::new_storage(self.tx_id, addr, storage_key, !is_cleared);
                let original_value =
                    eth_types::U256::from_little_endian(slot.original_value().as_le_slice());
                let present_value =
                    eth_types::U256::from_little_endian(slot.present_value().as_le_slice());
                let old = acc.storage.insert(storage_key, present_value);
                debug_assert_eq!(old.unwrap_or_default(), original_value);
                debug_assert!(!self.updates.contains_key(&key));
                self.updates
                    .insert(key, MptUpdate::new(key, original_value, present_value));
            }
        }

        self.tx_id += 1;
    }
}
