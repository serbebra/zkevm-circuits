use crate::{
    circuit_input_builder::CircuitInputBuilder,
    state_db::{Account, EMPTY_CODE_HASH_LE},
};
use eth_types::{l2_types::BlockTrace, H160, H256, U256};
use log::Level;
use revm::{db::DatabaseRef, AccountInfo, BlockEnv, Bytecode, Database, DatabaseCommit, Env};
use revm_precompile::{Bytes, HashMap};
use std::convert::Infallible;

impl From<&Account> for AccountInfo {
    fn from(acc: &Account) -> Self {
        AccountInfo {
            balance: acc.balance,
            nonce: acc.nonce.as_u64(),
            code_hash: acc.code_hash,
            keccak_code_hash: acc.keccak_code_hash,
            // if None, code_by_hash will be used to fetch it if code needs to be loaded from
            // inside revm.
            code: None,
        }
    }
}

impl DatabaseRef for CircuitInputBuilder {
    type Error = Infallible;

    fn basic(&self, addr: H160) -> Result<Option<AccountInfo>, Self::Error> {
        let (exist, acc) = self.sdb.get_account(&addr);
        log::trace!("loaded account: {addr:?}, exist: {exist}, acc: {acc:?}");
        if exist {
            let mut acc = AccountInfo::from(acc);
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

    fn block_hash(&self, number: U256) -> Result<H256, Self::Error> {
        Ok(self
            .block
            .headers
            .get(&number.as_u64()) // FIXME: is this correct?
            .expect("block not found")
            .eth_block
            .hash
            .unwrap())
    }
}

impl Database for CircuitInputBuilder {
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

impl DatabaseCommit for CircuitInputBuilder {
    fn commit(&mut self, changes: HashMap<H160, revm::Account>) {
        for (addr, acc) in changes {
            if log::log_enabled!(Level::Trace) {
                let mut acc = acc.clone();
                acc.info.code = None;
                log::trace!("commit: addr: {:?}, acc: {:?}", addr, acc);
            }
            self.sdb.set_account(
                &addr,
                Account {
                    nonce: U256::from(acc.info.nonce),
                    balance: acc.info.balance,
                    storage: Default::default(),
                    code_hash: acc.info.code_hash,
                    keccak_code_hash: acc.info.keccak_code_hash,
                    code_size: acc
                        .info
                        .code
                        .map(|c| U256::from(c.len()))
                        .unwrap_or_else(U256::zero),
                },
            );
        }
    }
}
