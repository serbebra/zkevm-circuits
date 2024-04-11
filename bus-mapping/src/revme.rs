use crate::{
    circuit_input_builder::{
        l2::update_codedb, Block, BlockContext, BlockHead, CircuitInputBuilder, CircuitsParams,
    },
    state_db,
    state_db::{Account, CodeDB, StateDB},
};
use eth_types::{
    l2_types::{BlockTrace, EthBlock, StorageTrace},
    Address, ToWord, Word, H160, H256, U256,
};
use log::{trace, Level};
use mpt_zktrie::state::ZktrieState;
use revm::{db::DatabaseRef, AccountInfo, Bytecode, Database, DatabaseCommit};
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

impl CircuitInputBuilder {
    /// create a new CircuitInputBuilder for revm
    pub fn new_revm(l2_trace: &BlockTrace, circuits_params: CircuitsParams) -> Self {
        let chain_id = l2_trace.chain_id;
        let old_root = l2_trace.storage_trace.root_before;
        let mpt_init_state = ZktrieState::from_trace_with_additional(
            old_root,
            collect_account_proofs(&l2_trace.storage_trace),
            collect_storage_proofs(&l2_trace.storage_trace),
            l2_trace
                .storage_trace
                .deletion_proofs
                .iter()
                .map(ethers_core::types::Bytes::as_ref),
        )
        .unwrap();
        log::debug!(
            "building partial statedb done, root {}",
            hex::encode(mpt_init_state.root())
        );

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

        // ? remove this will cause end_state_root wrong, why?
        let eth_block: EthBlock = EthBlock::from(l2_trace);
        let head = BlockHead::new(chain_id, vec![], &eth_block).unwrap();

        let mut builder_block = Block::from_headers(&[head], circuits_params);
        builder_block.chain_id = chain_id;
        builder_block.prev_state_root = old_root.to_word();
        builder_block.start_l1_queue_index = l2_trace.start_l1_queue_index;
        CircuitInputBuilder {
            sdb,
            code_db,
            block: builder_block,
            block_ctx: BlockContext::new(),
            mpt_init_state: Some(mpt_init_state),
        }
    }
}

fn collect_account_proofs(
    storage_trace: &StorageTrace,
) -> impl Iterator<Item = (&Address, impl IntoIterator<Item = &[u8]>)> + Clone {
    storage_trace.proofs.iter().flat_map(|kv_map| {
        kv_map
            .iter()
            .map(|(k, bts)| (k, bts.iter().map(ethers_core::types::Bytes::as_ref)))
    })
}

fn collect_storage_proofs(
    storage_trace: &StorageTrace,
) -> impl Iterator<Item = (&Address, &Word, impl IntoIterator<Item = &[u8]>)> + Clone {
    storage_trace.storage_proofs.iter().flat_map(|(k, kv_map)| {
        kv_map
            .iter()
            .map(move |(sk, bts)| (k, sk, bts.iter().map(ethers_core::types::Bytes::as_ref)))
    })
}
