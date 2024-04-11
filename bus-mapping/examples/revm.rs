use bus_mapping::{
    circuit_input_builder::{
        l2::update_codedb, Block, BlockContext, BlockHead, CircuitInputBuilder, CircuitsParams,
    },
    state_db,
    state_db::{CodeDB, StateDB},
};
use eth_types::{
    l2_types::{BlockTrace, EthBlock, StorageTrace},
    Address, ToWord, Word,
};
use ethers_core::types::Bytes;
use log::trace;
use mpt_zktrie::state::ZktrieState;

fn main() {
    env_logger::init();

    let circuits_params = CircuitsParams {
        max_rws: 100000,
        max_txs: 10,
        ..Default::default()
    };

    let i = 2640;
    {
        log::info!("block {}", i);
        let path = format!("/Users/hhq/workspace/scroll-prover/integration/tests/extra_traces/batch_24/chunk_115/block_{i}.json");
        let trace = std::fs::read_to_string(path).unwrap();

        let l2_trace: BlockTrace = serde_json::from_str(&trace).unwrap();

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
                .map(Bytes::as_ref),
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
        let eth_block: EthBlock = EthBlock::from(&l2_trace);
        let head = BlockHead::new(chain_id, vec![], &eth_block).unwrap();

        let mut builder_block = Block::from_headers(&[head], circuits_params);
        builder_block.chain_id = chain_id;
        builder_block.prev_state_root = old_root.to_word();
        builder_block.start_l1_queue_index = l2_trace.start_l1_queue_index;
        let builder = CircuitInputBuilder {
            sdb,
            code_db,
            block: builder_block,
            block_ctx: BlockContext::new(),
            mpt_init_state: Some(mpt_init_state),
        };
        let mut revm_builder = builder.clone();
        revm_builder.handle_block_revm(&l2_trace).unwrap();
        log::trace!(
            "revm: end_state_root={:#x} withdraw_root={:#x}",
            revm_builder.block.end_state_root(),
            revm_builder.block.withdraw_root
        );

        // let geth_traces = block_trace
        //     .execution_results
        //     .clone()
        //     .into_iter()
        //     .map(GethExecTrace::from)
        //     .collect::<Vec<_>>();
        // let block = builder.block.clone();
        // builder.handle_block(&block, &geth_traces).unwrap();
        // log::trace!(
        //     "bus: end_state_root={:#x} withdraw_root={:#x}",
        //     builder.block.end_state_root(),
        //     builder.block.withdraw_root
        // );
        //
        // assert_eq!(
        //     revm_builder.block.end_state_root(),
        //     builder.block.end_state_root()
        // );
        // assert_eq!(
        //     builder.block.end_state_root(),
        //     block_trace.storage_trace.root_after.to_word()
        // );
    }
}

fn collect_account_proofs(
    storage_trace: &StorageTrace,
) -> impl Iterator<Item = (&Address, impl IntoIterator<Item = &[u8]>)> + Clone {
    storage_trace.proofs.iter().flat_map(|kv_map| {
        kv_map
            .iter()
            .map(|(k, bts)| (k, bts.iter().map(Bytes::as_ref)))
    })
}

fn collect_storage_proofs(
    storage_trace: &StorageTrace,
) -> impl Iterator<Item = (&Address, &Word, impl IntoIterator<Item = &[u8]>)> + Clone {
    storage_trace.storage_proofs.iter().flat_map(|(k, kv_map)| {
        kv_map
            .iter()
            .map(move |(sk, bts)| (k, sk, bts.iter().map(Bytes::as_ref)))
    })
}
