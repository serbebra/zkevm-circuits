use bus_mapping::{
    circuit_input_builder::{AccessSet, Block, BlockHead, CircuitInputBuilder, CircuitsParams},
    state_db,
    state_db::{CodeDB, StateDB},
};
use eth_types::{
    evm_types::OpcodeId,
    l2_types::{BlockTrace, EthBlock},
    GethExecTrace, ToWord, H256, U256,
};
use ethers_core::utils::keccak256;
use log::trace;
use serde::Deserialize;
use std::collections::HashMap;

fn main() {
    env_logger::init();

    let trace = std::fs::read_to_string(std::env::var("TRACE_FILE").unwrap()).unwrap();

    let mut block_trace: BlockTrace = serde_json::from_str(&trace).unwrap();
    for trace in block_trace.execution_results.iter_mut() {
        for step in trace.exec_steps.iter_mut() {
            if matches!(step.op, OpcodeId::SLOAD | OpcodeId::SSTORE) {
                let proofs = step
                    .extra_data
                    .as_ref()
                    .unwrap()
                    .proof_list
                    .as_ref()
                    .unwrap();
                let mut storage = HashMap::new();
                for proof in proofs.iter() {
                    if let Some(ref s) = proof.storage {
                        storage.insert(s.key.unwrap(), s.value.unwrap());
                    }
                }
                step.storage = Some(storage);
            }
        }
    }
    let eth_block: EthBlock = EthBlock::from(&block_trace);

    let mut sdb = StateDB::new();
    let mut code_db = CodeDB::new();
    let mut access_set = AccessSet::default();

    access_set.add_account(eth_block.author.unwrap());
    for trace in block_trace.execution_results.iter() {
        access_set.extend_from_traces(&trace.prestate);
    }
    for addr in access_set.state.keys() {
        sdb.set_account(addr, state_db::Account::zero());
    }
    for trace in block_trace.execution_results.iter() {
        for (addr, prestate) in trace.prestate.iter() {
            let (code_hash, keccak_code_hash, code_size) = if let Some(ref code) = prestate.code {
                let keccak_code_hash = H256(keccak256(code));
                trace!("trace code {addr:?} {keccak_code_hash:?}");
                let code_hash = code_db.insert(code.to_vec());
                (code_hash, keccak_code_hash, code.len().to_word())
            } else {
                let empty_acc = state_db::Account::zero();
                (
                    empty_acc.code_hash,
                    empty_acc.keccak_code_hash,
                    empty_acc.code_size,
                )
            };
            sdb.set_account(
                addr,
                state_db::Account {
                    nonce: U256::from(prestate.nonce.unwrap_or_default()),
                    balance: prestate.balance.unwrap_or_default(),
                    storage: prestate.storage.clone().unwrap_or_default(),
                    code_hash,
                    keccak_code_hash,
                    code_size,
                },
            );
        }
        // FIXME: this is a workaround, prestate trace should have correct balance for `from`
        let from = trace.from.as_ref().unwrap();
        sdb.get_account_mut(&from.address.unwrap()).1.balance = from.balance.unwrap();
    }

    let head = BlockHead::new(block_trace.chain_id, vec![], &eth_block).unwrap();
    log::info!("head: {head:?}");
    let mut block = Block::from_headers(
        &[head],
        CircuitsParams {
            max_rws: 10000,
            ..Default::default()
        },
    );
    block.prev_state_root = block_trace.storage_trace.root_before.to_word();
    block.chain_id = block_trace.chain_id;
    let mut builder = CircuitInputBuilder::new(sdb, code_db, &block);
    let mut revm_builder = builder.clone();
    revm_builder.handle_block_revm(&block_trace).unwrap();
    log::trace!(
        "revm: end_state_root={:#x} withdraw_root={:#x}",
        revm_builder.block.end_state_root(),
        revm_builder.block.withdraw_root
    );

    let geth_traces = block_trace
        .execution_results
        .clone()
        .into_iter()
        .map(GethExecTrace::from)
        .collect::<Vec<_>>();
    builder.handle_block(&eth_block, &geth_traces).unwrap();
    log::trace!(
        "bus: end_state_root={:#x} withdraw_root={:#x}",
        builder.block.end_state_root(),
        builder.block.withdraw_root
    );

    assert_eq!(
        revm_builder.block.end_state_root(),
        builder.block.end_state_root()
    );
    assert_eq!(
        builder.block.end_state_root(),
        block_trace.storage_trace.root_after.to_word()
    );
}
