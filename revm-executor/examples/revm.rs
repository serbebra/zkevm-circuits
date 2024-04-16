use bus_mapping::circuit_input_builder::{CircuitInputBuilder, CircuitsParams};
use eth_types::{l2_types::BlockTrace, ToWord, U256};
use halo2_proofs::halo2curves::bn256::Fr;
use revm_executor::executor::EvmExecutor;
use std::env;
use zkevm_circuits::witness::{block_convert, Block};

fn main() {
    env_logger::init();

    let circuits_params = CircuitsParams {
        max_rws: 100000,
        max_txs: 10,
        ..Default::default()
    };

    let trace = std::fs::read_to_string(env::var("TRACE_PATH").unwrap()).unwrap();
    let l2_trace: BlockTrace = serde_json::from_str(&trace).unwrap();

    let root_after = l2_trace.storage_trace.root_after.to_word();

    let mut executor = EvmExecutor::new(&l2_trace);
    let revm_root_after = executor.handle_block(&l2_trace);
    let mut revm_updates = executor.db.updates;
    revm_updates.retain(|_, v| v.old_value != v.new_value);
    let revm_updates = revm_updates.into_values().collect::<Vec<_>>();

    let mut builder =
        CircuitInputBuilder::new_from_l2_trace(circuits_params, l2_trace, false, false).unwrap();
    builder.finalize_building().unwrap();
    let mut block: Block<Fr> = block_convert(&builder.block, &builder.code_db).unwrap();
    block
        .mpt_updates
        .fill_state_roots(builder.mpt_init_state.as_ref().unwrap());

    let mut busmapping_updates = block.mpt_updates.updates;
    busmapping_updates.retain(|_, v| v.old_value != v.new_value);
    for v in busmapping_updates.values_mut() {
        v.new_root = U256::zero();
        v.old_root = U256::zero();
        v.original_rws.clear();
    }
    let busmapping_updates = busmapping_updates.into_values().collect::<Vec<_>>();

    assert_eq!(revm_updates, busmapping_updates);
    assert_eq!(revm_root_after, root_after);
}
