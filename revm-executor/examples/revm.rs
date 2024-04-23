use bus_mapping::circuit_input_builder::{CircuitInputBuilder, CircuitsParams};
use eth_types::{l2_types::BlockTrace, ToWord};
use glob::glob;
use halo2_proofs::halo2curves::bn256::Fr;
use revm_executor::executor::EvmExecutor;
use std::env;
use zkevm_circuits::witness::{block_convert, Block};

fn main() {
    env_logger::init();

    let circuits_params = CircuitsParams {
        max_rws: 100000,
        max_txs: 100,
        ..Default::default()
    };

    for entry in glob(&format!(
        "{}/batch_*/**/*.json",
        env::var("TRACE_PATH").unwrap()
    ))
    .unwrap()
    {
        let path = entry.unwrap();
        log::info!("Processing {:?}", path);
        let trace = std::fs::read_to_string(&path).unwrap();
        let l2_trace: BlockTrace = serde_json::from_str(&trace).unwrap_or_else(|_| {
            #[derive(serde::Deserialize, Default, Debug, Clone)]
            pub struct BlockTraceJsonRpcResult {
                pub result: BlockTrace,
            }
            serde_json::from_str::<BlockTraceJsonRpcResult>(&trace)
                .unwrap()
                .result
        });

        let root_after = l2_trace.storage_trace.root_after.to_word();

        let mut executor = EvmExecutor::new(&l2_trace);
        let revm_root_after = executor.handle_block(&l2_trace);
        let mut revm_updates = executor.db.updates;
        revm_updates.retain(|_, v| v.old_value != v.new_value);

        let mut builder =
            CircuitInputBuilder::new_from_l2_trace(circuits_params, l2_trace, false, false)
                .unwrap();
        builder.finalize_building().unwrap();
        let mut block: Block<Fr> = block_convert(&builder.block, &builder.code_db).unwrap();
        block
            .mpt_updates
            .fill_state_roots(builder.mpt_init_state.as_ref().unwrap());

        block.mpt_updates.diff(revm_updates);
        if revm_root_after != root_after {
            log::error!(
                "Root mismatch: {:?}, revm {:x}, l2 {:x}",
                path,
                revm_root_after,
                root_after
            );
        }
    }
}
