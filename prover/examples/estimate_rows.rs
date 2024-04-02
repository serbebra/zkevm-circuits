use prover::{
    types::BlockTraceJsonRpcResult,
    zkevm::circuit::{SuperCircuit, TargetCircuit},
    BlockTrace,
};
use zkevm_circuits::evm_circuit::ExecutionState;

fn main() {
    let trace = std::fs::read_to_string(std::env::var("TRACE_FILE").unwrap()).unwrap();

    let block_trace: BlockTraceJsonRpcResult = serde_json::from_str(&trace).unwrap();
    let block_trace = vec![block_trace.result];
    println!("{}", ExecutionState::BeginTx.get_step_height());
    let now = std::time::Instant::now();
    let result = estimate_rows(block_trace);
    let elapsed = now.elapsed();
    println!("elapsed: {elapsed:?}, result: {result}");
}

#[inline(never)]
fn estimate_rows(trace: Vec<BlockTrace>) -> usize {
    let result = SuperCircuit::estimate_rows(trace).unwrap();
    result
}
