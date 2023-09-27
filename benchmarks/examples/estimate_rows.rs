use eth_types::l2_types::BlockTrace;
use prover::zkevm::circuit::{SuperCircuit, TargetCircuit};
use std::env::var;

fn main() {
    let trace = std::fs::read_to_string(var("TRACE_PATH").unwrap()).unwrap();
    let block_trace = serde_json::from_str::<BlockTrace>(&trace).expect("deserialize block trace");
    let result = SuperCircuit::estimate_rows(&vec![block_trace]).unwrap();
    println!("result: {result:?}");
}
