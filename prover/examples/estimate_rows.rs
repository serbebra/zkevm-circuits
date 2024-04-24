use prover::{
    zkevm::circuit::{SuperCircuit, TargetCircuit},
    BlockTrace,
};
use std::fs::File;
use zkevm_circuits::evm_circuit::ExecutionState;

fn main() {
    let trace = std::fs::read_to_string(std::env::var("TRACE_FILE").unwrap()).unwrap();

    let block_trace: BlockTrace = serde_json::from_str(&trace).unwrap();
    let block_trace = vec![block_trace];
    println!("{}", ExecutionState::BeginTx.get_step_height());
    let now = std::time::Instant::now();
    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(1000)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()
        .unwrap();
    let result = estimate_rows(block_trace);
    if let Ok(report) = guard.report().build() {
        let file = File::create("flamegraph.svg").unwrap();
        report.flamegraph(file).unwrap();
    };
    let elapsed = now.elapsed();
    println!("elapsed: {elapsed:?}, result: {result}");
}

#[inline(never)]
fn estimate_rows(trace: Vec<BlockTrace>) -> usize {
    let result = SuperCircuit::estimate_rows(trace).unwrap();
    result
}
