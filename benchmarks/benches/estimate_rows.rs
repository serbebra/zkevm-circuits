use benchmarks::utils::TracesFileIterator;
use criterion::*;
use eth_types::l2_types::BlockTrace;
use prover::zkevm::circuit::{SuperCircuit, TargetCircuit};
use std::env::var;

fn bench(c: &mut Criterion) {
    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
    let mut group = c.benchmark_group("estimate_rows");
    group.sample_size(10).plot_config(plot_config);

    let traces = TracesFileIterator::from_dir(var("TRACE_PATH").unwrap());

    for trace in traces {
        let size = trace.as_bytes().len();
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            let block_trace =
                serde_json::from_str::<BlockTrace>(&trace).expect("deserialize block trace");
            let traces = vec![block_trace];
            b.iter(|| SuperCircuit::estimate_rows(black_box(&traces)));
            // b.iter_batched(
            //     || block_trace.clone(),
            //     |trace| SuperCircuit::estimate_block_rows(trace),
            //     BatchSize::SmallInput,
            // )
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
