use benchmarks::utils::TracesFileIterator;
use criterion::*;
use eth_types::l2_types::BlockTrace;
use std::env::var;

fn bench(c: &mut Criterion) {
    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
    let mut group = c.benchmark_group("serde_block_trace");
    group.sample_size(10).plot_config(plot_config);

    let traces = TracesFileIterator::from_dir(var("TRACE_PATH").unwrap());

    for trace in traces {
        let size = trace.as_bytes().len();
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter_with_large_drop(|| serde_json::from_str::<BlockTrace>(black_box(&trace)))
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
