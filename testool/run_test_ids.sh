
export RUST_BACKTRACE=1
export RUST_LOG=trace

cargo run --features scroll --release -- --suite nightly --circuits sc --test-ids test_ids.txt --report

