// /// Circuit implementation of aggregation circuit.
// mod circuit;
// /// Config for aggregation circuit
// mod config;
/// Circuit implementation of aggregation circuit.
mod circuit_v2;
/// Config for aggregation circuit
mod config_v2;
/// config for RLC circuit
mod rlc;

pub use circuit_v2::AggregationCircuit;
pub use config_v2::AggregationConfig;
pub use rlc::RlcConfig;
