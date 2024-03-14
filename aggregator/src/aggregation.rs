/// Circuit implementation of aggregation circuit.
mod circuit;
/// Config for aggregation circuit
mod config;
/// config for RLC circuit
mod vanilla_plonk;

pub use circuit::AggregationCircuit;
pub use config::AggregationConfig;
pub(crate) use vanilla_plonk::VanillaPlonkConfig;
