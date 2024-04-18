//! Input a set of proofs, a simple aggregation circuit generates a new proof that asserts all input
//! proofs are correct.
//!
//! It re-exposes same public inputs from the input snarks.

/// Circuit implementation of simple aggregation circuit.
mod circuit;
/// CircuitExt implementation of simple aggregation circuit.
mod circuit_ext;
/// Config for simple aggregation circuit
mod config;

pub use circuit::SimpleAggregationCircuit;
pub use config::SimpleAggregationConfig;
