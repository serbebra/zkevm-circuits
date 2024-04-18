/// proof aggregation, with additional conditions on public inputs
mod aggregation;
/// This module implements `Batch` related data types.
/// A batch is a list of chunk.
mod batch;
// This module implements `Chunk` related data types.
// A chunk is a list of blocks.
mod chunk;
/// proof compression
mod compression;
/// Configurations
mod constants;
/// Core module for circuit assignment
mod core;
/// Parameters for compression circuit
mod param;
/// Simple aggregation; re-exporting public inputs
mod simple_aggregation;
/// utilities
mod util;

#[cfg(test)]
mod tests;

pub use self::core::extract_proof_and_instances_with_pairing_check;
pub use aggregation::*;
pub use batch::BatchHash;
pub use chunk::ChunkHash;
pub use compression::*;
pub use constants::MAX_AGG_SNARKS;
pub(crate) use constants::*;
pub use param::*;
