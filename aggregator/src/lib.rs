/// proof aggregation
mod aggregation;
/// This module implements `Batch` related data types.
/// A batch is a list of chunk.
mod batch;
// This module implements `Chunk` related data types.
// A chunk is a list of blocks.
mod chunk;
// /// proof compression
// mod compression;
mod compression_v2;
/// Configurations
mod constants;
// /// Core module for circuit assignment
// mod core;
/// Parameters for compression circuit
mod param;
/// utilities
mod util;

#[cfg(test)]
mod tests;

// pub use self::core::extract_proof_and_instances_with_pairing_check;
pub use aggregation::*;
pub use batch::BatchHash;
pub use chunk::ChunkHash;
// pub use compression::*;
pub use constants::MAX_AGG_SNARKS;

pub use param::*;

pub(crate) use compression_v2::*;
pub(crate) use constants::*;

use halo2_proofs::halo2curves::bn256::Bn256;
use snark_verifier::{
    pcs::kzg::{Bdfg21, KzgAs, LimbsEncoding},
    verifier,
};

/// accumulation scheme used for aggregator.
type AccScheme = KzgAs<Bn256, Bdfg21>;
/// prove the accumulators are generated faithfully; defer the accumulator check to decider.
type PlonkSuccinctVerifier =
    verifier::plonk::PlonkSuccinctVerifier<AccScheme, LimbsEncoding<LIMBS, BITS>>;
