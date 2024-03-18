// use halo2_proofs::{
//     circuit::{AssignedCell, Layouter, Region, Value},
//     halo2curves::bn256::Fr,
//     plonk::{Advice, Column, ConstraintSystem, Error, Fixed, SecondPhase},
// };
// use itertools::Itertools;

// /// Lookup table for the hash input and output RLCs
// #[derive(Debug, Clone, Copy)]
// pub(crate) struct HashValueLookupTable {
//     /// q_enable
//     pub q_enable: Column<Fixed>,
//     // todo: merge the two columns into one for optimization
//     /// Input RLCs
//     pub input_rlcs: Column<Advice>,
//     /// Output RLCs
//     pub output_rlcs: Column<Advice>,
// }
