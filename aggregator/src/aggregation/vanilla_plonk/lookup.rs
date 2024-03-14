// todo: remove
#![allow(dead_code)]

use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, SecondPhase},
};
use itertools::Itertools;
use zkevm_circuits::util::Challenges;

use crate::util::rlc;

/// Lookup table for the hash input and output RLCs
#[derive(Debug, Clone, Copy)]
pub(crate) struct HashValueLookupTable {
    /// q_enable
    pub q_enable: Column<Fixed>,
    // todo: merge the two columns into one for optimization
    /// Input RLCs
    pub input_rlcs: Column<Advice>,
    /// Output RLCs
    pub output_rlcs: Column<Advice>,
}

impl HashValueLookupTable {
    /// Construct a new HashValueLookupTable
    pub(crate) fn construct(meta: &mut ConstraintSystem<Fr>) -> Self {
        Self {
            q_enable: meta.fixed_column(),
            input_rlcs: meta.advice_column_in(SecondPhase),
            output_rlcs: meta.advice_column_in(SecondPhase),
        }
    }

    /// Assign the table with a list of hash inputs/outputs
    pub fn load(
        &self,
        layouter: &mut impl Layouter<Fr>,
        input_rlcs: &[Fr],
        output_rlcs: &[Fr],
    ) -> Result<(), Error> {
        fn assign_row(
            region: &mut Region<'_, Fr>,
            offset: usize,
            q_enable: Column<Fixed>,
            input_rlc: &Fr,
            input_rlc_column: Column<Advice>,
            output_rlc: &Fr,
            output_rlc_column: Column<Advice>,
        ) -> Result<(), Error> {
            let _ = region.assign_fixed(
                || format!("lookup table q_enable row {offset}"),
                q_enable,
                offset,
                || Value::known(Fr::one()),
            )?;

            let _ = region.assign_advice(
                || format!("lookup table input rlc row {offset}"),
                input_rlc_column,
                offset,
                || Value::known(*input_rlc),
            );
            let _ = region.assign_advice(
                || format!("lookup table output rlc row {offset}"),
                output_rlc_column,
                offset,
                || Value::known(*output_rlc),
            );
            Ok(())
        }

        assert_eq!(input_rlcs.len(), output_rlcs.len());

        // assign the RLC cells
        layouter.assign_region(
            || "hash lookup table",
            |mut region| {
                input_rlcs
                    .iter()
                    .zip_eq(output_rlcs.iter())
                    .enumerate()
                    .for_each(|(offset, (input_rlc, output_rlc))| {
                        assign_row(
                            &mut region,
                            offset,
                            self.q_enable,
                            input_rlc,
                            self.input_rlcs,
                            output_rlc,
                            self.output_rlcs,
                        )
                        .unwrap();
                    });
                Ok(())
            },
        )?;
        Ok(())
    }
}
