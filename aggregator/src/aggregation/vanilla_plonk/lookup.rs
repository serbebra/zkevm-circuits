// todo: remove
#![allow(dead_code)]

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, SecondPhase},
};
use itertools::Itertools;
use zkevm_circuits::table::LookupTable;

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
    pub(crate) fn construct(lookup_table: LookupTable) -> Self {
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
        input_rlc_cells: &[AssignedCell<Fr, Fr>],
        output_rlc_cells: &[AssignedCell<Fr, Fr>],
    ) -> Result<(), Error> {
        assert_eq!(input_rlc_cells.len(), output_rlc_cells.len());

        // assign the RLC cells
        layouter.assign_region(
            || "hash lookup table",
            |mut region| {
                input_rlc_cells
                    .iter()
                    .zip_eq(output_rlc_cells.iter())
                    .enumerate()
                    .for_each(|(offset, (input_rlc_cell, output_rlc_cell))| {
                        assign_row(
                            &mut region,
                            offset,
                            self.q_enable,
                            input_rlc_cell,
                            self.input_rlcs,
                            output_rlc_cell,
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

fn assign_row(
    region: &mut Region<'_, Fr>,
    offset: usize,
    q_enable: Column<Fixed>,
    input_rlc_cell: &AssignedCell<Fr, Fr>,
    input_rlc_column: Column<Advice>,
    output_rlc_cell: &AssignedCell<Fr, Fr>,
    output_rlc_column: Column<Advice>,
) -> Result<(), Error> {
    // enable selector for the current row
    {
        let _ = region.assign_fixed(
            || format!("lookup table q_enable row {offset}"),
            q_enable,
            offset,
            || Value::known(Fr::one()),
        )?;
    }
    // copy inputs to the current row
    {
        let mut input = Fr::zero();
        input_rlc_cell.value().map(|f| input = *f);

        let input_rlc_cell_local = region.assign_advice(
            || format!("lookup table input rlc row {offset}"),
            input_rlc_column,
            offset,
            || Value::known(input),
        )?;
        region.constrain_equal(input_rlc_cell.cell(), input_rlc_cell_local.cell())?;
    }
    //  copy outputs to the current row
    {
        let mut output = Fr::zero();
        output_rlc_cell.value().map(|f| output = *f);

        let output_rlc_cell_local = region.assign_advice(
            || format!("lookup table input rlc row {offset}"),
            output_rlc_column,
            offset,
            || Value::known(output),
        )?;
        region.constrain_equal(output_rlc_cell.cell(), output_rlc_cell_local.cell())?;
    }

    Ok(())
}
