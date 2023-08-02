//! Specialized version to replace LtChip for u16/u32/u64/u128 check
//!
//! only constrain input expressions to be in given range
//! do not output the result

use crate::util::Expr;
use eth_types::Field;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, TableColumn, VirtualCells},
    poly::Rotation,
};

/// Instruction that the Range chip needs to implement.
pub trait RangeCheckInstruction<F: FieldExt, const N_2BYTE: usize> {
    /// Assign the expr and u16 le repr witnesses to the Comparator chip's region.
    fn assign(&self, region: &mut Region<F>, offset: usize, value: F) -> Result<(), Error>;
}

/// Config for the Range chip.
///
/// `N_2BYTE` is size of range in (u16) 2-byte.
/// for u32, N_2BYTE = 2; for u64, N_2BYTE = 4; for u128, N_2BYTE = 8
///
/// `N_EXPR` is the number of lookup expressions to check.
#[derive(Clone, Copy, Debug)]
pub struct RangeCheckConfig<F, const N_2BYTE: usize> {
    /// Denotes the little-endian representation of expression in u16.
    pub u16_repr: [Column<Advice>; N_2BYTE],
    /// Denotes the u16 lookup table.
    pub u16_table: TableColumn,
    _marker: std::marker::PhantomData<F>,
}

/// Chip that checks if expressions are in range.
#[derive(Clone, Debug)]
pub struct RangeCheckChip<F, const N_2BYTE: usize> {
    config: RangeCheckConfig<F, N_2BYTE>,
}

impl<F: Field, const N_2BYTE: usize> RangeCheckChip<F, N_2BYTE> {
    /// Configures the range chip.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<F>) -> Expression<F> + Clone,
        expressions: impl FnOnce(&mut VirtualCells<F>) -> Expression<F>,
        u16_table: TableColumn,
    ) -> RangeCheckConfig<F, N_2BYTE> {
        let u16_repr = [(); N_2BYTE].map(|_| meta.advice_column());

        meta.create_gate("range gate", |meta| {
            let q_enable = q_enable.clone()(meta);
            let acc = (0..N_2BYTE)
                .rev()
                .map(|col_idx| meta.query_advice(u16_repr[col_idx], Rotation::cur()))
                .fold(0.expr(), |acc, cell| acc * 0x10000.expr() + cell);
            vec![q_enable.clone() * (expressions(meta) - acc)]
        });

        for column in u16_repr {
            meta.lookup(concat!("u16 cell range check"), |meta| {
                let q_enable = q_enable.clone()(meta);
                let cell = meta.query_advice(column, Rotation::cur());
                vec![(q_enable.clone() * cell, u16_table)]
            });
        }

        RangeCheckConfig {
            u16_repr,
            u16_table,
            _marker: Default::default(),
        }
    }

    pub fn construct(config: RangeCheckConfig<F, N_2BYTE>) -> Self {
        Self { config }
    }
}

impl<F: Field, const N_2BYTE: usize> RangeCheckInstruction<F, N_2BYTE>
    for RangeCheckChip<F, N_2BYTE>
{
    fn assign(&self, region: &mut Region<'_, F>, offset: usize, value: F) -> Result<(), Error> {
        let config = self.config();

        // assign u16 repr
        let repr: [u8; 32] = value.to_repr();
        for (col_idx, (column, value)) in config
            .u16_repr
            .iter()
            .copied()
            .zip(repr.chunks(2).take(N_2BYTE))
            .enumerate()
        {
            region.assign_advice(
                || format!("range expr u16_cell[{col_idx}]"),
                column,
                offset,
                || Value::known(F::from((value[0] as u16 | ((value[1] as u16) << 8)) as u64)),
            )?;
        }

        Ok(())
    }
}

impl<F: Field, const N_2BYTE: usize> Chip<F> for RangeCheckChip<F, N_2BYTE> {
    type Config = RangeCheckConfig<F, N_2BYTE>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
