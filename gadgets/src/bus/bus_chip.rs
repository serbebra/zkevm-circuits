use std::marker::PhantomData;

use crate::util::Expr;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, ThirdPhase},
    poly::Rotation,
};

/// A term of the bus sum check.
#[derive(Clone, Debug)]
pub struct BusTerm<F>(Expression<F>);

impl<F> BusTerm<F> {
    /// Wrap an expression to indicate that it was properly constructed as a bus term.
    pub fn verified(term: Expression<F>) -> Self {
        Self(term)
    }
}

impl<F: FieldExt> Expr<F> for BusTerm<F> {
    fn expr(&self) -> Expression<F> {
        self.0.clone()
    }
}

/// BusConfig
#[derive(Clone, Debug)]
pub struct BusConfig {
    enabled: Column<Fixed>,
    is_first: Column<Fixed>,
    is_last: Column<Fixed>,
    acc: Column<Advice>,
}

impl BusConfig {
    /// Create a new bus.
    pub fn new<F: FieldExt>(cs: &mut ConstraintSystem<F>, terms: &[BusTerm<F>]) -> Self {
        let enabled = cs.fixed_column();
        let is_first = cs.fixed_column();
        let is_last = cs.fixed_column();
        let acc = cs.advice_column_in(ThirdPhase);

        cs.create_gate("bus sum check", |cs| {
            let enabled = cs.query_fixed(enabled, Rotation::cur());
            let is_first = cs.query_fixed(is_first, Rotation::cur());
            let is_last = cs.query_fixed(is_last, Rotation::cur());

            let acc_next = cs.query_advice(acc, Rotation::next());
            let acc = cs.query_advice(acc.clone(), Rotation::cur());

            let sum = terms
                .iter()
                .fold(0.expr(), |acc, term| acc + term.0.clone());
            let next_or_zero = (1.expr() - is_last) * acc_next;

            [
                // If is_first, then initialize: `acc = 0`.
                is_first * acc.clone(),
                // If not is_last, then accumulate: `acc_next = acc + ∑terms`
                // If is_last, then the final sum is zero: `0 = acc + ∑terms`
                enabled * (next_or_zero - (acc.clone() + sum)),
            ]
        });

        Self {
            enabled,
            is_first,
            is_last,
            acc,
        }
    }

    /// Assign the helper witness.
    pub fn assign<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        n_rows: usize,
        terms: Value<&[F]>,
    ) -> Result<(), Error> {
        /*assert_eq!(
            region.global_offset(0),
            0,
            "The bus requires a global region"
        );*/

        region.assign_fixed(
            || "Bus_is_first",
            self.is_first,
            0,
            || Value::known(F::one()),
        )?;

        region.assign_fixed(
            || "Bus_is_last",
            self.is_last,
            n_rows - 1,
            || Value::known(F::one()),
        )?;

        for offset in 0..n_rows {
            region.assign_fixed(
                || "Bus_enable",
                self.enabled,
                offset,
                || Value::known(F::one()),
            )?;
        }

        println!("XXX bus enabled up to row {}", n_rows - 1);

        terms.map(|terms| {
            assert!(terms.len() <= n_rows, "Bus terms out-of-bound");
            let mut acc = F::zero();

            for offset in 0..n_rows {
                region
                    .assign_advice(|| "Bus_acc", self.acc, offset, || Value::known(acc))
                    .unwrap();

                if let Some(term) = terms.get(offset) {
                    acc = acc + term;
                }
            }
        });
        Ok(())
    }
}
