use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase},
    poly::Rotation,
};
use std::marker::PhantomData;

use crate::util::Expr;

/// A term of the bus sum check.
#[derive(Clone)]
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
#[derive(Clone)]
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
        let acc = cs.advice_column_in(SecondPhase);

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
        terms: &[Value<F>],
    ) -> Result<(), Error> {
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

        let mut acc = Value::known(F::zero());

        for offset in 0..n_rows {
            region.assign_advice(|| "Bus_acc", self.acc, offset, || acc)?;

            if let Some(term) = terms.get(offset) {
                acc = acc + term;
            }
        }
        Ok(())
    }
}

/// BusBuilder
pub struct BusBuilder<F> {
    rand: Expression<F>,
    terms: Vec<BusTerm<F>>,
}

impl<F: FieldExt> BusBuilder<F> {
    /// Create a new bus.
    pub fn new(rand: Expression<F>) -> Self {
        Self {
            rand,
            terms: vec![],
        }
    }

    /// Connect a port to the bus.
    pub fn connect_port<BP: BusPort<F>>(&mut self, meta: &mut ConstraintSystem<F>, port: &BP) {
        let term = port.create_term(meta, self.rand.clone());
        self.terms.push(term);
    }

    /// Return the collected terms.
    pub fn terms(self) -> Vec<BusTerm<F>> {
        self.terms
    }
}

/// BusPort prepares a term to be added to the bus.
pub trait BusPort<F: FieldExt> {
    /// The term to add to the bus. This expression must be fully constrained on all rows.
    fn create_term(&self, meta: &mut ConstraintSystem<F>, rand: Expression<F>) -> BusTerm<F>;
}
