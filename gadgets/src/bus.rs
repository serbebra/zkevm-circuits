//! LogUp chip

use eth_types::Field;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Phase, VirtualCells},
    poly::Rotation,
};
use std::marker::PhantomData;

use crate::util::{query_expression, Expr};

/// BusConfig
pub struct BusConfig<F> {
    enabled: Column<Fixed>,
    is_first: Column<Fixed>,
    is_last: Column<Fixed>,
    acc: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BusConfig<F> {
    /// Create a new bus.
    pub fn new(cs: &mut ConstraintSystem<F>, terms: &[Expression<F>]) -> Self {
        let enabled = cs.fixed_column();
        let is_first = cs.fixed_column();
        let is_last = cs.fixed_column();
        let acc = cs.advice_column();

        cs.create_gate("bus sum check", |cs| {
            let enabled = cs.query_fixed(enabled, Rotation::cur());
            let is_first = cs.query_fixed(is_first, Rotation::cur());
            let is_last = cs.query_fixed(is_last, Rotation::cur());

            let acc_next = cs.query_advice(acc, Rotation::next());
            let acc = cs.query_advice(acc.clone(), Rotation::cur());

            let sum = terms.iter().fold(0.expr(), |acc, term| acc + term.clone());
            let next_or_zero = (1.expr() - is_last) * acc_next;

            [
                // If is_first, then initialize: `acc = ∑terms`.
                is_first * (acc.clone() - sum.clone()),
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
            _marker: PhantomData,
        }
    }
}

/// BusBuilder
pub struct BusBuilder<F> {
    rand: Expression<F>,
    terms: Vec<Expression<F>>,
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
    pub fn terms(self) -> Vec<Expression<F>> {
        self.terms
    }
}

/// A bus operation.
pub struct BusOp<F> {
    count: Expression<F>,
    value: Expression<F>,
}

impl<F: FieldExt> BusOp<F> {
    /// Put an item. The expression evaluates to 0 or the number of copies.
    pub fn put(count: Expression<F>, value: Expression<F>) -> Self {
        Self { count, value }
    }

    /// Take an item. The expression evaluates to 0 or 1.
    pub fn take(count: Expression<F>, value: Expression<F>) -> Self {
        Self {
            count: -count,
            value,
        }
    }

    /// The expression of the count of items to put or take.
    pub fn count(&self) -> Expression<F> {
        self.count.clone()
    }

    /// The expression of the value to put or take.
    pub fn value(&self) -> Expression<F> {
        self.value.clone()
    }
}

/// BusPort prepares a term to be added to the bus.
pub trait BusPort<F: FieldExt> {
    /// The term to add to the bus. This expression must be fully constrained on all rows.
    fn create_term(&self, meta: &mut ConstraintSystem<F>, rand: Expression<F>) -> Expression<F>;
}

// ----------------------------------------

/// An access to the bus.
pub struct BusPortSingle<F> {
    helper: Expression<F>,
    op: BusOp<F>,
}

impl<F: FieldExt> BusPortSingle<F> {
    /// Create a new bus port with a single access.
    pub fn new(helper: Expression<F>, op: BusOp<F>) -> Self {
        Self { helper, op }
    }
}

impl<F: FieldExt> BusPort<F> for BusPortSingle<F> {
    fn create_term(&self, meta: &mut ConstraintSystem<F>, rand: Expression<F>) -> Expression<F> {
        let term = self.op.count() * self.helper.clone();

        meta.create_gate("bus access", |_| {
            // Verify that `term = count / (rand + value)`.
            //
            // If `count = 0`, then `term = 0` by definition. In that case, the helper cell is not
            // constrained, so it can be used for something else.
            [term.clone() * (rand + self.op.value()) - self.op.count()]
        });

        term
    }
}

// ----------------------------------------

/// A bus port with two accesses. BusPortDual uses only one witness cell, however the degree of
/// input expressions is more limited than with BusPortSingle.
pub struct BusPortDual<F> {
    helper: Expression<F>,
    ops: [BusOp<F>; 2],
}

impl<F: FieldExt> BusPortDual<F> {
    /// Create a new bus port with two accesses.
    pub fn new(helper: Expression<F>, ops: [BusOp<F>; 2]) -> Self {
        Self { helper, ops }
    }
}

impl<F: FieldExt> BusPort<F> for BusPortDual<F> {
    fn create_term(&self, meta: &mut ConstraintSystem<F>, rand: Expression<F>) -> Expression<F> {
        let rv_0 = rand.clone() + self.ops[0].value();
        let rv_1 = rand.clone() + self.ops[1].value();

        // With witness: helper = 1 / rv_0 / rv_1

        // term_0 = count_0 * helper * rv_1
        let count_0 = self.ops[0].count();
        let term_0 = count_0.clone() * self.helper.clone() * rv_1.clone();

        // term_1 = count_1 * helper * rv_0
        let count_1 = self.ops[1].count();
        let term_1 = count_1.clone() * self.helper.clone() * rv_0.clone();

        // Verify that:
        //     term_0 == count_0 / rv_0
        //     term_0 * rv_0 - count_0 == 0
        // And:
        //     term_1 == count_1 / rv_1
        //     term_1 * rv_1 - count_1 == 0
        //
        // In case both count_0 and count_1 are zero, then the helper cell is not constrained, so it
        // can be used for something else.
        meta.create_gate("bus access (dual)", |_| {
            [
                term_0.clone() * rv_0 - count_0,
                term_1.clone() * rv_1 - count_1,
            ]
        });

        term_0 + term_1
    }
}

// ----------------------------------------

/// BusPort to access the bus. It manages its own helper column.
pub struct BusPortColumn<F> {
    helper: Column<Advice>,
    multi: BusPortMulti<F>,
}

impl<F: FieldExt> BusPortColumn<F> {
    /// Create a new bus port with a single access.
    pub fn put(meta: &mut ConstraintSystem<F>, op: BusOp<F>) -> Self {
        let helper = meta.advice_column();
        let helper_expr = query_expression(meta, |meta| meta.query_advice(helper, Rotation::cur()));

        let multi = BusPortMulti::new(helper_expr, vec![op]);

        Self { helper, multi }
    }
}

impl<F: FieldExt> BusPort<F> for BusPortColumn<F> {
    fn create_term(&self, meta: &mut ConstraintSystem<F>, rand: Expression<F>) -> Expression<F> {
        self.multi.create_term(meta, rand)
    }
}

// ----------------------------------------

/// BusPort to access the bus. The most flexible port. The helper cell is provided by the caller. It
/// supports multiple put/take accesses, as long as only one is active at a time.
pub struct BusPortMulti<F> {
    helper: Expression<F>,
    ops: Vec<BusOp<F>>,
}

impl<F: FieldExt> BusPortMulti<F> {
    /// Put one out of several possible items to the bus.
    /// The operations `ops` must be mutually exclusives (only one `count` is non-zero at a time)
    /// across all puts and takes.
    pub fn put(helper: Expression<F>, ops: Vec<BusOp<F>>) -> Self {
        BusPortMulti { helper, ops }
    }

    /// Create a new bus port.
    fn new(helper: Expression<F>, ops: Vec<BusOp<F>>) -> Self {
        BusPortMulti { helper, ops }
    }
}

impl<F: FieldExt> BusPort<F> for BusPortMulti<F> {
    fn create_term(&self, meta: &mut ConstraintSystem<F>, rand: Expression<F>) -> Expression<F> {
        let rand = 1.expr(); // TODO

        meta.create_gate("bus access", |_| {
            self.ops
                .iter()
                .map(|op| {
                    // If count != 0, then helper = 1 / (rand + value)
                    op.count() * (self.helper.clone() * (rand.clone() + op.value()) - 1.expr())
                })
                .collect::<Vec<_>>()
        });

        let count_sum = self.ops.iter().fold(0.expr(), |acc, op| acc + op.count());

        self.helper.clone() * count_sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{ConstraintSystem, FirstPhase},
    };

    #[test]
    fn test_bus() {
        let cs = &mut ConstraintSystem::<Fr>::default();
        cs.advice_column(); // Bypass illogical validation.

        let rand = cs.challenge_usable_after(FirstPhase);
        let rand_expr = query_expression(cs, |cs| cs.query_challenge(rand));
        let mut bus_builder = BusBuilder::<Fr>::new(rand_expr);

        // Circuit 1.
        let port = BusPortColumn::put(cs, BusOp::put(1.expr(), 2.expr()));
        bus_builder.connect_port(cs, &port);

        // Circuit 2.
        let port = BusPortColumn::put(cs, BusOp::put(1.expr(), 2.expr()));
        bus_builder.connect_port(cs, &port);

        // Global bus connection.
        let bus_check = BusConfig::new(cs, &bus_builder.terms());
    }
}

/*

sum( (1 / item) for each value ) == 0

item = RLC(beta, [ 1, circuit_tag, RLC(alpha, x), y, z, … ] )
                   1,    RW,  address, value
                   1,   COPY, src, dst, len
                   …

+0*item
+3*item
-item
-item
-item


Bus Check:
- on each row, sum_next = sum_current + term_circuit1 + term_circuit2 + … + term_circut10
- if is_last, sum_current == 0

Circuit 1:
term_circuit1 * value == 1

*/
