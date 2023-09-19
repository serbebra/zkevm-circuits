use super::bus_chip::BusPort;
use crate::util::query_expression;
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Expression},
    poly::Rotation,
};

/// A bus operation.
#[derive(Clone)]
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

/// A chip to access to the bus.
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

/// A chip with two accesses to the bus. BusPortDual uses only one witness cell, however the
/// degree of input expressions is more limited than with BusPortSingle.
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

/// A chip to access the bus. It manages its own helper column.
pub struct BusPortColumn<F> {
    helper: Column<Advice>,
    port: BusPortSingle<F>,
}

impl<F: FieldExt> BusPortColumn<F> {
    /// Create a new bus port with a single access.
    pub fn put(meta: &mut ConstraintSystem<F>, op: BusOp<F>) -> Self {
        let helper = meta.advice_column();
        let helper_expr = query_expression(meta, |meta| meta.query_advice(helper, Rotation::cur()));

        let port = BusPortSingle::new(helper_expr, op);

        Self { helper, port }
    }
}

impl<F: FieldExt> BusPort<F> for BusPortColumn<F> {
    fn create_term(&self, meta: &mut ConstraintSystem<F>, rand: Expression<F>) -> Expression<F> {
        self.port.create_term(meta, rand)
    }
}
