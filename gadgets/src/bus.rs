//! LogUp chip

use eth_types::Field;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Phase, VirtualCells},
    poly::Rotation,
};
use std::marker::PhantomData;

use crate::util::{query_expression, Expr};

/// BusConfig
#[derive(Default)]
pub struct BusConfig<F> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BusConfig<F> {
    /// Create a new bus.
    pub fn new(meta: &mut ConstraintSystem<F>, terms: &[Expression<F>]) -> BusConfig<F> {
        BusConfig::default()
    }
}

/// BusBuilder
#[derive(Default)]
pub struct BusBuilder<F> {
    terms: Vec<Expression<F>>,
}

impl<F: FieldExt> BusBuilder<F> {
    /// Connect a port to the bus.
    pub fn connect_port<BP: BusPort<F>>(&mut self, meta: &mut ConstraintSystem<F>, port: &BP) {
        let term = port.create_term(meta);
        self.terms.push(term);
    }

    /// Return the collected terms.
    pub fn terms(self) -> Vec<Expression<F>> {
        self.terms
    }
}

/// BusPort prepares a term to be added to the bus.
pub trait BusPort<F: FieldExt> {
    /// The term to add to the bus. This expression must be fully constrained on all rows.
    fn create_term(&self, meta: &mut ConstraintSystem<F>) -> Expression<F>;
}

/// BusPort to access the bus. It manages its own helper column.
pub struct BusPortSingle<F> {
    helper: Column<Advice>,
    multi: BusPortMulti<F>,
}

impl<F: FieldExt> BusPortSingle<F> {
    /// Create a new bus port with a single access.
    pub fn put(meta: &mut ConstraintSystem<F>, op: BusOp<F>, value: Expression<F>) -> Self {
        let helper = meta.advice_column();
        let helper_expr = query_expression(meta, |meta| meta.query_advice(helper, Rotation::cur()));

        let multi = BusPortMulti::new(helper_expr, vec![(op, value.clone())]);

        Self { helper, multi }
    }
}

impl<F: FieldExt> BusPort<F> for BusPortSingle<F> {
    fn create_term(&self, meta: &mut ConstraintSystem<F>) -> Expression<F> {
        self.multi.create_term(meta)
    }
}

/// A bus operation.
pub enum BusOp<F> {
    /// Put an item. The expression evaluates to 0 or the number of copies.
    Put(Expression<F>),
    /// Take an item. The expression evaluates to 0 or 1.
    Take(Expression<F>),
}

impl<F: FieldExt> BusOp<F> {
    /// The expression of the count of items to put or take.
    pub fn expr(&self) -> Expression<F> {
        match self {
            BusOp::Put(e) => e.clone(),
            BusOp::Take(e) => -e.clone(),
        }
    }
}

/// BusPort to access the bus. The most flexible port. The helper cell is provided by the caller. It
/// supports multiple put/take accesses, as long as only one is active at a time.
pub struct BusPortMulti<F> {
    helper: Expression<F>,
    ops: Vec<(BusOp<F>, Expression<F>)>,
}

impl<F: FieldExt> BusPortMulti<F> {
    /// Put one out of several possible items to the bus.
    /// The operations `ops` must be mutually exclusives (only one `count` is non-zero at a time)
    /// across all puts and takes.
    pub fn put(helper: Expression<F>, ops: Vec<(BusOp<F>, Expression<F>)>) -> Self {
        BusPortMulti { helper, ops }
    }

    /// Create a new bus port.
    fn new(helper: Expression<F>, ops: Vec<(BusOp<F>, Expression<F>)>) -> Self {
        BusPortMulti { helper, ops }
    }
}

impl<F: FieldExt> BusPort<F> for BusPortMulti<F> {
    fn create_term(&self, meta: &mut ConstraintSystem<F>) -> Expression<F> {
        let rand = 1.expr(); // TODO

        meta.create_gate("bus access", |meta| {
            self.ops
                .iter()
                .map(|(count, value)| {
                    // If count != 0, then helper = 1 / (rand + value)
                    count.expr() * (self.helper.clone() * (rand.clone() + value.clone()) - 1.expr())
                })
                .collect::<Vec<_>>()
        });

        let count_sum = self
            .ops
            .iter()
            .fold(0.expr(), |acc, (count, _)| acc + count.expr());

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
        plonk::ConstraintSystem,
    };

    #[test]
    fn test_bus() {
        let cs = &mut ConstraintSystem::<Fr>::default();

        let mut bus_builder = BusBuilder::<Fr>::default();

        // Circuit 1.
        let port = BusPortSingle::put(cs, BusOp::Put(1.expr()), 2.expr());
        bus_builder.connect_port(cs, &port);

        // Circuit 2.
        let port = BusPortSingle::put(cs, BusOp::Put(1.expr()), 2.expr());
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