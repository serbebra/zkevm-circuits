use std::{collections::HashMap, ops::Neg};

use super::{
    bus_builder::{BusAssigner, BusBuilder, BusPort},
    bus_chip::BusTerm,
    util::from_isize,
};
use crate::util::query_expression;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    halo2curves::group::ff::BatchInvert,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, ThirdPhase},
    poly::Rotation,
};

/// A bus operation, as expressions for circuit config.
pub type BusOpExpr<F> = BusOp<Expression<F>, Expression<F>>;

/// A bus operation, as values for circuit assignment.
pub type BusOpF<F> = BusOp<Value<F>, isize>;

/// A bus operation.
#[derive(Clone, Debug)]
pub struct BusOp<M, C> {
    message: M,
    count: C,
}

impl<M, C> BusOp<M, C>
where
    M: Clone,
    C: Clone + Neg<Output = C>,
{
    /// Put an item. The expression evaluates to 0 or the number of copies.
    pub fn put(message: M, count: C) -> Self {
        Self { message, count }
    }

    /// Take an item. The expression evaluates to 0 or 1.
    pub fn take(message: M, count: C) -> Self {
        Self::put(message, -count)
    }

    /// The message to put or take.
    pub fn message(&self) -> M {
        self.message.clone()
    }

    /// The number of copies of the message to put (if positive) or take (if negative).
    pub fn count(&self) -> C {
        self.count.clone()
    }
}

/// A chip to access to the bus.
#[derive(Clone, Debug)]
pub struct BusPortSingle<F> {
    helper: Expression<F>,
    op: BusOpExpr<F>,
}

impl<F: FieldExt> BusPortSingle<F> {
    /// Create a new bus port with a single access.
    /// The helper cell can be used for something else if op.count is zero.
    pub fn new(helper: Expression<F>, op: BusOpExpr<F>) -> Self {
        Self { helper, op }
    }

    /// Return the witness that must be assigned to the helper cell.
    pub fn helper_witness(message: Value<F>, rand: Value<F>) -> Value<F> {
        (rand + message).map(|x| x.invert().unwrap_or(F::zero()))
    }

    /// Return the denominator of the helper cell, to be inverted.
    fn helper_denom(message: Value<F>, rand: Value<F>) -> Value<F> {
        rand + message
    }
}

impl<F: FieldExt> BusPort<F> for BusPortSingle<F> {
    fn create_term(&self, meta: &mut ConstraintSystem<F>, rand: Expression<F>) -> BusTerm<F> {
        let term = self.op.count() * self.helper.clone();

        meta.create_gate("bus access", |_| {
            // Verify that `term = count / (rand + message)`.
            //
            // With witness: helper = 1 / (rand + message)
            //
            // If `count = 0`, then `term = 0` by definition. In that case, the helper cell is not
            // constrained, so it can be used for something else.
            [term.clone() * (rand + self.op.message()) - self.op.count()]
        });

        BusTerm::verified(term)
    }
}

/// A chip with two accesses to the bus. BusPortDual uses only one helper cell, however the
/// degree of input expressions is more limited than with BusPortSingle.
/// The helper cell can be used for something else if both op.count are zero.
pub struct BusPortDual<F> {
    helper: Expression<F>,
    ops: [BusOpExpr<F>; 2],
}

impl<F: FieldExt> BusPortDual<F> {
    /// Create a new bus port with two accesses.
    pub fn new(helper: Expression<F>, ops: [BusOpExpr<F>; 2]) -> Self {
        Self { helper, ops }
    }

    /// Return the witness that must be assigned to the helper cell.
    pub fn helper_witness(messages: [Value<F>; 2], rand: Value<F>) -> Value<F> {
        ((rand + messages[0]) * (rand + messages[1])).map(|x| x.invert().unwrap_or(F::zero()))
    }
}

impl<F: FieldExt> BusPort<F> for BusPortDual<F> {
    fn create_term(&self, meta: &mut ConstraintSystem<F>, rand: Expression<F>) -> BusTerm<F> {
        let rm_0 = rand.clone() + self.ops[0].message();
        let rm_1 = rand.clone() + self.ops[1].message();

        // With witness: helper = 1 / rm_0 / rm_1

        // term_0 = count_0 * helper * rm_1
        let count_0 = self.ops[0].count();
        let term_0 = count_0.clone() * self.helper.clone() * rm_1.clone();

        // term_1 = count_1 * helper * rm_0
        let count_1 = self.ops[1].count();
        let term_1 = count_1.clone() * self.helper.clone() * rm_0.clone();

        // Verify that:
        //     term_0 == count_0 / (rand + message_0)
        //     term_0 * rm_0 - count_0 == 0
        //
        // And the same for term_1.
        //
        // In case both count_0 and count_1 are zero, then the helper cell is not constrained, so it
        // can be used for something else.
        meta.create_gate("bus access (dual)", |_| {
            [
                term_0.clone() * rm_0 - count_0,
                term_1.clone() * rm_1 - count_1,
            ]
        });

        BusTerm::verified(term_0 + term_1)
    }
}

/// A chip to access the bus. It manages its own helper column and gives one access per row.
#[derive(Clone, Debug)]
pub struct BusPortChip<F> {
    helper: Column<Advice>,
    port: BusPortSingle<F>,
}

impl<F: FieldExt> BusPortChip<F> {
    /// Create and connect a new bus port with a single access.
    pub fn connect(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F>,
        op: BusOpExpr<F>,
    ) -> Self {
        let port = Self::new(meta, op);
        bus_builder.connect_port(meta, &port);
        port
    }

    /// Create a new bus port with a single access.
    pub fn new(meta: &mut ConstraintSystem<F>, op: BusOpExpr<F>) -> Self {
        let helper = meta.advice_column_in(ThirdPhase);
        let helper_expr = query_expression(meta, |meta| meta.query_advice(helper, Rotation::cur()));

        let port = BusPortSingle::new(helper_expr, op);

        Self { helper, port }
    }

    /// Assign an operation.
    pub fn assign(&self, port_assigner: &mut PortAssigner<F>, offset: usize, op: BusOpF<F>) {
        port_assigner.set_op(offset, self.helper, 0, op);
    }

    /// Assign the helper witness based on a message.
    pub fn assign_message(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        message: Value<F>,
        rand: Value<F>,
    ) -> Result<Value<F>, Error> {
        let helper = BusPortSingle::helper_witness(message, rand);
        region.assign_advice(|| "BusPort_helper", self.helper, offset, || helper)?;
        Ok(helper)
    }

    /// Assign the helper witness based on a precomputed term (without count).
    pub fn assign_term(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        term: Value<F>,
    ) -> Result<(), Error> {
        region.assign_advice(|| "BusPort_helper", self.helper, offset, || term)?;
        Ok(())
    }
}

impl<F: FieldExt> BusPort<F> for BusPortChip<F> {
    fn create_term(&self, meta: &mut ConstraintSystem<F>, rand: Expression<F>) -> BusTerm<F> {
        self.port.create_term(meta, rand)
    }
}

/// TermBatch calculates helper witnesses, in batches for better performance.
struct HelperBatch<F, INFO> {
    denoms: Vec<(F, INFO)>,
    unknown: bool,
}

impl<F: FieldExt, INFO> HelperBatch<F, INFO> {
    /// Create a new term batch.
    fn new() -> Self {
        Self {
            denoms: vec![],
            unknown: false,
        }
    }

    /// Add a helper denominator to the batch. Some `info` can be attached for later use.
    fn add_denom(&mut self, denom: Value<F>, info: INFO) {
        if self.unknown {
            return;
        }
        if denom.is_none() {
            self.unknown = true;
            self.denoms.clear();
        } else {
            denom.map(|denom| self.denoms.push((denom, info)));
        }
    }

    /// Return the inverse of all denominators and their associated info.
    fn invert(mut self) -> Value<Vec<(F, INFO)>> {
        if self.unknown {
            Value::unknown()
        } else {
            self.denoms.iter_mut().map(|(d, _)| d).batch_invert();
            Value::known(self.denoms)
        }
    }
}

/// PortAssigner computes and assigns terms into helper cells and the bus.
pub struct PortAssigner<F> {
    rand: Value<F>,
    batch: HelperBatch<F, (usize, Column<Advice>, isize, isize)>,
    bus_op_counter: BusOpCounter,
}

impl<F: FieldExt> PortAssigner<F> {
    /// Create a new PortAssigner.
    pub fn new(rand: Value<F>) -> Self {
        Self {
            rand,
            batch: HelperBatch::new(),
            bus_op_counter: BusOpCounter::new(),
        }
    }

    /// Assign a message.
    pub fn set_op(
        &mut self,
        offset: usize,
        column: Column<Advice>,
        rotation: isize,
        op: BusOpF<F>,
    ) {
        self.bus_op_counter.set_op(&op);

        let denom = BusPortSingle::helper_denom(op.message(), self.rand);
        self.batch
            .add_denom(denom, (offset, column, rotation, op.count()));
    }

    /// Assign the helper cells and report the terms to the bus.
    pub fn finish(
        self,
        region: &mut Region<'_, F>,
        bus_assigner: &mut BusAssigner<F>,
    ) -> BusOpCounter {
        self.batch.invert().map(|terms| {
            // The batch has converted the messages into bus terms.
            for (term, (offset, column, rotation, count)) in terms {
                let term = Value::known(term);

                // Set the helper cell.
                let cell_offset = (offset as isize + rotation) as usize;
                region
                    .assign_advice(|| "BusPort_helper", column, cell_offset, || term)
                    .unwrap();

                // Report the term to the global bus.
                let global_offset = offset; // region.global_offset(offset);
                let count = Value::known(from_isize::<F>(count));
                bus_assigner.put_term(global_offset, count * term);
            }
        });
        self.bus_op_counter
    }
}

/// OpCounter tracks the messages taken, to help generating the puts.
#[derive(Clone, Debug, Default)]
pub struct BusOpCounter {
    counts: HashMap<Vec<u8>, isize>,
}

impl BusOpCounter {
    /// Create a new OpCounter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Report an operation.
    pub fn set_op<F: FieldExt>(&mut self, op: &BusOpF<F>) {
        op.message().map(|message| {
            self.counts
                .entry(Self::to_key(message))
                .and_modify(|c| *c = *c + op.count())
                .or_insert_with(|| op.count());
        });
    }

    /// Count how many times a message was taken (net of puts).
    pub fn count_takes<F: FieldExt>(&self, message: Value<F>) -> isize {
        (-self.count_ops(message)).max(0)
    }

    /// Count how many times a message was put (net of takes).
    pub fn count_puts<F: FieldExt>(&self, message: Value<F>) -> isize {
        self.count_ops(message).max(0)
    }

    /// Count how many times a message was put (net positive) or taken (net negative).
    fn count_ops<F: FieldExt>(&self, message: Value<F>) -> isize {
        let mut count = 0;
        message.map(|message| {
            count = *self.counts.get(&Self::to_key(message)).unwrap_or(&0);
        });
        count
    }

    fn to_key<F: FieldExt>(message: F) -> Vec<u8> {
        Vec::from(message.to_repr().as_ref())
    }
}
