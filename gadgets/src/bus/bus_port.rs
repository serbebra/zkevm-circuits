use super::{
    bus_builder::{BusAssigner, BusBuilder},
    bus_chip::BusTerm,
    bus_codec::{BusCodecExpr, BusCodecVal, BusMessage},
    util::{from_isize, HelperBatch},
};
use crate::util::query_expression;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Expression, ThirdPhase},
    poly::Rotation,
};
use std::{collections::HashMap, marker::PhantomData, ops::Neg};

/// A bus operation, as expressions for circuit config.
pub type BusOpX<F, M> = BusOp<M, Expression<F>>;

/// A bus operation, as values for circuit assignment.
pub type BusOpA<M> = BusOp<M, isize>;

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
pub struct BusPortSingle;

impl BusPortSingle {
    /// Create a new bus port with a single access.
    /// The helper cell can be used for something else if op.count is zero.
    pub fn connect<F: FieldExt, M: BusMessage<Expression<F>>>(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, M>,
        op: BusOpX<F, M>,
        helper: Expression<F>,
    ) {
        let term = Self::create_term(meta, bus_builder.codec(), op, helper);
        bus_builder.add_term(term);
    }

    /// Return the witness that must be assigned to the helper cell.
    /// Prefer using PortAssigner instead.
    pub fn helper_witness<F: FieldExt, M: BusMessage<Value<F>>>(
        codec: &BusCodecVal<F, M>,
        message: M,
    ) -> Value<F> {
        codec
            .compress(message)
            .map(|x| x.invert().unwrap_or(F::zero()))
    }

    fn create_term<F: FieldExt, M: BusMessage<Expression<F>>>(
        meta: &mut ConstraintSystem<F>,
        codec: &BusCodecExpr<F, M>,
        op: BusOpX<F, M>,
        helper: Expression<F>,
    ) -> BusTerm<F> {
        let term = op.count() * helper.clone();
        let denom = codec.compress(op.message());

        meta.create_gate("bus access", |_| {
            // Verify that `term = count / denom`.
            //
            // With witness: helper = 1 / denom
            //
            // If `count = 0`, then `term = 0` by definition. In that case, the helper cell is not
            // constrained, so it can be used for something else.
            [term.clone() * denom - op.count()]
        });

        BusTerm::verified(term)
    }
}

/// A chip with two accesses to the bus. BusPortDual uses only one helper cell, however the
/// degree of input expressions is more limited than with BusPortSingle.
/// The helper cell can be used for something else if both op.count are zero.
pub struct BusPortDual;

impl BusPortDual {
    /// Create a new bus port with two accesses.
    pub fn connect<F: FieldExt, M: BusMessage<Expression<F>>>(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, M>,
        ops: [BusOpX<F, M>; 2],
        helper: Expression<F>,
    ) {
        let term = Self::create_term(meta, bus_builder.codec(), ops, helper);
        bus_builder.add_term(term);
    }

    /// Return the witness that must be assigned to the helper cell.
    /// Prefer using PortAssigner instead.
    pub fn helper_witness<F: FieldExt, M: BusMessage<Value<F>>>(
        codec: &BusCodecVal<F, M>,
        messages: [M; 2],
    ) -> Value<F> {
        let [m0, m1] = messages;
        (codec.compress(m0) * codec.compress(m1)).map(|x| x.invert().unwrap_or(F::zero()))
    }

    fn create_term<F: FieldExt, M: BusMessage<Expression<F>>>(
        meta: &mut ConstraintSystem<F>,
        codec: &BusCodecExpr<F, M>,
        ops: [BusOpX<F, M>; 2],
        helper: Expression<F>,
    ) -> BusTerm<F> {
        let denom_0 = codec.compress(ops[0].message());
        let denom_1 = codec.compress(ops[1].message());

        // With witness: helper = 1 / (denom_0 * denom_1)

        // term_0 = count_0 * helper * denom_1
        let count_0 = ops[0].count();
        let term_0 = count_0.clone() * helper.clone() * denom_1.clone();

        // term_1 = count_1 * helper * denom_0
        let count_1 = ops[1].count();
        let term_1 = count_1.clone() * helper.clone() * denom_0.clone();

        // Verify that:
        //     term_0 == count_0 / denom_0
        //     term_0 * denom_0 - count_0 == 0
        //
        // And the same for term_1.
        //
        // In case both count_0 and count_1 are zero, then the helper cell is not constrained, so it
        // can be used for something else.
        meta.create_gate("bus access (dual)", |_| {
            [
                term_0.clone() * denom_0 - count_0,
                term_1.clone() * denom_1 - count_1,
            ]
        });

        BusTerm::verified(term_0 + term_1)
    }
}

/// A chip to access the bus. It manages its own helper column and gives one access per row.
#[derive(Clone, Debug)]
pub struct BusPortChip<F> {
    helper: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BusPortChip<F> {
    /// Create a new bus port with a single access.
    pub fn connect<M: BusMessage<Expression<F>>>(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, M>,
        op: BusOpX<F, M>,
    ) -> Self {
        let helper = meta.advice_column_in(ThirdPhase);
        let helper_expr = query_expression(meta, |meta| meta.query_advice(helper, Rotation::cur()));

        BusPortSingle::connect(meta, bus_builder, op, helper_expr);

        Self {
            helper,
            _marker: PhantomData,
        }
    }

    /// Assign an operation.
    pub fn assign<M: BusMessage<Value<F>>>(
        &self,
        port_assigner: &mut PortAssigner<F, M>,
        offset: usize,
        op: BusOpA<M>,
    ) {
        port_assigner.set_op(offset, self.helper, 0, op);
    }
}

/// A chip to access the bus. It manages its own helper columns and gives multiple accesses per row.
#[derive(Clone, Debug)]
pub struct BusPortMulti<F> {
    // TODO: implement with as few helper columns as possible.
    ports: Vec<BusPortChip<F>>,
}

impl<F: FieldExt> BusPortMulti<F> {
    /// Create and connect a new bus port with multiple accesses.
    pub fn connect<M: BusMessage<Expression<F>>>(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, M>,
        ops: Vec<BusOpX<F, M>>,
    ) -> Self {
        let ports = ops
            .into_iter()
            .map(|op| BusPortChip::connect(meta, bus_builder, op))
            .collect();
        Self { ports }
    }

    /// Assign operations.
    pub fn assign<M: BusMessage<Value<F>>>(
        &self,
        port_assigner: &mut PortAssigner<F, M>,
        offset: usize,
        ops: Vec<BusOpA<M>>,
    ) {
        assert_eq!(self.ports.len(), ops.len());
        for (port, op) in self.ports.iter().zip(ops) {
            port.assign(port_assigner, offset, op);
        }
    }
}

/// PortAssigner computes and assigns terms into helper cells and the bus.

pub struct PortAssigner<F, M> {
    codec: BusCodecVal<F, M>,
    batch: HelperBatch<F, (usize, Column<Advice>, isize, isize)>,
    bus_op_counter: BusOpCounter<F, M>,
}

impl<F: FieldExt, M: BusMessage<Value<F>>> PortAssigner<F, M> {
    /// Create a new PortAssigner.
    pub fn new(codec: BusCodecVal<F, M>) -> Self {
        Self {
            codec,
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
        op: BusOpA<M>,
    ) {
        self.bus_op_counter.set_op(&op);

        let denom = self.codec.compress(op.message());
        self.batch
            .add_denom(denom, (offset, column, rotation, op.count()));
    }

    /// Assign the helper cells and report the terms to the bus.
    pub fn finish(
        self,
        region: &mut Region<'_, F>,
        bus_assigner: &mut BusAssigner<F, M>,
    ) -> BusOpCounter<F, M> {
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
                bus_assigner.add_term(global_offset, count * term);
            }
        });
        self.bus_op_counter
    }
}

/// OpCounter tracks the messages taken, to help generating the puts.
#[derive(Clone, Debug)]
pub struct BusOpCounter<F, M> {
    counts: HashMap<Vec<u8>, isize>,
    _marker: PhantomData<(F, M)>,
}

impl<F: FieldExt, M: BusMessage<Value<F>>> BusOpCounter<F, M> {
    /// Create a new BusOpCounter.
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
            _marker: PhantomData,
        }
    }

    /// Report an operation.
    pub fn set_op(&mut self, op: &BusOpA<M>) {
        if let Some(key) = Self::to_key(op.message()) {
            self.counts
                .entry(key)
                .and_modify(|c| *c = *c + op.count())
                .or_insert_with(|| op.count());
        }
    }

    /// Count how many times a message was taken (net of puts).
    pub fn count_takes(&self, message: &M) -> isize {
        (-self.count_ops(message)).max(0)
    }

    /// Count how many times a message was put (net of takes).
    pub fn count_puts(&self, message: &M) -> isize {
        self.count_ops(message).max(0)
    }

    /// Count how many times a message was put (net positive) or taken (net negative).
    fn count_ops(&self, message: &M) -> isize {
        if let Some(key) = Self::to_key(message.clone()) {
            *self.counts.get(&key).unwrap_or(&0)
        } else {
            0
        }
    }

    fn to_key(message: M) -> Option<Vec<u8>> {
        let mut bytes = vec![];
        for v in message.into_items() {
            if v.is_none() {
                return None;
            }
            v.map(|v| bytes.extend_from_slice(v.to_repr().as_ref()));
        }
        Some(bytes)
    }
}
