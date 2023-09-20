use super::{bus_builder::BusPort, bus_chip::BusTerm};
use crate::util::query_expression;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    halo2curves::group::ff::BatchInvert,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, SecondPhase},
    poly::Rotation,
};

/// A bus operation.
#[derive(Clone)]
pub struct BusOp<F> {
    count: Expression<F>,
    message: Expression<F>,
}

impl<F: FieldExt> BusOp<F> {
    /// Put an item. The expression evaluates to 0 or the number of copies.
    pub fn put(count: Expression<F>, message: Expression<F>) -> Self {
        Self { count, message }
    }

    /// Take an item. The expression evaluates to 0 or 1.
    pub fn take(count: Expression<F>, message: Expression<F>) -> Self {
        Self::put(-count, message)
    }

    /// The expression of the count of items to put or take.
    pub fn count(&self) -> Expression<F> {
        self.count.clone()
    }

    /// The expression of the message to put or take.
    pub fn message(&self) -> Expression<F> {
        self.message.clone()
    }
}

/// A chip to access to the bus.
#[derive(Clone)]
pub struct BusPortSingle<F> {
    helper: Expression<F>,
    op: BusOp<F>,
}

impl<F: FieldExt> BusPortSingle<F> {
    /// Create a new bus port with a single access.
    /// The helper cell can be used for something else if op.count is zero.
    pub fn new(helper: Expression<F>, op: BusOp<F>) -> Self {
        Self { helper, op }
    }

    /// Return the witness that must be assigned to the helper cell.
    pub fn helper_witness(message: Value<F>, rand: Value<F>) -> Value<F> {
        (rand + message).map(|x| x.invert().unwrap_or(F::zero()))
    }

    /// Return the denominator of the helper cell, to be inverted.
    pub fn helper_denom(message: Value<F>, rand: Value<F>) -> Value<F> {
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
    ops: [BusOp<F>; 2],
}

impl<F: FieldExt> BusPortDual<F> {
    /// Create a new bus port with two accesses.
    pub fn new(helper: Expression<F>, ops: [BusOp<F>; 2]) -> Self {
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
#[derive(Clone)]
pub struct BusPortChip<F> {
    helper: Column<Advice>,
    port: BusPortSingle<F>,
}

impl<F: FieldExt> BusPortChip<F> {
    /// Create a new bus port with a single access.
    pub fn new(meta: &mut ConstraintSystem<F>, op: BusOp<F>) -> Self {
        let helper = meta.advice_column_in(SecondPhase);
        let helper_expr = query_expression(meta, |meta| meta.query_advice(helper, Rotation::cur()));

        let port = BusPortSingle::new(helper_expr, op);

        Self { helper, port }
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
pub struct HelperBatch<F, INFO> {
    denoms: Vec<(F, INFO)>,
    unknown: bool,
}

impl<F: FieldExt, INFO> HelperBatch<F, INFO> {
    /// Create a new term batch.
    pub fn new() -> Self {
        Self {
            denoms: vec![],
            unknown: false,
        }
    }

    /// Add a helper denominator to the batch. Some `info` can be attached for later use.
    pub fn add_denom(&mut self, denom: Value<F>, info: INFO) {
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
    pub fn invert(mut self) -> Value<Vec<(F, INFO)>> {
        if self.unknown {
            Value::unknown()
        } else {
            self.denoms.iter_mut().map(|(d, _)| d).batch_invert();
            Value::known(self.denoms)
        }
    }
}
