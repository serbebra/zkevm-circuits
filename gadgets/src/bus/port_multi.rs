
/// A chip with many accesses to the bus. BusPortDual uses only one helper cell, however the
/// degree of input expressions is more limited than with BusPortSingle.
/// The helper cell can be used for something else if all op.count are zero.
pub struct BusPortDual2;

impl BusPortDual2 {
    /// Create a new bus port with two accesses.
    pub fn connect<F: Field, M: BusMessageExpr<F>>(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, M>,
        ops: Vec<BusOpX<F, M>>,
        helper: Expression<F>,
    ) {
        let term = Self::create_term(meta, bus_builder.codec(), ops, helper);
        bus_builder.add_term(term);
    }

    /// Return the witness that must be assigned to the helper cell.
    /// Prefer using BusAssigner instead.
    pub fn helper_denom<F: Field, M: BusMessageF<F>>(
        codec: &BusCodecVal<F, M>,
        messages: Vec<M>,
    ) -> Value<F> {
        let m0 = messages[0].clone(); // TODO
        let m1 = messages[1].clone();
        codec.compress(m0) * codec.compress(m1)
    }

    fn create_term<F: Field, M: BusMessageExpr<F>>(
        meta: &mut ConstraintSystem<F>,
        codec: &BusCodecExpr<F, M>,
        ops: Vec<BusOpX<F, M>>,
        helper: Expression<F>,
    ) -> BusTerm<F> {
        let denoms = ops
            .iter()
            .map(|op| codec.compress(op.message()))
            .collect::<Vec<_>>();

        let others = Self::product_of_others(denoms.clone());

        let terms = ops
            .iter()
            .zip(others)
            .map(|(op, others)| op.count() * helper.clone() * others.clone())
            .collect::<Vec<_>>();

        meta.create_gate("bus access (multi)", |_| {
            ops.iter()
                .zip(denoms)
                .zip(terms.iter())
                .map(|((op, denom), term)| {
                    // Verify that:
                    //     term == count / denom
                    //     term * denom - count == 0
                    term.clone() * denom - op.count()
                })
        });

        let total_term = terms.into_iter().reduce(|acc, term| acc + term).unwrap();
        BusTerm::verified(total_term)
    }

    fn product_of_others<F: Field>(vals: Vec<Expression<F>>) -> Vec<Expression<F>> {
        // all_after[i] contains the product of all values after vals[i] (non-inclusive).
        let all_afters = {
            let mut all_after = 1.expr();
            let mut all_afters = Vec::with_capacity(vals.len());
            for val in vals.iter().rev() {
                all_afters.push(all_after.clone());
                all_after = all_after * val.clone();
            }
            all_afters.reverse();
            all_afters
        };

        let mut all_before = 1.expr();
        let mut all_others = Vec::with_capacity(vals.len());
        for (val, all_after) in vals.into_iter().zip(all_afters) {
            all_others.push(all_before.clone() * all_after);
            all_before = all_before * val;
        }

        all_others
    }
}


/// A chip to access the bus. It manages its own helper column and gives one access per row.
#[derive(Clone, Debug)]
pub struct BusPortChip2<F> {
    helper: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: Field> BusPortChip2<F> {
    /// Create a new bus port with a single access.
    pub fn connect<M: BusMessageExpr<F>>(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, M>,
        ops: Vec<BusOpX<F, M>>,
    ) -> Self {
        let helper = meta.advice_column_in(ThirdPhase);
        let helper_expr = query_expression(meta, |meta| meta.query_advice(helper, Rotation::cur()));

        BusPortDual2::connect(meta, bus_builder, ops, helper_expr);

        Self {
            helper,
            _marker: PhantomData,
        }
    }

    /// Assign an operation.
    pub fn assign<M: BusMessageF<F>>(
        &self,
        bus_assigner: &mut BusAssigner<F, M>,
        offset: usize,
        ops: Vec<BusOpA<M>>,
    ) {
        let messages = ops.iter().map(|op| op.message()).collect();
        let denom = BusPortDual2::helper_denom(bus_assigner.codec(), messages);

        let cmd = Box::new(BusPortAssigner2 {
            offset,
            column: self.helper,
            count: ops[0].count(), // TODO
        });

        for op in &ops {
            bus_assigner.op_counter().track_op(&op);
        }
        bus_assigner.port_assigner().assign_later(cmd, denom);
    }
}

struct BusPortAssigner2 {
    offset: usize,
    column: Column<Advice>,
    count: isize,
}

impl<F: Field> Assigner<F> for BusPortAssigner2 {
    fn assign(&self, region: &mut Region<'_, F>, helper: F) -> (usize, F) {
        region
            .assign_advice(
                || "BusPort_helper",
                self.column,
                self.offset,
                || Value::known(helper),
            )
            .unwrap();

        let term = from_isize::<F>(self.count) * helper;
        (self.offset, term)
    }
}
