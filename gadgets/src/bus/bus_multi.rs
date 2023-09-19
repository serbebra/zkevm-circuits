use super::{
    bus_chip::{BusPort, BusTerm},
    bus_port::{BusOp, BusPortSingle},
};
use crate::util::Expr;
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{ConstraintSystem, Expression},
};

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
}

impl<F: FieldExt> BusPort<F> for BusPortMulti<F> {
    fn create_term(&self, meta: &mut ConstraintSystem<F>, rand: Expression<F>) -> BusTerm<F> {
        let term = self
            .ops
            .iter()
            .map(|op| {
                BusPortSingle::new(self.helper.clone(), op.clone())
                    .create_term(meta, rand.clone())
                    .expr()
            })
            .reduce(|acc, term| acc + term)
            .unwrap_or(0.expr());

        BusTerm::verified(term)
    }
}
