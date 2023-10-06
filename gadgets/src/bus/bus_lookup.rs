//! The TableBus circuit puts items from a table to the bus.

use crate::util::query_expression;

use super::{
    bus_builder::{BusAssigner, BusBuilder},
    bus_codec::{BusMessageExpr, BusMessageF},
    bus_port::{BusOp, BusOpA, BusPortChip},
    util::from_isize,
    Field,
};
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression},
    poly::Rotation,
};

/// BusLookup exposes a table as a lookup through the bus.
#[derive(Clone, Debug)]
pub struct BusLookupConfig<F> {
    port: BusPortChip<F>,
    count: Column<Advice>,
}

impl<F: Field> BusLookupConfig<F> {
    /// Create and connect a new BusLookup circuit from the expressions of message and count.
    pub fn connect<M: BusMessageExpr<F>>(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, M>,
        message: M,
        enabled: Expression<F>,
    ) -> Self {
        let count = meta.advice_column();
        let count_expr = query_expression(meta, |meta| meta.query_advice(count, Rotation::cur()));

        let port =
            BusPortChip::connect(meta, bus_builder, BusOp::put(message, enabled * count_expr));

        Self { port, count }
    }

    /// Assign a lookup operation.
    pub fn assign<M: BusMessageF<F>>(
        &self,
        region: &mut Region<'_, F>,
        bus_assigner: &mut BusAssigner<F, M>,
        offset: usize,
        op: BusOpA<M>,
    ) -> Result<(), Error> {
        region.assign_advice(
            || "BusLookup",
            self.count,
            offset,
            || Value::known(from_isize::<F>(op.count())),
        )?;
        self.port.assign(bus_assigner, offset, op);
        Ok(())
    }
}
