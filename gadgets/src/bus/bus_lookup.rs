//! The TableBus circuit puts items from a table to the bus.

use crate::util::query_expression;

use super::{
    bus_builder::BusBuilder,
    bus_port::{BusOp, BusOpF, BusPortChip, PortAssigner},
    util::from_isize,
};
use halo2_proofs::{
    circuit::{Region, Value},
    halo2curves::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression},
    poly::Rotation,
};

/// BusLookup exposes a table as a lookup through the bus.
#[derive(Clone, Debug)]
pub struct BusLookupConfig<F> {
    port: BusPortChip<F>,
    count: Column<Advice>,
}

impl<F: FieldExt> BusLookupConfig<F> {
    /// Create a new BusLookup circuit from the expressions of message and count.
    pub fn new(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F>,
        message: Expression<F>,
        enabled: Expression<F>,
    ) -> Self {
        let count = meta.advice_column();
        let count_expr = query_expression(meta, |meta| meta.query_advice(count, Rotation::cur()));

        let port = BusPortChip::new(meta, BusOp::put(message, enabled * count_expr));
        bus_builder.connect_port(meta, &port);

        Self { port, count }
    }

    /// Assign a lookup operation.
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        port_assigner: &mut PortAssigner<F>,
        offset: usize,
        op: BusOpF<F>,
    ) -> Result<(), Error> {
        region.assign_advice(
            || "BusLookup",
            self.count,
            offset,
            || Value::known(from_isize::<F>(op.count())),
        )?;

        port_assigner.set_op(offset, self.port.column(), 0, op);
        Ok(())
    }
}
