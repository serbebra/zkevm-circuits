//! The TableBus circuit puts items from a table to the bus.

use std::marker::PhantomData;

use eth_types::Field;
use gadgets::bus::{
    bus_builder::{BusAssigner, BusBuilder},
    bus_port::{BusOp, BusOpVal, BusPortChip, PortAssigner},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression},
    poly::Rotation,
};

use crate::util::query_expression;

/// LookupBus exposes a table as a lookup through the bus.
#[derive(Clone, Debug)]
pub struct LookupBusConfig<F> {
    port: BusPortChip<F>,
    count: Column<Advice>,
}

impl<F: Field> LookupBusConfig<F> {
    /// Create a new LookupBus circuit from the expressions of message and count.
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
        op: BusOpVal<F>,
    ) -> Result<(), Error> {
        region.assign_advice(|| "LookupBus", self.count, offset, || op.count())?;

        port_assigner.set_op(offset, self.port.column(), 0, op);
        Ok(())
    }
}
