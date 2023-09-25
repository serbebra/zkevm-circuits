//! The TableBus circuit puts items from a table to the bus.

use std::marker::PhantomData;

use eth_types::Field;
use gadgets::bus::{
    bus_builder::{BusAssigner, BusBuilder},
    bus_port::{BusOp, BusPortChip, PortAssigner},
};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error},
};

use crate::{table::LookupTable, util::query_expression};

/// TableBusConfig
#[derive(Clone)]
pub struct TableBusConfig<F: Field> {
    port: BusPortChip<F>,
}

impl<F: Field> TableBusConfig<F> {
    /// Create a new TableBus circuit.
    pub fn new(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F>,
        table: &dyn LookupTable<F>,
    ) -> Self {
        let exprs = query_expression(meta, |meta| table.table_exprs(meta));

        let count = exprs[0].clone();
        let message = exprs[1].clone();
        // TODO: multi-column message.

        let port = BusPortChip::new(meta, BusOp::put(message, count));
        bus_builder.connect_port(meta, &port);

        Self { port }
    }
}

/// TableBusCircuit
#[derive(Clone, Default, Debug)]
pub struct TableBusCircuit<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> TableBusCircuit<F> {
    /// Create a new TableBus circuit.
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    /// Make the assignments to the circuit
    pub fn synthesize_sub(
        &self,
        config: &TableBusConfig<F>,
        challenges: &crate::util::Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
        bus_assigner: &mut BusAssigner<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "TableBus",
            |mut region| {
                let rand = challenges.lookup_input();
                let mut port_assigner = PortAssigner::new(rand);

                let message = Value::known(F::zero());
                let count = Value::known(F::zero());
                port_assigner.set_op(0, config.port.column(), 0, BusOp::take(message, count));

                port_assigner.finish(&mut region, bus_assigner);

                Ok(())
            },
        )?;

        Ok(())
    }
}
