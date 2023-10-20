use eth_types::Field;
use gadgets::bus::{
    bus_builder::{BusAssigner, BusBuilder},
    bus_lookup::BusLookupChip,
};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{ConstraintSystem, Error},
    poly::Rotation,
};
use itertools::Itertools;

use crate::{
    evm_circuit::table::{Lookup, MsgExpr, MsgF},
    table::TxTable,
    util::query_expression,
};

#[derive(Clone, Debug)]
pub struct EVMBus<F> {
    tx_lookup: BusLookupChip<F>,
}

impl<F: Field> EVMBus<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, MsgExpr<F>>,
        tx_table: TxTable,
    ) -> Self {
        let tx_lookup = {
            let tx_enabled = query_expression(meta, |meta| {
                meta.query_fixed(tx_table.q_enable, Rotation::cur())
            });
            let message = query_expression(meta, |meta| {
                MsgExpr::lookup(Lookup::Tx {
                    id: meta.query_advice(tx_table.tx_id, Rotation::cur()),
                    field_tag: meta.query_fixed(tx_table.tag, Rotation::cur()),
                    index: meta.query_advice(tx_table.index, Rotation::cur()),
                    value: meta.query_advice(tx_table.value, Rotation::cur()),
                })
            });
            BusLookupChip::connect(meta, bus_builder, tx_enabled, message)
        };

        Self { tx_lookup }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        bus_assigner: &mut BusAssigner<F, MsgF<F>>,
        tx_messages: Vec<(usize, MsgF<F>)>,
    ) -> Result<(), Error> {
        let mut closure_count = 0;
        layouter.assign_region(
            || "EVM Bus Tables",
            |mut region| {
                closure_count += 1;
                if closure_count == 1 {
                    return Ok(()); // TODO: deal with this some other way.
                }

                for (offset, message) in tx_messages.iter().unique_by(|(o, _)| *o) {
                    self.tx_lookup
                        .assign(&mut region, bus_assigner, *offset, message.clone())?;
                }

                bus_assigner.finish_ports(&mut region);
                Ok(())
            },
        )?;
        assert_eq!(closure_count, 2, "assign_region behavior changed");
        Ok(())
    }
}
