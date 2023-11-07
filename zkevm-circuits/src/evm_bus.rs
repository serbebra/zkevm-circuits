use eth_types::Field;
use gadgets::bus::{
    bus_builder::{BusAssigner, BusBuilder},
    bus_lookup::BusLookupChip,
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};

use crate::{
    evm_circuit::table::{Lookup, MsgExpr, MsgF, RwValues},
    table::{RwTable, TxTable},
    util::{assign_global, query_expression},
};

#[derive(Clone, Debug)]
pub struct EVMBusLookups<F> {
    rw_bus_table: BusTable<F>,
    tx_bus_table: BusTable<F>,
}

impl<F: Field> EVMBusLookups<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, MsgExpr<F>>,
        rw_table: &RwTable,
        tx_table: &TxTable,
    ) -> Self {
        let rw_bus_table = BusTable::configure(meta, bus_builder, rw_table);
        let tx_bus_table = BusTable::configure(meta, bus_builder, tx_table);
        Self {
            rw_bus_table,
            tx_bus_table,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        bus_assigner: &mut BusAssigner<F, MsgF<F>>,
    ) -> Result<(), Error> {
        assign_global(
            layouter,
            || "EVM Bus Tables",
            |mut region| {
                self.rw_bus_table.assign(&mut region, bus_assigner)?;
                self.tx_bus_table.assign(&mut region, bus_assigner)?;

                bus_assigner.finish_ports(&mut region);
                Ok(())
            },
        )
    }
}

#[derive(Clone, Debug)]
struct BusTable<F> {
    enabled: Expression<F>,
    message: MsgExpr<F>,
    chip: BusLookupChip<F>,
}

impl<F: Field> BusTable<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, MsgExpr<F>>,
        table: &dyn QueryTable<F>,
    ) -> Self {
        let (enabled, message) =
            query_expression(meta, |meta| (table.enabled(meta), table.message(meta)));
        BusTable {
            enabled: enabled.clone(),
            message: message.clone(),
            chip: BusLookupChip::connect(meta, bus_builder, enabled, message),
        }
    }

    fn assign(
        &self,
        region: &mut Region<F>,
        bus_assigner: &mut BusAssigner<F, MsgF<F>>,
    ) -> Result<(), Error> {
        for offset in 0..bus_assigner.n_rows() {
            let enabled = eval(region, offset, self.enabled.clone());
            if enabled.is_zero_vartime() {
                continue;
            }

            let message = self
                .message
                .clone()
                .map_values(|expr| eval(region, offset, expr));

            self.chip
                .assign(region, bus_assigner, offset, message.clone())?;
        }
        Ok(())
    }
}

fn eval<F: Field>(region: &Region<F>, offset: usize, expr: Expression<F>) -> F {
    // TODO: error handling.
    let value = expr.evaluate(
        &|scalar| Value::known(scalar),
        &|_| unimplemented!("selector column"),
        &|fixed_query| {
            Value::known(
                region
                    .query_fixed(
                        Column::new(fixed_query.column_index(), Fixed),
                        (offset as i32 + fixed_query.rotation().0) as usize,
                    )
                    .unwrap(),
            )
        },
        &|advice_query| {
            Value::known(
                region
                    .query_advice(
                        Column::new(advice_query.column_index(), Advice::default()),
                        (offset as i32 + advice_query.rotation().0) as usize,
                    )
                    .unwrap(),
            )
        },
        &|_| unimplemented!("instance column"),
        &|_| unimplemented!("challenge"),
        &|a| -a,
        &|a, b| a + b,
        &|a, b| a * b,
        &|a, scalar| a * Value::known(scalar),
    );
    let mut f = F::zero();
    value.map(|v| f = v);
    f
}

trait QueryTable<F: Field> {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F>;
    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F>;
}

impl<F: Field> QueryTable<F> for RwTable {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.q_enable, Rotation::cur())
    }

    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F> {
        let mut query = |col| meta.query_advice(col, Rotation::cur());

        MsgExpr::lookup(Lookup::Rw {
            counter: query(self.rw_counter),
            is_write: query(self.is_write),
            tag: query(self.tag),
            values: RwValues {
                id: query(self.id),
                address: query(self.address),
                field_tag: query(self.field_tag),
                storage_key: query(self.storage_key),
                value: query(self.value),
                value_prev: query(self.value_prev),
                aux1: query(self.aux1),
                aux2: query(self.aux2),
            },
        })
    }
}

impl<F: Field> QueryTable<F> for TxTable {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.q_enable, Rotation::cur())
    }

    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F> {
        MsgExpr::lookup(Lookup::Tx {
            id: meta.query_advice(self.tx_id, Rotation::cur()),
            field_tag: meta.query_fixed(self.tag, Rotation::cur()),
            index: meta.query_advice(self.index, Rotation::cur()),
            value: meta.query_advice(self.value, Rotation::cur()),
        })
    }
}
