use crate::util::{query_expression, Expr};
use eth_types::Field;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{
        Advice, Challenge, Circuit, Column, ConstraintSystem, Error, Expression, FirstPhase, Fixed,
        Phase, VirtualCells,
    },
    poly::Rotation,
};
use std::marker::PhantomData;

use super::{bus_chip::*, bus_multi::*, bus_port::*};

#[test]
fn test_bus() {
    test_circuit();
}

#[derive(Clone)]
struct TestCircuitConfig<F: FieldExt> {
    enabled: Column<Fixed>,
    count1: Column<Advice>,
    port1: BusPortColumn<F>,
    count2: Column<Advice>,
    port2: BusPortColumn<F>,
    bus_check: BusConfig,
    rand: Challenge,
    _marker: PhantomData<F>,
}

#[derive(Default, Clone)]
struct TestCircuit<F: FieldExt> {
    n_rows: usize,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
    type Config = TestCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        cs.advice_column(); // Bypass illogical validation.

        let enabled = cs.fixed_column();
        let enabled_expr = query_expression(cs, |cs| cs.query_fixed(enabled, Rotation::cur()));

        let rand = cs.challenge_usable_after(FirstPhase);
        let rand_expr = query_expression(cs, |cs| cs.query_challenge(rand));
        let mut bus_builder = BusBuilder::<F>::new(rand_expr);

        let value = 2.expr();

        // Circuit 1.
        let count1 = cs.advice_column();
        let count1_expr = query_expression(cs, |cs| cs.query_advice(count1, Rotation::cur()));
        let port1 = BusPortColumn::new(
            cs,
            BusOp::put(enabled_expr.clone() * count1_expr, value.clone()),
        );
        bus_builder.connect_port(cs, &port1);

        // Circuit 2.
        let count2 = cs.advice_column();
        let count2_expr = query_expression(cs, |cs| cs.query_advice(count2, Rotation::cur()));
        let port2 = BusPortColumn::new(cs, BusOp::take(enabled_expr * count2_expr, value));
        bus_builder.connect_port(cs, &port2);

        // Global bus connection.
        let bus_check = BusConfig::new(cs, &bus_builder.terms());

        TestCircuitConfig {
            enabled,
            bus_check,
            count1,
            port1,
            count2,
            port2,
            rand,
            _marker: PhantomData,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let rand = layouter.get_challenge(config.rand);

        layouter.assign_region(
            || "witness",
            |mut region| {
                let value = Value::known(F::from(2));

                for offset in 0..self.n_rows {
                    region.assign_fixed(
                        || "Port_enable",
                        config.enabled,
                        offset,
                        || Value::known(F::one()),
                    )?;
                }

                let mut terms = vec![Value::known(F::zero()); self.n_rows];

                // Circuit 1.
                let off1 = 1;
                region.assign_advice(
                    || "count1",
                    config.count1,
                    off1,
                    || Value::known(F::one()),
                )?;
                let h1 = config.port1.assign(&mut region, off1, value, rand)?;
                terms[off1] = terms[off1] + h1;

                // Circuit 2.
                let off2 = 3;
                region.assign_advice(
                    || "count2",
                    config.count2,
                    off2,
                    || Value::known(F::one()),
                )?;
                let h2 = config.port2.assign(&mut region, off2, value, rand)?;
                terms[off2] = terms[off2] - h2;

                config.bus_check.assign(&mut region, self.n_rows, &terms)?;

                Ok(())
            },
        )
    }
}

fn test_circuit() {
    let circuit = TestCircuit::<Fr> {
        n_rows: 10,
        _marker: PhantomData,
    };
    let k = 10;
    let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied_par()
}
