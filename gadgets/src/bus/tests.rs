use crate::util::{query_expression, Expr};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{Advice, Challenge, Circuit, Column, ConstraintSystem, Error, FirstPhase, Fixed},
    poly::Rotation,
};
use std::marker::PhantomData;

use super::{bus_builder::*, bus_chip::*, bus_port::*};

#[test]
fn test_bus() {
    test_circuit();
}

#[derive(Clone)]
struct TestCircuitConfig<F: FieldExt> {
    enabled: Column<Fixed>,
    count1: Column<Advice>,
    port1: BusPortChip<F>,
    port2: BusPortChip<F>,
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

        // Circuit 1 puts values dynamically.
        let count1 = cs.advice_column();
        let count1_expr = enabled_expr.clone()
            * query_expression(cs, |cs| cs.query_advice(count1, Rotation::cur()));

        let port1 = BusPortChip::new(cs, BusOp::put(count1_expr, value.clone()));
        bus_builder.connect_port(cs, &port1);

        // Circuit 2 takes one value per row.
        let count2_expr = enabled_expr * 1.expr();

        let port2 = BusPortChip::new(cs, BusOp::take(count2_expr, value));
        bus_builder.connect_port(cs, &port2);

        // Global bus connection.
        let bus_check = BusConfig::new(cs, &bus_builder.build());

        TestCircuitConfig {
            enabled,
            bus_check,
            count1,
            port1,
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

                let mut bus_assigner = BusAssigner::new(self.n_rows);

                // Circuit 1 puts the value once, but it is worth `count` times.
                {
                    let count = Value::known(F::from(self.n_rows as u64));
                    let offset = 3; // can be anywhere.
                    region.assign_advice(|| "count1", config.count1, offset, || count)?;
                    let term = config.port1.assign(&mut region, offset, value, rand)?;
                    bus_assigner.put_term(offset, count * term);
                }

                // Circuit 2 takes the value once per row.
                for offset in 0..self.n_rows {
                    let term = config.port2.assign(&mut region, offset, value, rand)?;
                    bus_assigner.take_term(offset, term);
                }

                config
                    .bus_check
                    .assign(&mut region, self.n_rows, bus_assigner.terms())?;

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
