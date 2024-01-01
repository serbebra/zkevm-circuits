use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    halo2curves::bn256::{Bn256, Fr},
    plonk::{Circuit, ConstraintSystem, Error, Selector},
    poly::kzg::commitment::ParamsKZG,
};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::gates::{
    circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, CircuitBuilderStage},
    flex_gate::MultiPhaseThreadBreakPoints,
};
use snark_verifier_sdk::{
    halo2::aggregation::{AggregationCircuit as ComCircuit, VerifierUniversality},
    CircuitExt, Snark, LIMBS,
};

use crate::{AccScheme, ConfigParams};

use super::config::CompressionConfig;

/// Input a proof, this compression circuit generates a new proof that may have smaller size.
///
/// It re-exposes same public inputs from the input snark.
/// All this circuit does is to reduce the proof size.
#[derive(Clone, Debug)]
pub struct CompressionCircuit {
    pub(crate) circuit: ComCircuit,
}

impl Circuit<Fr> for CompressionCircuit {
    type Config = CompressionConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // todo: build config from Params rather than ENV VARs
        Self::Config::new(meta)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fr>) -> Result<(), Error> {
        let witness_time = start_timer!(|| "synthesize | compression Circuit");
        self.circuit
            .builder
            .borrow()
            .synthesize(config.base_field_config, layouter)?;
        println!(
            "instance len: {}",
            self.circuit.builder.borrow().assigned_instances.len()
        );
        self.circuit.builder.borrow_mut().clear();
        end_timer!(witness_time);
        Ok(())
    }
}

impl CompressionCircuit {
    /// Build a new circuit from a snark, with a flag whether this snark has been compressed before
    pub fn new(
        stage: CircuitBuilderStage,
        config_params: &ConfigParams,
        params: &ParamsKZG<Bn256>,
        snark: Snark,
    ) -> Result<Self, snark_verifier::Error> {
        let witness_time = start_timer!(|| "new | compression Circuit");

        let config_params: BaseCircuitParams = config_params.into();
        let circuit = ComCircuit::new::<AccScheme>(
            stage,
            config_params.try_into().unwrap(),
            params,
            vec![snark],
            VerifierUniversality::None,
        );
        end_timer!(witness_time);

        Ok(Self { circuit })
    }

    /// The break points of the circuit.
    pub fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        self.circuit.builder.borrow().break_points()
    }

    /// Returns new with break points
    pub fn use_break_points(mut self, break_points: MultiPhaseThreadBreakPoints) -> Self {
        self.circuit.set_break_points(break_points);
        self
    }
}

impl CircuitExt<Fr> for CompressionCircuit {
    /// Return the number of instances of the circuit.
    /// This may depend on extra circuit parameters but NOT on private witnesses.
    fn num_instance(&self) -> Vec<usize> {
        // todo: re-expose the accumulator if not fresh
        self.circuit.builder.borrow().num_instance()
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        // todo: re-expose the accumulator if not fresh
        self.circuit.builder.borrow().instances()
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        Some((0..4 * LIMBS).map(|idx| (0, idx)).collect())
    }

    /// Output the simple selector columns (before selector compression) of the circuit
    fn selectors(config: &Self::Config) -> Vec<Selector> {
        BaseCircuitBuilder::selectors(&config.base_field_config)
    }
}
