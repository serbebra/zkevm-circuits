use bus_mapping::circuit_input_builder::PrecompileEcParams;
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Challenge, Circuit, ConstraintSystem, Error},
};

use crate::{
    table::EccTable,
    util::{Challenges, SubCircuit, SubCircuitConfig},
};

use super::{EccCircuit, EccCircuitConfig, EccCircuitConfigArgs};

impl<F: Field> Circuit<F> for EccCircuit<F> {
    type Config = (EccCircuitConfig<F>, Challenges<Challenge>);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let ecc_table = EccTable::construct(meta);
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        (
            EccCircuitConfig::new(
                meta,
                EccCircuitConfigArgs {
                    ecc_table,
                    challenges: challenge_exprs,
                },
            ),
            challenges,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenge_values = config.1.values(&layouter);
        config.0.ecc_table.dev_load(
            &mut layouter,
            PrecompileEcParams {
                ec_add: self.max_add_ops,
                ec_mul: self.max_mul_ops,
                ec_pairing: self.max_pairing_ops,
            },
            &self.add_ops,
            &self.mul_ops,
            &self.pairing_ops,
            &challenge_values,
        )?;
        self.synthesize_sub(&config.0, &challenge_values, &mut layouter)
    }
}
