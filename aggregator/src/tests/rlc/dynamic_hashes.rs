use ark_std::test_rng;
use ethers_core::utils::keccak256;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;
use snark_verifier_sdk::{gen_pk, gen_snark_shplonk, verify_snark_shplonk, CircuitExt};
use zkevm_circuits::{
    keccak_circuit::{
        keccak_packed_multi::multi_keccak, KeccakCircuit, KeccakCircuitConfig,
        KeccakCircuitConfigArgs,
    },
    table::{KeccakTable, LookupTable},
    util::{Challenges, SubCircuitConfig},
};

use crate::{aggregation::VanillaPlonkConfig, constants::LOG_DEGREE};

#[derive(Default, Debug, Clone)]
struct DynamicHashCircuit {
    inputs: Vec<u8>,
}

#[derive(Debug, Clone)]
struct DynamicHashCircuitConfig {
    /// Keccak circuit configurations
    pub keccak_circuit_config: KeccakCircuitConfig<Fr>,
    /// RLC config
    pub plonk_config: VanillaPlonkConfig,
}

impl Circuit<Fr> for DynamicHashCircuit {
    type Config = (DynamicHashCircuitConfig, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let challenges = Challenges::construct(meta);

        // hash config
        // hash configuration for aggregation circuit
        let keccak_circuit_config = {
            let keccak_table = KeccakTable::construct(meta);
            let challenges_exprs = challenges.exprs(meta);

            let keccak_circuit_config_args = KeccakCircuitConfigArgs {
                keccak_table,
                challenges: challenges_exprs,
            };

            KeccakCircuitConfig::new(meta, keccak_circuit_config_args)
        };

        // plonk configuration
        let plonk_config =
            VanillaPlonkConfig::configure(meta, keccak_circuit_config.keccak_table, challenges);

        let config = DynamicHashCircuitConfig {
            plonk_config,
            keccak_circuit_config,
        };

        (config, challenges)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let (config, challenges) = config;

        config
            .keccak_circuit_config
            .load_aux_tables(&mut layouter)?;

        let challenge = challenges.values(&layouter);
        let hash_digest = keccak256(self.inputs.as_slice());

        let witness = multi_keccak(
            &[self.inputs.clone()],
            challenge,
            KeccakCircuit::<Fr>::capacity_for_row(1 << LOG_DEGREE),
        )
        .unwrap();

        layouter.assign_region(
            || "mock circuit",
            |mut region| -> Result<(), Error> {
                config.plonk_config.init(&mut region)?;

                // ==============================
                // keccak part
                // ==============================
                for (offset, keccak_row) in witness.iter().enumerate() {
                    let _ =
                        config
                            .keccak_circuit_config
                            .set_row(&mut region, offset, keccak_row)?;

                    // if offset < 1000 {
                    //     println!(
                    //         "{offset}-th keccak row:{:?} {:?} {:?} {:?}",
                    //         row[0].value(),
                    //         row[1].value(),
                    //         row[2].value(),
                    //         row[3].value(),
                    //     );
                    // }
                }

                config
                    .keccak_circuit_config
                    .keccak_table
                    .annotate_columns_in_region(&mut region);

                config.keccak_circuit_config.annotate_circuit(&mut region);

                // ==============================
                // rlc part
                // ==============================
                let mut offset = 0;

                let rlc_input_cell = {
                    let input_rlc_challenge = {
                        let mut tmp = Fr::zero();
                        challenge.keccak_input().map(|x| tmp = x);
                        config
                            .plonk_config
                            .load_private(&mut region, &tmp, &mut offset)?
                    };

                    let rlc_inputs = self
                        .inputs
                        .iter()
                        .map(|&x| {
                            config
                                .plonk_config
                                .load_private(&mut region, &Fr::from(x as u64), &mut offset)
                                .unwrap()
                        })
                        .collect::<Vec<_>>();

                    config.plonk_config.rlc(
                        &mut region,
                        &rlc_inputs,
                        &input_rlc_challenge,
                        &mut offset,
                    )?
                };

                let rlc_output_cell = {
                    let output_rlc_challenge = {
                        let mut tmp = Fr::zero();
                        challenge.evm_word().map(|x| tmp = x);
                        config
                            .plonk_config
                            .load_private(&mut region, &tmp, &mut offset)?
                    };
                    let rlc_outputs = hash_digest
                        .iter()
                        .map(|&x| {
                            config
                                .plonk_config
                                .load_private(&mut region, &Fr::from(x as u64), &mut offset)
                                .unwrap()
                        })
                        .collect::<Vec<_>>();
                    config.plonk_config.rlc(
                        &mut region,
                        &rlc_outputs,
                        &output_rlc_challenge,
                        &mut offset,
                    )?
                };

                config.plonk_config.lookup_keccak_rlcs(
                    &mut region,
                    &rlc_input_cell,
                    &rlc_output_cell,
                    &mut offset,
                )?;

                Ok(())
            },
        )?;
        Ok(())
    }
}

impl CircuitExt<Fr> for DynamicHashCircuit {}

#[test]
fn test_hash_circuit() {
    const LEN: usize = 100;
    let a = (0..LEN).map(|x| x as u8).collect::<Vec<u8>>();
    let circuit = DynamicHashCircuit { inputs: a };
    let prover = MockProver::run(LOG_DEGREE, &circuit, vec![]).unwrap();
    prover.assert_satisfied_par();
    println!("circuit satisfied");
}

#[ignore = "it takes too much time"]
#[test]
fn test_dynamic_hash_circuit() {
    let params = gen_srs(LOG_DEGREE);
    let mut rng = test_rng();
    const LEN: usize = 100;

    let a = (0..LEN).map(|x| x as u8).collect::<Vec<u8>>();
    let circuit = DynamicHashCircuit { inputs: a };
    let prover = MockProver::run(LOG_DEGREE, &circuit, vec![]).unwrap();
    prover.assert_satisfied_par();
    println!("circuit satisfied");

    let pk = gen_pk(&params, &circuit, None);

    // pk verifies the original circuit
    {
        let snark = gen_snark_shplonk(&params, &pk, circuit, &mut rng, None::<String>);
        assert!(verify_snark_shplonk::<DynamicHashCircuit>(
            &params,
            snark,
            pk.get_vk()
        ));
        println!("1 round keccak verified with same pk");
    }
    // pk verifies the circuit with 3 round of keccak
    {
        let a: Vec<u8> = (0..LEN * 3).map(|x| x as u8).collect::<Vec<u8>>();
        let circuit = DynamicHashCircuit { inputs: a };

        let snark = gen_snark_shplonk(&params, &pk, circuit, &mut rng, None::<String>);
        assert!(verify_snark_shplonk::<DynamicHashCircuit>(
            &params,
            snark,
            pk.get_vk()
        ));
        println!("3 round keccak verified with same pk");
    }
}
