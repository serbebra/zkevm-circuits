use std::borrow::{Borrow, BorrowMut};

use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    halo2curves::bn256::{Bn256, Fr},
    plonk::{Circuit, ConstraintSystem, Error, Selector},
    poly::kzg::commitment::ParamsKZG,
};
use rand::Rng;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::gates::circuit::{
    builder::BaseCircuitBuilder, BaseCircuitParams, CircuitBuilderStage,
};
use snark_verifier_sdk::{
    halo2::aggregation::{AggregationCircuit as AggCircuit, VerifierUniversality},
    CircuitExt, Snark,
};
use zkevm_circuits::util::Challenges;

use crate::{
    core::assign_batch_hashes, 
    util::parse_hash_digest_cells, AccScheme, AggregationConfig,
    BatchHash, ConfigParams, ACC_LEN, DIGEST_LEN, MAX_AGG_SNARKS,
};

/// Aggregation circuit that does not re-expose any public inputs from aggregated snarks
#[derive(Clone)]
pub struct AggregationCircuit {
    /// snark verifier's aggregation circuit builder
    pub agg_circuit: AggCircuit,
    // the batch's public_input_hash (32 elements)
    pub pi_instances: Vec<Fr>,
    // batch hash circuit for which the snarks are generated
    // the chunks in this batch are also padded already
    pub batch_hash: BatchHash,
}

impl AggregationCircuit {
    pub fn new(
        stage: CircuitBuilderStage,
        config_params: &ConfigParams,
        params: &ParamsKZG<Bn256>,
        snarks_with_padding: &[Snark],
        rng: impl Rng + Send,
        batch_hash: BatchHash,
        break_points: Option<Vec<Vec<usize>>>,
    ) -> Result<Self, snark_verifier::Error> {
        let timer = start_timer!(|| "new | aggregation circuit");

        // sanity check: snarks's public input matches chunk_hashes
        for (chunk, snark) in batch_hash
            .chunks_with_padding
            .iter()
            .zip(snarks_with_padding.iter())
        {
            let chunk_hash_bytes = chunk.public_input_hash();
            let snark_hash_bytes = &snark.instances[0];

            println!(
                "snark hash bytes ({}): {:?}",
                snark_hash_bytes.len(),
                snark_hash_bytes
            );
            assert_eq!(snark_hash_bytes.len(), ACC_LEN + DIGEST_LEN);

            for i in 0..DIGEST_LEN {
                // for each snark,
                //  first 12 elements are accumulator
                //  next 32 elements are public_input_hash
                //  accumulator + public_input_hash = snark public input
                assert_eq!(
                    Fr::from(chunk_hash_bytes.as_bytes()[i] as u64),
                    snark_hash_bytes[i + ACC_LEN]
                );
            }
        }

        let config_params: BaseCircuitParams = config_params.into();

        let agg_circuit = match stage {
            CircuitBuilderStage::Prover => AggCircuit::new::<AccScheme>(
                stage,
                config_params.try_into().unwrap(),
                params,
                snarks_with_padding.into_iter().cloned(),
                VerifierUniversality::None,
            )
            .use_break_points(break_points.unwrap()),
            _ => AggCircuit::new::<AccScheme>(
                stage,
                config_params.try_into().unwrap(),
                params,
                snarks_with_padding.into_iter().cloned(),
                VerifierUniversality::None,
            ),
        };

        // extract batch's public input hash
        let pi_instances = batch_hash.instances_exclude_acc()[0].clone();
        println!("pi bytes ({}): {:?}", pi_instances.len(), pi_instances);

        // let param = agg_circuit.borrow_mut().calculate_params(None);
        // println!("param: {:?}", param);

        end_timer!(timer);
        Ok(Self {
            agg_circuit,
            pi_instances,
            batch_hash,
        })
    }
}

impl Circuit<Fr> for AggregationCircuit {
    type Config = (AggregationConfig, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    // todo: pass params
    type Params = ();

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }


    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let config =
            AggregationConfig::configure(meta, ConfigParams::aggregation_param(), challenges);
        // todo: build config from Params rather than ENV VARs
        (config, challenges)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let (config, challenge) = config;

        // ==============================================
        // Step 1: snark aggregation circuit
        // ==============================================
        // let param = self.agg_circuit.clone().borrow_mut().calculate_params(None);
        // println!("\n\nparam: {:?}\n\n", param);
        self.agg_circuit
            .builder
            .borrow()
            .synthesize_ref_layouter(config.base_field_config.clone(), &mut layouter)?;
            // .synthesize(config.base_field_config, layouter)?;

        // ==============================================
        // step 2: public input aggregation circuit
        // ==============================================
        // extract all the hashes and load them to the hash table
        let challenges = challenge.values(&layouter);

        let timer = start_timer!(|| "load aux table");

        let hash_digest_cells = {
            config
                .keccak_circuit_config
                .load_aux_tables(&mut layouter)?;
            end_timer!(timer);

            let timer = start_timer!(|| "extract hash");
            // orders:
            // - batch_public_input_hash
            // - chunk\[i\].piHash for i in \[0, MAX_AGG_SNARKS)
            // - batch_data_hash_preimage
            let preimages = self.batch_hash.extract_hash_preimages();
            assert_eq!(
                preimages.len(),
                MAX_AGG_SNARKS + 2,
                "error extracting preimages"
            );
            end_timer!(timer);

            let timer = start_timer!(|| ("assign hash cells").to_string());
            let chunks_are_valid = self
                .batch_hash
                .chunks_with_padding
                .iter()
                .map(|chunk| !chunk.is_padding)
                .collect::<Vec<_>>();
            let hash_digest_cells = assign_batch_hashes(
                &config,
                &mut layouter,
                challenges,
                &chunks_are_valid,
                &preimages,
            )
            .map_err(|_e| Error::ConstraintSystemFailure)?;
            end_timer!(timer);
            hash_digest_cells
        };
        // digests
        let (batch_pi_hash_digest, chunk_pi_hash_digests, _potential_batch_data_hash_digest) =
            parse_hash_digest_cells(&hash_digest_cells);

        // ==============================================
        // step 3: assert public inputs to the snarks are correct
        // ==============================================
        for (i, chunk) in chunk_pi_hash_digests.iter().enumerate() {
            let hash = self.batch_hash.chunks_with_padding[i].public_input_hash();
            for j in 0..4 {
                for k in 0..8 {
                    log::trace!(
                        "pi {:02x} {:?}",
                        hash[j * 8 + k],
                        chunk[8 * (3 - j) + k].value()
                    );
                }
            }
        }

        self.agg_circuit.builder.borrow_mut().clear();
        Ok(())
    }
}

impl CircuitExt<Fr> for AggregationCircuit {
    fn num_instance(&self) -> Vec<usize> {
        // 12 elements from accumulator
        // 32 elements from batch's public_input_hash
        vec![ACC_LEN + DIGEST_LEN]
    }

    // 12 elements from accumulator
    // 32 elements from batch's public_input_hash
    fn instances(&self) -> Vec<Vec<Fr>> {
        let mut res = self.agg_circuit.builder.borrow().instances();
        res.extend([self.pi_instances.clone()]);
        res
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        // the accumulator are the first 12 cells in the instance
        Some((0..ACC_LEN).map(|idx| (0, idx)).collect())
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        // - advice columns from flex gate
        // - selector from RLC gate
        BaseCircuitBuilder::selectors(&config.0.base_field_config)
            // .into_iter()
            // .chain(
            //     [
            //         config.0.rlc_config.selector,
            //         config.0.rlc_config.enable_challenge,
            //     ]
            //     .iter()
            //     .cloned(),
            // )
            // .collect()
    }
}
