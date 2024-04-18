//! Circuit implementation for compression circuit.

use std::fs::File;

use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    circuit::{Cell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::G1Affine,
    plonk::{Circuit, ConstraintSystem, Error},
};
use rand::Rng;
use snark_verifier::{
    loader::halo2::{
        halo2_ecc::{
            halo2_base,
            halo2_base::{
                halo2_proofs::{
                    halo2curves::bn256::{Bn256, Fr},
                    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
                },
                Context, ContextParams,
            },
        },
        Halo2Loader,
    },
    pcs::kzg::{Bdfg21, Kzg, KzgSuccinctVerifyingKey},
};
use snark_verifier_sdk::{aggregate, flatten_accumulator, types::Svk, Snark, SnarkWitness};

use crate::{core::extract_proof_and_instances_with_pairing_check, param::ConfigParams, ACC_LEN};

use super::config::SimpleAggregationConfig;

/// Input a proof, this compression circuit generates a new proof that may have smaller size.
///
/// It re-exposes same public inputs from the input snark.
/// All this circuit does is to reduce the proof size.
#[derive(Clone, Debug)]
pub struct SimpleAggregationCircuit {
    pub(crate) svk: KzgSuccinctVerifyingKey<G1Affine>,
    pub(crate) snarks: Vec<SnarkWitness>,
    /// instances, flattened.
    /// It re-exposes same public inputs from the input snarks.
    /// This flattened_instances excludes the previous accumulator.
    pub(crate) flattened_instances: Vec<Fr>,
    // accumulation scheme proof, private input
    pub(crate) as_proof: Value<Vec<u8>>,
}

impl Circuit<Fr> for SimpleAggregationCircuit {
    type Config = SimpleAggregationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        let flattened_instances = self
            .snarks
            .iter()
            .flat_map(|snark| {
                snark
                    .instances
                    .iter()
                    .flat_map(|instance| instance.iter().map(|_| Fr::zero()))
            })
            .collect();

        let snarks = self
            .snarks
            .iter()
            .map(|snark| SnarkWitness::without_witnesses(snark))
            .collect();

        Self {
            svk: self.svk,
            snarks,
            flattened_instances,
            as_proof: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // Too bad that configure function doesn't take additional input
        // it would be nicer to load parameters from API rather than ENV
        let path = std::env::var("COMPRESSION_CONFIG")
            .unwrap_or_else(|_| "configs/compression_wide.config".to_owned());
        let params: ConfigParams = serde_json::from_reader(
            File::open(path.as_str()).unwrap_or_else(|_| panic!("{path:?} does not exist")),
        )
        .unwrap_or_else(|_| ConfigParams::default_compress_wide_param());

        log::info!(
            "compression circuit configured with k = {} and {:?} advice columns",
            params.degree,
            params.num_advice
        );

        // circuit configuration is built from config with given num columns etc
        // can be wide or thin circuit
        Self::Config::configure(meta, params)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let witness_time = start_timer!(|| "synthesize | compression Circuit");
        config
            .range()
            .load_lookup_table(&mut layouter)
            .expect("load range lookup table");

        let mut first_pass = halo2_base::SKIP_FIRST_PASS;

        let instances = layouter.assign_region(
            || "compression circuit",
            |region| -> Result<Vec<Cell>, Error> {
                if first_pass {
                    first_pass = false;
                    return Ok(vec![]);
                }
                let mut instances = vec![];
                let ctx = Context::new(
                    region,
                    ContextParams {
                        max_rows: config.gate().max_rows,
                        num_context_ids: 1,
                        fixed_columns: config.gate().constants.clone(),
                    },
                );

                let ecc_chip = config.ecc_chip();
                let loader = Halo2Loader::new(ecc_chip, ctx);
                let (assigned_instances, acc) = aggregate::<Kzg<Bn256, Bdfg21>>(
                    &self.svk,
                    &loader,
                    &self.snarks,
                    self.as_proof(),
                );

                // instance of the compression circuit is defined as
                // - accumulators
                // - re-export the public input from snark
                instances.extend(
                    flatten_accumulator(acc)
                        .iter()
                        .map(|assigned| assigned.cell()),
                );
                // the snark is not a fresh one, assigned_instances already contains an
                // accumulator so we want to skip the first 12 elements from the public input
                instances.extend(assigned_instances.iter().flat_map(|instance_column| {
                    instance_column.iter().skip(ACC_LEN).map(|x| x.cell())
                }));

                config.range().finalize(&mut loader.ctx_mut());

                loader.ctx_mut().print_stats(&["Range"]);
                Ok(instances)
            },
        )?;

        // Expose instances
        for (i, cell) in instances.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.instance, i)?;
        }

        end_timer!(witness_time);
        Ok(())
    }
}

impl SimpleAggregationCircuit {
    /// Build a new circuit from a snark, with a flag whether this snark has been compressed before
    pub fn new(
        params: &ParamsKZG<Bn256>,
        snarks: &[Snark],
        rng: impl Rng + Send,
    ) -> Result<Self, snark_verifier::Error> {
        let svk = params.get_g()[0].into();

        // for the proof compression, only ONE snark is under accumulation
        // it is turned into an accumulator via KzgAs accumulation scheme
        // in case not first time:
        log::trace!("compression circuit pairing check");
        let (as_proof, acc_instances) =
            extract_proof_and_instances_with_pairing_check(params, &snarks, rng)?;

        // skip the old accumulator
        let snark_instance = snarks.iter().flat_map(|snark| {
            snark
                .instances
                .iter()
                .flat_map(|instance| instance.iter().skip(ACC_LEN))
        });

        let flattened_instances = acc_instances
            .iter()
            .chain(snark_instance)
            .cloned()
            .collect::<Vec<_>>();

        let snark_witnesses = snarks
            .iter()
            .map(|snark| SnarkWitness::from(snark.clone()))
            .collect();

        {
            log::trace!("flattened instances:");
            for i in flattened_instances.iter() {
                log::trace!("{:?}", i);
            }
        }

        Ok(Self {
            svk,
            snarks: snark_witnesses,
            flattened_instances,
            as_proof: Value::known(as_proof),
        })
    }

    pub fn succinct_verifying_key(&self) -> &Svk {
        &self.svk
    }

    pub fn as_proof(&self) -> Value<&[u8]> {
        self.as_proof.as_ref().map(Vec::as_slice)
    }
}
