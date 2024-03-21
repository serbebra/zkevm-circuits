use crate::{
    aggregation::{BlobDataConfig, RlcConfig},
    barycentric::BarycentricEvaluationConfig,
    blob::{Blob, BlobAssignments, BLOB_WIDTH},
    param::ConfigParams,
    BatchHash, MAX_AGG_SNARKS,
};
use eth_types::U256;
use halo2_base::{
    gates::range::{RangeConfig, RangeStrategy},
    AssignedValue, Context, ContextParams,
};
use halo2_ecc::bigint::CRTInteger;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    halo2curves::bn256::{Fq, Fr},
    plonk::{Circuit, ConstraintSystem, Error},
};
use zkevm_circuits::{
    table::{KeccakTable, LookupTable, RangeTable, U8Table},
    util::Challenges,
};

struct BlobCircuit {
    blob: Blob,
}

#[derive(Clone, Debug)]
struct BlobConfig {
    challenges: Challenges,

    u8_table: U8Table,
    range_table: RangeTable<MAX_AGG_SNARKS>,
    keccak_table: KeccakTable,

    rlc: RlcConfig,
    blob_data: BlobDataConfig,
    barycentric: BarycentricEvaluationConfig,
}

impl Circuit<Fr> for BlobCircuit {
    type Config = BlobConfig;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let u8_table = U8Table::construct(meta);
        let range_table = RangeTable::construct(meta);
        let challenges = Challenges::construct(meta);
        let keccak_table = KeccakTable::construct(meta);

        let rlc = RlcConfig::configure(meta, challenges);

        let parameters = ConfigParams::aggregation_param();
        let range = RangeConfig::<Fr>::configure(
            meta,
            RangeStrategy::Vertical,
            &parameters.num_advice,
            &parameters.num_lookup_advice,
            parameters.num_fixed,
            parameters.lookup_bits,
            0,
            parameters.degree.try_into().unwrap(),
        );
        let barycentric = BarycentricEvaluationConfig::construct(range);

        let challenge_expressions = challenges.exprs(meta);
        let blob_data = BlobDataConfig::configure(
            meta,
            challenge_expressions,
            u8_table,
            range_table,
            &keccak_table,
        );

        BlobConfig {
            challenges,

            u8_table,
            range_table,
            keccak_table,

            rlc,
            blob_data,
            barycentric,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let challenge_values = config.challenges.values(&layouter);

        config.u8_table.load(&mut layouter)?;
        config.range_table.load(&mut layouter)?;
        // config.keccak_table.dev_load(&mut layouter, &config.challenges)?;

        let mut batch_hash = BatchHash::default();
        batch_hash.blob = BlobAssignments {
            challenge_digest: U256::zero(),
            evaluation: U256::one(),
            coefficients: [U256::one(); BLOB_WIDTH],
        };

        let mut first_pass = halo2_base::SKIP_FIRST_PASS;
        let barycentric_assignments = layouter.assign_region(
            || "aggregation",
            |region| -> Result<
                (
                    Vec<CRTInteger<Fr>>,
                    Vec<AssignedValue<Fr>>,
                    Vec<AssignedValue<Fr>>,
                ),
                Error,
            > {
                if first_pass {
                    first_pass = false;
                    return Ok((vec![], vec![], vec![]));
                }

                let gate = &config.barycentric.scalar.range.gate;
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        max_rows: gate.max_rows,
                        num_context_ids: 1,
                        fixed_columns: gate.constants.clone(),
                    },
                );

                Ok(config.barycentric.assign2(
                    &mut ctx,
                    [U256::one(); 4096],
                    U256::zero(),
                    U256::zero(),
                ))
            },
        )?;

        config.blob_data.assign(
            &mut layouter,
            challenge_values,
            20, // mut rlc_config_offset: usize,
            &config.rlc,
            &batch_hash,
            &barycentric_assignments.0,
        )?;
        Ok(())
    }
}

#[test]
fn empty_blob() {
    let k = 20;
    let mock_prover = MockProver::<Fr>::run(
        k,
        &BlobCircuit {
            blob: Blob::default(),
        },
        vec![],
    )
    .expect("failed to run mock prover");
    mock_prover.assert_satisfied_par();
    panic!();
}
