#![allow(missing_docs)]
//! wrapping of mpt-circuit
use crate::{
    table::{MptTable, PoseidonTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness,
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::bn256::Fr,
    plonk::{ConstraintSystem, Error},
};
use mpt_circuits::mpt;

/// Circuit wrapped with mpt table data
#[derive(Clone, Debug, Default)]
pub struct MptCircuit<F: Field> {
    base_circuit: mpt::MptCircuit,
    mpt_updates: witness::MptUpdates,
    _phantom: std::marker::PhantomData<F>,
}

/// Circuit configuration argument ts
pub struct MptCircuitConfigArgs {
    /// PoseidonTable
    pub poseidon_table: PoseidonTable,
    /// MptTable
    pub mpt_table: MptTable,
    /// Challenges
    pub challenges: Challenges,
}

/// re-wrapping for mpt config
#[derive(Clone)]
pub struct MptCircuitConfig<F: Field>(
    pub(crate) mpt::MptCircuitConfig,
    pub(crate) MptTable,
    std::marker::PhantomData<F>,
);

impl SubCircuitConfig<Fr> for MptCircuitConfig<Fr> {
    type ConfigArgs = MptCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<Fr>,
        Self::ConfigArgs {
            poseidon_table,
            mpt_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let poseidon_table = (
            poseidon_table.q_enable,
            [
                poseidon_table.input0,
                poseidon_table.input1,
                poseidon_table.hash_id,
                poseidon_table.control,
                poseidon_table.heading_mark,
            ],
        );
        let mpt_table_inp = //(
            //mpt_table.q_enable,
            [
                mpt_table.address,
                mpt_table.storage_key,
                mpt_table.proof_type,
                mpt_table.new_root,
                mpt_table.old_root,
                mpt_table.new_value,
                mpt_table.old_value,
            ];

        let conf = mpt::MptCircuitConfig::create(
            meta,
            mpt_table_inp,
            poseidon_table,
            challenges.evm_word(),
        );
        Self(conf, mpt_table, Default::default())
    }
}

#[cfg(any(feature = "test", test))]
impl SubCircuit<Fr> for MptCircuit<Fr> {
    type Config = MptCircuitConfig<Fr>;

    fn new_from_block(block: &witness::Block<Fr>) -> Self {
        use itertools::Itertools;

        let traces: Vec<_> = block
            .mpt_updates
            .proof_types
            .iter()
            .cloned()
            .zip_eq(block.mpt_updates.smt_traces.iter().cloned())
            .collect();

        Self {
            base_circuit: mpt::MptCircuit::from_traces(traces, block.circuits_params.max_mpt_rows),
            mpt_updates: block.mpt_updates.clone(),
            ..Default::default()
        }
    }

    fn min_num_rows_block(block: &witness::Block<Fr>) -> (usize, usize) {
        // FIXME
        (
            block.circuits_params.max_mpt_rows,
            block.circuits_params.max_mpt_rows,
        )
    }

    /// Make the assignments to the MptCircuit, notice it fill mpt table
    /// but not fill hash table
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<Fr>>,
        layouter: &mut impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let base = &self.base_circuit;
        config.0.assign(
            layouter,
            challenges.evm_word(),
            &base.proofs,
            base.row_limit,
        )?;
        config.1.load(
            layouter,
            &self.mpt_updates,
            base.row_limit,
            challenges.evm_word(),
        )?;
        Ok(())
    }

    /// powers of randomness for instance columns
    fn instance(&self) -> Vec<Vec<Fr>> {
        vec![]
    }
}


#[cfg(any(feature = "test", test))]
impl Circuit<Fr> for MptCircuit {
    type Config = (MptCircuitConfig, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            n_rows: 0,
            traces: vec![],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let poseidon_table = PoseidonTable::dev_construct(meta);
        let mpt_table = MptTable::construct(meta);

        let config = {
            //let challenges = challenges.exprs(meta);

            MptCircuitConfig::new(
                meta,
                MptCircuitConfigArgs {
                    poseidon_table,
                    mpt_table,
                    challenges,
                },
            )
        };

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);
        //let proofs: Vec<Proof> = self.traces.iter().map(Proof::from).collect();
        //config.poseidon_table.dev_load(&mut layouter, &hash_traces(&proofs));
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}