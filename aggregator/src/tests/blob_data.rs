use crate::{aggregation::BlobDataConfig, blob::Blob, MAX_AGG_SNARKS};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};
use zkevm_circuits::{
    table::{KeccakTable, LookupTable, RangeTable, U8Table},
    util::Challenges,
};

struct BlobDataCircuit {
    blob: Blob,
}

impl Circuit<Fr> for BlobDataCircuit {
    type Config = (
        Challenges,
        U8Table,
        RangeTable<MAX_AGG_SNARKS>,
        KeccakTable,
        BlobDataConfig,
    );
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let u8_table = U8Table::construct(meta);
        let range_table = RangeTable::construct(meta);
        let challenges = Challenges::construct(meta);
        let challenge_expressions = challenges.exprs(meta);
        let keccak_table = KeccakTable::construct(meta);
        let blob_data_config = BlobDataConfig::configure(
            meta,
            challenge_expressions,
            u8_table,
            range_table,
            &keccak_table,
        );
        (
            challenges,
            u8_table,
            range_table,
            keccak_table,
            blob_data_config,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
