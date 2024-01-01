use std::fs::File;

use halo2_proofs::{
    halo2curves::bn256::Fr,
    plonk::{Circuit, Column, ConstraintSystem, Instance},
};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::gates::circuit::{
    builder::BaseCircuitBuilder, BaseConfig,
};
use zkevm_circuits::{
    keccak_circuit::{KeccakCircuitConfig, KeccakCircuitConfigArgs},
    table::KeccakTable,
    util::{Challenges, SubCircuitConfig},
};

use crate::{ConfigParams, RlcConfig};

#[derive(Debug, Clone)]
#[rustfmt::skip]
/// Configurations for aggregation circuit.
/// This config is hard coded for BN256 curve.
pub struct AggregationConfig {
    /// Non-native field chip configurations
    pub base_field_config: BaseConfig<Fr>,
    /// Keccak circuit configurations
    pub keccak_circuit_config: KeccakCircuitConfig<Fr>,    
    /// RLC config
    pub rlc_config: RlcConfig,
    /// There are two instances for public input;
    /// - accumulator from aggregation, 12 elements, stored in base_field_config.instance
    /// - batch_public_input_hash, 32 elements, stored here
    /// - the number of valid SNARKs, 1 element, stored here
    pub pi_instance: Column<Instance>,
}

impl AggregationConfig {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<Fr>,
        params: ConfigParams,
        challenges: Challenges,
    ) -> Self {
        // It is wired that if we config ...
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

        let columns = keccak_circuit_config.cell_manager.columns();
        log::info!("keccak uses {} columns", columns.len(),);

        // enabling equality for preimage column
        meta.enable_equality(columns[keccak_circuit_config.preimage_column_index].advice);
        // enable equality for the digest column
        meta.enable_equality(columns.last().unwrap().advice);
        // enable equality for the data RLC column
        meta.enable_equality(keccak_circuit_config.keccak_table.input_rlc);
        // enable equality for the input data len column
        meta.enable_equality(keccak_circuit_config.keccak_table.input_len);
        // enable equality for the is_final column
        meta.enable_equality(keccak_circuit_config.keccak_table.is_final);


        let base_field_config = BaseCircuitBuilder::configure_with_params(meta, (&params).into());

        // RLC configuration
        let rlc_config = RlcConfig::configure(meta, challenges);

        // Instance column stores public input column
        // - the batch public input hash
        // - the number of valid SNARKs
        let pi_instance = meta.instance_column();
        meta.enable_equality(pi_instance);

        Self {
            base_field_config,
            keccak_circuit_config,
            rlc_config,
            pi_instance,
        }
    }

    /// Expose the instance columns
    /// There are two instances for public input;
    /// - accumulator from aggregation, 12 elements, stored in base_field_config.instance
    /// - batch_public_input_hash, 32 elements, stored here
    /// - the number of valid SNARKs, 1 element, stored here
    pub fn instance_columns(&self) -> Vec<Column<Instance>> {
        let mut instances = self.base_field_config.instance.clone();
        instances.extend([self.pi_instance]);
        instances
    }
}
