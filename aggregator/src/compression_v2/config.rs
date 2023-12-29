use std::fs::File;

use halo2_proofs::{
    halo2curves::bn256::Fr,
    plonk::{Circuit, Column, ConstraintSystem, Instance},
};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::gates::circuit::{
    builder::BaseCircuitBuilder, BaseConfig,
};

use crate::ConfigParams;

#[derive(Clone, Debug)]
/// Configurations for compression circuit
/// This config is hard coded for BN256 curve
pub struct CompressionConfig {
    /// Non-native field chip configurations
    pub base_field_config: BaseConfig<Fr>,
    // /// Instance for public input
    // pub instance: Column<Instance>,
}

impl CompressionConfig {
    pub(crate) fn new(meta: &mut ConstraintSystem<Fr>) -> Self {
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
        let base_field_config = BaseCircuitBuilder::configure_with_params(meta, (&params).into());
        // let instance = meta.instance_column();
        // meta.enable_equality(instance);

        Self {
            base_field_config,
            // instance,
        }
    }
}
