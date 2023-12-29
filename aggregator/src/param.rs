// use snark_verifier::loader::halo2::halo2_ecc::fields::fp::FpStrategy;

use snark_verifier::loader::halo2::halo2_ecc::halo2_base::gates::circuit::BaseCircuitParams;

use crate::{BITS, LIMBS};

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
/// Parameters for aggregation circuit and compression circuit configs.
pub struct ConfigParams {
    pub degree: u32,
    pub num_advice: Vec<usize>,
    pub num_lookup_advice: Vec<usize>,
    pub num_fixed: usize,
    pub lookup_bits: usize,
}

impl From<&ConfigParams> for BaseCircuitParams {
    fn from(config_param: &ConfigParams) -> Self {
        Self {
            k: config_param.degree as usize,
            num_advice_per_phase: config_param.num_advice.clone(),
            num_fixed: config_param.num_fixed,
            num_lookup_advice_per_phase: config_param.num_lookup_advice.clone(),
            lookup_bits: Some(config_param.lookup_bits),
            num_instance_columns: 1,
        }
    }
}

impl ConfigParams {
    pub(crate) fn aggregation_param() -> Self {
        Self {
            // strategy: FpStrategy::Simple,
            degree: 19,
            num_advice: vec![64],
            num_lookup_advice: vec![8],
            num_fixed: 2,
            lookup_bits: 18,
        }
    }

    pub(crate) fn default_compress_wide_param() -> Self {
        Self {
            // strategy: FpStrategy::Simple,
            degree: 22,
            num_advice: vec![35],
            num_lookup_advice: vec![1],
            num_fixed: 1,
            lookup_bits: 20,
        }
    }

    pub(crate) fn compress_thin_param() -> Self {
        Self {
            // strategy: FpStrategy::Simple,
            degree: 25,
            num_advice: vec![1],
            num_lookup_advice: vec![1],
            num_fixed: 1,
            lookup_bits: 20,
        }
    }
}
