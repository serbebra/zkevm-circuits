use eth_types::{self, Field};
use halo2_base::gates::circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, BaseConfig};
use halo2_proofs::{
    plonk::{Advice, Circuit, Column, ConstraintSystem, Expression, Selector},
    poly::Rotation,
};

use crate::{
    evm_circuit::util::not,
    sig_circuit::{
        calc_required_advices, calc_required_lookup_advices, LOG_TOTAL_NUM_ROWS, MAX_NUM_SIG,
    },
    table::{KeccakTable, SigTable},
    util::{Challenges, Expr, SubCircuitConfig},
};

/// Circuit configuration arguments
pub struct SigCircuitConfigArgs<F: Field> {
    /// KeccakTable
    pub keccak_table: KeccakTable,
    /// SigTable
    pub sig_table: SigTable,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
}

/// SignVerify Configuration
#[derive(Debug, Clone)]
pub struct SigCircuitConfig<F: Field> {
    /// halo2-lib config
    pub range_config: BaseConfig<F>,
    // /// halo2-lib config
    // pub base_config: BaseConfig<F>,
    /// ECDSA parameters
    /// TODO: move to somewhere else
    num_limbs: usize,
    limb_bits: usize,
    /// An advice column to store RLC witnesses
    pub rlc_column: Column<Advice>,
    /// selector for keccak lookup table
    pub q_keccak: Selector,
    /// Used to lookup pk->pk_hash(addr)
    pub keccak_table: KeccakTable,
    /// The exposed table to be used by tx circuit and ecrecover
    pub sig_table: SigTable,
}

impl<F: Field> SubCircuitConfig<F> for SigCircuitConfig<F> {
    type ConfigArgs = SigCircuitConfigArgs<F>;

    /// Return a new SigConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            keccak_table,
            sig_table,
            challenges: _,
        }: Self::ConfigArgs,
    ) -> Self {
        #[cfg(feature = "onephase")]
        let num_advice = [calc_required_advices(MAX_NUM_SIG)];
        #[cfg(not(feature = "onephase"))]
        // need an additional phase 2 column/basic gate to hold the witnesses during RLC
        // computations
        let num_advice = vec![calc_required_advices(MAX_NUM_SIG), 1];

        let num_lookup_advice = vec![calc_required_lookup_advices(MAX_NUM_SIG), 1];

        #[cfg(feature = "onephase")]
        log::info!("configuring ECDSA chip with single phase");
        #[cfg(not(feature = "onephase"))]
        log::info!("configuring ECDSA chip with multiple phases");

        // halo2-ecc's range config
        // todo: move param to Cricuit::Param once SubCircuit trait supports Param
        let range_circuit_param = BaseCircuitParams {
            k: LOG_TOTAL_NUM_ROWS,
            num_advice_per_phase: num_advice,
            num_fixed: 1,
            num_lookup_advice_per_phase: num_lookup_advice,
            lookup_bits: Some(LOG_TOTAL_NUM_ROWS - 1),
            num_instance_columns: 0,
        };

        let range_circuit_config =
            BaseCircuitBuilder::configure_with_params(meta, range_circuit_param);

        // we need one phase 2 column to store RLC results
        #[cfg(feature = "onephase")]
        let rlc_column = meta.advice_column_in(halo2_proofs::plonk::FirstPhase);
        #[cfg(not(feature = "onephase"))]
        //
        let rlc_column = meta.advice_column_in(halo2_proofs::plonk::SecondPhase);
        // let rlc_column = meta.advice_column_in(halo2_proofs::plonk::FirstPhase);

        meta.enable_equality(rlc_column);

        meta.enable_equality(sig_table.recovered_addr);
        meta.enable_equality(sig_table.sig_r_rlc);
        meta.enable_equality(sig_table.sig_s_rlc);
        meta.enable_equality(sig_table.sig_v);
        meta.enable_equality(sig_table.is_valid);
        meta.enable_equality(sig_table.msg_hash_rlc);

        // Ref. spec SignVerifyChip 1. Verify that keccak(pub_key_bytes) = pub_key_hash
        // by keccak table lookup, where pub_key_bytes is built from the pub_key
        // in the ecdsa_chip.
        let q_keccak = meta.complex_selector();

        meta.lookup_any("keccak lookup table", |meta| {
            // When address is 0, we disable the signature verification by using a dummy pk,
            // msg_hash and signature which is not constrained to match msg_hash_rlc nor
            // the address.
            // Layout:
            // | q_keccak |       rlc       |
            // | -------- | --------------- |
            // |     1    | is_address_zero |
            // |          |    pk_rlc       |
            // |          |    pk_hash_rlc  |
            let q_keccak = meta.query_selector(q_keccak);
            let is_address_zero = meta.query_advice(rlc_column, Rotation::cur());
            let is_enable = q_keccak * not::expr(is_address_zero);

            let input = [
                is_enable.clone(),
                is_enable.clone(),
                is_enable.clone() * meta.query_advice(rlc_column, Rotation(1)),
                is_enable.clone() * 64usize.expr(),
                is_enable * meta.query_advice(rlc_column, Rotation(2)),
            ];
            let table = [
                meta.query_fixed(keccak_table.q_enable, Rotation::cur()),
                meta.query_advice(keccak_table.is_final, Rotation::cur()),
                meta.query_advice(keccak_table.input_rlc, Rotation::cur()),
                meta.query_advice(keccak_table.input_len, Rotation::cur()),
                meta.query_advice(keccak_table.output_rlc, Rotation::cur()),
            ];

            input.into_iter().zip(table).collect()
        });

        Self {
            range_config: range_circuit_config,
            // base_config: base_circuit_config,
            limb_bits: 88,
            num_limbs: 3,
            keccak_table,
            sig_table,
            q_keccak,
            rlc_column,
        }
    }
}
