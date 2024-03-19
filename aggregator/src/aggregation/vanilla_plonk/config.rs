use halo2_proofs::{
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Expression, Fixed, SecondPhase, Selector},
    poly::Rotation,
};

#[cfg(test)]
use halo2_proofs::plonk::FirstPhase;
use zkevm_circuits::{table::KeccakTable, util::Challenges};

// use super::lookup::HashValueLookupTable;

/// This config is used to compute RLCs for bytes.
/// It requires a phase 2 column
#[derive(Debug, Clone)]
pub struct VanillaPlonkConfig {
    #[cfg(test)]
    // Test requires a phase 1 column before proceed to phase 2.
    pub(crate) _phase_1_column: Column<Advice>,
    pub(crate) phase_2_column: Column<Advice>,
    pub(crate) fixed: Column<Fixed>,
    pub(crate) plonk_gate_selector: Selector,
    pub(crate) preimage_lookup_selector: Selector,
    pub(crate) digest_lookup_selector: Selector,
    pub(crate) enable_challenge: Selector,
}

impl VanillaPlonkConfig {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<Fr>,
        keccak_table: KeccakTable,
        challenge: Challenges,
    ) -> Self {
        let plonk_gate_selector = meta.complex_selector();
        let preimage_lookup_selector = meta.complex_selector();
        let digest_lookup_selector = meta.complex_selector();
        let enable_challenge = meta.complex_selector();
        let challenge_expr = challenge.exprs(meta);

        #[cfg(test)]
        // CS requires existence of at least one phase 1 column if we operate on phase 2 columns.
        // This column is not really used.
        let _phase_1_column = {
            let column = meta.advice_column_in(FirstPhase);
            meta.enable_equality(column);
            column
        };

        let phase_2_column = meta.advice_column_in(SecondPhase);
        meta.enable_equality(phase_2_column);

        let fixed = meta.fixed_column();
        meta.enable_equality(fixed);

        meta.create_gate("vanilla_plonk_gate", |meta| {
            // phase_2_column | plonk_gate_selector | enable_challenge
            // ---------------|---------------------|------------------
            // a              | q1                  | q2
            // b              | 0                   | 0
            // c              | 0                   | 0
            // d              | 0                   | 0
            //
            // constraint: q1*(a*b+c-d) = 0
            let a = meta.query_advice(phase_2_column, Rotation(0));
            let b = meta.query_advice(phase_2_column, Rotation(1));
            let c = meta.query_advice(phase_2_column, Rotation(2));
            let d = meta.query_advice(phase_2_column, Rotation(3));
            let q1 = meta.query_selector(plonk_gate_selector);
            let cs1 = q1 * (a.clone() * b.clone() + c - d);

            // constraint: q2*(a-keccak_challenge) = 0 and q2*(a-evm_challenge) = 0
            // FIXME later: Pretty wasteful to have a dedicated custom gate and selector column just
            // to extract the keccak challenge cells...
            let q2 = meta.query_selector(enable_challenge);
            let cs2 = q2.clone() * (a - challenge_expr.keccak_input());
            let cs3 = q2 * (b - challenge_expr.evm_word());

            vec![cs1, cs2, cs3]
        });

        //        vanilla plonk config
        //
        // phase_2_column | lookup_preimage | lookup_digest |
        // ---------------|-----------------|---------------|
        // a              | q1              | q2
        // b              | 0               | 0

        //        keccak table config
        //
        // q_enable      | input_rlc            | output_rlc         | is_final
        // --------------|----------------------|--------------------|----------
        // table_enabled | table_input_value    | table_output_value | q_final

        // constraint:
        // - if (q1, q2) == (1, 0) a*q1 \in input_rlc * table_enabled
        // - if (q1, q2) == (0, 1) b*q2 \in output_rlc * table_enabled
        // - if (q1, q2) == (1, 1) (a*q, b*q) \in (input_rlc * table_enabled, output_rlc *
        //   table_enabled)

        meta.lookup_any("keccak lookup", |meta| {
            //        vanilla plonk config
            //
            // phase_2_column | lookup_preimage | lookup_digest |
            // ---------------|-----------------|---------------|
            // a              | q1              | q2
            // b              | 0               | 0

            //        keccak table config
            //
            // q_enable      | input_rlc            | output_rlc         | is_final
            // --------------|----------------------|--------------------|----------
            // table_enabled | table_input_value    | table_output_value | q_final

            // constraint:
            // - if (q1, q2) == (1, 0) a*q1 \in input_rlc * table_enabled
            // - if (q1, q2) == (0, 1) b*q2 \in output_rlc * table_enabled
            // - if (q1, q2) == (1, 1) (a*q, b*q) \in (input_rlc * table_enabled, output_rlc *
            //   table_enabled)

            let q1 = meta.query_selector(preimage_lookup_selector);
            let q2 = meta.query_selector(digest_lookup_selector);
            let input_rlc = meta.query_advice(phase_2_column, Rotation::cur());
            // let output_rlc = meta.query_advice(phase_2_column, Rotation::next());
            let table_enabled = meta.query_any(keccak_table.q_enable, Rotation::cur());
            let table_input_value = meta.query_any(keccak_table.input_rlc, Rotation::cur());
            // let table_output_value = meta.query_any(keccak_table.output_rlc, Rotation::cur());
            let table_final = meta.query_any(keccak_table.is_final, Rotation::cur());

            vec![
                (
                    q1 * (Expression::Constant(Fr::one()) - q2) * input_rlc,
                    table_enabled.clone() * table_final.clone() * table_input_value,
                ),
                // (
                //     q2 * output_rlc,
                //     table_enabled * table_final * table_output_value,
                // ),
            ]
        });

        meta.lookup_any("keccak lookup", |meta| {
            //        vanilla plonk config
            //
            // phase_2_column | lookup_preimage | lookup_digest |
            // ---------------|-----------------|---------------|
            // a              | q1              | q2
            // b              | 0               | 0

            //        keccak table config
            //
            // q_enable      | input_rlc            | output_rlc         | is_final
            // --------------|----------------------|--------------------|----------
            // table_enabled | table_input_value    | table_output_value | q_final

            // constraint:
            // - if (q1, q2) == (1, 0) a*q1 \in input_rlc * table_enabled
            // - if (q1, q2) == (0, 1) b*q2 \in output_rlc * table_enabled
            // - if (q1, q2) == (1, 1) (a*q, b*q) \in (input_rlc * table_enabled, output_rlc *
            //   table_enabled)

            let q1 = meta.query_selector(preimage_lookup_selector);
            let q2 = meta.query_selector(digest_lookup_selector);
            // let input_rlc = meta.query_advice(phase_2_column, Rotation::cur());
            let output_rlc = meta.query_advice(phase_2_column, Rotation::cur());
            let table_enabled = meta.query_any(keccak_table.q_enable, Rotation::cur());
            // let table_input_value = meta.query_any(keccak_table.input_rlc, Rotation::cur());
            let table_output_value = meta.query_any(keccak_table.output_rlc, Rotation::cur());
            let table_final = meta.query_any(keccak_table.is_final, Rotation::cur());

            vec![
                // (
                //     q1 * input_rlc,
                //     table_enabled.clone() * table_final.clone() * table_input_value,
                // ),
                (
                    (Expression::Constant(Fr::one()) - q1) * q2 * output_rlc,
                    table_enabled * table_final * table_output_value,
                ),
            ]
        });

        meta.lookup_any("keccak lookup", |meta| {
            let q1 = meta.query_selector(preimage_lookup_selector);
            let q2 = meta.query_selector(digest_lookup_selector);
            let input_rlc = meta.query_advice(phase_2_column, Rotation::cur());
            let output_rlc = meta.query_advice(phase_2_column, Rotation::next());
            let table_enabled = meta.query_any(keccak_table.q_enable, Rotation::cur());
            let table_input_value = meta.query_any(keccak_table.input_rlc, Rotation::cur());
            let table_output_value = meta.query_any(keccak_table.output_rlc, Rotation::cur());
            let table_final = meta.query_any(keccak_table.is_final, Rotation::cur());

            vec![
                (
                    q1.clone() * q2.clone() * input_rlc,
                    table_enabled.clone() * table_final.clone() * table_input_value,
                ),
                (
                    q1 * q2 * output_rlc,
                    table_enabled * table_final * table_output_value,
                ),
            ]
        });

        Self {
            #[cfg(test)]
            _phase_1_column,
            phase_2_column,
            fixed,
            plonk_gate_selector,
            preimage_lookup_selector,
            digest_lookup_selector,
            enable_challenge,
        }
    }
}
