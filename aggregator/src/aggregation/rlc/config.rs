use halo2_proofs::{
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Fixed, SecondPhase, Selector},
    poly::Rotation,
};

#[cfg(test)]
use halo2_proofs::plonk::FirstPhase;
use zkevm_circuits::{table::KeccakTable, util::{Challenges, Expr}};

/// This config is used to compute RLCs for bytes.
/// It requires a phase 2 column
#[derive(Debug, Clone, Copy)]
pub struct RlcConfig {
    #[cfg(test)]
    // Test requires a phase 1 column before proceed to phase 2.
    pub(crate) _phase_1_column: Column<Advice>,
    pub(crate) phase_2_column: Column<Advice>,
    pub(crate) selector: Selector,
    pub(crate) lookup_gate_selector: Selector,
    pub(crate) fixed: Column<Fixed>,
    pub(crate) enable_challenge1: Selector,
    pub(crate) enable_challenge2: Selector,
}

impl RlcConfig {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<Fr>,
        keccak_table: &KeccakTable,
        challenge: Challenges,
    ) -> Self {
        let selector = meta.complex_selector();
        let lookup_gate_selector = meta.complex_selector();
        let enable_challenge1 = meta.complex_selector();
        let enable_challenge2 = meta.complex_selector();
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

        meta.create_gate("rlc_gate", |meta| {
            // phase_2_column | advice | enable_challenge
            // ---------------|--------|------------------
            // a              | q1     | q2
            // b              | 0      | 0
            // c              | 0      | 0
            // d              | 0      | 0
            //
            // constraint: q1*(a*b+c-d) = 0
            let a = meta.query_advice(phase_2_column, Rotation(0));
            let b = meta.query_advice(phase_2_column, Rotation(1));
            let c = meta.query_advice(phase_2_column, Rotation(2));
            let d = meta.query_advice(phase_2_column, Rotation(3));
            let q1 = meta.query_selector(selector);
            let cs1 = q1 * (a.clone() * b + c - d);

            // constraint: q2*(a-challenge) = 0
            // FIXME later: Pretty wasteful to have a dedicated custom gate and selector column just
            // to extract the keccak challenge cell...
            let q2 = meta.query_selector(enable_challenge1);
            let cs2 = q2 * (a.expr() - challenge_expr.keccak_input());

            let q3 = meta.query_selector(enable_challenge2);
            let cs3 = q3 * (a - challenge_expr.evm_word());

            vec![cs1, cs2, cs3]
        });

        // enabling the following lookup gate will introduce an error
        meta.lookup_any("rlc keccak lookup", |meta| {
            let q = meta.query_selector(lookup_gate_selector);
            let input_rlc = meta.query_advice(phase_2_column, Rotation::cur());
            let output_rlc = meta.query_advice(phase_2_column, Rotation::next());
            let data_len = meta.query_advice(phase_2_column, Rotation(2));
            let table_enabled = meta.query_any(keccak_table.q_enable, Rotation::cur());
            let table_input_value = meta.query_any(keccak_table.input_rlc, Rotation::cur());
            let table_output_value = meta.query_any(keccak_table.output_rlc, Rotation::cur());
            let table_data_len = meta.query_any(keccak_table.input_len, Rotation::cur());
            let table_final = meta.query_any(keccak_table.is_final, Rotation::cur());

            vec![
                (
                    q.clone() * input_rlc,
                    table_enabled.clone() * table_final.clone() * table_input_value,
                ),
                (
                    q.clone() * output_rlc,
                    table_enabled.clone() * table_final.clone() * table_output_value,
                ),
                (q * data_len, table_enabled * table_final * table_data_len),
            ]
        });

        Self {
            #[cfg(test)]
            _phase_1_column,
            phase_2_column,
            selector,
            lookup_gate_selector,
            fixed,
            enable_challenge1,
            enable_challenge2,
        }
    }
}
