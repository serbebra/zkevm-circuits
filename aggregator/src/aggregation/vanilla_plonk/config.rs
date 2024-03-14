use halo2_proofs::{
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Fixed, SecondPhase, Selector},
    poly::Rotation,
};

#[cfg(test)]
use halo2_proofs::plonk::FirstPhase;
use zkevm_circuits::util::Challenges;

use super::lookup::HashValueLookupTable;

/// This config is used to compute RLCs for bytes.
/// It requires a phase 2 column
#[derive(Debug, Clone, Copy)]
pub struct VanillaPlonkConfig {
    #[cfg(test)]
    // Test requires a phase 1 column before proceed to phase 2.
    pub(crate) _phase_1_column: Column<Advice>,
    pub(crate) phase_2_column: Column<Advice>,
    pub(crate) fixed: Column<Fixed>,
    pub(crate) plonk_gate_selector: Selector,
    pub(crate) lookup_gate_selector: Selector,
    pub(crate) enable_challenge: Selector,
    pub(crate) lookup_table: HashValueLookupTable,
}

impl VanillaPlonkConfig {
    pub(crate) fn configure(meta: &mut ConstraintSystem<Fr>, challenge: Challenges) -> Self {
        let plonk_gate_selector = meta.complex_selector();
        let lookup_gate_selector = meta.complex_selector();
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
            let cs1 = q1 * (a.clone() * b + c - d);

            // constraint: q2*(a-challenge) = 0
            // FIXME later: Pretty wasteful to have a dedicated custom gate and selector column just
            // to extract the keccak challenge cell...
            let q2 = meta.query_selector(enable_challenge);
            let cs2 = q2 * (a - challenge_expr.keccak_input());

            vec![cs1, cs2]
        });

        let lookup_table = HashValueLookupTable::construct(meta);

        meta.lookup_any("hash values lookup", |meta| {
            let q = meta.query_selector(lookup_gate_selector);
            let input_rlc = meta.query_advice(phase_2_column, Rotation::cur());
            let output_rlc = meta.query_advice(phase_2_column, Rotation::next());
            let table_enabled = meta.query_any(lookup_table.q_enable, Rotation::cur());
            let table_input_value = meta.query_any(lookup_table.input_rlcs, Rotation::cur());
            let table_output_value = meta.query_any(lookup_table.output_rlcs, Rotation::cur());

            vec![
                (
                    q.clone() * input_rlc,
                    table_enabled.clone() * table_input_value,
                ),
                (q * output_rlc, table_enabled * table_output_value),
            ]
        });

        Self {
            #[cfg(test)]
            _phase_1_column,
            phase_2_column,
            fixed,
            plonk_gate_selector,
            lookup_gate_selector,
            enable_challenge,
            lookup_table,
        }
    }
}
