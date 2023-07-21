use bus_mapping::precompile::PrecompileCalls;
use eth_types::Field;
use gadgets::util::{and, not, or, Expr};
use halo2_proofs::plonk::Error;

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{IsZeroGadget, LtGadget},
            CachedRegion, Cell,
        },
    },
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};

/// Note: input_len ∈ { 0, 192, 384, 576, 768 } if valid.
///
/// Note: input bytes are padded to 768 bytes within our zkEVM implementation to standardise a
/// pairing operation, such that each pairing op has 4 pairs: [(G1, G2); 4].
#[derive(Clone, Debug)]
pub struct EcPairingGadget<F> {
    // Random linear combination of input bytes to the precompile ecPairing.
    input_rlc: Cell<F>,
    // Boolean output from the ecPairing call, denoting whether or not the pairing check was
    // successful.
    output: Cell<F>,

    // Verify invalidity of input bytes. We basically check `or(1, 2)` where:
    // 1. input_len > 4 * 192
    // 2. input_len % 192 != 0
    input_is_zero: IsZeroGadget<F>,
    input_lt_769: LtGadget<F, 2>,
    input_mod_192: Cell<F>,
    input_mod_192_lt: LtGadget<F, 1>,
    input_mod_192_is_zero: IsZeroGadget<F>,

    is_success: Cell<F>,
    callee_address: Cell<F>,
    caller_id: Cell<F>,
    call_data_offset: Cell<F>,
    call_data_length: Cell<F>,
    return_data_offset: Cell<F>,
    return_data_length: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for EcPairingGadget<F> {
    const NAME: &'static str = "EC_PAIRING";

    const EXECUTION_STATE: ExecutionState = ExecutionState::PrecompileBn256Pairing;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let (input_rlc, output) = (cb.query_cell_phase2(), cb.query_bool());

        let [is_success, callee_address, caller_id, call_data_offset, call_data_length, return_data_offset, return_data_length] =
            [
                CallContextFieldTag::IsSuccess,
                CallContextFieldTag::CalleeAddress,
                CallContextFieldTag::CallerId,
                CallContextFieldTag::CallDataOffset,
                CallContextFieldTag::CallDataLength,
                CallContextFieldTag::ReturnDataOffset,
                CallContextFieldTag::ReturnDataLength,
            ]
            .map(|tag| cb.call_context(None, tag));

        cb.precompile_info_lookup(
            cb.execution_state().as_u64().expr(),
            callee_address.expr(),
            cb.execution_state().precompile_base_gas_cost().expr(),
        );

        // validate successful call to the precompile ecPairing.
        cb.condition(is_success.expr(), |cb| {
            // Covers the following cases:
            // 1. successful pairing check (where input_rlc == 0).
            // 2. successful pairing check (where input_rlc != 0).
            // 3. unsuccessful pairing check.
            cb.ecc_table_lookup(
                u64::from(PrecompileCalls::Bn128Pairing).expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                // TODO: manage padding of input bytes.
                input_rlc.expr(),
                output.expr(),
                0.expr(),
            );

            cb.require_in_set(
                "input_len ∈ { 0, 192, 384, 576, 768 } if valid",
                call_data_length.expr(),
                vec![0.expr(), 192.expr(), 384.expr(), 576.expr(), 768.expr()],
            );
        });

        // helpers for validating len(input).
        let input_is_zero =
            IsZeroGadget::construct(cb, "ecPairing(call_data_length)", call_data_length.expr());
        let input_lt_769 = LtGadget::construct(cb, call_data_length.expr(), 769.expr());
        let (input_mod_192, input_mod_192_lt) = cb.condition(
            // if len(input) > 0
            // if len(input) <= 768
            and::expr([not::expr(input_is_zero.expr()), input_lt_769.expr()]),
            |cb| {
                // r == len(input) % 192
                let input_mod_192 = cb.query_byte();
                // r < 192
                let input_mod_192_lt = LtGadget::construct(cb, input_mod_192.expr(), 192.expr());
                cb.require_equal("len(input) % 192 < 192", input_mod_192_lt.expr(), 1.expr());
                // q == len(input) // 192
                let input_div_192 = cb.query_cell();
                cb.require_in_set(
                    "len(input) // 192 ∈ { 0, 1, 2, 3 }",
                    input_div_192.expr(),
                    vec![0.expr(), 1.expr(), 2.expr(), 3.expr()],
                );

                // q * 192 + r == call_data_length
                cb.require_equal(
                    "q * 192 + r == len(input)",
                    input_div_192.expr() * 192.expr() + input_mod_192.expr(),
                    call_data_length.expr(),
                );

                (input_mod_192, input_mod_192_lt)
            },
        );
        let input_mod_192_is_zero = IsZeroGadget::construct(
            cb,
            "ecPairing(call_data_length % 192)",
            input_mod_192.expr(),
        );

        // validate failed call to the precompile ecPairing.
        cb.condition(not::expr(is_success.expr()), |cb| {
            cb.require_zero("if ecPairing call fails: output == 0", output.expr());

            // Failure could be because of the following reasons:
            // 1. Invalid number of bytes supplied to the precompile ecPairing.
            // 2. TODO: If a deserialized point is not on the respective curves (G1 or G2).
            cb.require_true(
                "if ecPairing fails: or(invalid_input_len, point_not_on_curve) == true",
                or::expr([not::expr(input_mod_192_is_zero.expr()), false.expr()]),
            );
        });

        let restore_context = RestoreContextGadget::construct(
            cb,
            is_success.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
        );

        Self {
            input_rlc,
            output,

            input_is_zero,
            input_lt_769,
            input_mod_192,
            input_mod_192_lt,
            input_mod_192_is_zero,

            is_success,
            callee_address,
            caller_id,
            call_data_offset,
            call_data_length,
            return_data_offset,
            return_data_length,
            restore_context,
        }
    }

    fn assign_exec_step(
        &self,
        _region: &mut CachedRegion<'_, '_, F>,
        _offset: usize,
        _block: &Block<F>,
        _transaction: &Transaction,
        _call: &Call,
        _step: &ExecStep,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}
