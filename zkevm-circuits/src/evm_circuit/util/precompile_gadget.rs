use bus_mapping::precompile::PrecompileCalls;
use eth_types::Field;
use gadgets::util::{not, or, select, Expr};
use halo2_proofs::{circuit::Value, plonk::Expression};

use crate::evm_circuit::{
    param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64},
    step::{ExecutionState, ExecutionState::ErrorOutOfGasPrecompile},
};

use super::{
    constraint_builder::{BoxedClosure, ConstrainBuilderCommon, EVMConstraintBuilder},
    math_gadget::{BinaryNumberGadget, LtGadget},
    padding_gadget::PaddingGadget,
    CachedRegion,
};

#[derive(Clone, Debug)]
pub struct PrecompileGadget<F> {
    address: BinaryNumberGadget<F, 4>,
    pad_right: LtGadget<F, N_BYTES_U64>,
    padding_gadget: PaddingGadget<F>,
}

impl<F: Field> PrecompileGadget<F> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        _is_success: Expression<F>,
        callee_address: Expression<F>,
        _caller_id: Expression<F>,
        _cd_offset: Expression<F>,
        cd_length: Expression<F>,
        _rd_offset: Expression<F>,
        _rd_length: Expression<F>,
        precompile_return_length: Expression<F>,
        // input bytes to precompile call.
        input_bytes_rlc: Expression<F>,
        // output result from precompile call.
        output_bytes_rlc: Expression<F>,
        // returned bytes back to caller.
        return_bytes_rlc: Expression<F>,
    ) -> Self {
        let address = BinaryNumberGadget::construct(cb, callee_address.expr());

        // input length represents:
        // - 128 bytes for ecrecover/ecAdd
        // - 96 bytes for ecMul
        // - calldata length for all other cases
        let input_len = {
            let len_128 = or::expr([
                address.value_equals(PrecompileCalls::Ecrecover),
                address.value_equals(PrecompileCalls::Bn128Add),
            ]);
            let len_96 = address.value_equals(PrecompileCalls::Bn128Mul);
            let len_192 = address.value_equals(PrecompileCalls::Modexp);
            select::expr(
                len_128,
                128.expr(),
                select::expr(
                    len_96,
                    96.expr(),
                    select::expr(len_192, 192.expr(), cd_length.expr()),
                ),
            )
        };
        let pad_right = LtGadget::construct(cb, cd_length.expr(), input_len.expr());

        // we right-pad zeroes only if calldata length provided was less than the expected/required
        // input length for that precompile call.
        let padding_gadget = cb.condition(pad_right.expr(), |cb| {
            PaddingGadget::construct(
                cb,
                input_bytes_rlc.expr(),
                cd_length.expr(),
                input_len.expr(),
            )
        });
        cb.condition(not::expr(pad_right.expr()), |cb| {
            cb.require_equal(
                "no padding implies both equal",
                padding_gadget.padded_rlc(),
                input_bytes_rlc.expr(),
            );
        });

        let conditions = vec![
            address.value_equals(PrecompileCalls::Ecrecover),
            address.value_equals(PrecompileCalls::Sha256),
            address.value_equals(PrecompileCalls::Ripemd160),
            address.value_equals(PrecompileCalls::Identity),
            address.value_equals(PrecompileCalls::Modexp),
            address.value_equals(PrecompileCalls::Bn128Add),
            address.value_equals(PrecompileCalls::Bn128Mul),
            address.value_equals(PrecompileCalls::Bn128Pairing),
            address.value_equals(PrecompileCalls::Blake2F),
        ]
        .into_iter()
        .map(|cond| {
            cond.expr() * not::expr(cb.next.execution_state_selector([ErrorOutOfGasPrecompile]))
        })
        .collect::<Vec<_>>();
        let next_states = vec![
            ExecutionState::PrecompileEcrecover,
            ExecutionState::PrecompileSha256,
            ExecutionState::PrecompileRipemd160,
            ExecutionState::PrecompileIdentity,
            ExecutionState::PrecompileBigModExp,
            ExecutionState::PrecompileBn256Add,
            ExecutionState::PrecompileBn256ScalarMul,
            ExecutionState::PrecompileBn256Pairing,
            ExecutionState::PrecompileBlake2f,
        ];
        let constraints: Vec<BoxedClosure<F>> = vec![
            Box::new(|cb| {
                /* Ecrecover */
                let (recovered, msg_hash_rlc, sig_v_rlc, sig_r_rlc, sig_s_rlc, recovered_addr_rlc) = (
                    cb.query_bool(),
                    cb.query_cell_phase2(),
                    cb.query_cell_phase2(),
                    cb.query_cell_phase2(),
                    cb.query_cell_phase2(),
                    cb.query_keccak_rlc::<N_BYTES_ACCOUNT_ADDRESS>(),
                );
                let (r_pow_32, r_pow_64, r_pow_96) = {
                    let challenges = cb.challenges().keccak_powers_of_randomness::<16>();
                    let r_pow_16 = challenges[15].clone();
                    let r_pow_32 = r_pow_16.square();
                    let r_pow_64 = r_pow_32.expr().square();
                    let r_pow_96 = r_pow_64.expr() * r_pow_32.expr();
                    (r_pow_32, r_pow_64, r_pow_96)
                };
                cb.require_equal(
                    "input bytes (RLC) = [msg_hash | sig_v_rlc | sig_r | sig_s]",
                    padding_gadget.padded_rlc(),
                    (msg_hash_rlc.expr() * r_pow_96)
                        + (sig_v_rlc.expr() * r_pow_64)
                        + (sig_r_rlc.expr() * r_pow_32)
                        + sig_s_rlc.expr(),
                );
                // RLC of output bytes always equals RLC of the recovered address.
                cb.require_equal(
                    "output bytes (RLC) = recovered address",
                    output_bytes_rlc.expr(),
                    recovered_addr_rlc.expr(),
                );
                // If the address was not recovered, RLC(address) == RLC(output) == 0.
                cb.condition(not::expr(recovered.expr()), |cb| {
                    cb.require_zero("output bytes == 0", output_bytes_rlc.expr());
                });
            }),
            Box::new(|_cb| { /* Sha256 */ }),
            Box::new(|_cb| { /* Ripemd160 */ }),
            Box::new(|cb| {
                /* Identity */
                cb.require_equal(
                    "input and output bytes are the same",
                    input_bytes_rlc.expr(),
                    output_bytes_rlc.expr(),
                );
                cb.require_equal(
                    "input length and precompile return length are the same",
                    cd_length,
                    precompile_return_length,
                );
            }),
            Box::new(|cb| {
                /* Modexp */
                let (input_bytes_acc_copied, output_bytes_acc_copied) =
                    (cb.query_cell_phase2(), cb.query_cell_phase2());
                cb.require_equal(
                    "copy padded input bytes",
                    padding_gadget.padded_rlc(),
                    input_bytes_acc_copied.expr(),
                );
                cb.require_equal(
                    "copy output bytes",
                    output_bytes_rlc.clone(),
                    output_bytes_acc_copied.expr(),
                );
            }),
            Box::new(|cb| {
                /* EcAdd */
                let (p_x_rlc, p_y_rlc, q_x_rlc, q_y_rlc, r_x_rlc, r_y_rlc) = (
                    cb.query_cell_phase2(),
                    cb.query_cell_phase2(),
                    cb.query_cell_phase2(),
                    cb.query_cell_phase2(),
                    cb.query_cell_phase2(),
                    cb.query_cell_phase2(),
                );
                let (r_pow_32, r_pow_64, r_pow_96) = {
                    let challenges = cb.challenges().keccak_powers_of_randomness::<16>();
                    let r_pow_16 = challenges[15].clone();
                    let r_pow_32 = r_pow_16.square();
                    let r_pow_64 = r_pow_32.expr().square();
                    let r_pow_96 = r_pow_64.expr() * r_pow_32.expr();
                    (r_pow_32, r_pow_64, r_pow_96)
                };
                cb.require_equal(
                    "input bytes (RLC) = [ p_x | p_y | q_x | q_y ]",
                    padding_gadget.padded_rlc(),
                    (p_x_rlc.expr() * r_pow_96)
                        + (p_y_rlc.expr() * r_pow_64)
                        + (q_x_rlc.expr() * r_pow_32.expr())
                        + q_y_rlc.expr(),
                );
                // RLC of output bytes always equals RLC of result elliptic curve point R.
                cb.require_equal(
                    "output bytes (RLC) = [ r_x | r_y ]",
                    output_bytes_rlc.expr(),
                    r_x_rlc.expr() * r_pow_32 + r_y_rlc.expr(),
                );
            }),
            Box::new(|cb| {
                /* EcMul */
                let (p_x_rlc, p_y_rlc, scalar_s_raw_rlc, r_x_rlc, r_y_rlc) = (
                    cb.query_cell_phase2(),
                    cb.query_cell_phase2(),
                    cb.query_cell_phase2(),
                    cb.query_cell_phase2(),
                    cb.query_cell_phase2(),
                );
                let (r_pow_32, r_pow_64) = {
                    let challenges = cb.challenges().keccak_powers_of_randomness::<16>();
                    let r_pow_16 = challenges[15].clone();
                    let r_pow_32 = r_pow_16.square();
                    let r_pow_64 = r_pow_32.expr().square();
                    (r_pow_32, r_pow_64)
                };
                cb.require_equal(
                    "input bytes (RLC) = [ p_x | p_y | s ]",
                    padding_gadget.padded_rlc(),
                    (p_x_rlc.expr() * r_pow_64)
                        + (p_y_rlc.expr() * r_pow_32.expr())
                        + scalar_s_raw_rlc.expr(),
                );
                // RLC of output bytes always equals RLC of result elliptic curve point R.
                cb.require_equal(
                    "output bytes (RLC) = [ r_x | r_y ]",
                    output_bytes_rlc.expr(),
                    r_x_rlc.expr() * r_pow_32 + r_y_rlc.expr(),
                );
            }),
            Box::new(|cb| {
                /* EcPairing */
                let (evm_input_rlc, output) = (cb.query_cell_phase2(), cb.query_bool());
                cb.require_equal(
                    "input bytes (RLC) equality",
                    padding_gadget.padded_rlc(),
                    evm_input_rlc.expr(),
                );
                // RLC of output bytes always equals boolean result of pairing check.
                cb.require_equal(
                    "output bytes (RLC) equality",
                    output_bytes_rlc.expr(),
                    output.expr(),
                );
            }),
            Box::new(|_cb| { /* Blake2F */ }),
        ];
        cb.constrain_mutually_exclusive_next_step(conditions, next_states, constraints);

        Self {
            address,
            pad_right,
            padding_gadget,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        address: PrecompileCalls,
        input_rlc: Value<F>,
        cd_len: u64,
        keccak_rand: Value<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        self.address.assign(region, offset, address)?;
        let input_len =
            self.padding_gadget
                .assign(region, offset, address, input_rlc, cd_len, keccak_rand)?;
        self.pad_right
            .assign(region, offset, F::from(cd_len), F::from(input_len))?;

        Ok(())
    }
}
