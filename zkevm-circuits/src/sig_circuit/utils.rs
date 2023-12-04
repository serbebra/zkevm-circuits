use std::iter;

use eth_types::{
    self,
    sign_types::{pk_bytes_le, pk_bytes_swap_endianness, SignData},
    Field,
};
use ethers_core::utils::keccak256;
use halo2_base::{
    gates::{GateChip, GateInstructions, RangeInstructions},
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    ecc::{EcPoint, EccChip},
    fields::{fp::FpChip, FieldChip},
};
use halo2_proofs::{
    circuit::{AssignedCell, Cell, Region, Value},
    halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
    plonk::Error,
};
use itertools::Itertools;

use super::{config::SigCircuitConfig, SigCircuit};
use crate::{
    evm_circuit::util::rlc, sig_circuit::ecdsa::ecdsa_verify_no_pubkey_check, util::Challenges,
};

// Hard coded parameters.
// FIXME: allow for a configurable param.
pub(super) const MAX_NUM_SIG: usize = 128;
// Each ecdsa signature requires 461174 cells
pub(super) const CELLS_PER_SIG: usize = 461174;
// Each ecdsa signature requires 63276 lookup cells
pub(super) const LOOKUP_CELLS_PER_SIG: usize = 63276;
// Total number of rows allocated for ecdsa chip
pub(super) const LOG_TOTAL_NUM_ROWS: usize = 20;
// Max number of columns allowed
pub(super) const COLUMN_NUM_LIMIT: usize = 58;
// Max number of lookup columns allowed
pub(super) const LOOKUP_COLUMN_NUM_LIMIT: usize = 9;

pub(super) fn calc_required_advices(num_verif: usize) -> usize {
    let mut num_adv = 1;
    let total_cells = num_verif * CELLS_PER_SIG;
    let row_num = 1 << LOG_TOTAL_NUM_ROWS;
    while num_adv < COLUMN_NUM_LIMIT {
        if num_adv * row_num > total_cells {
            log::debug!(
                "ecdsa chip uses {} advice columns for {} signatures",
                num_adv,
                num_verif
            );
            return num_adv;
        }
        num_adv += 1;
    }
    panic!("the required advice columns exceeds {COLUMN_NUM_LIMIT} for {num_verif} signatures");
}

pub(super) fn calc_required_lookup_advices(num_verif: usize) -> usize {
    let mut num_adv = 1;
    let total_cells = num_verif * LOOKUP_CELLS_PER_SIG;
    let row_num = 1 << LOG_TOTAL_NUM_ROWS;
    while num_adv < LOOKUP_COLUMN_NUM_LIMIT {
        if num_adv * row_num > total_cells {
            log::debug!(
                "ecdsa chip uses {} lookup advice columns for {} signatures",
                num_adv,
                num_verif
            );
            return num_adv;
        }
        num_adv += 1;
    }
    panic!("the required lookup advice columns exceeds {LOOKUP_COLUMN_NUM_LIMIT} for {num_verif} signatures");
}

pub(crate) struct AssignedECDSA<F: Field, FC: FieldChip<F>> {
    pub(super) pk: EcPoint<F, FC::FieldPoint>,
    pub(super) pk_is_zero: AssignedValue<F>,
    pub(super) msg_hash: ProperCrtUint<F>,
    pub(super) integer_r: ProperCrtUint<F>,
    pub(super) integer_s: ProperCrtUint<F>,
    pub(super) v: AssignedValue<F>,
    pub(super) sig_is_valid: AssignedValue<F>,
}

#[derive(Debug, Clone)]
pub(crate) struct AssignedSignatureVerify<F: Field> {
    pub(crate) address: AssignedValue<F>,
    pub(crate) msg_len: usize,
    pub(crate) msg_rlc: Value<F>,
    pub(crate) msg_hash_rlc: AssignedValue<F>,
    pub(crate) r_rlc: AssignedValue<F>,
    pub(crate) s_rlc: AssignedValue<F>,
    pub(crate) v: AssignedValue<F>,
    pub(crate) sig_is_valid: AssignedValue<F>,
}

#[derive(Debug, Clone)]
pub(crate) struct TransmutedSignatureVerify<F: Field> {
    pub(crate) address: Cell,
    pub(crate) msg_len: usize,
    pub(crate) msg_rlc: Value<F>,
    pub(crate) msg_hash_rlc: Cell,
    pub(crate) r_rlc: Cell,
    pub(crate) s_rlc: Cell,
    pub(crate) v: Cell,
    pub(crate) sig_is_valid: Cell,
}

/// Transmute data from halo2 lib to halo2 proof; and vice versa
pub(crate) struct TransmuteData<F: Field> {
    pub(crate) assigned_keccak_values: Vec<[AssignedValue<F>; 3]>,
    pub(crate) assigned_keccak_cells: Vec<Vec<Cell>>,
    pub(crate) assigned_sig_values: Vec<AssignedSignatureVerify<F>>,
    pub(crate) transmuted_sig_values: Vec<TransmutedSignatureVerify<F>>,
}

pub(crate) struct SignDataDecomposed<F: Field> {
    pub(super) pk_hash_cells: Vec<QuantumCell<F>>,
    pub(super) msg_hash_cells: Vec<QuantumCell<F>>,
    pub(super) pk_cells: Vec<QuantumCell<F>>,
    pub(super) address: AssignedValue<F>,
    pub(super) is_address_zero: AssignedValue<F>,
    pub(super) r_cells: Vec<QuantumCell<F>>,
    pub(super) s_cells: Vec<QuantumCell<F>>,
}

impl<F: Field> SigCircuit<F> {
    /// Assert an CRTInteger's byte representation is correct.
    /// inputs
    /// - crt_int with 3 limbs [88, 88, 80]
    /// - byte representation of the integer
    /// - a sequence of [1, 2^8, 2^16, ...]
    /// - a overriding flag that sets output to 0 if set
    pub(crate) fn assert_crt_int_byte_repr(
        &self,
        ctx: &mut Context<F>,
        flex_gate_chip: &GateChip<F>,
        crt_int: &ProperCrtUint<F>,
        byte_repr: &[QuantumCell<F>],
        powers_of_256: &[QuantumCell<F>],
    ) -> Result<(), Error> {
        // length of byte representation is 32
        assert_eq!(byte_repr.len(), 32);
        // need to support decomposition of up to 88 bits
        assert!(powers_of_256.len() >= 11);

        // apply the overriding flag
        let limbs = crt_int.limbs();
        let limb1_value = limbs[0];
        let limb2_value = limbs[1];
        let limb3_value = limbs[2];

        // assert the byte_repr is the right decomposition of overflow_int
        // overflow_int is an overflowing integer with 3 limbs, of sizes 88, 88, and 80
        // we reconstruct the three limbs from the bytes repr, and
        // then enforce equality with the CRT integer
        let limb1_recover = flex_gate_chip.inner_product(
            ctx,
            byte_repr[0..11].to_vec(),
            powers_of_256[0..11].to_vec(),
        );
        let limb2_recover = flex_gate_chip.inner_product(
            ctx,
            byte_repr[11..22].to_vec(),
            powers_of_256[0..11].to_vec(),
        );
        let limb3_recover = flex_gate_chip.inner_product(
            ctx,
            byte_repr[22..].to_vec(),
            powers_of_256[0..10].to_vec(),
        );
        ctx.constrain_equal(&limb1_value, &limb1_recover);
        ctx.constrain_equal(&limb2_value, &limb2_recover);
        ctx.constrain_equal(&limb3_value, &limb3_recover);

        log::trace!(
            "limb 1 \ninput {:?}\nreconstructed {:?}",
            limb1_value.value(),
            limb1_recover.value()
        );
        log::trace!(
            "limb 2 \ninput {:?}\nreconstructed {:?}",
            limb2_value.value(),
            limb2_recover.value()
        );
        log::trace!(
            "limb 3 \ninput {:?}\nreconstructed {:?}",
            limb3_value.value(),
            limb3_recover.value()
        );

        Ok(())
    }

    /// Verifies the ecdsa relationship. I.e., prove that the signature
    /// is (in)valid or not under the given public key and the message hash in
    /// the circuit. Does not enforce the signature is valid.
    ///
    /// Returns the cells for
    /// - public keys
    /// - message hashes
    /// - a boolean whether the signature is correct or not
    ///
    /// WARNING: this circuit does not enforce the returned value to be true
    /// make sure the caller checks this result!
    pub(crate) fn assign_ecdsa(
        &self,
        ctx: &mut Context<F>,
        ecdsa_chip: &EccChip<F, FpChip<F, Fp>>,
        sign_data: &SignData,
    ) -> Result<AssignedECDSA<F, FpChip<F, Fp>>, Error> {
        let gate = ecdsa_chip.field_chip().gate();
        let base_chip = ecdsa_chip.field_chip;
        let scalar_chip =
            FpChip::<F, Fq>::new(base_chip.range, base_chip.limb_bits, base_chip.num_limbs);

        let zero = ctx.load_constant(F::zero());

        let SignData {
            signature,
            pk,
            msg: _,
            msg_hash,
        } = sign_data;
        let (sig_r, sig_s, v) = signature;

        // build ecc chip from Fp chip
        let pk_assigned = ecdsa_chip.load_private_unchecked(ctx, (pk.x, pk.y));
        let pk_is_valid = ecdsa_chip.is_on_curve_or_infinity::<Secp256k1Affine>(ctx, &pk_assigned);
        gate.assert_is_const(ctx, &pk_is_valid, &F::one());

        // build Fq chip from Fp chip
        // let fq_chip = FqChip::construct(ecdsa_chip.range.clone(), 88, 3, modulus::<Fq>());
        let integer_r = scalar_chip.load_private(ctx, *sig_r);
        let integer_s = scalar_chip.load_private(ctx, *sig_s);
        let msg_hash = scalar_chip.load_private(ctx, *msg_hash);

        // returns the verification result of ecdsa signature
        //
        // WARNING: this circuit does not enforce the returned value to be true
        // make sure the caller checks this result!
        let (sig_is_valid, pk_is_zero, y_coord) =
            ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
                &ecdsa_chip,
                ctx,
                &pk_assigned,
                &integer_r,
                &integer_s,
                &msg_hash,
                4,
                4,
            );

        // =======================================
        // constrains v == y.is_oddness()
        // =======================================
        assert!(*v == 0 || *v == 1, "v is not boolean");

        // we constrain:
        // - v + 2*tmp = y where y is already range checked (88 bits)
        // - v is a binary
        // - tmp is also < 88 bits (this is crucial otherwise tmp may wrap around and break
        //   soundness)

        let assigned_y_is_odd = ctx.load_witness(F::from(*v as u64));
        gate.assert_bit(ctx, assigned_y_is_odd);

        // the last 88 bits of y
        let assigned_y_limb = &y_coord.limbs()[0];
        let y_value = *assigned_y_limb.value();

        // y_tmp = (y_value - y_last_bit)/2
        let y_tmp = (y_value - F::from(*v as u64)) * F::TWO_INV;
        let assigned_y_tmp = ctx.load_witness(y_tmp);

        // y_tmp_double = (y_value - y_last_bit)
        let y_tmp_double = gate.mul(ctx, assigned_y_tmp, QuantumCell::Constant(F::from(2)));
        let y_rec = gate.add(ctx, y_tmp_double, assigned_y_is_odd);
        let y_is_ok = gate.is_equal(ctx, *assigned_y_limb, y_rec);

        // last step we want to constrain assigned_y_tmp is 87 bits
        let assigned_y_tmp = gate.select(ctx, zero, assigned_y_tmp, pk_is_zero);
        base_chip.range.range_check(ctx, assigned_y_tmp, 87);

        let pk_not_zero = gate.not(ctx, QuantumCell::Existing(pk_is_zero));
        let sig_is_valid = gate.and(ctx, sig_is_valid, y_is_ok);
        let sig_is_valid = gate.and(ctx, sig_is_valid, pk_not_zero);

        Ok(AssignedECDSA {
            pk: pk_assigned,
            pk_is_zero,
            msg_hash,
            integer_r,
            integer_s,
            v: assigned_y_is_odd,
            sig_is_valid,
        })
    }

    pub(crate) fn enable_keccak_lookup(
        &self,
        config: &SigCircuitConfig<F>,
        region: &mut Region<F>,
        offset: usize,
        is_address_zero: &AssignedValue<F>,
        pk_rlc: &AssignedValue<F>,
        pk_hash_rlc: &AssignedValue<F>,
    ) -> Result<[AssignedCell<F, F>; 3], Error> {
        log::trace!("keccak lookup");

        // Layout:
        // | q_keccak |        rlc      |
        // | -------- | --------------- |
        // |     1    | is_address_zero |
        // |          |    pk_rlc       |
        // |          |    pk_hash_rlc  |
        config.q_keccak.enable(region, offset)?;

        // is_address_zero
        let is_address_zero = region.assign_advice(
            || "is_address_zero",
            config.rlc_column,
            offset,
            || Value::known(*is_address_zero.value()),
        )?;

        // pk_rlc
        let pk_rlc = region.assign_advice(
            || "pk_rlc",
            config.rlc_column,
            offset + 1,
            || Value::known(*pk_rlc.value()),
        )?;

        // pk_hash_rlc
        let pk_hash_rlc = region.assign_advice(
            || "pk_hash_rlc",
            config.rlc_column,
            offset + 2,
            || Value::known(*pk_hash_rlc.value()),
        )?;

        log::trace!("finished keccak lookup");
        Ok([is_address_zero, pk_rlc, pk_hash_rlc])
    }

    /// Input the signature data,
    /// Output the cells for byte decomposition of the keys and messages
    pub(crate) fn sign_data_decomposition(
        &self,
        ctx: &mut Context<F>,
        ecc_chip: &EccChip<F, FpChip<F, Fp>>,
        sign_data: &SignData,
        assigned_data: &AssignedECDSA<F, FpChip<F, Fp>>,
    ) -> Result<SignDataDecomposed<F>, Error> {
        let flex_gate_chip = ecc_chip.field_chip.gate();
        let zero = ctx.load_constant(F::ZERO);

        // ================================================
        // step 0. powers of aux parameters
        // ================================================
        let powers_of_256 =
            iter::successors(Some(F::one()), |coeff| Some(F::from(256) * coeff)).take(32);
        let powers_of_256_cells = powers_of_256
            .map(|x| QuantumCell::Constant(x))
            .collect_vec();

        // ================================================
        // pk hash cells
        // ================================================
        let pk_le = pk_bytes_le(&sign_data.pk);
        let pk_be = pk_bytes_swap_endianness(&pk_le);
        let pk_hash = keccak256(pk_be).map(|byte| F::from(byte as u64));

        log::trace!("pk hash {:0x?}", pk_hash);
        let pk_hash_cells = pk_hash
            .iter()
            .map(|&x| QuantumCell::Witness(x))
            .rev()
            .collect_vec();

        // address is the random linear combination of the public key
        // it is fine to use a phase 1 gate here
        let address = flex_gate_chip.inner_product(
            ctx,
            powers_of_256_cells[..20].to_vec(),
            pk_hash_cells[..20].to_vec(),
        );
        let address = flex_gate_chip.select(ctx, zero, address, assigned_data.pk_is_zero);
        let is_address_zero = flex_gate_chip.is_equal(ctx, address, zero);
        log::trace!("address: {:?}", address.value());

        // ================================================
        // message hash cells
        // ================================================
        let assert_crt = |ctx: &mut Context<F>,
                          bytes: [u8; 32],
                          crt_integer: &ProperCrtUint<F>|
         -> Result<_, Error> {
            let byte_cells: Vec<QuantumCell<F>> = bytes
                .iter()
                .map(|&x| QuantumCell::Witness(F::from(x as u64)))
                .collect_vec();
            self.assert_crt_int_byte_repr(
                ctx,
                &flex_gate_chip,
                crt_integer,
                &byte_cells,
                &powers_of_256_cells,
            )?;
            Ok(byte_cells)
        };

        // assert the assigned_msg_hash_le is the right decomposition of msg_hash
        // msg_hash is an overflowing integer with 3 limbs, of sizes 88, 88, and 80
        let assigned_msg_hash_le =
            assert_crt(ctx, sign_data.msg_hash.to_bytes(), &assigned_data.msg_hash)?;

        // ================================================
        // pk cells
        // ================================================
        let pk_x_le = sign_data
            .pk
            .x
            .to_bytes()
            .iter()
            .map(|&x| QuantumCell::Witness(F::from_u128(x as u128)))
            .collect_vec();
        let pk_y_le = sign_data
            .pk
            .y
            .to_bytes()
            .iter()
            .map(|&y| QuantumCell::Witness(F::from_u128(y as u128)))
            .collect_vec();
        let pk_assigned =
            ecc_chip.load_private::<Secp256k1Affine>(ctx, (sign_data.pk.x, sign_data.pk.y));

        self.assert_crt_int_byte_repr(
            ctx,
            &flex_gate_chip,
            &pk_assigned.x,
            &pk_x_le,
            &powers_of_256_cells,
        )?;
        self.assert_crt_int_byte_repr(
            ctx,
            &flex_gate_chip,
            &pk_assigned.y,
            &pk_y_le,
            &powers_of_256_cells,
        )?;

        let assigned_pk_le_selected = [pk_y_le, pk_x_le].concat();
        log::trace!("finished data decomposition");

        let r_cells = assert_crt(
            ctx,
            sign_data.signature.0.to_bytes(),
            &assigned_data.integer_r,
        )?;
        let s_cells = assert_crt(
            ctx,
            sign_data.signature.1.to_bytes(),
            &assigned_data.integer_s,
        )?;

        Ok(SignDataDecomposed {
            pk_hash_cells,
            msg_hash_cells: assigned_msg_hash_le,
            pk_cells: assigned_pk_le_selected,
            address,
            is_address_zero,
            r_cells,
            s_cells,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn assign_sig_verify(
        &self,
        ctx: &mut Context<F>,
        flex_gate_chip: &GateChip<F>,
        sign_data: &SignData,
        sign_data_decomposed: &SignDataDecomposed<F>,
        challenges: &Challenges<Value<F>>,
        assigned_ecdsa: &AssignedECDSA<F, FpChip<F, Fp>>,
    ) -> Result<([AssignedValue<F>; 3], AssignedSignatureVerify<F>), Error> {
        // ================================================
        // step 0. powers of aux parameters
        // ================================================
        let evm_challenge_powers = {
            let mut evm_word = F::default();
            challenges.evm_word().map(|x| evm_word = x);
            // let start_point = F::from(evm_word != F::ZERO);
            // iter::successors(Some(start_point), |&coeff| Some(evm_word * coeff))
            iter::successors(Some(F::one()), |&coeff| Some(evm_word * coeff))
                .take(32)
                .map(|x| QuantumCell::Witness(x))
                .collect_vec()
        };

        log::trace!("evm challenge: {:?} ", challenges.evm_word());

        let keccak_challenge_powers = {
            let mut keccak_input = F::default();
            challenges.keccak_input().map(|x| keccak_input = x);
            // let start_point = F::from(keccak_input != F::ZERO);
            // iter::successors(Some(start_point), |coeff| Some(keccak_input * coeff))
            iter::successors(Some(F::one()), |coeff| Some(keccak_input * coeff))
                .take(64)
                .map(|x| QuantumCell::Witness(x))
                .collect_vec()
        };

        // ================================================
        // step 1 random linear combination of message hash
        // ================================================
        // Ref. spec SignVerifyChip 3. Verify that the signed message in the ecdsa_chip
        // with RLC encoding corresponds to msg_hash_rlc
        let msg_hash_rlc = flex_gate_chip.inner_product(
            ctx,
            sign_data_decomposed
                .msg_hash_cells
                .iter()
                .take(32)
                .cloned()
                .collect_vec(),
            evm_challenge_powers.clone(),
        );

        println!("assigned msg hash rlc: {:?}", msg_hash_rlc.value());

        // ================================================
        // step 2 random linear combination of pk
        // ================================================
        let pk_rlc = flex_gate_chip.inner_product(
            ctx,
            sign_data_decomposed.pk_cells.clone(),
            keccak_challenge_powers,
        );
        println!("pk rlc: {:?}", pk_rlc.value());

        // ================================================
        // step 3 random linear combination of pk_hash
        // ================================================
        let pk_hash_rlc = flex_gate_chip.inner_product(
            ctx,
            sign_data_decomposed.pk_hash_cells.clone(),
            evm_challenge_powers.clone(),
        );

        // step 4: r,s rlc
        let r_rlc = flex_gate_chip.inner_product(
            ctx,
            sign_data_decomposed.r_cells.clone(),
            evm_challenge_powers.clone(),
        );
        let s_rlc = flex_gate_chip.inner_product(
            ctx,
            sign_data_decomposed.s_cells.clone(),
            evm_challenge_powers,
        );

        println!("pk hash rlc halo2ecc: {:?}", pk_hash_rlc.value());
        log::trace!("finished sign verify");
        let to_be_keccak_checked = [sign_data_decomposed.is_address_zero, pk_rlc, pk_hash_rlc];
        println!(
            "to be keccaked: {:?}",
            sign_data_decomposed.is_address_zero.value()
        );
        println!("to be keccaked: {:?}", pk_rlc.value());
        println!("to be keccaked: {:?}", pk_hash_rlc.value());
        let assigned_sig_verif = AssignedSignatureVerify {
            address: sign_data_decomposed.address,
            msg_len: sign_data.msg.len(),
            msg_rlc: challenges
                .keccak_input()
                .map(|r| rlc::value(sign_data.msg.iter().rev(), r)),
            msg_hash_rlc,
            sig_is_valid: assigned_ecdsa.sig_is_valid,
            r_rlc,
            s_rlc,
            v: assigned_ecdsa.v,
        };
        Ok((to_be_keccak_checked, assigned_sig_verif))
    }
}
