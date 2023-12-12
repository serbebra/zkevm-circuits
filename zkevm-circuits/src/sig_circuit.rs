//! Circuit to verify multiple ECDSA secp256k1 signatures.
//
// This module uses halo2-ecc's ecdsa chip
//  - to prove the correctness of secp signatures
//  - to compute the RLC in circuit
//  - to perform keccak lookup table
//
// Naming notes:
// - *_be: Big-Endian bytes
// - *_le: Little-Endian bytes

mod config;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod dev;
mod ecdsa;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod test;
mod utils;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
pub(crate) use utils::*;

use std::cell::RefCell;

use eth_types::{self, sign_types::SignData, Field};
use halo2_base::{
    gates::{circuit::builder::RangeCircuitBuilder, GateChip, RangeChip},
    AssignedValue,
};
use halo2_ecc::{ecc::EccChip, fields::fp::FpChip};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::secp256k1::Fp,
    plonk::{ConstraintSystem, Error},
};
use itertools::Itertools;
use log::error;

use crate::{
    evm_circuit::EvmCircuit,
    keccak_circuit::KeccakCircuit,
    table::{KeccakTable, SigTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
};

use self::config::SigCircuitConfig;

/// Verify a message hash is signed by the public
/// key corresponding to an Ethereum Address.
#[derive(Clone, Debug, Default)]
pub struct SigCircuit<F: Field> {
    /// halo2-lib circuit builders
    pub two_phase_builder: RefCell<RangeCircuitBuilder<F>>,
    /// chip used for halo2-lib
    pub gate_chip: GateChip<F>,
    /// Max number of verifications
    pub max_verif: usize,
    /// Without padding
    pub signatures: Vec<SignData>,
}

impl<F: Field> SubCircuit<F> for SigCircuit<F> {
    type Config = SigCircuitConfig<F>;

    fn new_from_block(block: &crate::witness::Block<F>) -> Self {
        assert!(block.circuits_params.max_txs <= MAX_NUM_SIG);
        let two_phase_builder = RangeCircuitBuilder::new(false);
        SigCircuit {
            two_phase_builder: RefCell::new(two_phase_builder),
            gate_chip: GateChip::new(),
            max_verif: MAX_NUM_SIG,
            signatures: block.get_sign_data(true),
        }
    }

    /// Returns number of unusable rows of the SubCircuit, which should be
    /// `meta.blinding_factors() + 1`.
    fn unusable_rows() -> usize {
        [
            KeccakCircuit::<F>::unusable_rows(),
            EvmCircuit::<F>::unusable_rows(),
            // may include additional subcircuits here
        ]
        .into_iter()
        .max()
        .unwrap()
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self.assign_main(config, layouter, &self.signatures, challenges)?;
        // clear the builder before finalizing the synthesizing process
        self.two_phase_builder.borrow_mut().clear();
        Ok(())
    }

    // Since sig circuit / halo2-lib use vertical cell assignment,
    // so the returned pair is consisted of same values
    fn min_num_rows_block(block: &crate::witness::Block<F>) -> (usize, usize) {
        let row_num = if block.circuits_params.max_vertical_circuit_rows == 0 {
            Self::min_num_rows()
        } else {
            block.circuits_params.max_vertical_circuit_rows
        };

        let ecdsa_verif_count = block
            .txs
            .iter()
            .filter(|tx| !tx.tx_type.is_l1_msg())
            .count()
            + block.precompile_events.get_ecrecover_events().len();
        // Reserve one ecdsa verification for padding tx such that the bad case in which some tx
        // calls MAX_NUM_SIG - 1 ecrecover precompile won't happen. If that case happens, the sig
        // circuit won't have more space for the padding tx's ECDSA verification. Then the
        // prover won't be able to produce any valid proof.
        let max_num_verif = MAX_NUM_SIG - 1;

        // Instead of showing actual minimum row usage,
        // halo2-lib based circuits use min_row_num to represent a percentage of total-used capacity
        // This functionality allows l2geth to decide if additional ops can be added.
        let min_row_num = (row_num / max_num_verif) * ecdsa_verif_count;

        (min_row_num, row_num)
    }
}

impl<F: Field> SigCircuit<F> {
    /// Return a new SigCircuit
    pub fn new(max_verif: usize) -> Self {
        let two_phase_builder = RangeCircuitBuilder::new(false);
        SigCircuit {
            two_phase_builder: RefCell::new(two_phase_builder),
            gate_chip: GateChip::default(),
            max_verif,
            signatures: Vec::new(),
        }
    }

    /// Return the minimum number of rows required to prove an input of a
    /// particular size.
    pub fn min_num_rows() -> usize {
        // SigCircuit can't determine usable rows independently.
        // Instead, the blinding area is determined by other advise columns with most counts of
        // rotation queries. This value is typically determined by either the Keccak or EVM
        // circuit.

        // the cells are allocated vertically, i.e., given a TOTAL_NUM_ROWS * NUM_ADVICE
        // matrix, the allocator will try to use all the cells in the first column, then
        // the second column, etc.

        let max_blinding_factor = Self::unusable_rows() - 1;

        // same formula as halo2-lib's FlexGate
        (1 << LOG_TOTAL_NUM_ROWS) - (max_blinding_factor + 3)
    }
}

impl<F: Field> SigCircuit<F> {
    /// extract the data from halo2-lib
    /// move the builder to phase 2
    /// to not clear the builder
    fn extract_transmute_data(
        &self,
        config: &SigCircuitConfig<F>,
        layouter: &mut impl Layouter<F>,
        signatures: &[SignData],
        challenges: &Challenges<Value<F>>,
    ) -> Result<TransmuteData<F>, Error> {
        println!("start extract_transmute_data");

        // ================================================
        // First phase
        // ================================================
        let (assigned_ecdsas, sign_data_decomposed) = {
            let mut builder = self.two_phase_builder.borrow_mut();
            let lookup_manager = builder.lookup_manager().clone();

            let range_chip = RangeChip::new(LOG_TOTAL_NUM_ROWS - 1, lookup_manager);
            let fp_chip = FpChip::<F, Fp>::new(&range_chip, 88, 3);
            let ecc_chip = EccChip::new(&fp_chip);

            let mut ctx = builder.main(0);

            // ================================================
            // step 1: assert the signature is valid in circuit
            // ================================================

            let assigned_ecdsas = signatures
                .iter()
                .chain(std::iter::repeat(&SignData::default()))
                .take(self.max_verif)
                .map(|sign_data| self.assign_ecdsa(&mut ctx, &ecc_chip, sign_data))
                .collect::<Result<Vec<AssignedECDSA<F, FpChip<F, Fp>>>, Error>>()?;

            // ================================================
            // step 2: decompose the keys and messages
            // ================================================
            let sign_data_decomposed = signatures
                .iter()
                .chain(std::iter::repeat(&SignData::default()))
                .take(self.max_verif)
                .zip_eq(assigned_ecdsas.iter())
                .map(|(sign_data, assigned_ecdsa)| {
                    self.sign_data_decomposition(&mut ctx, &ecc_chip, sign_data, assigned_ecdsa)
                })
                .collect::<Result<Vec<SignDataDecomposed<F>>, Error>>()?;

            builder.synthesize_ref_layouter_phase_0(config.range_config.clone(), layouter)?;
            log::info!("phase 0 builder status {:?}", builder.statistics());

            (assigned_ecdsas, sign_data_decomposed)
        };

        // ================================================
        // Second phase
        // ================================================
        // ================================================
        // step 3: compute RLC of keys and messages
        // ================================================
        let (
            assigned_keccak_values,
            assigned_keccak_cells,
            assigned_sig_values,
            transmuted_sig_values,
        ) = {
            let mut builder = self.two_phase_builder.borrow_mut();
            let lookup_manager = builder.lookup_manager().clone();
            let range_chip = RangeChip::new(LOG_TOTAL_NUM_ROWS - 1, lookup_manager);

            // proceed to second phase
            let mut ctx = builder.main(1);
            let (assigned_keccak_values, assigned_sig_values): (
                Vec<[AssignedValue<F>; 3]>,
                Vec<AssignedSignatureVerify<F>>,
            ) = signatures
                .iter()
                .chain(std::iter::repeat(&SignData::default()))
                .take(self.max_verif)
                .zip_eq(assigned_ecdsas.iter())
                .zip_eq(sign_data_decomposed.iter())
                .map(|((sign_data, assigned_ecdsa), sign_data_decomp)| {
                    self.assign_sig_verify(
                        &mut ctx,
                        &range_chip.gate,
                        sign_data,
                        sign_data_decomp,
                        challenges,
                        assigned_ecdsa,
                    )
                })
                .collect::<Result<Vec<([AssignedValue<F>; 3], AssignedSignatureVerify<F>)>, Error>>(
                )?
                .into_iter()
                .unzip();

            builder.synthesize_ref_layouter_phase_1(config.range_config.clone(), layouter)?;
            log::info!("phase 1 builder status {:?}", builder.statistics());

            // ================================================
            // finalize the virtual cells and get their indexes
            // ================================================
            let copy_manager = builder.core().copy_manager.lock().unwrap();
            let hash_map = &copy_manager.assigned_advices;
            log::info!("hash map size: {:?}", hash_map.len());

            // transmute keccak cells to halo2 proof
            let assigned_keccak_cells = assigned_keccak_values
                .iter()
                .map(|array| {
                    array
                        .iter()
                        .map(|elem| *hash_map.get(&elem.cell.unwrap()).unwrap())
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();

            // transmute SignatureVerify cells to halo2 proof
            let mut transmuted_sig_values = vec![];
            {
                for sig_values in assigned_sig_values.iter() {
                    let address = *hash_map.get(&sig_values.address.cell.unwrap()).unwrap();
                    let msg_hash_rlc = *hash_map
                        .get(&sig_values.msg_hash_rlc.cell.unwrap())
                        .unwrap();
                    let r_rlc = *hash_map.get(&sig_values.r_rlc.cell.unwrap()).unwrap();
                    let s_rlc = *hash_map.get(&sig_values.s_rlc.cell.unwrap()).unwrap();
                    let v = *hash_map.get(&sig_values.v.cell.unwrap()).unwrap();
                    let sig_is_valid = *hash_map
                        .get(&sig_values.sig_is_valid.cell.unwrap())
                        .unwrap();
                    transmuted_sig_values.push(TransmutedSignatureVerify {
                        address,
                        msg_len: sig_values.msg_len,
                        msg_rlc: sig_values.msg_rlc,
                        msg_hash_rlc,
                        r_rlc,
                        s_rlc,
                        v,
                        sig_is_valid,
                    })
                }
            }

            drop(copy_manager);

            (
                assigned_keccak_values,
                assigned_keccak_cells,
                assigned_sig_values,
                transmuted_sig_values,
            )
        };

        Ok(TransmuteData {
            assigned_keccak_values,
            assigned_keccak_cells,
            assigned_sig_values,
            transmuted_sig_values,
        })
    }

    fn equality_constraints(
        &self,
        config: &SigCircuitConfig<F>,
        layouter: &mut impl Layouter<F>,
        data: &TransmuteData<F>,
        halo2_proof_cells: &[[AssignedCell<F, F>; 3]],
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "equality constraints",
            |mut region| {
                for (a, b) in halo2_proof_cells
                    .iter()
                    .zip(data.assigned_keccak_cells.iter())
                {
                    for (aa, &bb) in a.iter().zip(b.iter()) {
                        region.constrain_equal(aa.cell(), bb)?;
                    }
                }

                Ok(())
            },
        )?;

        // TODO: is this correct?
        layouter.assign_region(
            || "expose sig table",
            |mut region| {
                // ================================================
                // step 5: export as a lookup table
                // ================================================
                for (idx, (tranmuted_cells, assigned_sig_verif)) in data
                    .transmuted_sig_values
                    .iter()
                    .zip(data.assigned_sig_values.iter())
                    .enumerate()
                {
                    region.assign_fixed(
                        || "assign sig_table selector",
                        config.sig_table.q_enable,
                        idx,
                        || Value::known(F::one()),
                    )?;

                    {
                        let assigned_address = region.assign_advice(
                            || "address",
                            config.sig_table.recovered_addr,
                            idx,
                            || Value::known(assigned_sig_verif.address.value),
                        )?;
                        region.constrain_equal(assigned_address.cell(), tranmuted_cells.address)?;
                    }

                    {
                        let assigned_msg_hash_rlc = region.assign_advice(
                            || "msg_hash_rlc",
                            config.sig_table.msg_hash_rlc,
                            idx,
                            || Value::known(assigned_sig_verif.msg_hash_rlc.value),
                        )?;
                        region.constrain_equal(
                            assigned_msg_hash_rlc.cell(),
                            tranmuted_cells.msg_hash_rlc,
                        )?;
                    }

                    {
                        let assigned_r_rlc = region.assign_advice(
                            || "r rlc",
                            config.sig_table.sig_r_rlc,
                            idx,
                            || Value::known(assigned_sig_verif.r_rlc.value),
                        )?;
                        region.constrain_equal(assigned_r_rlc.cell(), tranmuted_cells.r_rlc)?;
                    }

                    {
                        let assigned_s_rlc = region.assign_advice(
                            || "s rlc",
                            config.sig_table.sig_s_rlc,
                            idx,
                            || Value::known(assigned_sig_verif.s_rlc.value),
                        )?;
                        region.constrain_equal(assigned_s_rlc.cell(), tranmuted_cells.s_rlc)?;
                    }

                    {
                        let assigned_v = region.assign_advice(
                            || "v",
                            config.sig_table.sig_v,
                            idx,
                            || Value::known(assigned_sig_verif.v.value),
                        )?;
                        region.constrain_equal(assigned_v.cell(), tranmuted_cells.v)?;
                    }

                    {
                        let assigned_sig_is_valid = region.assign_advice(
                            || "sig is valid",
                            config.sig_table.is_valid,
                            idx,
                            || Value::known(assigned_sig_verif.sig_is_valid.value),
                        )?;
                        region.constrain_equal(
                            assigned_sig_is_valid.cell(),
                            tranmuted_cells.sig_is_valid,
                        )?;
                    }
                }
                Ok(())
            },
        )?;

        Ok(())
    }

    /// Assign witness data to the sig circuit.
    /// Main entrance of the circuit assignment.
    pub(crate) fn assign_main(
        &self,
        config: &SigCircuitConfig<F>,
        layouter: &mut impl Layouter<F>,
        signatures: &[SignData],
        challenges: &Challenges<Value<F>>,
    ) -> Result<Vec<AssignedSignatureVerify<F>>, Error> {
        if signatures.len() > self.max_verif {
            error!(
                "signatures.len() = {} > max_verif = {}",
                signatures.len(),
                self.max_verif
            );
            return Err(Error::Synthesis);
        }

        // ================================================
        // step 1: assert the signature is valid in circuit
        // step 2: decompose the keys and messages
        // step 3: compute RLC of keys and messages
        // ================================================
        let transmute_data =
            self.extract_transmute_data(config, layouter, signatures, challenges)?;

        // ================================================
        // step 4: deferred keccak checks
        // ================================================
        let deferred_keccak_cells = layouter.assign_region(
            || "deferred keccak checks",
            |mut region| {
                let mut res = vec![];
                for (i, [is_address_zero, pk_rlc, pk_hash_rlc]) in
                    transmute_data.assigned_keccak_values.iter().enumerate()
                {
                    let offset = i * 3;
                    let cells = self.enable_keccak_lookup(
                        config,
                        &mut region,
                        offset,
                        is_address_zero,
                        pk_rlc,
                        pk_hash_rlc,
                    )?;
                    res.push(cells);
                }
                Ok(res)
            },
        )?;

        println!("{:?}", self.two_phase_builder.borrow().statistics());

        // ================================================
        // step 5: export as a lookup table
        // ================================================
        self.equality_constraints(config, layouter, &transmute_data, &deferred_keccak_cells)?;
        Ok(transmute_data.assigned_sig_values)
    }
}
