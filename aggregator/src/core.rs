use ark_std::{end_timer, start_timer};
use ethers_core::utils::keccak256;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    halo2curves::{
        bn256::{Bn256, Fq, Fr, G1Affine, G2Affine},
        pairing::Engine,
    },
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use itertools::Itertools;
use rand::Rng;
use snark_verifier::{
    loader::{halo2::halo2_ecc::halo2_base, native::NativeLoader},
    pcs::{
        kzg::{Bdfg21, Kzg, KzgAccumulator, KzgAs},
        AccumulationSchemeProver,
    },
    util::arithmetic::fe_to_limbs,
    verifier::PlonkVerifier,
    Error,
};
use snark_verifier_sdk::{
    types::{PoseidonTranscript, Shplonk, POSEIDON_SPEC},
    Snark,
};
use zkevm_circuits::{
    keccak_circuit::{
        keccak_packed_multi::{self, multi_keccak},
        KeccakCircuit, KeccakCircuitConfig,
    },
    table::{KeccakTable, LookupTable},
    util::Challenges,
};

use crate::{
    constants::{CHAIN_ID_LEN, DIGEST_LEN, INPUT_LEN_PER_ROUND, LOG_DEGREE, MAX_AGG_SNARKS},
    util::{
        assert_conditional_equal, assert_equal, get_indices, get_max_keccak_updates,
        parse_hash_preimage_cells, parse_pi_hash_rlc_cells,
    },
    AggregationConfig, VanillaPlonkConfig, BITS, CHUNK_DATA_HASH_INDEX, LIMBS,
    POST_STATE_ROOT_INDEX, PREV_STATE_ROOT_INDEX, WITHDRAW_ROOT_INDEX,
};

/// Subroutine for the witness generations.
/// Extract the accumulator and proof that from previous snarks.
/// Uses SHPlonk for accumulation.
pub(crate) fn extract_accumulators_and_proof(
    params: &ParamsKZG<Bn256>,
    snarks: &[Snark],
    rng: impl Rng + Send,
    g2: &G2Affine,
    s_g2: &G2Affine,
) -> Result<(KzgAccumulator<G1Affine, NativeLoader>, Vec<u8>), Error> {
    let svk = params.get_g()[0].into();

    let mut transcript_read =
        PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(&[], POSEIDON_SPEC.clone());
    let accumulators = snarks
        .iter()
        .flat_map(|snark| {
            transcript_read.new_stream(snark.proof.as_slice());
            let proof = Shplonk::read_proof(
                &svk,
                &snark.protocol,
                &snark.instances,
                &mut transcript_read,
            );
            // each accumulator has (lhs, rhs) based on Shplonk
            // lhs and rhs are EC points
            Shplonk::succinct_verify(&svk, &snark.protocol, &snark.instances, &proof)
        })
        .collect::<Vec<_>>();
    // sanity check on the accumulator
    {
        for (i, acc) in accumulators.iter().enumerate() {
            let KzgAccumulator { lhs, rhs } = acc;
            let left = Bn256::pairing(lhs, g2);
            let right = Bn256::pairing(rhs, s_g2);
            log::trace!("acc extraction {}-th acc check: left {:?}", i, left);
            log::trace!("acc extraction {}-th acc check: right {:?}", i, right);
            if left != right {
                return Err(snark_verifier::Error::AssertionFailure(format!(
                    "accumulator check failed {left:?} {right:?}, index {i}",
                )));
            }
            //assert_eq!(left, right, "accumulator check failed");
        }
    }

    let mut transcript_write =
        PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(vec![], POSEIDON_SPEC.clone());
    // We always use SHPLONK for accumulation scheme when aggregating proofs
    let accumulator =
        // core step
        // KzgAs does KZG accumulation scheme based on given accumulators and random number (for adding blinding)
        // accumulated ec_pt = ec_pt_1 * 1 + ec_pt_2 * r + ... + ec_pt_n * r^{n-1}
        // ec_pt can be lhs and rhs
        // r is the challenge squeezed from proof
        KzgAs::<Kzg<Bn256, Bdfg21>>::create_proof::<PoseidonTranscript<NativeLoader, Vec<u8>>, _>(
            &Default::default(),
            &accumulators,
            &mut transcript_write,
            rng,
        )?;
    Ok((accumulator, transcript_write.finalize()))
}

/// Subroutine for the witness generations.
/// Extract proof from previous snarks and check pairing for accumulation.
pub fn extract_proof_and_instances_with_pairing_check(
    params: &ParamsKZG<Bn256>,
    snarks: &[Snark],
    rng: impl Rng + Send,
) -> Result<(Vec<u8>, Vec<Fr>), snark_verifier::Error> {
    // (old_accumulator, public inputs) -> (new_accumulator, public inputs)
    let (accumulator, as_proof) =
        extract_accumulators_and_proof(params, snarks, rng, &params.g2(), &params.s_g2())?;

    // the instance for the outer circuit is
    // - new accumulator, consists of 12 elements
    // - inner circuit's instance, flattened (old accumulator is stripped out if exists)
    //
    // it is important that new accumulator is the first 12 elements
    // as specified in CircuitExt::accumulator_indices()
    let KzgAccumulator::<G1Affine, NativeLoader> { lhs, rhs } = accumulator;

    // sanity check on the accumulator
    {
        let left = Bn256::pairing(&lhs, &params.g2());
        let right = Bn256::pairing(&rhs, &params.s_g2());
        log::trace!("circuit acc check: left {:?}", left);
        log::trace!("circuit acc check: right {:?}", right);

        if left != right {
            return Err(snark_verifier::Error::AssertionFailure(format!(
                "accumulator check failed {left:?} {right:?}",
            )));
        }
    }

    let acc_instances = [lhs.x, lhs.y, rhs.x, rhs.y]
        .map(fe_to_limbs::<Fq, Fr, { LIMBS }, { BITS }>)
        .concat();

    Ok((as_proof, acc_instances))
}

#[derive(Default)]
pub(crate) struct ExtractedHashCells {
    hash_input_cells: Vec<AssignedCell<Fr, Fr>>,
    hash_output_cells: Vec<AssignedCell<Fr, Fr>>,
    data_rlc_cells: Vec<AssignedCell<Fr, Fr>>,
    hash_rlc_cells: Vec<AssignedCell<Fr, Fr>>,
    hash_input_len_cells: Vec<AssignedCell<Fr, Fr>>,
    is_final_cells: Vec<AssignedCell<Fr, Fr>>,
}

#[derive(Default)]
pub(crate) struct ExtractedHashCells2 {
    input_rlcs: Vec<AssignedCell<Fr, Fr>>,
    output_rlcs: Vec<AssignedCell<Fr, Fr>>,
    data_lens: Vec<AssignedCell<Fr, Fr>>,
}
impl ExtractedHashCells2 {
    pub(crate) fn assign_hash_rlc_cells(
        plonk_config: &VanillaPlonkConfig,
        region: &mut Region<Fr>,
        offset: &mut usize,
        challenges: Challenges<Value<Fr>>,
        preimages: &[Vec<u8>],
    ) -> Result<Self, halo2_proofs::plonk::Error> {
        let [keccak_input_challenge, evm_word_challenge] =
            plonk_config.read_challenges(region, challenges, offset)?;

        let mut input_rlcs = vec![];
        let mut output_rlcs = vec![];
        let mut data_lens = vec![];
        for preimage in preimages.iter() {
            {
                let mut preimage_cells = vec![];
                for input in preimage.iter() {
                    let v = Fr::from(*input as u64);
                    let cell = plonk_config.load_private(region, &v, offset)?;
                    preimage_cells.push(cell);
                }
                let input_rlc =
                    plonk_config.rlc(region, &preimage_cells, &keccak_input_challenge, offset)?;

                input_rlcs.push(input_rlc);
            }
            {
                let mut digest_cells = vec![];
                let digest = keccak256(preimage);
                for output in digest.iter() {
                    let v = Fr::from(*output as u64);
                    let cell = plonk_config.load_private(region, &v, offset)?;
                    digest_cells.push(cell);
                }
                let output_rlc =
                    plonk_config.rlc(region, &digest_cells, &evm_word_challenge, offset)?;

                output_rlcs.push(output_rlc)
            }

            data_lens.push(plonk_config.load_private(
                region,
                &Fr::from(preimage.len() as u64),
                offset,
            )?);
        }
        Ok(Self {
            input_rlcs,
            output_rlcs,
            data_lens,
        })
    }

    pub(crate) fn check_rlc_cells(
        &self,
        plonk_config: &VanillaPlonkConfig,
        region: &mut Region<Fr>,
        offset: &mut usize,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        for (input_rlcs, (output_rlcs, data_len)) in self
            .input_rlcs
            .iter()
            .zip_eq(self.output_rlcs.iter().zip(self.data_lens.iter()))
        {
            plonk_config.lookup_keccak_rlcs(region, input_rlcs, output_rlcs, data_len, offset)?;
        }
        for (i, (input_rlcs, output_rlcs)) in self
            .input_rlcs
            .iter()
            .zip_eq(self.output_rlcs.iter())
            .enumerate()
        {
            println!(
                "{}-th rlc {:?} {:?}",
                i,
                input_rlcs.value(),
                output_rlcs.value()
            );
        }
        Ok(())
    }
}

/// Input the hash input bytes,
/// assign the circuit for the hash function,
/// return
/// - cells of the hash digests
//
// This function asserts the following constraints on the hashes
//
// 1. batch_data_hash digest is reused for public input hash
// 2. batch_pi_hash used same roots as chunk_pi_hash
// 2.1. batch_pi_hash and chunk[0] use a same prev_state_root
// 2.2. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same post_state_root
// 2.3. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same withdraw_root
// 3. batch_data_hash and chunk[i].pi_hash use a same chunk[i].data_hash when chunk[i] is not padded
// 4. chunks are continuous: they are linked via the state roots
// 5. batch and all its chunks use a same chain id
// 6. chunk[i]'s chunk_pi_hash_rlc_cells == chunk[i-1].chunk_pi_hash_rlc_cells when chunk[i] is
// padded
// 7. the hash input length are correct
// - first MAX_AGG_SNARKS + 1 hashes all have 136 bytes input
// - batch's data_hash length is 32 * number_of_valid_snarks
// 8. batch data hash is correct w.r.t. its RLCs
// 9. is_final_cells are set correctly
pub(crate) fn assign_batch_hashes(
    config: &AggregationConfig,
    layouter: &mut impl Layouter<Fr>,
    challenges: Challenges<Value<Fr>>,
    chunks_are_valid: &[bool],
    preimages: &[Vec<u8>],
) -> Result<Vec<AssignedCell<Fr, Fr>>, Error> {
    let extracted_hash_cells = extract_hash_cells(
        &config.keccak_circuit_config,
        layouter,
        challenges,
        preimages,
    )?;

    // 2. batch_pi_hash used same roots as chunk_pi_hash
    // 2.1. batch_pi_hash and chunk[0] use a same prev_state_root
    // 2.2. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same post_state_root
    // 2.3. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same withdraw_root
    // 5. batch and all its chunks use a same chain id
    copy_constraints(layouter, &extracted_hash_cells.hash_input_cells)?;

    // 1. batch_data_hash digest is reused for public input hash
    // 3. batch_data_hash and chunk[i].pi_hash use a same chunk[i].data_hash when chunk[i] is not
    // padded
    // 4. chunks are continuous: they are linked via the state roots
    // 6. chunk[i]'s chunk_pi_hash_rlc_cells == chunk[i-1].chunk_pi_hash_rlc_cells when chunk[i] is
    // padded
    // 7. the hash input length are correct
    // - first MAX_AGG_SNARKS + 1 hashes all have 136 bytes input
    // - batch's data_hash length is 32 * number_of_valid_snarks
    // 8. batch data hash is correct w.r.t. its RLCs
    // 9. is_final_cells are set correctly
    conditional_constraints(
        &config.plonk_config,
        layouter,
        challenges,
        chunks_are_valid,
        &extracted_hash_cells,
        preimages,
    )?;

    Ok(extracted_hash_cells.hash_output_cells)
}

pub(crate) fn extract_hash_cells(
    keccak_config: &KeccakCircuitConfig<Fr>,
    layouter: &mut impl Layouter<Fr>,
    challenges: Challenges<Value<Fr>>,
    preimages: &[Vec<u8>],
) -> Result<ExtractedHashCells, Error> {
    let mut is_first_time = true;
    let keccak_capacity = KeccakCircuit::<Fr>::capacity_for_row(1 << LOG_DEGREE);
    let max_keccak_updates = get_max_keccak_updates(MAX_AGG_SNARKS);
    let keccak_f_rows = keccak_packed_multi::get_num_rows_per_update();

    let timer = start_timer!(|| ("multi keccak").to_string());
    // preimages consists of the following parts
    // (1) batchPiHash preimage =
    //      (chain_id ||
    //      chunk[0].prev_state_root ||
    //      chunk[k-1].post_state_root ||
    //      chunk[k-1].withdraw_root ||
    //      batch_data_hash)
    // (2) chunk[i].piHash preimage =
    //      (chain id ||
    //      chunk[i].prevStateRoot || chunk[i].postStateRoot ||
    //      chunk[i].withdrawRoot || chunk[i].datahash)
    // (3) batchDataHash preimage =
    //      (chunk[0].dataHash || ... || chunk[k-1].dataHash)
    // each part of the preimage is mapped to image by Keccak256
    let witness = multi_keccak(preimages, challenges, keccak_capacity)
        .map_err(|e| Error::AssertionFailure(format!("multi keccak assignment failed: {e:?}")))?;
    end_timer!(timer);

    // extract the indices of the rows for which the preimage and the digest cells lie in
    let (preimage_indices, digest_indices) = get_indices(preimages);

    let extracted_hash_cells = layouter
        .assign_region(
            || "assign keccak rows",
            |mut region| -> Result<ExtractedHashCells, halo2_proofs::plonk::Error> {
                if is_first_time {
                    is_first_time = false;
                    let offset = witness.len() - 1;
                    keccak_config.set_row(&mut region, offset, &witness[offset])?;
                    return Ok(ExtractedHashCells::default());
                }

                let mut preimage_indices_iter = preimage_indices.iter();
                let mut digest_indices_iter = digest_indices.iter();

                let mut cur_preimage_index = preimage_indices_iter.next();
                let mut cur_digest_index = digest_indices_iter.next();

                // ====================================================
                // Step 1. Extract the hash cells
                // ====================================================
                let mut hash_input_cells = vec![];
                let mut hash_output_cells = vec![];
                let mut data_rlc_cells = vec![];
                let mut hash_input_len_cells = vec![];
                let mut is_final_cells = vec![];
                let mut hash_rlc_cells = vec![];

                let timer = start_timer!(|| "assign row");
                log::trace!("witness length: {}", witness.len());
                let input_bytes_col_idx =
                    keccak_packed_multi::get_input_bytes_col_idx_in_cell_manager()
                        + <KeccakTable as LookupTable<Fr>>::columns(&keccak_config.keccak_table)
                            .len()
                        - 1;
                for (offset, keccak_row) in witness.iter().enumerate() {
                    let row = keccak_config.set_row(&mut region, offset, keccak_row)?;

                    if cur_preimage_index.is_some() && *cur_preimage_index.unwrap() == offset {
                        hash_input_cells.push(row[input_bytes_col_idx].clone());
                        cur_preimage_index = preimage_indices_iter.next();
                    }
                    if cur_digest_index.is_some() && *cur_digest_index.unwrap() == offset {
                        // last column is Keccak output in Keccak circuit
                        hash_output_cells.push(row.last().unwrap().clone()); // sage unwrap
                        cur_digest_index = digest_indices_iter.next();
                    }
                    if offset % keccak_f_rows == 0 && offset / keccak_f_rows <= max_keccak_updates {
                        // first column is is_final
                        is_final_cells.push(row[0].clone());
                        // second column is data rlc (i.e, input rlc)
                        data_rlc_cells.push(row[1].clone());
                        // third column is hash len
                        hash_input_len_cells.push(row[2].clone());
                        // fourth column is hash rlc (i.e, output rlc)
                        hash_rlc_cells.push(row[3].clone());
                    }
                }
                end_timer!(timer);
                for (i, e) in is_final_cells.iter().enumerate() {
                    log::trace!("{}-th round is final {:?}", i, e.value());
                }

                // sanity
                assert_eq!(
                    hash_input_cells.len(),
                    max_keccak_updates * INPUT_LEN_PER_ROUND
                );
                assert_eq!(hash_output_cells.len(), (MAX_AGG_SNARKS + 5) * DIGEST_LEN);

                keccak_config
                    .keccak_table
                    .annotate_columns_in_region(&mut region);
                keccak_config.annotate_circuit(&mut region);

                println!("{}", data_rlc_cells.len());
                println!("{}", hash_rlc_cells.len());

                for i in 0..data_rlc_cells.len() {
                    println!(
                        "rlcs: {} {:?} {:?}",
                        i,
                        data_rlc_cells[i].value(),
                        hash_rlc_cells[i].value(),
                    )
                }

                Ok(ExtractedHashCells {
                    hash_input_cells,
                    hash_output_cells,
                    data_rlc_cells,
                    hash_input_len_cells,
                    is_final_cells,
                    hash_rlc_cells,
                })
            },
        )
        .map_err(|e| Error::AssertionFailure(format!("assign keccak rows: {e}")))?;

    for (i, e) in extracted_hash_cells.hash_input_len_cells.iter().enumerate() {
        log::trace!("{}'s round hash input len {:?}", i, e.value())
    }

    Ok(extracted_hash_cells)
}

// Assert the following constraints
// 2. batch_pi_hash used same roots as chunk_pi_hash
// 2.1. batch_pi_hash and chunk[0] use a same prev_state_root
// 2.2. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same post_state_root
// 2.3. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same withdraw_root
// 5. batch and all its chunks use a same chain id
fn copy_constraints(
    layouter: &mut impl Layouter<Fr>,
    hash_input_cells: &[AssignedCell<Fr, Fr>],
) -> Result<(), Error> {
    let mut is_first_time = true;

    layouter
        .assign_region(
            || "copy constraints",
            |mut region| -> Result<(), halo2_proofs::plonk::Error> {
                if is_first_time {
                    // this region only use copy constraints and do not affect the shape of the
                    // layouter
                    is_first_time = false;
                    return Ok(());
                }
                // ====================================================
                // parse the hashes
                // ====================================================
                // preimages
                let (
                    batch_pi_hash_preimage,
                    chunk_pi_hash_preimages,
                    _potential_batch_data_hash_preimage,
                ) = parse_hash_preimage_cells(hash_input_cells);

                // ====================================================
                // Constraint the relations between hash preimages
                // via copy constraints
                // ====================================================
                //
                // 2 batch_pi_hash used same roots as chunk_pi_hash
                //
                // batch_pi_hash =
                //   keccak(
                //      chain_id ||
                //      chunk[0].prev_state_root ||
                //      chunk[k-1].post_state_root ||
                //      chunk[k-1].withdraw_root ||
                //      batchData_hash )
                //
                // chunk[i].piHash =
                //   keccak(
                //        chain id ||
                //        chunk[i].prevStateRoot ||
                //        chunk[i].postStateRoot ||
                //        chunk[i].withdrawRoot  ||
                //        chunk[i].datahash)
                //
                // PREV_STATE_ROOT_INDEX, POST_STATE_ROOT_INDEX, WITHDRAW_ROOT_INDEX
                // used below are byte positions for
                // prev_state_root, post_state_root, withdraw_root
                for i in 0..DIGEST_LEN {
                    // 2.1 chunk[0].prev_state_root
                    // sanity check
                    assert_equal(
                        &batch_pi_hash_preimage[i + PREV_STATE_ROOT_INDEX],
                        &chunk_pi_hash_preimages[0][i + PREV_STATE_ROOT_INDEX],
                        format!(
                            "chunk and batch's prev_state_root do not match: {:?} {:?}",
                            &batch_pi_hash_preimage[i + PREV_STATE_ROOT_INDEX].value(),
                            &chunk_pi_hash_preimages[0][i + PREV_STATE_ROOT_INDEX].value(),
                        )
                        .as_str(),
                    )?;
                    region.constrain_equal(
                        batch_pi_hash_preimage[i + PREV_STATE_ROOT_INDEX].cell(),
                        chunk_pi_hash_preimages[0][i + PREV_STATE_ROOT_INDEX].cell(),
                    )?;
                    // 2.2 chunk[k-1].post_state_root
                    // sanity check
                    assert_equal(
                        &batch_pi_hash_preimage[i + POST_STATE_ROOT_INDEX],
                        &chunk_pi_hash_preimages[MAX_AGG_SNARKS - 1][i + POST_STATE_ROOT_INDEX],
                        format!(
                            "chunk and batch's post_state_root do not match: {:?} {:?}",
                            &batch_pi_hash_preimage[i + POST_STATE_ROOT_INDEX].value(),
                            &chunk_pi_hash_preimages[MAX_AGG_SNARKS - 1][i + POST_STATE_ROOT_INDEX]
                                .value(),
                        )
                        .as_str(),
                    )?;
                    region.constrain_equal(
                        batch_pi_hash_preimage[i + POST_STATE_ROOT_INDEX].cell(),
                        chunk_pi_hash_preimages[MAX_AGG_SNARKS - 1][i + POST_STATE_ROOT_INDEX]
                            .cell(),
                    )?;
                    // 2.3 chunk[k-1].withdraw_root
                    assert_equal(
                        &batch_pi_hash_preimage[i + WITHDRAW_ROOT_INDEX],
                        &chunk_pi_hash_preimages[MAX_AGG_SNARKS - 1][i + WITHDRAW_ROOT_INDEX],
                        format!(
                            "chunk and batch's withdraw_root do not match: {:?} {:?}",
                            &batch_pi_hash_preimage[i + WITHDRAW_ROOT_INDEX].value(),
                            &chunk_pi_hash_preimages[MAX_AGG_SNARKS - 1][i + WITHDRAW_ROOT_INDEX]
                                .value(),
                        )
                        .as_str(),
                    )?;
                    region.constrain_equal(
                        batch_pi_hash_preimage[i + WITHDRAW_ROOT_INDEX].cell(),
                        chunk_pi_hash_preimages[MAX_AGG_SNARKS - 1][i + WITHDRAW_ROOT_INDEX].cell(),
                    )?;
                }

                // 5 assert hashes use a same chain id
                for (i, chunk_pi_hash_preimage) in chunk_pi_hash_preimages.iter().enumerate() {
                    for (lhs, rhs) in batch_pi_hash_preimage
                        .iter()
                        .take(CHAIN_ID_LEN)
                        .zip(chunk_pi_hash_preimage.iter().take(CHAIN_ID_LEN))
                    {
                        // sanity check
                        assert_equal(
                            lhs,
                            rhs,
                            format!(
                                "chunk_{i} and batch's chain id do not match: {:?} {:?}",
                                &lhs.value(),
                                &rhs.value(),
                            )
                            .as_str(),
                        )?;
                        region.constrain_equal(lhs.cell(), rhs.cell())?;
                    }
                }
                Ok(())
            },
        )
        .map_err(|e| Error::AssertionFailure(format!("assign keccak rows: {e}")))?;
    Ok(())
}

// Assert the following constraints
// This function asserts the following constraints on the hashes
// 1. batch_data_hash digest is reused for public input hash
// 3. batch_data_hash and chunk[i].pi_hash use a same chunk[i].data_hash when chunk[i] is not padded
// 4. chunks are continuous: they are linked via the state roots
// 6. chunk[i]'s chunk_pi_hash_rlc_cells == chunk[i-1].chunk_pi_hash_rlc_cells when chunk[i] is
// padded
// 7. the hash input length are correct
// - first MAX_AGG_SNARKS + 1 hashes all have 136 bytes input
// - batch's data_hash length is 32 * number_of_valid_snarks
// 8. batch data hash is correct w.r.t. its RLCs
// 9. is_final_cells are set correctly
pub(crate) fn conditional_constraints(
    plonk_config: &VanillaPlonkConfig,
    layouter: &mut impl Layouter<Fr>,
    challenges: Challenges<Value<Fr>>,
    chunks_are_valid: &[bool],
    extracted_hash_cells: &ExtractedHashCells,
    preimages: &[Vec<u8>],
) -> Result<(), Error> {
    let mut first_pass = halo2_base::SKIP_FIRST_PASS;
    let ExtractedHashCells {
        hash_input_cells,
        hash_output_cells,
        hash_input_len_cells,
        data_rlc_cells,
        is_final_cells,
        hash_rlc_cells,
    } = extracted_hash_cells;

    layouter
        .assign_region(
            || "rlc conditional constraints",
            |mut region| -> Result<(), halo2_proofs::plonk::Error> {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                plonk_config.init(&mut region)?;
                let mut offset = 0;

                // ====================================================
                // build the flags to indicate the chunks are empty or not
                // ====================================================
                let chunk_is_valid_cells = chunks_are_valid
                    .iter()
                    .map(|chunk_is_valid| -> Result<_, halo2_proofs::plonk::Error> {
                        plonk_config.load_private(
                            &mut region,
                            &Fr::from(*chunk_is_valid as u64),
                            &mut offset,
                        )
                    })
                    .collect::<Result<Vec<_>, halo2_proofs::plonk::Error>>()?;

                let chunk_is_valid_cell32s = chunk_is_valid_cells
                    .iter()
                    .flat_map(|cell| vec![cell; 32])
                    .cloned()
                    .collect::<Vec<_>>();

                let num_valid_snarks = constrain_flags(
                    plonk_config,
                    &mut region,
                    &chunk_is_valid_cells,
                    &mut offset,
                )?;

                // todo! merge this
                let [keccak_input_challenge, evm_word_challenge] =
                    plonk_config.read_challenges(&mut region, challenges, &mut offset)?;
                // ====================================================
                // extract the RLCs for the input and output of the hash
                // this validates the hash inputs and outputs as they are looked up from the table
                // ====================================================
                let rlcs = ExtractedHashCells2::assign_hash_rlc_cells(
                    plonk_config,
                    &mut region,
                    &mut offset,
                    challenges,
                    preimages,
                )?;
                for (i, e) in rlcs.input_rlcs.iter().enumerate() {
                    println!("{}-th input rlcs: {:?}", i, e.value());
                }

                for (i, e) in rlcs.output_rlcs.iter().enumerate() {
                    println!("{}-th output rlcs: {:?}", i, e.value());
                }
                rlcs.check_rlc_cells(plonk_config, &mut region, &mut offset)?;

                // ====================================================
                // parse the hashes
                // ====================================================
                // preimages
                let (
                    batch_pi_hash_preimage,
                    chunk_pi_hash_preimages,
                    potential_batch_data_hash_preimage,
                ) = parse_hash_preimage_cells(hash_input_cells);

                // digests
                // let (
                //     _batch_pi_hash_digest,
                //     _chunk_pi_hash_digests,
                //     potential_batch_data_hash_digest,
                // ) = parse_hash_digest_cells(hash_output_cells);
                // ====================================================
                // 1. batch_data_hash digest is reused for public input hash
                // ====================================================
                //
                //
                // public input hash is build as
                // public_input_hash = keccak(
                //      chain_id ||
                //      chunk[0].prev_state_root ||
                //      chunk[k-1].post_state_root ||
                //      chunk[k-1].withdraw_root ||
                //      batch_data_hash )
                //
                // batchDataHash = keccak(chunk[0].dataHash || ... || chunk[k-1].dataHash)

                let batch_data_hash_rlc = plonk_config.rlc(
                    &mut region,
                    batch_pi_hash_preimage
                        [CHUNK_DATA_HASH_INDEX..CHUNK_DATA_HASH_INDEX + DIGEST_LEN]
                        .as_ref(),
                    &evm_word_challenge,
                    &mut offset,
                )?;
                plonk_config.lookup_keccak_digest(
                    &mut region,
                    &batch_data_hash_rlc,
                    &mut offset,
                )?;

                // ====================================================
                // 3 batch_data_hash and chunk[i].pi_hash use a same chunk[i].data_hash when
                // chunk[i] is not padded
                // ====================================================
                //
                // batchDataHash = keccak(chunk[0].dataHash || ... || chunk[k-1].dataHash)
                //
                // chunk[i].piHash =
                //     keccak(
                //        &chain id ||
                //        chunk[i].prevStateRoot ||
                //        chunk[i].postStateRoot ||
                //        chunk[i].withdrawRoot  ||
                //        chunk[i].datahash)

                // the strategy here is to generate the RLCs of the chunk[i].dataHash and compare it
                // with batchDataHash's input RLC

                let batch_data_hash_reconstructed_rlc = {
                    let batch_data_hash_reconstructed = chunk_pi_hash_preimages
                        .iter()
                        .flat_map(|&chunk_pi_hash_preimage| {
                            chunk_pi_hash_preimage
                                [CHUNK_DATA_HASH_INDEX..CHUNK_DATA_HASH_INDEX + DIGEST_LEN]
                                .iter()
                        })
                        .cloned()
                        .collect::<Vec<_>>();

                    plonk_config.rlc_with_flag(
                        &mut region,
                        &batch_data_hash_reconstructed,
                        &keccak_input_challenge,
                        &chunk_is_valid_cell32s,
                        &mut offset,
                    )?
                };

                plonk_config.lookup_keccak_preimage(
                    &mut region,
                    &batch_data_hash_reconstructed_rlc,
                    &mut offset,
                )?;

                // ====================================================
                // 4  __valid__ chunks are continuous: they are linked via the state roots
                // ====================================================
                // chunk[i].piHash =
                // keccak(
                //        chain id ||
                //        chunk[i].prevStateRoot || chunk[i].postStateRoot || chunk[i].withdrawRoot
                //        || chunk[i].datahash)

                for i in 0..MAX_AGG_SNARKS - 1 {
                    for j in 0..DIGEST_LEN {
                        // sanity check
                        assert_conditional_equal(
                            &chunk_pi_hash_preimages[i + 1][PREV_STATE_ROOT_INDEX + j],
                            &chunk_pi_hash_preimages[i][POST_STATE_ROOT_INDEX + j],
                            &chunk_is_valid_cells[i + 1],
                            format!(
                                "chunk_{i} is not continuous: {:?} {:?} {:?}",
                                &chunk_pi_hash_preimages[i + 1][PREV_STATE_ROOT_INDEX + j].value(),
                                &chunk_pi_hash_preimages[i][POST_STATE_ROOT_INDEX + j].value(),
                                &chunk_is_valid_cells[i + 1].value(),
                            )
                            .as_str(),
                        )?;
                        plonk_config.conditional_enforce_equal(
                            &mut region,
                            &chunk_pi_hash_preimages[i + 1][PREV_STATE_ROOT_INDEX + j],
                            &chunk_pi_hash_preimages[i][POST_STATE_ROOT_INDEX + j],
                            &chunk_is_valid_cells[i + 1],
                            &mut offset,
                        )?;
                    }
                }

                // ====================================================
                // 6. chunk[i]'s chunk_pi_hash_rlc_cells == chunk[i-1].chunk_pi_hash_rlc_cells when
                // chunk[i] is padded
                // ====================================================
                let chunks_are_padding = chunk_is_valid_cells
                    .iter()
                    .map(|chunk_is_valid| {
                        plonk_config.not(&mut region, chunk_is_valid, &mut offset)
                    })
                    .collect::<Result<Vec<_>, halo2_proofs::plonk::Error>>()?;

                let chunk_pi_hash_rlc_cells = parse_pi_hash_rlc_cells(data_rlc_cells);

                for i in 1..MAX_AGG_SNARKS {
                    plonk_config.conditional_enforce_equal(
                        &mut region,
                        chunk_pi_hash_rlc_cells[i - 1],
                        chunk_pi_hash_rlc_cells[i],
                        &chunks_are_padding[i],
                        &mut offset,
                    )?;
                }

                for (i, (e, f)) in chunk_pi_hash_rlc_cells
                    .iter()
                    .zip(chunk_is_valid_cells.iter())
                    .enumerate()
                {
                    log::trace!("{i}-th chunk rlc:      {:?}", e.value());
                    log::trace!("{i}-th chunk is valid: {:?}", f.value());
                }

                // ====================================================
                // 7. the hash input length are correct
                // ====================================================
                // - first MAX_AGG_SNARKS + 1 hashes all have 136 bytes input
                // - batch's data_hash length is 32 * number_of_valid_snarks

                // - first MAX_AGG_SNARKS + 1 hashes all have 136 bytes input
                rlcs.data_lens
                    .iter()
                    .take(MAX_AGG_SNARKS + 1)
                    .for_each(|data_len| {
                        region
                            .constrain_equal(
                                data_len.cell(),
                                plonk_config
                                    .one_hundred_and_thirty_six_cell(data_len.cell().region_index),
                            )
                            .unwrap()
                    });

                // - batch's data_hash length is 32 * number_of_valid_snarks
                let const32 = plonk_config.load_private(&mut region, &Fr::from(32), &mut offset)?;
                let const32_cell = plonk_config.thirty_two_cell(const32.cell().region_index);
                region.constrain_equal(const32.cell(), const32_cell)?;
                let data_hash_inputs_len =
                    plonk_config.mul(&mut region, &num_valid_snarks, &const32, &mut offset)?;
                region.constrain_equal(
                    rlcs.data_lens[MAX_AGG_SNARKS + 1].cell(),
                    data_hash_inputs_len.cell(),
                )?;

                // ====================================================
                // 8. batch data hash is correct w.r.t. its RLCs
                // ====================================================
                // batchDataHash = keccak(chunk[0].dataHash || ... || chunk[k-1].dataHash)

                let rlc_cell = plonk_config.rlc_with_flag(
                    &mut region,
                    potential_batch_data_hash_preimage[..DIGEST_LEN * MAX_AGG_SNARKS].as_ref(),
                    &keccak_input_challenge,
                    &chunk_is_valid_cell32s,
                    &mut offset,
                )?;

                plonk_config.lookup_keccak_preimage(&mut region, &rlc_cell, &mut offset)?;

                log::trace!("rlc chip uses {} rows", offset);
                Ok(())
            },
        )
        .map_err(|e| Error::AssertionFailure(format!("aggregation: {e}")))?;
    Ok(())
}

/// Input a list of flags whether the snark is valid
///
/// Assert the following relations on the flags:
/// - all elements are binary
/// - the first element is 1
/// - for the next elements, if the element is 1, the previous element must also be 1
///
/// Return a cell for number of valid snarks
fn constrain_flags(
    plonk_config: &VanillaPlonkConfig,
    region: &mut Region<Fr>,
    chunk_are_valid: &[AssignedCell<Fr, Fr>],
    offset: &mut usize,
) -> Result<AssignedCell<Fr, Fr>, halo2_proofs::plonk::Error> {
    assert!(!chunk_are_valid.is_empty());

    let one = {
        let one = plonk_config.load_private(region, &Fr::one(), offset)?;
        let one_cell = plonk_config.one_cell(chunk_are_valid[0].cell().region_index);
        region.constrain_equal(one.cell(), one_cell)?;
        one
    };

    // the first element is 1
    region.constrain_equal(chunk_are_valid[0].cell(), one.cell())?;

    let mut res = chunk_are_valid[0].clone();
    for (index, cell) in chunk_are_valid.iter().enumerate().skip(1) {
        plonk_config.enforce_binary(region, cell, offset)?;

        // if the element is 1, the previous element must also be 1
        plonk_config.conditional_enforce_equal(
            region,
            &chunk_are_valid[index - 1],
            &one,
            cell,
            offset,
        )?;

        res = plonk_config.add(region, &res, cell, offset)?;
    }
    Ok(res)
}

// pub(crate) fn load_hash_lookup_table(
//     layouter: &mut impl Layouter<Fr>,
//     config: &AggregationConfig,
//     extracted_hash_cells: &ExtractedHashCells,
// ) {

//     config.plonk_config.keccak_table.load(
//         layouter,
//         &extracted_hash_cells.data_rlc_cells,
//         &extracted_hash_cells.hash_rlc_cells,
//     ).unwrap();
// }
