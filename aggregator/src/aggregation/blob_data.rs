use ethers_core::utils::keccak256;
use halo2_ecc::bigint::CRTInteger;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, SecondPhase, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use zkevm_circuits::{
    table::{KeccakTable, LookupTable, RangeTable, U8Table},
    util::{Challenges, Expr},
};

use crate::{
    batch::{
        BLOB_WIDTH, N_BYTES_31, N_BYTES_32, N_ROWS_BLOB_DATA_CONFIG, N_ROWS_DATA,
        N_ROWS_DIGEST_BYTES, N_ROWS_DIGEST_RLC, N_ROWS_METADATA,
    },
    BatchHash, RlcConfig, MAX_AGG_SNARKS,
};

#[derive(Clone, Debug)]
pub struct BlobDataConfig {
    /// The byte value at this row.
    byte: Column<Advice>,
    /// The accumulator serves several purposes.
    /// 1. For the metadata section, the accumulator holds the running linear combination of the
    ///    chunk size.
    /// 2. For the chunk data section, the accumulator holds the incremental chunk size, which
    ///    resets to 1 if we encounter a chunk boundary. The accumulator here is referenced while
    ///    doing a lookup to the Keccak table that requires the input length.
    accumulator: Column<Advice>,
    /// An increasing counter that denotes the chunk ID. The chunk ID is from [1, MAX_AGG_SNARKS].
    chunk_idx: Column<Advice>,
    /// A boolean witness that is set only when we encounter the end of a chunk. We enable a lookup
    /// to the Keccak table when the boundary is met.
    is_boundary: Column<Advice>,
    /// A boolean witness to indicate padded rows at the end of the data section.
    is_padding: Column<Advice>,
    /// Represents the running random linear combination of bytes seen so far, that are a part of
    /// the preimage to the Keccak hash. It resets whenever we encounter a chunk boundary.
    preimage_rlc: Column<Advice>,
    /// Represents the random linear combination of the Keccak digest. This has meaningful values
    /// only at the rows where we actually do the Keccak lookup.
    digest_rlc: Column<Advice>,
    /// Boolean to let us know we are in the data section.
    data_selector: Selector,
    /// Boolean to let us know we are in the hash section.
    hash_selector: Selector,
    u8_table: U8Table,
    chunk_idx_range_table: RangeTable<MAX_AGG_SNARKS>,
}

pub struct AssignedBlobDataExport {
    pub blob_fields: Vec<Vec<AssignedCell<Fr, Fr>>>,
    pub challenge_digest: Vec<AssignedCell<Fr, Fr>>,
    pub chunk_data_digests: Vec<Vec<AssignedCell<Fr, Fr>>>,
}

struct AssignedBlobDataConfig {
    pub byte: AssignedCell<Fr, Fr>,
    pub accumulator: AssignedCell<Fr, Fr>,
    pub chunk_idx: AssignedCell<Fr, Fr>,
    pub is_boundary: AssignedCell<Fr, Fr>,
    pub preimage_rlc: AssignedCell<Fr, Fr>,
    pub digest_rlc: AssignedCell<Fr, Fr>,
}

impl BlobDataConfig {
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        challenge: Challenges<Expression<Fr>>,
        u8_table: U8Table,
        range_table: RangeTable<MAX_AGG_SNARKS>,
        keccak_table: &KeccakTable,
    ) -> Self {
        let config = Self {
            u8_table,
            chunk_idx_range_table: range_table,
            byte: meta.advice_column(),
            accumulator: meta.advice_column(),
            is_boundary: meta.advice_column(),
            chunk_idx: meta.advice_column(),
            is_padding: meta.advice_column(),
            preimage_rlc: meta.advice_column_in(SecondPhase),
            digest_rlc: meta.advice_column_in(SecondPhase),
            data_selector: meta.complex_selector(),
            hash_selector: meta.complex_selector(),
        };

        // TODO: reduce the number of permutation columns
        meta.enable_equality(config.byte);
        meta.enable_equality(config.accumulator);
        meta.enable_equality(config.is_boundary);
        meta.enable_equality(config.chunk_idx);
        meta.enable_equality(config.preimage_rlc);
        meta.enable_equality(config.digest_rlc);

        let r = challenge.keccak_input();

        meta.lookup("BlobDataConfig (0 < byte < 256)", |meta| {
            let byte_value = meta.query_advice(config.byte, Rotation::cur());
            vec![(byte_value, u8_table.into())]
        });

        meta.lookup(
            "BlobDataConfig (chunk idx transition on boundary)",
            |meta| {
                let is_data = meta.query_selector(config.data_selector);
                let is_padding = meta.query_advice(config.is_padding, Rotation::next());
                let is_boundary = meta.query_advice(config.is_boundary, Rotation::cur());
                // if we are in the data section, encounter a boundary and the next row is not
                // padding.
                let cond = is_data * is_boundary * (1.expr() - is_padding);
                let chunk_idx_curr = meta.query_advice(config.chunk_idx, Rotation::cur());
                let chunk_idx_next = meta.query_advice(config.chunk_idx, Rotation::next());
                vec![(cond * (chunk_idx_next - chunk_idx_curr), range_table.into())]
            },
        );

        meta.create_gate("BlobDataConfig (transition when boundary)", |meta| {
            let is_data = meta.query_selector(config.data_selector);
            let is_boundary = meta.query_advice(config.is_boundary, Rotation::cur());
            let is_padding_next = meta.query_advice(config.is_padding, Rotation::next());

            let cond = is_data * is_boundary;

            let len_next = meta.query_advice(config.accumulator, Rotation::next());
            let preimage_rlc_next = meta.query_advice(config.preimage_rlc, Rotation::next());
            let byte_next = meta.query_advice(config.byte, Rotation::next());

            vec![
                // if boundary followed by padding, length and preimage_rlc is 0.
                cond.expr() * is_padding_next.expr() * len_next.expr(),
                cond.expr() * is_padding_next.expr() * preimage_rlc_next.expr(),
                // if boundary not followed by padding, length resets to 1, preimage_rlc resets to
                // the byte value.
                cond.expr() * (1.expr() - is_padding_next.expr()) * (len_next.expr() - 1.expr()),
                cond.expr()
                    * (1.expr() - is_padding_next.expr())
                    * (preimage_rlc_next - byte_next.expr()),
            ]
        });

        meta.create_gate("BlobDataConfig (transition when no boundary)", |meta| {
            let is_data = meta.query_selector(config.data_selector);
            let is_boundary = meta.query_advice(config.is_boundary, Rotation::cur());
            let is_padding = meta.query_advice(config.is_padding, Rotation::cur());

            // in the data section (not padding) when we traverse the same chunk.
            let cond = is_data * (1.expr() - is_padding) * (1.expr() - is_boundary);

            let chunk_idx_curr = meta.query_advice(config.chunk_idx, Rotation::cur());
            let chunk_idx_next = meta.query_advice(config.chunk_idx, Rotation::next());
            let len_curr = meta.query_advice(config.accumulator, Rotation::cur());
            let len_next = meta.query_advice(config.accumulator, Rotation::next());
            let preimage_rlc_curr = meta.query_advice(config.preimage_rlc, Rotation::cur());
            let preimage_rlc_next = meta.query_advice(config.preimage_rlc, Rotation::next());
            let byte_next = meta.query_advice(config.byte, Rotation::next());

            vec![
                // chunk idx unchanged.
                cond.expr() * (chunk_idx_next - chunk_idx_curr),
                // length is accumulated.
                cond.expr() * (len_next - len_curr - 1.expr()),
                // preimage rlc is updated.
                cond.expr() * (preimage_rlc_curr * r + byte_next - preimage_rlc_next),
            ]
        });

        meta.create_gate("BlobDataConfig (boundary/padding)", |meta| {
            let is_data = meta.query_selector(config.data_selector);
            let is_boundary = meta.query_advice(config.is_boundary, Rotation::cur());
            let is_padding_curr = meta.query_advice(config.is_padding, Rotation::cur());
            let is_padding_next = meta.query_advice(config.is_padding, Rotation::next());
            let diff = is_padding_next - is_padding_curr.expr();

            vec![
                // is_boundary is boolean.
                is_data.expr() * is_boundary.expr() * (1.expr() - is_boundary.expr()),
                // is_padding is boolean.
                is_data.expr() * is_padding_curr.expr() * (1.expr() - is_padding_curr.expr()),
                // is_padding transitions from 0 -> 1 only once.
                is_data.expr() * diff.expr() * (1.expr() - diff.expr()),
            ]
        });

        // lookup to keccak table.
        meta.lookup_any("BlobDataConfig (keccak table)", |meta| {
            let is_data = meta.query_selector(config.data_selector);
            let is_hash = meta.query_selector(config.hash_selector);
            let is_not_hash = 1.expr() - is_hash;
            let is_boundary = meta.query_advice(config.is_boundary, Rotation::cur());

            // in the "metadata" or "chunk data" section, wherever is_boundary is set.
            let cond = is_not_hash * is_boundary;

            let accumulator = meta.query_advice(config.accumulator, Rotation::cur());
            let preimage_len =
                is_data.expr() * accumulator + (1.expr() - is_data) * N_ROWS_METADATA.expr();

            [
                1.expr(),                                                // q_enable
                1.expr(),                                                // is final
                meta.query_advice(config.preimage_rlc, Rotation::cur()), // input RLC
                preimage_len,                                            // input len
                meta.query_advice(config.digest_rlc, Rotation::cur()),   // output RLC
            ]
            .into_iter()
            .zip_eq(keccak_table.table_exprs(meta))
            .map(|(value, table)| (cond.expr() * value, table))
            .collect()
        });

        // lookup for digest RLC to the hash section.
        meta.lookup_any("BlobDataConfig (hash section)", |meta| {
            let is_data = meta.query_selector(config.data_selector);
            let is_boundary = meta.query_advice(config.is_boundary, Rotation::cur());

            // in the "chunk data" section when we encounter a chunk boundary
            let cond = is_data * is_boundary;

            let hash_section_table = vec![
                meta.query_selector(config.hash_selector),
                meta.query_advice(config.chunk_idx, Rotation::cur()),
                meta.query_advice(config.accumulator, Rotation::cur()),
                meta.query_advice(config.digest_rlc, Rotation::cur()),
            ];
            [
                1.expr(),                                               // hash section
                meta.query_advice(config.chunk_idx, Rotation::cur()),   // chunk idx
                meta.query_advice(config.accumulator, Rotation::cur()), // chunk len
                meta.query_advice(config.digest_rlc, Rotation::cur()),  // digest rlc
            ]
            .into_iter()
            .zip(hash_section_table)
            .map(|(value, table)| (cond.expr() * value, table))
            .collect()
        });

        // lookup for challenge_digest := keccak(preimage_challenge_digest)
        meta.lookup_any("BlobDataConfig (z := keccak(preimage_z))", |meta| {
            let is_hash = meta.query_selector(config.hash_selector);
            let is_boundary = meta.query_advice(config.is_boundary, Rotation::cur());

            // when is_boundary is set in the "digest RLC" section.
            // this is also the last row of the "digest RLC" section.
            let cond = is_hash * is_boundary;

            // - metadata_digest: 32 bytes
            // - chunk[i].chunk_data_digest: 32 bytes each
            let preimage_len = 32.expr() * (MAX_AGG_SNARKS + 1).expr();

            [
                1.expr(),                                                // q_enable
                1.expr(),                                                // is final
                meta.query_advice(config.preimage_rlc, Rotation::cur()), // input rlc
                preimage_len,                                            // input len
                meta.query_advice(config.digest_rlc, Rotation::cur()),   // output rlc
            ]
            .into_iter()
            .zip_eq(keccak_table.table_exprs(meta))
            .map(|(value, table)| (cond.expr() * value, table))
            .collect()
        });

        assert!(meta.degree() <= 5);
        config
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<Fr>,
        challenge_value: Challenges<Value<Fr>>,
        rlc_config: &RlcConfig,
        batch: &BatchHash,
        barycentric_assignments: &[CRTInteger<Fr>],
    ) -> Result<AssignedBlobDataExport, Error> {
        // load tables
        self.u8_table.load(layouter)?;
        self.chunk_idx_range_table.load(layouter)?;

        let assigned_rows = layouter.assign_region(
            || "BlobData rows",
            |mut region| {
                let rows = batch.to_blob_data().to_rows(challenge_value);
                assert_eq!(rows.len(), N_ROWS_BLOB_DATA_CONFIG);

                // enable data selector
                for offset in N_ROWS_METADATA..N_ROWS_METADATA + N_ROWS_DATA {
                    self.data_selector.enable(&mut region, offset)?;
                }

                // enable hash selector
                for offset in N_ROWS_METADATA + N_ROWS_DATA..N_ROWS_BLOB_DATA_CONFIG {
                    self.hash_selector.enable(&mut region, offset)?;
                }

                let mut assigned_rows = Vec::with_capacity(N_ROWS_BLOB_DATA_CONFIG);
                for (i, row) in rows.iter().enumerate() {
                    let byte = region.assign_advice(
                        || "byte",
                        self.byte,
                        i,
                        || Value::known(Fr::from(row.byte as u64)),
                    )?;
                    let accumulator = region.assign_advice(
                        || "accumulator",
                        self.accumulator,
                        i,
                        || Value::known(Fr::from(row.accumulator)),
                    )?;
                    let chunk_idx = region.assign_advice(
                        || "chunk_idx",
                        self.chunk_idx,
                        i,
                        || Value::known(Fr::from(row.chunk_idx)),
                    )?;
                    let is_boundary = region.assign_advice(
                        || "is_boundary",
                        self.is_boundary,
                        i,
                        || Value::known(Fr::from(row.is_boundary as u64)),
                    )?;
                    let _is_padding = region.assign_advice(
                        || "is_padding",
                        self.is_padding,
                        i,
                        || Value::known(Fr::from(row.is_padding as u64)),
                    )?;
                    let preimage_rlc = region.assign_advice(
                        || "preimage_rlc",
                        self.preimage_rlc,
                        i,
                        || row.preimage_rlc,
                    )?;
                    let digest_rlc = region.assign_advice(
                        || "digest_rlc",
                        self.digest_rlc,
                        i,
                        || row.digest_rlc,
                    )?;
                    assigned_rows.push(AssignedBlobDataConfig {
                        byte,
                        accumulator,
                        chunk_idx,
                        is_boundary,
                        preimage_rlc,
                        digest_rlc,
                    });
                }

                Ok(assigned_rows)
            },
        )?;

        layouter.assign_region(
            || "BlobData internal checks",
            |mut region| {
                rlc_config.init(&mut region)?;
                let mut rlc_config_offset = 0;

                ////////////////////////////////////////////////////////////////////////////////
                ////////////////////////////////// NUM_CHUNKS //////////////////////////////////
                ////////////////////////////////////////////////////////////////////////////////

                let two_fifty_six = {
                    let two_fifty_six = rlc_config.load_private(
                        &mut region,
                        &Fr::from(256),
                        &mut rlc_config_offset,
                    )?;
                    let two_fifty_six_fixed = rlc_config
                        .two_hundred_and_fifty_size_cell(two_fifty_six.cell().region_index);
                    region.constrain_equal(two_fifty_six.cell(), two_fifty_six_fixed)?;
                    two_fifty_six
                };
                let rows = assigned_rows.iter().take(2).collect::<Vec<_>>();
                let (byte_hi, byte_lo, lc1, lc2) = (
                    &rows[0].byte,
                    &rows[1].byte,
                    &rows[0].accumulator,
                    &rows[1].accumulator,
                );

                // the linear combination starts with the most-significant byte.
                region.constrain_equal(byte_hi.cell(), lc1.cell())?;

                // do the linear combination.
                let num_chunks = rlc_config.mul_add(
                    &mut region,
                    lc1,
                    &two_fifty_six,
                    byte_lo,
                    &mut rlc_config_offset,
                )?;
                region.constrain_equal(num_chunks.cell(), lc2.cell())?;

                ////////////////////////////////////////////////////////////////////////////////
                ////////////////////////////////// CHUNK_SIZE //////////////////////////////////
                ////////////////////////////////////////////////////////////////////////////////

                let mut num_nonempty_chunks = {
                    let zero = rlc_config.load_private(
                        &mut region,
                        &Fr::zero(),
                        &mut rlc_config_offset,
                    )?;
                    let zero_cell = rlc_config.zero_cell(zero.cell().region_index);
                    region.constrain_equal(zero.cell(), zero_cell)?;
                    zero
                };
                let mut is_empty_chunks = Vec::with_capacity(MAX_AGG_SNARKS);
                let mut chunk_sizes = Vec::with_capacity(MAX_AGG_SNARKS);
                for i in 0..MAX_AGG_SNARKS {
                    let rows = assigned_rows
                        .iter()
                        .skip(2 + 4 * i)
                        .take(4)
                        .collect::<Vec<_>>();
                    let (byte0, byte1, byte2, byte3) =
                        (&rows[0].byte, &rows[1].byte, &rows[2].byte, &rows[3].byte);
                    let (acc0, acc1, acc2, acc3) = (
                        &rows[0].accumulator,
                        &rows[1].accumulator,
                        &rows[2].accumulator,
                        &rows[3].accumulator,
                    );

                    // the linear combination starts with the most-significant byte.
                    region.constrain_equal(byte0.cell(), acc0.cell())?;

                    // do the linear combination.
                    let lc = rlc_config.mul_add(
                        &mut region,
                        acc0,
                        &two_fifty_six,
                        byte1,
                        &mut rlc_config_offset,
                    )?;
                    region.constrain_equal(lc.cell(), acc1.cell())?;
                    let lc = rlc_config.mul_add(
                        &mut region,
                        acc1,
                        &two_fifty_six,
                        byte2,
                        &mut rlc_config_offset,
                    )?;
                    region.constrain_equal(lc.cell(), acc2.cell())?;
                    let chunk_size = rlc_config.mul_add(
                        &mut region,
                        acc2,
                        &two_fifty_six,
                        byte3,
                        &mut rlc_config_offset,
                    )?;
                    region.constrain_equal(chunk_size.cell(), acc3.cell())?;

                    let is_empty_chunk =
                        rlc_config.is_zero(&mut region, &chunk_size, &mut rlc_config_offset)?;
                    let is_nonempty_chunk =
                        rlc_config.not(&mut region, &is_empty_chunk, &mut rlc_config_offset)?;
                    num_nonempty_chunks = rlc_config.add(
                        &mut region,
                        &is_nonempty_chunk,
                        &num_nonempty_chunks,
                        &mut rlc_config_offset,
                    )?;
                    is_empty_chunks.push(is_empty_chunk);
                    chunk_sizes.push(chunk_size);
                }
                region.constrain_equal(num_nonempty_chunks.cell(), num_chunks.cell())?;

                // on the last row of the "metadata" section we want to ensure the keccak table
                // lookup would be enabled for the metadata digest
                let one = {
                    let one =
                        rlc_config.load_private(&mut region, &Fr::one(), &mut rlc_config_offset)?;
                    let one_cell = rlc_config.one_cell(one.cell().region_index);
                    region.constrain_equal(one.cell(), one_cell)?;
                    one
                };
                region.constrain_equal(
                    assigned_rows
                        .get(N_ROWS_METADATA - 1)
                        .unwrap()
                        .is_boundary
                        .cell(),
                    one.cell(),
                )?;

                ////////////////////////////////////////////////////////////////////////////////
                ////////////////////////////////// CHUNK_DATA //////////////////////////////////
                ////////////////////////////////////////////////////////////////////////////////

                // the first data row has a length (accumulator) of 1.
                let row = assigned_rows.get(N_ROWS_METADATA).unwrap();
                region.constrain_equal(row.accumulator.cell(), one.cell())?;

                let rows = assigned_rows
                    .iter()
                    .skip(N_ROWS_METADATA)
                    .take(N_ROWS_DATA)
                    .collect::<Vec<_>>();
                let mut num_lookups = {
                    let zero = rlc_config.load_private(
                        &mut region,
                        &Fr::zero(),
                        &mut rlc_config_offset,
                    )?;
                    let zero_cell = rlc_config.zero_cell(zero.cell().region_index);
                    region.constrain_equal(zero.cell(), zero_cell)?;
                    zero
                };
                // TODO: optimize this loop as each add takes 4 rows
                for row in rows.iter() {
                    num_lookups = rlc_config.add(
                        &mut region,
                        &row.is_boundary,
                        &num_lookups,
                        &mut rlc_config_offset,
                    )?;
                }
                log::debug!(
                    "rlc_config_offset after getting num_lookups: {}",
                    rlc_config_offset
                );
                region.constrain_equal(num_lookups.cell(), num_chunks.cell())?;

                ////////////////////////////////////////////////////////////////////////////////
                ////////////////////////////////// DIGEST RLC //////////////////////////////////
                ////////////////////////////////////////////////////////////////////////////////

                let rows = assigned_rows
                    .iter()
                    .skip(N_ROWS_METADATA + N_ROWS_DATA)
                    .take(N_ROWS_DIGEST_RLC)
                    .collect::<Vec<_>>();

                // rows have chunk_idx set from 0 (metadata) -> MAX_AGG_SNARKS.
                rlc_config.enforce_zero(&mut region, &rows[0].chunk_idx)?;
                let zero = {
                    let zero = rlc_config.load_private(
                        &mut region,
                        &Fr::zero(),
                        &mut rlc_config_offset,
                    )?;
                    let zero_cell = rlc_config.zero_cell(zero.cell().region_index);
                    region.constrain_equal(zero.cell(), zero_cell)?;
                    zero
                };
                let mut i_val = zero.clone();
                for row in rows.iter().skip(1).take(MAX_AGG_SNARKS) {
                    i_val = rlc_config.add(&mut region, &i_val, &one, &mut rlc_config_offset)?;
                    region.constrain_equal(i_val.cell(), row.chunk_idx.cell())?;
                }

                let r_keccak = rlc_config.read_challenge1(
                    &mut region,
                    challenge_value,
                    &mut rlc_config_offset,
                )?;
                let r_evm = rlc_config.read_challenge2(
                    &mut region,
                    challenge_value,
                    &mut rlc_config_offset,
                )?;
                // keccak_input ^ 32
                let r32 = {
                    let r2 = rlc_config.mul(
                        &mut region,
                        &r_keccak,
                        &r_keccak,
                        &mut rlc_config_offset,
                    )?;
                    let r4 = rlc_config.mul(&mut region, &r2, &r2, &mut rlc_config_offset)?;
                    let r8 = rlc_config.mul(&mut region, &r4, &r4, &mut rlc_config_offset)?;
                    let r16 = rlc_config.mul(&mut region, &r8, &r8, &mut rlc_config_offset)?;
                    rlc_config.mul(&mut region, &r16, &r16, &mut rlc_config_offset)?
                };

                // RLC of digest of empty bytes = RLC(keccak([]), r)
                let mut empty_digest_cells = Vec::with_capacity(N_BYTES_32);
                for (i, &byte) in keccak256([]).iter().enumerate() {
                    let cell = rlc_config.load_private(
                        &mut region,
                        &Fr::from(byte as u64),
                        &mut rlc_config_offset,
                    )?;
                    let fixed_cell = rlc_config.empty_keccak_cell_i(cell.cell().region_index, i);
                    region.constrain_equal(cell.cell(), fixed_cell)?;
                    empty_digest_cells.push(cell);
                }
                let empty_digest_evm_rlc = rlc_config.rlc(
                    &mut region,
                    &empty_digest_cells,
                    &r_evm,
                    &mut rlc_config_offset,
                )?;

                let blob_preimage_rlc_specified = &rows.last().unwrap().preimage_rlc;
                let blob_digest_rlc_specified = &rows.last().unwrap().digest_rlc;

                // ensure that on the last row of this section the is_boundary is turned on
                // which would enable the keccak table lookup for challenge_digest
                region.constrain_equal(rows.last().unwrap().is_boundary.cell(), one.cell())?;

                let metadata_digest_rlc_computed =
                    &assigned_rows.get(N_ROWS_METADATA - 1).unwrap().digest_rlc;
                let metadata_digest_rlc_specified = &rows.first().unwrap().digest_rlc;
                region.constrain_equal(
                    metadata_digest_rlc_computed.cell(),
                    metadata_digest_rlc_specified.cell(),
                )?;

                let mut chunk_digest_evm_rlcs = Vec::with_capacity(MAX_AGG_SNARKS);
                for ((row, chunk_size_decoded), is_empty) in rows
                    .iter()
                    .skip(1)
                    .take(MAX_AGG_SNARKS)
                    .zip_eq(chunk_sizes)
                    .zip_eq(is_empty_chunks)
                {
                    // if the chunk is empty, the chunk data digest should be the empty keccak
                    // digest.
                    rlc_config.conditional_enforce_equal(
                        &mut region,
                        &row.digest_rlc,
                        &empty_digest_evm_rlc,
                        &is_empty,
                        &mut rlc_config_offset,
                    )?;

                    // constrain chunk size specified here against decoded in metadata.
                    let chunk_size_specified = rlc_config.select(
                        &mut region,
                        &zero,
                        &row.accumulator,
                        &is_empty,
                        &mut rlc_config_offset,
                    )?;
                    region
                        .constrain_equal(chunk_size_specified.cell(), chunk_size_decoded.cell())?;

                    chunk_digest_evm_rlcs.push(&row.digest_rlc);
                }

                ////////////////////////////////////////////////////////////////////////////////
                ///////////////////////////////// DIGEST BYTES /////////////////////////////////
                ////////////////////////////////////////////////////////////////////////////////

                let mut blob_preimage_keccak_rlc = zero.clone();
                let rows = assigned_rows
                    .iter()
                    .skip(N_ROWS_METADATA + N_ROWS_DATA + N_ROWS_DIGEST_RLC)
                    .take(N_ROWS_DIGEST_BYTES)
                    .collect::<Vec<_>>();
                for (i, digest_rlc_specified) in std::iter::once(metadata_digest_rlc_specified)
                    .chain(chunk_digest_evm_rlcs)
                    .chain(std::iter::once(blob_digest_rlc_specified))
                    .enumerate()
                {
                    let digest_rows = rows
                        .iter()
                        .skip(N_BYTES_32 * i)
                        .take(N_BYTES_32)
                        .collect::<Vec<_>>();
                    let digest_bytes = digest_rows
                        .iter()
                        .map(|row| row.byte.clone())
                        .collect::<Vec<_>>();
                    let digest_rlc_computed = rlc_config.rlc(
                        &mut region,
                        &digest_bytes,
                        &r_evm,
                        &mut rlc_config_offset,
                    )?;
                    region
                        .constrain_equal(digest_rlc_computed.cell(), digest_rlc_specified.cell())?;

                    // compute the keccak input RLC:
                    // we do this only for the metadata and chunks, not for the blob row itself.
                    if i < MAX_AGG_SNARKS + 1 {
                        let digest_keccak_rlc = rlc_config.rlc(
                            &mut region,
                            &digest_bytes,
                            &r_keccak,
                            &mut rlc_config_offset,
                        )?;
                        blob_preimage_keccak_rlc = rlc_config.mul_add(
                            &mut region,
                            &blob_preimage_keccak_rlc,
                            &r32,
                            &digest_keccak_rlc,
                            &mut rlc_config_offset,
                        )?;
                    }
                }
                region.constrain_equal(
                    blob_preimage_keccak_rlc.cell(),
                    blob_preimage_rlc_specified.cell(),
                )?;

                ////////////////////////////////////////////////////////////////////////////////
                //////////////////////////////////// EXPORT ////////////////////////////////////
                ////////////////////////////////////////////////////////////////////////////////

                let mut blob_fields = Vec::with_capacity(BLOB_WIDTH);
                let blob_bytes = assigned_rows
                    .iter()
                    .take(N_ROWS_METADATA + N_ROWS_DATA)
                    .map(|row| row.byte.clone())
                    .collect::<Vec<_>>();
                for chunk in blob_bytes.chunks_exact(N_BYTES_31) {
                    blob_fields.push(chunk.to_vec());
                }
                let mut chunk_data_digests = Vec::with_capacity(MAX_AGG_SNARKS);
                let chunk_data_digests_bytes = assigned_rows
                    .iter()
                    .skip(N_ROWS_METADATA + N_ROWS_DATA + N_ROWS_DIGEST_RLC + N_BYTES_32)
                    .take(MAX_AGG_SNARKS * N_BYTES_32)
                    .map(|row| row.byte.clone())
                    .collect::<Vec<_>>();
                for chunk in chunk_data_digests_bytes.chunks_exact(N_BYTES_32) {
                    chunk_data_digests.push(chunk.to_vec());
                }
                let export = AssignedBlobDataExport {
                    blob_fields,
                    challenge_digest: assigned_rows
                        .iter()
                        .rev()
                        .take(N_BYTES_32)
                        .map(|row| row.byte.clone())
                        .collect(),
                    chunk_data_digests,
                };

                ////////////////////////////////////////////////////////////////////////////////
                //////////////////////////////////// LINKING ///////////////////////////////////
                ////////////////////////////////////////////////////////////////////////////////

                assert_eq!(barycentric_assignments.len(), BLOB_WIDTH + 1);
                let blob_crts = barycentric_assignments
                    .iter()
                    .take(BLOB_WIDTH)
                    .collect::<Vec<_>>();
                let challenge_digest_crt = barycentric_assignments
                    .get(BLOB_WIDTH)
                    .expect("challenge digest CRT");
                let powers_of_256 = std::iter::successors(Some(Ok(one)), |coeff| {
                    Some(rlc_config.mul(
                        &mut region,
                        &two_fifty_six,
                        coeff.as_ref().expect("coeff expected"),
                        &mut rlc_config_offset,
                    ))
                })
                .take(11)
                .collect::<Result<Vec<_>, Error>>()?;

                let challenge_digest_limb1 = rlc_config.inner_product(
                    &mut region,
                    &export.challenge_digest[0..11],
                    &powers_of_256[0..11],
                    &mut rlc_config_offset,
                )?;
                let challenge_digest_limb2 = rlc_config.inner_product(
                    &mut region,
                    &export.challenge_digest[11..22],
                    &powers_of_256[0..11],
                    &mut rlc_config_offset,
                )?;
                let challenge_digest_limb3 = rlc_config.inner_product(
                    &mut region,
                    &export.challenge_digest[22..32],
                    &powers_of_256[0..10],
                    &mut rlc_config_offset,
                )?;
                region.constrain_equal(
                    challenge_digest_limb1.cell(),
                    challenge_digest_crt.truncation.limbs[0].cell(),
                )?;
                region.constrain_equal(
                    challenge_digest_limb2.cell(),
                    challenge_digest_crt.truncation.limbs[1].cell(),
                )?;
                region.constrain_equal(
                    challenge_digest_limb3.cell(),
                    challenge_digest_crt.truncation.limbs[2].cell(),
                )?;
                for (blob_crt, blob_field) in blob_crts.iter().zip_eq(export.blob_fields.iter()) {
                    let limb1 = rlc_config.inner_product(
                        &mut region,
                        &blob_field[0..11],
                        &powers_of_256[0..11],
                        &mut rlc_config_offset,
                    )?;
                    let limb2 = rlc_config.inner_product(
                        &mut region,
                        &blob_field[11..22],
                        &powers_of_256[0..11],
                        &mut rlc_config_offset,
                    )?;
                    let limb3 = rlc_config.inner_product(
                        &mut region,
                        &blob_field[22..31],
                        &powers_of_256[0..9],
                        &mut rlc_config_offset,
                    )?;
                    region.constrain_equal(limb1.cell(), blob_crt.truncation.limbs[0].cell())?;
                    region.constrain_equal(limb2.cell(), blob_crt.truncation.limbs[1].cell())?;
                    region.constrain_equal(limb3.cell(), blob_crt.truncation.limbs[2].cell())?;
                }

                Ok(export)
            },
        )
    }
}