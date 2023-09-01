// A chain_id is u64 and uses 8 bytes
#[allow(dead_code)]
pub(crate) const CHAIN_ID_LEN: usize = 8;

// ================================
// hash parameters
// ================================

/// Digest length
pub(crate) const DIGEST_LEN: usize = 32;
/// Input length per round
pub(crate) const INPUT_LEN_PER_ROUND: usize = 136;

// TODO(ZZ): update to the right degree
#[allow(dead_code)]
pub(crate) const LOG_DEGREE: u32 = 19;

/// A list of constants that indicates how many multiples of 32 bytes
/// a given round can host
///
/// This can be generated via
///   [ceil((x*32+1)/136) for x in range(1,30)]
// 1 round:  32  ... 128 in [0,   136), can store up to 4 rounds
// 2 rounds: 160 ... 256 in [136, 272), can store up to 8 rounds
// 3 rounds: 288 ... 384 in [272, 408), can store up to 12 rounds
// 4 rounds: 416 ... 512 in [408, 544), can store up to 16 rounds
// 5 rounds: 544 ... 672 in [544, 680), can store up to 21 rounds
// 6 rounds: 704 ... 800 in [680, 816), can store up to 25 rounds
pub(crate) const KECCAK_ROUND_CONSTANTS: [u8; 6] = [4, 8, 12, 16, 21, 25];

// ================================
// indices for hash table
// ================================
//
// the preimages are arranged as
// - chain_id:          8 bytes
// - prev_state_root    32 bytes
// - post_state_root    32 bytes
// - withdraw_root      32 bytes
// - chunk_data_hash    32 bytes
//

pub(crate) const PREV_STATE_ROOT_INDEX: usize = 8;
pub(crate) const POST_STATE_ROOT_INDEX: usize = 40;
pub(crate) const WITHDRAW_ROOT_INDEX: usize = 72;
pub(crate) const CHUNK_DATA_HASH_INDEX: usize = 104;

// ================================
// aggregator parameters
// ================================

/// An decomposed accumulator consists of 12 field elements
pub(crate) const ACC_LEN: usize = 12;

/// number of limbs when decomposing a field element in the ECC chip
pub(crate) const LIMBS: usize = 3;
/// number of bits in each limb in the ECC chip
pub(crate) const BITS: usize = 88;

/// Max number of snarks to be aggregated in a chunk.
/// If the input size is less than this, dummy snarks
/// will be padded.
pub const MAX_AGG_SNARKS: usize = 29;
