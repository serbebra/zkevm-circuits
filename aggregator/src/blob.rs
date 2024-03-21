use crate::{barycentric::interpolate, ChunkHash};
use eth_types::U256;
use ethers_core::utils::keccak256;
use halo2_proofs::halo2curves::bls12_381::Scalar;

pub const BLOB_WIDTH: usize = 4096;
pub const BYTES_PER_BLOB_ELEMENT: usize = 32;
pub const LOG_BLOG_WIDTH: usize = 12;

#[derive(Clone, Debug, Default)]
pub struct Blob(Vec<Vec<u8>>);

impl Blob {
    pub fn new(chunk_hashes: &[ChunkHash]) -> Self {
        Self(
            chunk_hashes
                .iter()
                .map(|chunk_hash| chunk_hash.tx_bytes.clone())
                .collect(),
        )
    }

    pub fn coefficients(&self) -> [U256; BLOB_WIDTH] {
        let mut le_bytes = [[0; BYTES_PER_BLOB_ELEMENT]; BLOB_WIDTH];
        for (i, byte) in self.bytes().enumerate() {
            le_bytes[i / 31][i % 31] = byte;
        }
        le_bytes.map(|bytes| U256::from_little_endian(&bytes))
    }

    pub fn challenge_point(&self) -> U256 {
        let chunk_tx_bytes_hashes = self.0.iter().flat_map(keccak256);

        let input: Vec<_> = keccak256(self.metadata_bytes().collect::<Vec<_>>())
            .into_iter()
            .chain(chunk_tx_bytes_hashes)
            .collect();

        U256::from_big_endian(&keccak256(input))
    }

    fn metadata_bytes(&self) -> impl Iterator<Item = u8> + '_ {
        let n_chunks = self.0.len();
        let chunk_lengths = self.0.iter().map(Vec::len);
        std::iter::empty()
            .chain(u16::try_from(n_chunks).unwrap().to_be_bytes())
            .chain(chunk_lengths.flat_map(|x| u32::try_from(x).unwrap().to_be_bytes()))
    }

    fn bytes(&self) -> impl Iterator<Item = u8> + '_ {
        self.metadata_bytes()
            .chain(self.0.iter().flat_map(|x| x.iter().copied()))
    }
}

#[derive(Clone, Debug)]
pub struct BlobAssignments {
    pub z: U256,
    pub challenge_digest: U256,
    pub evaluation: U256,
    pub coefficients: [U256; BLOB_WIDTH],
}

impl From<&Blob> for BlobAssignments {
    fn from(blob: &Blob) -> Self {
        let coefficients = blob.coefficients();
        let coefficients_scalar = coefficients.map(|coeff| Scalar::from_raw(coeff.0));
        let challenge_digest = blob.challenge_point();
        let bls_modulus = U256::from_str_radix(
            "52435875175126190479447740508185965837690552500527637822603658699938581184513",
            10,
        )
        .unwrap();
        let (_, z) = challenge_digest.div_mod(bls_modulus);

        Self {
            z,
            challenge_digest,
            evaluation: U256::from_little_endian(
                &interpolate(Scalar::from_raw(challenge_digest.0), coefficients_scalar).to_bytes(),
            ),
            coefficients,
        }
    }
}

impl Default for BlobAssignments {
    fn default() -> Self {
        Self {
            z: U256::default(),
            challenge_digest: U256::default(),
            evaluation: U256::default(),
            coefficients: [U256::default(); BLOB_WIDTH],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::barycentric::ROOTS_OF_UNITY;
    use reth_primitives::{
        constants::eip4844::MAINNET_KZG_TRUSTED_SETUP,
        kzg::{Blob as RethBlob, KzgProof},
    };

    #[test]
    fn empty_chunks_random_point() {
        let empty_blob = Blob::default();
        assert_eq!(
            empty_blob.challenge_point(),
            U256::from(keccak256(keccak256([0u8; 2])))
        )
    }

    #[test]
    fn zero_blob() {
        let blob = Blob::default();

        let z = Scalar::from_raw(blob.challenge_point().0);
        let y = interpolate(
            z,
            blob.coefficients().map(|coeff| Scalar::from_raw(coeff.0)),
        );

        assert_eq!(
            z,
            from_str("5873b6a7dba2cdd5b65ea27b1b6c38558a800375fbb233b7046040818a289743")
        );
        assert_eq!(y, Scalar::zero());
    }

    #[test]
    fn generic_blob() {
        let blob = Blob(vec![
            vec![30; 56],
            (0..128).collect(),
            vec![0; 340],
            vec![10, 32, 123, 13, 123, 123, 123],
            vec![14; 23],
            vec![255; 23],
        ]);

        let z = Scalar::from_raw(blob.challenge_point().0);
        let y = interpolate(
            z,
            blob.coefficients().map(|coeff| Scalar::from_raw(coeff.0)),
        );

        assert_eq!(
            z,
            from_str("624a9e56fc016794941343c48d00b77fc2088e17cb8cff5eedb437304c5faa01")
        );
        assert_eq!(
            y,
            from_str("04d2236ec4f34d2275f041273c6a0490d8f5c60100fa65e97fb7afc35efde3e7")
        );
    }

    #[test]
    fn interpolate_matches_reth_implementation() {
        let blob = Blob(vec![
            vec![30; 56],
            vec![200; 100],
            vec![0; 340],
            vec![10; 23],
        ]);

        for z in 0..10 {
            let z = Scalar::from(u64::try_from(13241234 + z).unwrap());
            assert_eq!(
                reth_point_evaluation(z, blob.coefficients().map(|c| Scalar::from_raw(c.0))),
                interpolate(z, blob.coefficients().map(|c| Scalar::from_raw(c.0)))
            );
        }
    }

    fn reth_point_evaluation(z: Scalar, coefficients: [Scalar; BLOB_WIDTH]) -> Scalar {
        let blob = RethBlob::from_bytes(
            &coefficients
                .into_iter()
                .flat_map(to_be_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let (_proof, y) =
            KzgProof::compute_kzg_proof(&blob, &to_be_bytes(z).into(), &MAINNET_KZG_TRUSTED_SETUP)
                .unwrap();
        from_canonical_be_bytes(*y)
    }

    #[test]
    fn reth_kzg_implementation() {
        // check that we are calling the reth implementation correctly
        for z in 0..10 {
            let z = Scalar::from(u64::try_from(z).unwrap());
            assert_eq!(reth_point_evaluation(z, *ROOTS_OF_UNITY), z)
        }
    }

    fn to_be_bytes(x: Scalar) -> [u8; 32] {
        let mut bytes = x.to_bytes();
        bytes.reverse();
        bytes
    }

    fn from_canonical_be_bytes(bytes: [u8; 32]) -> Scalar {
        let mut bytes = bytes;
        bytes.reverse();
        Scalar::from_bytes(&bytes).expect("non-canonical bytes")
    }

    fn from_str(x: &str) -> Scalar {
        let mut bytes: [u8; 32] = hex::decode(x)
            .expect("bad hex string")
            .try_into()
            .expect("need 32 bytes");
        bytes.reverse();
        Scalar::from_bytes(&bytes).expect("non-canonical representation")
    }

    #[test]
    fn test_be_bytes() {
        let mut be_bytes_one = [0; 32];
        be_bytes_one[31] = 1;
        assert_eq!(to_be_bytes(Scalar::one()), be_bytes_one);
    }
}
