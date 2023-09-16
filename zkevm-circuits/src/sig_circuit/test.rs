use eth_types::{
    sign_types::{sign, SignData},
    Field,
};
use halo2_proofs::{
    arithmetic::Field as HaloField,
    dev::MockProver,
    halo2curves::{
        bn256::Fr,
        group::Curve,
        secp256k1::{self, Secp256k1Affine},
    },
};
use rand::{Rng, RngCore};
use std::marker::PhantomData;

use crate::sig_circuit::SigCircuit;

#[test]
fn test_edge_cases() {
    use super::utils::LOG_TOTAL_NUM_ROWS;
    use eth_types::{
        sign_types::{biguint_to_32bytes_le, recover_pk, SECP256K1_Q},
        word, ToBigEndian, ToLittleEndian, Word,
    };
    use halo2_proofs::halo2curves::{group::ff::PrimeField, secp256k1::Fq};
    use num::{BigUint, Integer};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use snark_verifier::util::arithmetic::PrimeCurveAffine;

    let mut rng = XorShiftRng::seed_from_u64(1);

    // helper
    let to_sig = |(r, s, v): (Word, Word, u8)| -> (Fq, Fq, u8) {
        (
            Fq::from_bytes(&r.to_le_bytes()).unwrap(),
            Fq::from_bytes(&s.to_le_bytes()).unwrap(),
            v,
        )
    };

    // Vec<(msg_hash, r, s, v)>
    //
    // good data for ecrecover is (big-endian):
    // - msg_hash: 0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3
    // - r: 0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608
    // - s: 0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada
    // - v: 28, i.e. v == 1 for sig circuit
    let good_ecrecover_data = (
        word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"),
        word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"),
        word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"),
        1u8,
    );
    let ecrecover_data = vec![
        (
            word!("0xbf8b1c970c00aaee95d14297775b60c4cb81ba60a98eed616b4c3827efdf7c1f"),
            word!("0x9257255cbe0feb4887f6c9183f97b3e2104bc4534d7443734a479be147bd7565"),
            word!("0x77891e2ac09ed1bd3a9a71b75886decd469ab0850b44fc6ab0a786128d8b4675"),
            1u8,
        ),
        (
            word!("0x571b659b539a9da729fca1f2efdd8b07d6a7042e0640ac5ce3a8c5e3445523d7"),
            word!("0x5d14c6d7824ddecc43d307891c4fae49307e370f827fae93e014796665705800"),
            word!("0x6b0c5c6fb456b976d50eb155a6a15c9e9e93c4afa99d4cad4d86f4ba0cc175fd"),
            1u8,
        ),
        (
            word!("0x723dc59107206ce630dd06cd8255e37c008e09d975fc9abae242baea938d4e10"),
            word!("0xe6252f1746377abadfcef2006a6691908249b0d5f40a85f154e8e7889147e799"),
            word!("0x42afbe6922469e4c9c4cd153de7c62c4f2b15f5c566f3b6c4f190d1b7bc2e880"),
            1u8,
        ),
        (
            word!("0x02a091ae82cec2dd9fba5b896ddb84993911d3b0a4e384215611404640283810"),
            word!("0x75ad626aaaa03dbec5aeff7e8a0385db304ca0a42abf5f82b37faf0732b3caf9"),
            word!("0x0876b7bf2490a27387b1ec15548dc7853075f77bdff2533290a0515ac9159d04"),
            0u8,
        ),
        (
            word!("0x78316e682c7fadcddcc5f0bd605fdbd7d298d28dbde406b1034ccbf4bc657f49"),
            word!("0x41710bb0ec56cc1c1ed1a2d5f087a84972f6f881e1d710e4fdec6bca55b2ce0b"),
            word!("0x355ac68eb223986c7396170b119c6a92d48b6f86b7ce798afd168563ffa92371"),
            1u8,
        ),
        (
            word!("0x254e4d6aee7126aec44aecc77cb07a2121b0f6285770ccdcd734c9c61361a2c6"),
            word!("0xe02b1cbeacb541f488ad5c0176534fd78973aff2380aadc856841953b001a0e0"),
            word!("0x6b9248d0b2e85ee57e8b71bd92825b900bd3025a0ffcfff5d5b90bc4b891d852"),
            1u8,
        ),
        (
            word!("0xfeb09775634a8b9eb6d15f8858430ef452562e44028bd0b957bd5333d1ca4361"),
            word!("0x0f54d9f839cda418b20da71a40320a5c88b258c3e27dc8c4f5f2d88d3b2637bc"),
            word!("0x4778d4ff9d5e0dc0cdabf05cb43fca3184141ee0eab8ccdc88a60b566e62e6f7"),
            0u8,
        )
    
    ];
    let signatures = ecrecover_data
        .iter()
        .map(|&(msg_hash, r, s, v)| SignData {
            signature: to_sig((r, s, v)),
            pk: recover_pk(v, &r, &s, &msg_hash.to_be_bytes())
                .unwrap_or(Secp256k1Affine::identity()),
            msg_hash: {
                let msg_hash = BigUint::from_bytes_be(&msg_hash.to_be_bytes());
                let msg_hash = msg_hash.mod_floor(&*SECP256K1_Q);
                let msg_hash_le = biguint_to_32bytes_le(msg_hash);
                secp256k1::Fq::from_repr(msg_hash_le).unwrap()
            },
            ..Default::default()
        })
        .collect();
    log::debug!("signatures=");
    log::debug!("{:#?}", signatures);

    run::<Fr>(LOG_TOTAL_NUM_ROWS as u32, 7, signatures);
}

#[test]
fn sign_verify() {
    use super::utils::LOG_TOTAL_NUM_ROWS;
    use crate::sig_circuit::utils::MAX_NUM_SIG;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use sha3::{Digest, Keccak256};
    let mut rng = XorShiftRng::seed_from_u64(1);

    // msg_hash == 0
    {
        log::debug!("testing for msg_hash = 0");
        let mut signatures = Vec::new();

        let (sk, pk) = gen_key_pair(&mut rng);
        let msg = gen_msg(&mut rng);
        let msg_hash = secp256k1::Fq::zero();
        let (r, s, v) = sign_with_rng(&mut rng, sk, msg_hash);
        signatures.push(SignData {
            signature: (r, s, v),
            pk,
            msg: msg.into(),
            msg_hash,
        });

        let k = LOG_TOTAL_NUM_ROWS as u32;
        run::<Fr>(k, 1, signatures);

        log::debug!("end of testing for msg_hash = 0");
    }
    // msg_hash == 1
    {
        log::debug!("testing for msg_hash = 1");
        let mut signatures = Vec::new();

        let (sk, pk) = gen_key_pair(&mut rng);
        let msg = gen_msg(&mut rng);
        let msg_hash = secp256k1::Fq::one();
        let (r, s, v) = sign_with_rng(&mut rng, sk, msg_hash);
        signatures.push(SignData {
            signature: (r, s, v),
            pk,
            msg: msg.into(),
            msg_hash,
        });

        let k = LOG_TOTAL_NUM_ROWS as u32;
        run::<Fr>(k, 1, signatures);

        log::debug!("end of testing for msg_hash = 1");
    }
    // random msg_hash
    let max_sigs = [1, 16, MAX_NUM_SIG];
    for max_sig in max_sigs.iter() {
        log::debug!("testing for {} signatures", max_sig);
        let mut signatures = Vec::new();
        for _ in 0..*max_sig {
            let (sk, pk) = gen_key_pair(&mut rng);
            let msg = gen_msg(&mut rng);
            let msg_hash: [u8; 32] = Keccak256::digest(&msg)
                .as_slice()
                .to_vec()
                .try_into()
                .expect("hash length isn't 32 bytes");
            let msg_hash = secp256k1::Fq::from_bytes(&msg_hash).unwrap();
            let (r, s, v) = sign_with_rng(&mut rng, sk, msg_hash);
            signatures.push(SignData {
                signature: (r, s, v),
                pk,
                msg: msg.into(),
                msg_hash,
            });
        }

        let k = LOG_TOTAL_NUM_ROWS as u32;
        run::<Fr>(k, *max_sig, signatures);

        log::debug!("end of testing for {} signatures", max_sig);
    }
}

// Generate a test key pair
fn gen_key_pair(rng: impl RngCore) -> (secp256k1::Fq, Secp256k1Affine) {
    // generate a valid signature
    let generator = Secp256k1Affine::generator();
    let sk = secp256k1::Fq::random(rng);
    let pk = generator * sk;
    let pk = pk.to_affine();

    (sk, pk)
}

// Generate a test message hash
fn gen_msg_hash(rng: impl RngCore) -> secp256k1::Fq {
    secp256k1::Fq::random(rng)
}

// Generate a test message.
fn gen_msg(mut rng: impl RngCore) -> Vec<u8> {
    let msg_len: usize = rng.gen_range(0..128);
    let mut msg = vec![0; msg_len];
    rng.fill_bytes(&mut msg);
    msg
}

// Returns (r, s, v)
fn sign_with_rng(
    rng: impl RngCore,
    sk: secp256k1::Fq,
    msg_hash: secp256k1::Fq,
) -> (secp256k1::Fq, secp256k1::Fq, u8) {
    let randomness = secp256k1::Fq::random(rng);
    sign(randomness, sk, msg_hash)
}

fn run<F: Field>(k: u32, max_verif: usize, signatures: Vec<SignData>) {
    // SignVerifyChip -> ECDSAChip -> MainGate instance column
    let circuit = SigCircuit::<Fr> {
        max_verif,
        signatures,
        _marker: PhantomData,
    };

    let prover = match MockProver::run(k, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{e:#?}"),
    };
    assert_eq!(prover.verify(), Ok(()));
}
