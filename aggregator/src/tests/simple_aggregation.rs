use std::{fs, path::Path, process};

use ark_std::{end_timer, start_timer, test_rng};
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr, poly::commitment::Params};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::{halo2_proofs, utils::fs::gen_srs};
use snark_verifier_sdk::{gen_pk, gen_snark_shplonk, verify_snark_shplonk, CircuitExt};

use crate::{
    layer_0,
    simple_aggregation::SimpleAggregationCircuit, tests::mock_chunk::MockChunkCircuit,
};

#[ignore = "it takes too much time"]
#[test]
fn test_mock_simple_aggregation() {
    env_logger::init();

    if std::path::Path::new("data").is_dir() {
        println!("data folder already exists\n");
    } else {
        println!("Generating data folder used for testing\n");
        std::fs::create_dir("data").unwrap();
    }

    let dir = format!("data/{}", process::id());
    let path = Path::new(dir.as_str());
    fs::create_dir(path).unwrap();

    let k0 = 8;
    let k1 = 22;

    let mut rng = test_rng();
    let params = gen_srs(k1);

    // Proof for test circuit
    let circuit_1 = MockChunkCircuit::random(&mut rng, false, false);
    let layer_0_snark_1 = layer_0!(circuit_1, MockChunkCircuit, params, k0, path);
    let circuit_2 = MockChunkCircuit::random(&mut rng, false, false);
    let layer_0_snark_2 = layer_0!(circuit_2, MockChunkCircuit, params, k0, path);

    std::env::set_var("COMPRESSION_CONFIG", "./configs/compression_wide.config");
    // layer 1 proof compression
    {
        let param = {
            let mut param = params;
            param.downsize(k1);
            param
        };
        let compression_circuit =
            SimpleAggregationCircuit::new(&param, &[layer_0_snark_1, layer_0_snark_2], &mut rng)
                .unwrap();
        let instance = compression_circuit.instances();
        println!("instance length {:?}", instance.len());

        let mock_prover = MockProver::<Fr>::run(k1, &compression_circuit, instance).unwrap();

        mock_prover.assert_satisfied_par()
    }
}
