use std::{fs, path::Path, process};

use ark_std::{end_timer, start_timer, test_rng};
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr, poly::commitment::Params};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::{
    gates::circuit::CircuitBuilderStage, halo2_proofs, utils::fs::gen_srs,
};
use snark_verifier_sdk::{
    evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier},
    gen_pk,
    halo2::{gen_snark_shplonk, verify_snark_shplonk},
    CircuitExt,
};

use crate::{
    layer_0, tests::mock_chunk::MockChunkCircuit, AccScheme, CompressionCircuit, ConfigParams,
};

#[ignore = "it takes too much time"]
#[test]
fn test_mock_compression() {
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
    let circuit = MockChunkCircuit::random(&mut rng, false, false);
    let layer_0_snark = layer_0!(circuit, MockChunkCircuit, params, k0, path);

    std::env::set_var("COMPRESSION_CONFIG", "./configs/compression_wide.config");
    // layer 1 proof compression
    {
        let param = {
            let mut param = params;
            param.downsize(k1);
            param
        };
        let compression_circuit = CompressionCircuit::new(
            CircuitBuilderStage::Keygen,
            &ConfigParams::default_compress_wide_param(),
            &param,
            layer_0_snark,
        )
        .unwrap();
        let instance = compression_circuit.instances();
        println!("instance length {:?}", instance.len());

        let mock_prover = MockProver::<Fr>::run(k1, &compression_circuit, instance).unwrap();

        mock_prover.assert_satisfied_par()
    }
}

// This test takes about 1 hour on CPU
#[ignore = "it takes too much time"]
#[test]
fn test_two_layer_proof_compression() {
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

    let k0 = 19;
    let k1 = 25;
    let k2 = 25;

    let mut rng = test_rng();
    let layer_2_params = gen_srs(k2);

    // layer 0
    let circuit = MockChunkCircuit::random(&mut rng, false, false);
    let layer_0_snark = layer_0!(circuit, MockChunkCircuit, layer_2_params, k0, path);

    // layer 1
    let layer_1_snark = {
        let timer = start_timer!(|| format!("gen layer {} snark", 1));

        let param = {
            let mut param = layer_2_params.clone();
            param.downsize(k1);
            param
        };

        let mut rng = test_rng();

        let compression_circuit = CompressionCircuit::new(
            CircuitBuilderStage::Keygen,
            &ConfigParams::default_compress_wide_param(),
            &param,
            layer_0_snark.clone(),
        )
        .unwrap();

        let pk = gen_pk(&param, &compression_circuit, None);
        let break_points = compression_circuit.break_points();

        let compression_circuit = CompressionCircuit::new(
            CircuitBuilderStage::Prover,
            &ConfigParams::default_compress_wide_param(),
            &param,
            layer_0_snark.clone(),
        )
        .unwrap()
        .use_break_points(break_points.clone());

        // build the snark for next layer
        let snark = gen_snark_shplonk(
            &param,
            &pk,
            compression_circuit.clone(),
            &mut rng,
            None::<String>, // Some(&$path.join(Path::new("layer_1.snark"))),
        );
        log::trace!("finished layer {} snark generation for circuit", 1);

        assert!(verify_snark_shplonk::<CompressionCircuit>(
            &param,
            snark.clone(),
            pk.get_vk()
        ));

        end_timer!(timer);
        snark
    };

    // layer 2
    {
        let timer = start_timer!(|| format!("gen layer {} snark", 2));

        let param = layer_2_params;

        let mut rng = test_rng();

        let compression_circuit = CompressionCircuit::new(
            CircuitBuilderStage::Keygen,
            &ConfigParams::_compress_thin_param(),
            &param,
            layer_1_snark.clone(),
        )
        .unwrap();

        let pk = gen_pk(&param, &compression_circuit, None);
        let break_points = compression_circuit.break_points();

        let compression_circuit = CompressionCircuit::new(
            CircuitBuilderStage::Prover,
            &ConfigParams::default_compress_wide_param(),
            &param,
            layer_1_snark.clone(),
        )
        .unwrap()
        .use_break_points(break_points.clone());

        let instances = compression_circuit.instances();

        // build the snark for next layer
        let proof = gen_evm_proof_shplonk(
            &param,
            &pk,
            compression_circuit.clone(),
            instances.clone(),
            &mut rng,
        );
        log::trace!("finished layer {} snark generation for circuit", 1);

        let deployment_code = gen_evm_verifier::<CompressionCircuit, AccScheme>(
            &param,
            pk.get_vk(),
            compression_circuit.num_instance(),
            None,
        );

        println!("finished bytecode generation");
        evm_verify(deployment_code, instances, proof);
        end_timer!(timer);
    }
}
