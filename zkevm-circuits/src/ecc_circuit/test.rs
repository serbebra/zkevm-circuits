use std::marker::PhantomData;

use bus_mapping::circuit_input_builder::{EcAddOp, EcMulOp, EcPairingOp, PrecompileEcParams};
use eth_types::Field;
use halo2_proofs::dev::MockProver;

use crate::ecc_circuit::EccCircuit;

fn run<F: Field>(
    k: u32,
    max_ec_ops: PrecompileEcParams,
    add_ops: Vec<EcAddOp>,
    mul_ops: Vec<EcMulOp>,
    pairing_ops: Vec<EcPairingOp>,
) {
    let circuit = EccCircuit::<F> {
        max_add_ops: max_ec_ops.ec_add,
        max_mul_ops: max_ec_ops.ec_mul,
        max_pairing_ops: max_ec_ops.ec_pairing,
        add_ops,
        mul_ops,
        pairing_ops,
        _marker: PhantomData,
    };

    let prover = match MockProver::run(k, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    log::info!("prover was run OK");
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_ecc_circuit() {
    use halo2_proofs::halo2curves::bn256::Fr;
    run::<Fr>(
        20,
        PrecompileEcParams {
            ec_add: 2,
            ec_mul: 2,
            ec_pairing: 0,
        },
        vec![],
        vec![],
        vec![],
    )
}
