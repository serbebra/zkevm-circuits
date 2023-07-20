use halo2_proofs::halo2curves::{
    bn256::{G1Affine, G2Affine},
    group::cofactor::CofactorCurveAffine,
    serde::SerdeObject,
};
use itertools::Itertools;

use crate::{
    circuit_input_builder::{
        CircuitInputStateRef, EcPairingOp, ExecStep, PrecompileEvent, N_PAIRING_PER_OP,
    },
    precompile::{EcPairingAuxData, EcPairingError, PrecompileAuxData, PrecompileError},
};

const N_BYTES_PER_PAIR: usize = 192;

pub(crate) fn handle(
    input_bytes: Option<Vec<u8>>,
    output_bytes: Option<Vec<u8>>,
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
) {
    // assertions.
    let output_bytes = output_bytes.expect("precompile should return at least 0 on failure");
    debug_assert_eq!(output_bytes.len(), 32, "ecPairing returns EVM word: 1 or 0");
    let pairing_check = output_bytes[31];
    debug_assert!(
        pairing_check == 1 || pairing_check == 0,
        "ecPairing returns 1 or 0"
    );
    debug_assert_eq!(output_bytes.iter().take(31).sum::<u8>(), 0);
    debug_assert_eq!(input_bytes.is_none(), pairing_check == 1);

    // aux data: Result<Box<PrecompileAuxData>, PrecompileError>
    let aux_data = if let Some(input) = input_bytes {
        // if input bytes provided.
        if input.len() % N_BYTES_PER_PAIR != 0 || input.len() > N_PAIRING_PER_OP * N_BYTES_PER_PAIR
        {
            // if number of bytes provided were not what we expected.
            Err(PrecompileError::EcPairing(EcPairingError::InvalidInputSize))
        } else {
            // process input bytes.
            let res_pairs = input
                .chunks_exact(N_BYTES_PER_PAIR)
                .map(|chunk| {
                    // process 192 bytes chunk at a time.
                    // process g1.
                    let g1_bytes = std::iter::empty()
                        .chain(chunk[0x00..0x20].iter().rev())
                        .chain(chunk[0x20..0x40].iter().rev())
                        .cloned()
                        .collect_vec();
                    let g1 = G1Affine::from_raw_bytes(g1_bytes.as_slice());
                    // process g2.
                    let g2_bytes = std::iter::empty()
                        .chain(chunk[0x40..0x60].iter().rev())
                        .chain(chunk[0x60..0x80].iter().rev())
                        .chain(chunk[0x80..0xA0].iter().rev())
                        .chain(chunk[0xA0..0xC0].iter().rev())
                        .cloned()
                        .collect_vec();
                    let g2 = G2Affine::from_raw_bytes(g2_bytes.as_slice());
                    g1.zip(g2)
                        .ok_or(PrecompileError::EcPairing(EcPairingError::NotOnCurve))
                })
                .collect::<Result<Vec<(G1Affine, G2Affine)>, PrecompileError>>();
            if let Ok(mut pairs) = res_pairs {
                // pad with placeholder pairs.
                pairs.resize(
                    N_PAIRING_PER_OP,
                    (G1Affine::identity(), G2Affine::generator()),
                );
                Ok(Box::new(EcPairingAuxData(EcPairingOp {
                    inputs: <[_; N_PAIRING_PER_OP]>::try_from(pairs)
                        .expect("pairs.len() <= N_PAIRING_PER_OP"),
                    output: 1.into(),
                })))
            } else {
                Err(PrecompileError::EcPairing(EcPairingError::NotOnCurve))
            }
        }
    } else {
        // TODO: take care of insufficient gas here?
        // if no input bytes.
        let ec_pairing_op = EcPairingOp {
            inputs: [
                (G1Affine::identity(), G2Affine::generator()),
                (G1Affine::identity(), G2Affine::generator()),
                (G1Affine::identity(), G2Affine::generator()),
                (G1Affine::identity(), G2Affine::generator()),
            ],
            output: 1.into(),
        };
        Ok(Box::new(EcPairingAuxData(ec_pairing_op)))
    };

    // update step and state.
    // TODO: for now the ECC sub-circuit only handles OK cases. Once we verify invalidity of inputs
    // as well, we will also push the Err cases.
    if let Ok(ref data) = aux_data {
        state.push_precompile_event(PrecompileEvent::EcPairing(Box::new(data.0.clone())));
    }
    exec_step.aux_data = Some(PrecompileAuxData::EcPairing(aux_data));
}
