use crate::{
    circuit_input_builder::{EcAddOp, PrecompileEvent},
    precompile::{EcAddAuxData, PrecompileAuxData},
};

pub(crate) fn opt_data(
    input_bytes: Option<Vec<u8>>,
    output_bytes: Option<Vec<u8>>,
) -> (Option<PrecompileEvent>, Option<PrecompileAuxData>) {
    let input_bytes = input_bytes.map_or(vec![0u8; 128], |mut bytes| {
        bytes.resize(128, 0u8);
        bytes
    });
    let output_bytes = output_bytes.map_or(vec![0u8; 64], |mut bytes| {
        bytes.resize(64, 0u8);
        bytes
    });

    let aux_data = EcAddAuxData::new(&input_bytes, &output_bytes);
    log::info!("aux data OK");
    let ec_add_op = EcAddOp::new_from_bytes(&input_bytes, &output_bytes);
    log::info!("op  data OK");

    (
        Some(PrecompileEvent::EcAdd(ec_add_op)),
        Some(PrecompileAuxData::EcAdd(aux_data)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opt_data() {
        let bytes: Vec<u8> = hex::decode("30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD4830644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD49").unwrap();
        let (a, b) = opt_data(Some(bytes), None);
        dbg!(a);
        dbg!(b);
    }
}
