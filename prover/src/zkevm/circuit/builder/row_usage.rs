use crate::zkevm::circuit::{
    TargetCircuit, SuperCircuit,
};
use anyhow::{Result};
use halo2_proofs::halo2curves::bn256::Fr;
use types::eth::{BlockTrace};
use zkevm_circuits::{
    evm_circuit::witness::{Block},
};

// TODO: optimize it later
pub fn calculate_row_usage_of_trace(
    block_trace: &BlockTrace,
) -> Result<Vec<zkevm_circuits::super_circuit::SubcircuitRowUsage>> {
    let witness_block = block_traces_to_witness_block(std::slice::from_ref(block_trace))?;
    calculate_row_usage_of_witness_block(&witness_block)
}

pub fn calculate_row_usage_of_witness_block(
    witness_block: &Block<Fr>,
) -> Result<Vec<zkevm_circuits::super_circuit::SubcircuitRowUsage>> {
    let rows = <SuperCircuit as TargetCircuit>::Inner::min_num_rows_block_subcircuits(
        witness_block,
    );

    log::debug!(
        "row usage of block {:?}, tx num {:?}, tx calldata len sum {}, rows needed {:?}",
        witness_block
            .context
            .ctxs
            .first_key_value()
            .map_or(0.into(), |(_, ctx)| ctx.number),
        witness_block.txs.len(),
        witness_block
            .txs
            .iter()
            .map(|t| t.call_data_length)
            .sum::<usize>(),
        rows,
    );
    Ok(rows)
}
