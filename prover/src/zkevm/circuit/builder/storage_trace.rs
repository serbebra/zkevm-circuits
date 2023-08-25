use super::{
    CHAIN_ID
};
use anyhow::{Result};
use eth_types::{ToBigEndian, H256};
use halo2_proofs::halo2curves::bn256::Fr;
use mpt_zktrie::state::ZktrieState;
use std::{
    collections::{HashMap},
};
use types::eth::{BlockTrace, StorageTrace};
use zkevm_circuits::{
    evm_circuit::witness::{Block},
    witness::WithdrawProof,
};

pub fn storage_trace_to_padding_witness_block(storage_trace: StorageTrace) -> Result<Block<Fr>> {
    log::debug!(
        "withdraw proof {}",
        serde_json::to_string_pretty(&storage_trace)?
    );

    let mut state = ZktrieState::construct(storage_trace.root_before);
    let dummy_chunk_traces = vec![BlockTrace {
        chain_id: *CHAIN_ID,
        storage_trace,
        ..Default::default()
    }];
    fill_zktrie_state_from_proofs(&mut state, &dummy_chunk_traces, false)?;
    block_traces_to_witness_block_with_updated_state(&[], &mut state, false)
}

pub fn normalize_withdraw_proof(proof: &WithdrawProof) -> StorageTrace {
    let address = *bus_mapping::l2_predeployed::message_queue::ADDRESS;
    let key = *bus_mapping::l2_predeployed::message_queue::WITHDRAW_TRIE_ROOT_SLOT;
    StorageTrace {
        // Not typo! We are preparing `StorageTrace` for the dummy padding chunk
        // So `post_state_root` of prev chunk will be `root_before` for new chunk
        root_before: H256::from(proof.state_root.to_be_bytes()),
        root_after: H256::from(proof.state_root.to_be_bytes()),
        proofs: Some(HashMap::from([(
            address,
            proof
                .account_proof
                .iter()
                .map(|b| b.clone().into())
                .collect(),
        )])),
        storage_proofs: HashMap::from([(
            address,
            HashMap::from([(
                key,
                proof
                    .storage_proof
                    .iter()
                    .map(|b| b.clone().into())
                    .collect(),
            )]),
        )]),
        deletion_proofs: Default::default(),
    }
}
