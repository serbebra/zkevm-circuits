use super::{
    TargetCircuit, AUTO_TRUNCATE, CHAIN_ID, MAX_BYTECODE, MAX_CALLDATA, MAX_EXP_STEPS,
    MAX_INNER_BLOCKS, MAX_KECCAK_ROWS, MAX_MPT_ROWS, MAX_PRECOMPILE_EC_ADD, MAX_PRECOMPILE_EC_MUL,
    MAX_PRECOMPILE_EC_PAIRING, MAX_RWS, MAX_TXS,
};
use crate::config::INNER_DEGREE;
use anyhow::{bail, Result};
use bus_mapping::{
    circuit_input_builder::{
        self, BlockHead, CircuitInputBuilder, CircuitsParams, PrecompileEcParams,
    },
    state_db::{Account, CodeDB, StateDB},
};
use eth_types::{evm_types::opcode_ids::OpcodeId, ToAddress, ToBigEndian, H256};
use ethers_core::types::{Bytes, U256};
use halo2_proofs::halo2curves::bn256::Fr;
use is_even::IsEven;
use itertools::Itertools;
use mpt_zktrie::state::ZktrieState;
use std::{
    collections::{hash_map::Entry, HashMap},
    time::Instant,
};
use types::eth::{BlockTrace, EthBlock, ExecStep, StorageTrace};
use zkevm_circuits::{
    evm_circuit::witness::{block_apply_mpt_state, block_convert_with_l1_queue_index, Block},
    util::SubCircuit,
    witness::WithdrawProof,
};

// This function also mutates the block trace.
pub fn check_or_truncate_chunk_trace(block_traces: &mut Vec<BlockTrace>) -> Result<()> {
    let block_traces_len = block_traces.len();
    let total_tx_count = block_traces
        .iter()
        .map(|b| b.transactions.len())
        .sum::<usize>();
    let total_tx_len_sum = block_traces
        .iter()
        .flat_map(|b| b.transactions.iter().map(|t| t.data.len()))
        .sum::<usize>();
    log::info!(
        "check capacity of block traces, num_block {}, num_tx {}, tx total len {}",
        block_traces_len,
        total_tx_count,
        total_tx_len_sum
    );

    if block_traces_len > MAX_INNER_BLOCKS {
        bail!("too many blocks");
    }

    if !*AUTO_TRUNCATE {
        log::debug!("AUTO_TRUNCATE=false, keep batch as is");
        return Ok(());
    }

    let t = Instant::now();
    let mut acc: Vec<crate::zkevm::SubCircuitRowUsage> = Vec::new();
    let mut n_txs = 0;
    let mut truncate_idx = block_traces.len();
    for (idx, block) in block_traces.iter().enumerate() {
        let usage = calculate_row_usage_of_trace(block)?
            .into_iter()
            .map(|x| crate::zkevm::SubCircuitRowUsage {
                name: x.name,
                row_number: x.row_num_real,
            })
            .collect_vec();
        if acc.is_empty() {
            acc = usage.clone();
        } else {
            acc.iter_mut().zip(usage.iter()).for_each(|(acc, usage)| {
                acc.row_number += usage.row_number;
            });
        }
        let rows: usize = itertools::max(acc.iter().map(|x| x.row_number)).unwrap();
        log::debug!(
            "row usage after block {}({:?}): {}, {:?}",
            idx,
            block.header.number,
            rows,
            usage
        );
        n_txs += block.transactions.len();
        if rows > (1 << *INNER_DEGREE) - 256 || n_txs > MAX_TXS {
            log::warn!(
                "truncate blocks [{}..{}), n_txs {}, rows {}",
                idx,
                block_traces_len,
                n_txs,
                rows
            );
            truncate_idx = idx;
            break;
        }
    }
    log::debug!("check_batch_capacity takes {:?}", t.elapsed());
    block_traces.truncate(truncate_idx);
    let total_tx_count2 = block_traces
        .iter()
        .map(|b| b.transactions.len())
        .sum::<usize>();
    if total_tx_count != 0 && total_tx_count2 == 0 {
        // the circuit cannot even prove the first non-empty block...
        bail!("circuit capacity not enough");
    }
    Ok(())
}

pub fn fill_zktrie_state_from_proofs(
    zktrie_state: &mut ZktrieState,
    block_traces: &[BlockTrace],
    light_mode: bool,
) -> Result<()> {
    log::debug!(
        "building partial statedb, old root {}, light_mode {}",
        hex::encode(zktrie_state.root()),
        light_mode
    );
    let account_proofs = block_traces.iter().flat_map(|block| {
        log::trace!("account proof for block {:?}:", block.header.number);
        block.storage_trace.proofs.iter().flat_map(|kv_map| {
            kv_map
                .iter()
                .map(|(k, bts)| (k, bts.iter().map(Bytes::as_ref)))
        })
    });
    let storage_proofs = block_traces.iter().flat_map(|block| {
        log::trace!("storage proof for block {:?}:", block.header.number);
        block
            .storage_trace
            .storage_proofs
            .iter()
            .flat_map(|(k, kv_map)| {
                kv_map
                    .iter()
                    .map(move |(sk, bts)| (k, sk, bts.iter().map(Bytes::as_ref)))
            })
    });
    let additional_proofs = block_traces.iter().flat_map(|block| {
        log::trace!("storage proof for block {:?}:", block.header.number);
        log::trace!("additional proof for block {:?}:", block.header.number);
        block
            .storage_trace
            .deletion_proofs
            .iter()
            .map(Bytes::as_ref)
    });
    zktrie_state.update_statedb_from_proofs(
        account_proofs.clone(),
        storage_proofs.clone(),
        additional_proofs.clone(),
    )?;
    if !light_mode {
        zktrie_state.update_nodes_from_proofs(account_proofs, storage_proofs, additional_proofs)?;
    }
    log::debug!(
        "building partial statedb done, root {}",
        hex::encode(zktrie_state.root())
    );
    Ok(())
}

pub fn block_traces_to_witness_block(block_traces: &[BlockTrace]) -> Result<Block<Fr>> {
    let block_num = block_traces.len();
    let total_tx_num = block_traces
        .iter()
        .map(|b| b.transactions.len())
        .sum::<usize>();
    if total_tx_num > MAX_TXS {
        bail!(
            "tx num overflow {}, block range {} to {}",
            total_tx_num,
            block_traces[0].header.number.unwrap(),
            block_traces[block_num - 1].header.number.unwrap()
        );
    }
    log::info!(
        "block_traces_to_witness_block, block num {}, tx num {}",
        block_num,
        total_tx_num,
    );
    for block_trace in block_traces {
        log::debug!("start_l1_queue_index: {}", block_trace.start_l1_queue_index,);
    }
    let old_root = if block_traces.is_empty() {
        eth_types::Hash::zero()
    } else {
        block_traces[0].storage_trace.root_before
    };
    let mut state = ZktrieState::construct(old_root);
    fill_zktrie_state_from_proofs(&mut state, block_traces, false)?;
    block_traces_to_witness_block_with_updated_state(block_traces, &mut state, false)
}

pub fn block_traces_to_padding_witness_block(block_traces: &[BlockTrace]) -> Result<Block<Fr>> {
    log::debug!(
        "block_traces_to_padding_witness_block, input len {:?}",
        block_traces.len()
    );
    let chain_id = block_traces
        .iter()
        .map(|block_trace| block_trace.chain_id)
        .next()
        .unwrap_or(*CHAIN_ID);
    if *CHAIN_ID != chain_id {
        bail!(
            "CHAIN_ID env var is wrong. chain id in trace {chain_id}, CHAIN_ID {}",
            *CHAIN_ID
        );
    }
    let old_root = if block_traces.is_empty() {
        eth_types::Hash::zero()
    } else {
        block_traces[0].storage_trace.root_before
    };
    let mut state = ZktrieState::construct(old_root);
    fill_zktrie_state_from_proofs(&mut state, block_traces, false)?;

    // the only purpose here it to get the updated zktrie state
    let prev_witness_block =
        block_traces_to_witness_block_with_updated_state(block_traces, &mut state, false)?;

    // TODO: when prev_witness_block.tx.is_empty(), the `withdraw_proof` here should be a subset of
    // storage proofs of prev block
    let storage_trace = normalize_withdraw_proof(&prev_witness_block.mpt_updates.withdraw_proof);
    storage_trace_to_padding_witness_block(storage_trace)
}

pub fn block_traces_to_witness_block_with_updated_state(
    block_traces: &[BlockTrace],
    zktrie_state: &mut ZktrieState,
    light_mode: bool, // light_mode used in row estimation
) -> Result<Block<Fr>> {
    let chain_id = block_traces
        .iter()
        .map(|block_trace| block_trace.chain_id)
        .next()
        .unwrap_or(*CHAIN_ID);
    let start_l1_queue_index = block_traces
        .iter()
        .map(|block_trace| block_trace.start_l1_queue_index)
        .next()
        .unwrap_or(0);
    if *CHAIN_ID != chain_id {
        bail!(
            "CHAIN_ID env var is wrong. chain id in trace {chain_id}, CHAIN_ID {}",
            *CHAIN_ID
        );
    }

    let mut state_db: StateDB = zktrie_state.state().clone();

    let (zero_coinbase_exist, _) = state_db.get_account(&Default::default());
    if !zero_coinbase_exist {
        state_db.set_account(&Default::default(), Account::zero());
    }

    let code_db = build_codedb(&state_db, block_traces)?;
    let circuit_params = CircuitsParams {
        max_evm_rows: MAX_RWS,
        max_rws: MAX_RWS,
        max_copy_rows: MAX_RWS,
        max_txs: MAX_TXS,
        max_calldata: MAX_CALLDATA,
        max_bytecode: MAX_BYTECODE,
        max_inner_blocks: MAX_INNER_BLOCKS,
        max_keccak_rows: MAX_KECCAK_ROWS,
        max_exp_steps: MAX_EXP_STEPS,
        max_mpt_rows: MAX_MPT_ROWS,
        max_rlp_rows: MAX_CALLDATA,
        max_ec_ops: PrecompileEcParams {
            ec_add: MAX_PRECOMPILE_EC_ADD,
            ec_mul: MAX_PRECOMPILE_EC_MUL,
            ec_pairing: MAX_PRECOMPILE_EC_PAIRING,
        },
    };
    let mut builder_block = circuit_input_builder::Block::from_headers(&[], circuit_params);
    builder_block.chain_id = chain_id;
    builder_block.prev_state_root = U256::from(zktrie_state.root());
    let mut builder = CircuitInputBuilder::new(state_db.clone(), code_db, &builder_block);
    for (idx, block_trace) in block_traces.iter().enumerate() {
        let is_last = idx == block_traces.len() - 1;
        let eth_block: EthBlock = block_trace.clone().into();

        let mut geth_trace = Vec::new();
        for result in &block_trace.execution_results {
            geth_trace.push(result.into());
        }
        // TODO: Get the history_hashes.
        let mut header = BlockHead::new_with_l1_queue_index(
            chain_id,
            block_trace.start_l1_queue_index,
            Vec::new(),
            &eth_block,
        )?;
        // override zeroed minder field with additional "coinbase" field in blocktrace
        if let Some(address) = block_trace.coinbase.address {
            header.coinbase = address;
        }
        let block_num = header.number.as_u64();
        builder.block.start_l1_queue_index = block_trace.start_l1_queue_index;
        builder.block.headers.insert(block_num, header);
        builder.handle_block_inner(&eth_block, geth_trace.as_slice(), false, is_last)?;
        log::debug!("handle_block_inner done for block {:?}", block_num);
        let per_block_metric = false;
        if per_block_metric {
            let t = Instant::now();
            let block = block_convert_with_l1_queue_index::<Fr>(
                &builder.block,
                &builder.code_db,
                block_trace.start_l1_queue_index,
            )?;
            log::debug!("block convert time {:?}", t.elapsed());
            let rows = <super::SuperCircuit as TargetCircuit>::Inner::min_num_rows_block(&block);
            log::debug!(
                "after block {}, tx num {:?}, tx len sum {}, rows needed {:?}. estimate time: {:?}",
                idx,
                builder.block.txs().len(),
                builder
                    .block
                    .txs()
                    .iter()
                    .map(|t| t.input.len())
                    .sum::<usize>(),
                rows,
                t.elapsed()
            );
        }
    }

    builder.set_value_ops_call_context_rwc_eor();
    builder.set_end_block()?;

    log::debug!("converting builder.block to witness block");
    let mut witness_block =
        block_convert_with_l1_queue_index(&builder.block, &builder.code_db, start_l1_queue_index)?;
    log::debug!(
        "witness_block built with circuits_params {:?}",
        witness_block.circuits_params
    );

    if !light_mode && zktrie_state.root() != &[0u8; 32] {
        log::debug!("block_apply_mpt_state");
        block_apply_mpt_state(&mut witness_block, zktrie_state);
        log::debug!("block_apply_mpt_state done");
    }
    zktrie_state.set_state(builder.sdb.clone());
    log::debug!(
        "finish replay trie updates, root {}",
        hex::encode(zktrie_state.root())
    );
    Ok(witness_block)
}

pub fn build_codedb(sdb: &StateDB, blocks: &[BlockTrace]) -> Result<CodeDB> {
    let mut cdb = CodeDB::new();
    log::debug!("building codedb");

    cdb.insert(Vec::new());

    for block in blocks.iter().rev() {
        log::debug!("build_codedb for block {:?}", block.header.number);
        for (er_idx, execution_result) in block.execution_results.iter().enumerate() {
            if let Some(bytecode) = &execution_result.byte_code {
                let bytecode = decode_bytecode(bytecode)?.to_vec();

                let code_hash = execution_result
                    .to
                    .as_ref()
                    .and_then(|t| t.poseidon_code_hash)
                    .unwrap_or_else(|| CodeDB::hash(&bytecode));
                let code_hash = if code_hash.is_zero() {
                    CodeDB::hash(&bytecode)
                } else {
                    code_hash
                };
                if let Entry::Vacant(e) = cdb.0.entry(code_hash) {
                    e.insert(bytecode);
                    //log::debug!("inserted tx bytecode {:?} {:?}", code_hash, hash);
                }
                if execution_result.account_created.is_none() {
                    //assert_eq!(Some(hash), execution_result.code_hash);
                }
            }

            for step in execution_result.exec_steps.iter().rev() {
                if let Some(data) = &step.extra_data {
                    match step.op {
                        OpcodeId::CALL
                        | OpcodeId::CALLCODE
                        | OpcodeId::DELEGATECALL
                        | OpcodeId::STATICCALL => {
                            let code_idx = if block.transactions[er_idx].to.is_none() {
                                0
                            } else {
                                1
                            };
                            let callee_code = data.get_code_at(code_idx);
                            if callee_code.is_none() {
                                bail!("invalid trace: cannot get code of call: {:?}", step);
                            }
                            let code_hash = match step.op {
                                OpcodeId::CALL | OpcodeId::CALLCODE => data.get_code_hash_at(1),
                                OpcodeId::STATICCALL => data.get_code_hash_at(0),
                                _ => None,
                            };
                            trace_code(&mut cdb, code_hash, callee_code.unwrap(), step, sdb, 1);
                        }
                        OpcodeId::CREATE | OpcodeId::CREATE2 => {
                            // notice we do not need to insert code for CREATE,
                            // bustmapping do this job
                        }
                        OpcodeId::EXTCODESIZE | OpcodeId::EXTCODECOPY => {
                            let code = data.get_code_at(0);
                            if code.is_none() {
                                bail!("invalid trace: cannot get code of ext: {:?}", step);
                            }
                            trace_code(&mut cdb, None, code.unwrap(), step, sdb, 0);
                        }

                        _ => {}
                    }
                }
            }
        }
    }

    log::debug!("building codedb done");
    for (k, v) in &cdb.0 {
        assert!(!k.is_zero());
        log::trace!("codedb codehash {:?}, len {}", k, v.len());
    }
    Ok(cdb)
}
