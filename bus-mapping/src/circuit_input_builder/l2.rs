use mpt_zktrie::state::{ZktrieState, AccountData, StorageData};
use crate::state_db::{self, CodeDB, StateDB};
use crate::circuit_input_builder::{self, CircuitInputBuilder, CircuitsParams};
use ethers_core::types::{Bytes, U256};
use eth_types::{
    self,
    l2_types::{BlockTrace, ExecStep, EthBlock},
    evm_types::OpcodeId,
    geth_types,
    sign_types::{pk_bytes_le, pk_bytes_swap_endianness, SignData},
    ToAddress, Address, GethExecStep, GethExecTrace, ToBigEndian, ToWord, Word, H256,
};
use std::{
    collections::{hash_map::Entry, HashMap},
};

impl From<&AccountData> for state_db::Account {

    fn from(acc_data: &AccountData) -> Self {
        Self {
            nonce: acc_data.nonce.into(),
            balance: acc_data.balance,
            code_hash: acc_data.poseidon_code_hash,
            keccak_code_hash: acc_data.keccak_code_hash,
            code_size: acc_data.code_size.into(),
            storage: Default::default(),            
        }
    }
}

impl From<&ZktrieState> for StateDB {

    fn from(mpt_state: &ZktrieState) -> Self {

        let mut sdb = StateDB::new();

        for (addr, acc) in mpt_state.state() {
            sdb.set_account(addr, acc.into())
        }

        for (storage_key, data) in mpt_state.storage() {
            //TODO: add an warning on non-existed account?
            let (_, acc) = sdb.get_account_mut(&storage_key.0);
            acc.storage.insert(*&storage_key.1, *data.as_ref());
        }

        sdb
    }    
}

fn decode_bytecode(bytecode: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let mut stripped = if let Some(stripped) = bytecode.strip_prefix("0x") {
        stripped.to_string()
    } else {
        bytecode.to_string()
    };

    let bytecode_len = stripped.len() as u64;
    if (bytecode_len & 1) != 0 {
        stripped = format!("0{stripped}");
    }

    hex::decode(stripped)
}

fn trace_code(
    cdb: &mut CodeDB,
    code_hash: Option<H256>,
    code: Bytes,
    step: &ExecStep,
    sdb: &StateDB,
    stack_pos: usize,
) {
    // first, try to read from sdb
    let stack = step
        .stack
        .as_ref()
        .expect("should have stack in call context");
    let addr = stack[stack.len() - stack_pos - 1].to_address(); //stack N-stack_pos

    let code_hash = code_hash.or_else(|| {
        let (_existed, acc_data) = sdb.get_account(&addr);
        if acc_data.code_hash != CodeDB::empty_code_hash() && !code.is_empty() {
            // they must be same
            Some(acc_data.code_hash)
        } else {
            // let us re-calculate it
            None
        }
    });
    let code_hash = match code_hash {
        Some(code_hash) => {
            if code_hash.is_zero() {
                CodeDB::hash(&code)
            } else {
                if log::log_enabled!(log::Level::Trace) {
                    assert_eq!(
                        code_hash,
                        CodeDB::hash(&code),
                        "bytecode len {:?}, step {:?}",
                        code.len(),
                        step
                    );
                }
                code_hash
            }
        }
        None => {
            let hash = CodeDB::hash(&code);
            log::debug!(
                "hash_code done: addr {addr:?}, size {}, hash {hash:?}",
                &code.len()
            );
            hash
        }
    };

    cdb.0.entry(code_hash).or_insert_with(|| {
        log::trace!(
            "trace code addr {:?}, size {} hash {:?}",
            addr,
            &code.len(),
            code_hash
        );
        code.to_vec()
    });
}

fn update_codedb(cdb: &mut CodeDB, sdb: &StateDB, block: &BlockTrace) {

    log::debug!("build_codedb for block {:?}", block.header.number);
    for (er_idx, execution_result) in block.execution_results.iter().enumerate() {
        if let Some(bytecode) = &execution_result.byte_code {
            let bytecode = decode_bytecode(bytecode).unwrap().to_vec();

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
                        assert!(callee_code.is_none(), "invalid trace: cannot get code of call: {:?}", step);
                        let code_hash = match step.op {
                            OpcodeId::CALL | OpcodeId::CALLCODE => data.get_code_hash_at(1),
                            OpcodeId::STATICCALL => data.get_code_hash_at(0),
                            _ => None,
                        };
                        trace_code(cdb, code_hash, callee_code.unwrap(), step, sdb, 1);
                    }
                    OpcodeId::CREATE | OpcodeId::CREATE2 => {
                        // notice we do not need to insert code for CREATE,
                        // bustmapping do this job
                    }
                    OpcodeId::EXTCODESIZE | OpcodeId::EXTCODECOPY => {
                        let code = data.get_code_at(0);
                        assert!(code.is_none(), "invalid trace: cannot get code of ext: {:?}", step);
                        trace_code(cdb, None, code.unwrap(), step, sdb, 0);
                    }

                    _ => {}
                }
            }
        }
    }

    log::debug!("updating codedb done");
}

fn dump_code_db(cdb: &CodeDB){
    for (k, v) in &cdb.0 {
        assert!(!k.is_zero());
        log::trace!("codedb codehash {:?}, len {}", k, v.len());
    }    
}

impl CircuitInputBuilder {
    /// Create a new CircuitInputBuilder from the given `l2_trace` and `circuits_params`
    pub fn new_from_l2_trace(
        circuits_params: CircuitsParams,
        l2_trace: &BlockTrace,
        more: bool,
    ) -> Self {

        let chain_id = l2_trace.chain_id;
        let start_l1_queue_index = l2_trace.start_l1_queue_index;

        let mut code_db = CodeDB::new();
        code_db.insert(Vec::new());

        if !more {
            dump_code_db(&code_db);
        }

        let old_root = l2_trace.storage_trace.root_before;
        log::debug!(
            "building zktrie state for block {:?}, old root {}",
            l2_trace.header.number,
            hex::encode(old_root),
        );
        let account_proofs = l2_trace
            .storage_trace
            .proofs.iter().flat_map(
                |kv_map| {
                kv_map
                    .iter()
                    .map(|(k, bts)| (k, bts.iter().map(Bytes::as_ref)))
            });
        let storage_proofs = l2_trace
            .storage_trace
            .storage_proofs
            .iter()
            .flat_map(|(k, kv_map)| {
                kv_map
                    .iter()
                    .map(move |(sk, bts)| (k, sk, bts.iter().map(Bytes::as_ref)))
            });
        let additional_proofs = l2_trace
            .storage_trace
            .deletion_proofs
            .iter()
            .map(Bytes::as_ref);

        let mpt_state = ZktrieState::from_trace_with_additional(
            old_root, 
            account_proofs, 
            storage_proofs, 
            additional_proofs
        ).unwrap();

        log::debug!(
            "building partial statedb done, root {}",
            hex::encode(mpt_state.root())
        );

        let sdb = StateDB::from(&mpt_state);

        let mut builder_block = circuit_input_builder::Block::from_headers(&[], circuits_params);
        builder_block.chain_id = chain_id;
        builder_block.prev_state_root = U256::from(mpt_state.root());
        let mut builder = CircuitInputBuilder::new(sdb, code_db, &builder_block);

        let eth_block: EthBlock = l2_trace.clone().into();

        builder
    }
    
}

