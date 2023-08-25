use anyhow::{Result};
use bus_mapping::{
    state_db::{CodeDB, StateDB},
};
use eth_types::{ToAddress, H256};
use ethers_core::types::{Bytes};
use is_even::IsEven;
use types::eth::{ExecStep};

pub fn decode_bytecode(bytecode: &str) -> Result<Vec<u8>> {
    let mut stripped = if let Some(stripped) = bytecode.strip_prefix("0x") {
        stripped.to_string()
    } else {
        bytecode.to_string()
    };

    let bytecode_len = stripped.len() as u64;
    if !bytecode_len.is_even() {
        stripped = format!("0{stripped}");
    }

    hex::decode(stripped).map_err(|e| e.into())
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
