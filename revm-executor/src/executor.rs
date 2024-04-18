use crate::{
    database::EvmDatabase,
    utils::{collect_account_proofs, collect_storage_proofs},
};
use eth_types::{
    l2_types::{BlockTrace, ExecutionResult},
    ToWord, H256, U256,
};
use mpt_zktrie::state::ZktrieState;
use revm::primitives::{BlockEnv, Env, TxEnv};
use zkevm_circuits::witness::MptUpdates;

#[derive(Debug)]
pub struct EvmExecutor {
    pub db: EvmDatabase,
    old_root: H256,
    mpt_init_state: ZktrieState,
}

impl EvmExecutor {
    pub fn new(l2_trace: &BlockTrace) -> Self {
        let old_root = l2_trace.storage_trace.root_before;
        let mpt_init_state = ZktrieState::from_trace_with_additional(
            old_root,
            collect_account_proofs(&l2_trace.storage_trace),
            collect_storage_proofs(&l2_trace.storage_trace),
            l2_trace
                .storage_trace
                .deletion_proofs
                .iter()
                .map(ethers_core::types::Bytes::as_ref),
        )
        .unwrap();
        log::debug!(
            "building partial statedb done, root {}",
            hex::encode(mpt_init_state.root())
        );

        let db = EvmDatabase::new(l2_trace);

        Self {
            db,
            old_root,
            mpt_init_state,
        }
    }

    pub fn handle_block(&mut self, l2_trace: &BlockTrace) -> U256 {
        let mut env = Box::new(Env::default());
        env.cfg.chain_id = l2_trace.chain_id;
        env.block = BlockEnv::from(l2_trace);

        for (tx, exec) in l2_trace
            .transactions
            .iter()
            .zip(l2_trace.execution_results.iter())
        {
            let mut env = env.clone();
            env.tx = TxEnv::from(tx);
            log::debug!("{env:#?}");
            {
                let mut revm = revm::Evm::builder()
                    .with_db(&mut self.db)
                    .with_env(env)
                    .build();
                let result = revm.transact_commit().unwrap();
                log::trace!("{result:#?}");
            }

            self.post_check(exec);
        }

        let mut mpt_updates = MptUpdates {
            old_root: self.old_root.to_word(),
            updates: self.db.updates.clone(),
            ..Default::default()
        };
        mpt_updates.fill_state_roots(&self.mpt_init_state);
        mpt_updates.new_root
    }

    fn post_check(&mut self, exec: &ExecutionResult) {
        for account_post_state in exec.account_after.iter() {
            if let Some(address) = account_post_state.address {
                let local_acc = self.db.sdb.get_account(&address).1;
                log::trace!("local acc {local_acc:?}, trace acc {account_post_state:?}");
                if local_acc.balance != account_post_state.balance.unwrap() {
                    let local = local_acc.balance;
                    let post = account_post_state.balance.unwrap();
                    log::error!(
                        "incorrect balance, local {:#x} {} post {:#x} (diff {}{:#x})",
                        local,
                        if local < post { "<" } else { ">" },
                        post,
                        if local < post { "-" } else { "+" },
                        if local < post {
                            post - local
                        } else {
                            local - post
                        }
                    )
                }
                if local_acc.nonce != account_post_state.nonce.unwrap().into() {
                    log::error!("incorrect nonce")
                }
                let p_hash = account_post_state.poseidon_code_hash.unwrap();
                if p_hash.is_zero() {
                    if !local_acc.is_empty() {
                        log::error!("incorrect poseidon_code_hash")
                    }
                } else {
                    if local_acc.code_hash != p_hash {
                        log::error!("incorrect poseidon_code_hash")
                    }
                }
                let k_hash = account_post_state.keccak_code_hash.unwrap();
                if k_hash.is_zero() {
                    if !local_acc.is_empty() {
                        log::error!("incorrect keccak_code_hash")
                    }
                } else {
                    if local_acc.keccak_code_hash != k_hash {
                        log::error!("incorrect keccak_code_hash")
                    }
                }
                if let Some(storage) = account_post_state.storage.clone() {
                    let k = storage.key.unwrap();
                    let local_v = self.db.sdb.get_storage(&address, &k).1;
                    if *local_v != storage.value.unwrap() {
                        log::error!("incorrect storage for k = {k}")
                    }
                }
            }
        }
    }
}
