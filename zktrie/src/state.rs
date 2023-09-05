//! Represent the storage state under zktrie as implement
use eth_types::{Address, Hash, Word, H160, H256, U256};
use mpt_circuits::{serde::SMTTrace, MPTProofType};

use std::{collections::HashMap, io::Error};
pub use zktrie::{Hash as ZkTrieHash, ZkMemoryDb, ZkTrie, ZkTrieNode};

pub mod builder;
pub mod witness;
use crate::state::witness::ActiveZktrieState;
pub use builder::{AccountData, StorageData};

use std::{cell::RefCell, fmt, rc::Rc};

/// represent a storage state being applied in specified block
#[derive(Clone, Default)]
struct CommitZktrieState {
    accounts: HashMap<Address, AccountData>,
    account_storages: HashMap<(Address, Word), StorageData>,
    zk_db: Rc<RefCell<ZkMemoryDb>>,
    trie_root: ZkTrieHash,
}

/// ..
pub struct ZktrieState {
    /// ..
    init_state: CommitZktrieState,
    /// ..
    live_state: ActiveZktrieState,
}

unsafe impl Send for CommitZktrieState {}

impl fmt::Debug for ZktrieState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ZktrieState: {{accounts: {:?}, storage: {:?}, trie: {:x?}}}",
            self.init_state.accounts, self.init_state.account_storages, self.init_state.trie_root,
        )
    }
}

impl Default for ZktrieState {
    fn default() -> Self {
        Self::construct(H256::zero())
    }
}

impl ZktrieState {
    /// help to query account data
    pub fn init_root(&self) -> ZkTrieHash {
        self.init_state.trie_root
    }

    /// help to query account data
    pub fn cur_root(&self) -> ZkTrieHash {
        self.live_state.root()
    }

    /// dump inner data for debugging
    pub fn dump(&self) {
        self.live_state.dump()
    }

    /// get account proof
    pub fn account_proof(&self, address: Address) -> Vec<Vec<u8>> {
        self.live_state.account_proof(address)
    }

    /// get storage proof
    pub fn storage_proof(&self, address: Address, key: Word) -> Vec<Vec<u8>> {
        self.live_state.storage_proof(address, key)
    }

    /// help to query account data
    pub fn state(&self) -> &HashMap<Address, AccountData> {
        &self.init_state.accounts
    }

    /// help to query storage data
    pub fn storage(&self) -> &HashMap<(Address, Word), StorageData> {
        &self.init_state.account_storages
    }

    /// ..
    pub fn get_storage(&self, k: &(H160, U256)) -> Option<StorageData> {
        self.init_state.account_storages.get(k).cloned()
    }

    /// use one entry in mpt table to build the corresponding mpt operation (via
    /// SMTTrace)
    pub fn handle_new_state(
        &mut self,
        proof_type: MPTProofType,
        address: Address,
        new_val: Word,
        old_val: Word,
        key: Option<Word>,
    ) -> SMTTrace {
        self.live_state
            .handle_new_state(proof_type, address, new_val, old_val, key)
    }

    /// construct from external data
    pub fn construct(
        //sdb: StateDB,
        state_root: Hash,
        //proofs: impl IntoIterator<Item = &'d [u8]>,
        //acc_storage_roots: impl IntoIterator<Item = (Address, Hash)>,
    ) -> Self {
        assert!(
            *builder::HASH_SCHEME_DONE,
            "must set hash scheme into zktrie"
        );

        let zk_db = ZkMemoryDb::default();
        let init_state = CommitZktrieState {
            zk_db: Rc::new(RefCell::new(zk_db)),
            trie_root: state_root.0,
            ..Default::default()
        };
        Self {
            live_state: ActiveZktrieState::from(&init_state),
            init_state,
        }
    }

    /// incremental updating for account from external data, catch each written of new account in
    /// tries
    pub fn update_account_from_proofs<'d, BYTES>(
        &mut self,
        account_proofs: impl Iterator<Item = (&'d Address, BYTES)>,
        mut on_account: impl FnMut(&Address, &AccountData) -> Result<(), Error> + 'd,
    ) -> Result<(), Error>
    where
        BYTES: IntoIterator<Item = &'d [u8]>,
    {
        use builder::{AccountProof, BytesArray};

        for (addr, bytes) in account_proofs {
            let acc_proof = builder::verify_proof_leaf(
                AccountProof::try_from(BytesArray(bytes.into_iter()))?,
                &builder::extend_address_to_h256(addr),
            );
            let acc_data = acc_proof.data;
            let acc = self.init_state.accounts.get(addr);
            if acc.is_some() {
                log::trace!(
                    "skip trace account into sdb: addr {:?}, new {:?}, keep old: {:?}",
                    addr,
                    acc_data,
                    acc
                );
                continue;
            }
            if acc_proof.key.is_some() {
                log::trace!("trace account into sdb: {:?} => {:?}", addr, acc_data);
                on_account(addr, &acc_data)?;
                self.init_state.accounts.insert(*addr, acc_data);
            } else {
                on_account(addr, &Default::default())?;
                self.init_state.accounts.insert(*addr, Default::default());
            }
        }

        Ok(())
    }

    /// incremental updating for storage from external data, catch each written of new (non-zero)
    /// value in tries
    pub fn update_storage_from_proofs<'d, BYTES>(
        &mut self,
        storage_proofs: impl Iterator<Item = (&'d Address, &'d Word, BYTES)>,
        mut on_storage: impl FnMut(&(Address, Word), &StorageData) -> Result<(), Error> + 'd,
    ) -> Result<(), Error>
    where
        BYTES: IntoIterator<Item = &'d [u8]>,
    {
        use builder::{BytesArray, StorageProof};

        for (&addr, &key, bytes) in storage_proofs {
            let storage_key: (Address, Word) = (addr, key);
            let old_value = self.init_state.account_storages.get(&storage_key);
            if old_value.is_some() {
                continue;
            }
            let mut key_buf = [0u8; 32];
            key.to_big_endian(key_buf.as_mut_slice());
            let bytes_array = BytesArray(bytes.into_iter());
            let store_proof =
                builder::verify_proof_leaf(StorageProof::try_from(bytes_array)?, &key_buf);
            if store_proof.key.is_some() {
                log::trace!(
                    "insert storage key {:?} value {:?}",
                    storage_key,
                    *store_proof.data.as_ref()
                );

                on_storage(&storage_key, &store_proof.data)?;
                self.init_state
                    .account_storages
                    .insert(storage_key, store_proof.data);
            } else {
                log::trace!("insert storage key {:?} for zero", storage_key);
                self.init_state
                    .account_storages
                    .insert(storage_key, Default::default());
            }
        }

        Ok(())
    }

    /// incremental updating nodes in db from external data
    pub fn update_nodes_from_proofs<'d, BYTES1, BYTES2>(
        &mut self,
        account_proofs: impl Iterator<Item = (&'d Address, BYTES1)>,
        storage_proofs: impl Iterator<Item = (&'d Address, &'d Word, BYTES2)>,
        additional_proofs: impl Iterator<Item = &'d [u8]>,
    ) where
        BYTES1: IntoIterator<Item = &'d [u8]>,
        BYTES2: IntoIterator<Item = &'d [u8]>,
    {
        let proofs = account_proofs
            .flat_map(|(_, bytes)| bytes)
            .chain(storage_proofs.flat_map(|(_, _, bytes)| bytes))
            .chain(additional_proofs);
        let mut zk_db = self.init_state.zk_db.borrow_mut();
        for bytes in proofs {
            zk_db.add_node_bytes(bytes).unwrap();
        }
    }

    /// construct from external data, with additional proofs (trie node) can be
    /// provided
    pub fn from_trace_with_additional<'d, BYTES1, BYTES2>(
        state_root: Hash,
        account_proofs: impl Iterator<Item = (&'d Address, BYTES1)> + Clone,
        storage_proofs: impl Iterator<Item = (&'d Address, &'d Word, BYTES2)> + Clone,
        additional_proofs: impl Iterator<Item = &'d [u8]>,
        light_mode: bool,
    ) -> Result<Self, Error>
    where
        BYTES1: IntoIterator<Item = &'d [u8]>,
        BYTES2: IntoIterator<Item = &'d [u8]>,
    {
        let mut state = ZktrieState::construct(state_root);
        if !light_mode {
            // a lot of poseidon computation
            state.update_nodes_from_proofs(
                account_proofs.clone(),
                storage_proofs.clone(),
                additional_proofs,
            );
        }
        state.update_account_from_proofs(account_proofs, |_, _| Ok(()))?;
        state.update_storage_from_proofs(storage_proofs, |_, _| Ok(()))?;

        Ok(state)
    }
}

#[cfg(any(feature = "test", test))]
mod test;
