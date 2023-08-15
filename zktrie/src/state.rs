//! Represent the storage state under zktrie as implement
use eth_types::{Address, Hash, Word};
use mpt_circuits::MPTProofType;

use std::{collections::HashMap, io::Error};
pub use zktrie::{Hash as ZkTrieHash, ZkMemoryDb, ZkTrie, ZkTrieNode};

pub mod builder;
pub mod witness;
pub use builder::{AccountData, StorageData};

use std::{cell::RefCell, fmt, rc::Rc};

/// represent a storage state being applied in specified block
#[derive(Clone, Default)]
pub struct ZktrieState {
    accounts: HashMap<Address, AccountData>,
    account_storages: HashMap<(Address, Word), StorageData>,
    zk_db: Rc<RefCell<ZkMemoryDb>>,
    trie_root: ZkTrieHash,
}

unsafe impl Send for ZktrieState {}

impl fmt::Debug for ZktrieState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ZktrieState: {{accounts: {:?}, storage: {:?}, trie: {:x?}}}",
            self.accounts, self.account_storages, self.trie_root,
        )
    }
}

impl ZktrieState {
    /// help to query account data
    pub fn root(&self) -> &ZkTrieHash {
        &self.trie_root
    }

    /// help to query account data
    pub fn state(&self) -> &HashMap<Address, AccountData> {
        &self.accounts
    }

    /// help to query storage data
    pub fn storage(&self) -> &HashMap<(Address, Word), StorageData> {
        &self.account_storages
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
        Self {
            zk_db: Rc::new(RefCell::new(zk_db)),
            trie_root: state_root.0,
            ..Default::default()
        }
    }

    fn update_state_from_proofs<'d, BYTES>(
        &mut self,
        account_proofs: impl Iterator<Item = (&'d Address, BYTES)>,
        storage_proofs: impl Iterator<Item = (&'d Address, &'d Word, BYTES)>,
        mut on_account: impl FnMut(&Address, &AccountData) -> Result<(), Error> + 'd,
        mut on_storage: impl FnMut(&(Address, Word), &StorageData) -> Result<(), Error> + 'd,
    ) -> Result<(), Error>
    where
        BYTES: IntoIterator<Item = &'d [u8]>,
    {
        use builder::{AccountProof, BytesArray, StorageProof};

        for (addr, bytes) in account_proofs {
            let acc_proof = builder::verify_proof_leaf(
                AccountProof::try_from(BytesArray(bytes.into_iter()))?,
                &builder::extend_address_to_h256(addr),
            );
            let acc_data = acc_proof.data;
            let acc = self.accounts.get(addr);
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
                // self.sdb.set_account(
                //     addr,
                //     Account {
                //         nonce: acc_data.nonce.into(),
                //         balance: acc_data.balance,
                //         code_hash: acc_data.poseidon_code_hash,
                //         keccak_code_hash: acc_data.keccak_code_hash,

                //         code_size: acc_data.code_size.into(),
                //         storage: Default::default(),
                //     },
                // );

                on_account(addr, &acc_data)?;
                self.accounts.insert(*addr, acc_data);
            } else {
                //self.sdb.set_account(addr, Account::zero());
                self.accounts.insert(*addr, Default::default());
            }
        }

        for (&addr, &key, bytes) in storage_proofs {
            let storage_key = (addr, key);
            let old_value = self.account_storages.get(&storage_key);
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
                self.account_storages.insert(storage_key, store_proof.data);
            } else {
                log::trace!("insert storage key {:?} for zero", storage_key,);
                self.account_storages
                    .insert(storage_key, Default::default());
            }
        }

        Ok(())
    }

    /// incremental updating from external data, also catch each written of leaf in tries
    pub fn update_from_proofs<'d, BYTES>(
        &mut self,
        account_proofs: impl Iterator<Item = (&'d Address, BYTES)> + Clone,
        storage_proofs: impl Iterator<Item = (&'d Address, &'d Word, BYTES)> + Clone,
        additional_proofs: impl Iterator<Item = &'d [u8]> + Clone,
        on_account: impl FnMut(&Address, &AccountData) -> Result<(), Error> + 'd,
        on_storage: impl FnMut(&(Address, Word), &StorageData) -> Result<(), Error> + 'd,
    ) -> Result<(), Error>
    where
        BYTES: IntoIterator<Item = &'d [u8]>,
    {
        self.update_state_from_proofs(
            account_proofs.clone(),
            storage_proofs.clone(),
            on_account,
            on_storage,
        )?;

        let proofs = account_proofs
            .flat_map(|(_, bytes)| bytes)
            .chain(storage_proofs.flat_map(|(_, _, bytes)| bytes))
            .chain(additional_proofs);
        let mut zk_db = self.zk_db.borrow_mut();
        for bytes in proofs {
            zk_db.add_node_bytes(bytes).unwrap();
        }
        Ok(())
    }

    /// construct from external data, with additional proofs (trie node) can be
    /// provided
    pub fn from_trace_with_additional<'d, BYTES>(
        state_root: Hash,
        account_proofs: impl Iterator<Item = (&'d Address, BYTES)> + Clone,
        storage_proofs: impl Iterator<Item = (&'d Address, &'d Word, BYTES)> + Clone,
        additional_proofs: impl Iterator<Item = &'d [u8]> + Clone,
    ) -> Result<Self, Error>
    where
        BYTES: IntoIterator<Item = &'d [u8]>,
    {
        let mut state = ZktrieState::construct(state_root);
        state.update_from_proofs(
            account_proofs,
            storage_proofs,
            additional_proofs,
            |_, _| Ok(()),
            |_, _| Ok(()),
        )?;
        Ok(state)
    }
}

#[cfg(any(feature = "test", test))]
mod test;
