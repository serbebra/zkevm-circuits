use crate::{
    l2_types::{BlockTrace, TransactionTrace},
    ToBigEndian,
};
use revm::primitives::{Address, BlockEnv, CreateScheme, TransactTo, TxEnv, B256, U256};

impl From<&BlockTrace> for BlockEnv {
    fn from(block: &BlockTrace) -> Self {
        BlockEnv {
            number: U256::from(block.header.number.unwrap().as_u64()),
            coinbase: Address::from(block.coinbase.address.unwrap().to_fixed_bytes()),
            timestamp: U256::from_be_bytes(block.header.timestamp.to_be_bytes()),
            gas_limit: U256::from_be_bytes(block.header.gas_limit.to_be_bytes()),
            basefee: U256::from_be_bytes(
                block
                    .header
                    .base_fee_per_gas
                    .unwrap_or_default()
                    .to_be_bytes(),
            ),
            difficulty: U256::from_be_bytes(block.header.difficulty.to_be_bytes()),
            prevrandao: block
                .header
                .mix_hash
                .map(|h| B256::from(h.to_fixed_bytes())),
            blob_excess_gas_and_price: None,
        }
    }
}

impl From<&TransactionTrace> for TxEnv {
    fn from(tx: &TransactionTrace) -> Self {
        TxEnv {
            caller: Address::from(tx.from.to_fixed_bytes()),
            gas_limit: tx.gas,
            gas_price: U256::from_be_bytes(tx.gas_price.to_be_bytes()),
            transact_to: match tx.to {
                Some(to) => TransactTo::Call(Address::from(to.to_fixed_bytes())),
                None => TransactTo::Create(CreateScheme::Create), /* FIXME: is this correct?
                                                                   * CREATE2? */
            },
            value: U256::from_be_bytes(tx.value.to_be_bytes()),
            data: revm::primitives::Bytes::copy_from_slice(tx.data.as_ref()),
            nonce: Some(tx.nonce),
            chain_id: Some(tx.chain_id.as_u64()),
            access_list: tx
                .access_list
                .as_ref()
                .map(|v| {
                    v.iter()
                        .map(|e| {
                            (
                                Address::from(e.address.to_fixed_bytes()),
                                e.storage_keys
                                    .iter()
                                    .map(|s| U256::from_be_bytes(s.to_fixed_bytes()))
                                    .collect(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default(),
            gas_priority_fee: tx.gas_tip_cap.map(|g| U256::from_be_bytes(g.to_be_bytes())),
            blob_hashes: vec![],
            max_fee_per_blob_gas: None,
            l1_fee: Default::default(),
        }
    }
}
