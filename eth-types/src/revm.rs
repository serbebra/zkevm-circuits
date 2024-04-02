use crate::{
    l2_types::{BlockTrace, TransactionTrace},
    U256,
};
use revm::{BlockEnv, CreateScheme, TransactTo, TxEnv};

impl From<&BlockTrace> for BlockEnv {
    fn from(block: &BlockTrace) -> Self {
        BlockEnv {
            number: U256::from(block.header.number.unwrap().as_u64()),
            coinbase: block.coinbase.address.unwrap(),
            timestamp: block.header.timestamp,
            difficulty: block.header.difficulty,
            prevrandao: block.header.mix_hash, // FIXME: is this correct?
            basefee: block.header.base_fee_per_gas.unwrap_or_default(),
            gas_limit: block.header.gas_limit,
        }
    }
}

impl From<&TransactionTrace> for TxEnv {
    fn from(tx: &TransactionTrace) -> Self {
        TxEnv {
            caller: tx.from,
            gas_limit: tx.gas,
            gas_price: tx.gas_price,
            gas_priority_fee: tx.gas_tip_cap,
            l1_fee: U256::zero(),
            transact_to: match tx.to {
                Some(to) => TransactTo::Call(to),
                None => TransactTo::Create(CreateScheme::Create), /* FIXME: is this correct?
                                                                   * CREATE2? */
            },
            value: tx.value,
            data: tx.data.0.clone(),
            chain_id: Some(tx.chain_id.as_u64()),
            nonce: Some(tx.nonce),
            access_list: tx
                .access_list
                .as_ref()
                .map(|a| {
                    a.iter()
                        .map(|e| {
                            (
                                e.address,
                                e.storage_keys
                                    .iter()
                                    .map(|s| U256::from_big_endian(s.as_ref()))
                                    .collect(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}
