//! l2 predeployed contract helpers

use eth_types::Address;

/// helper for L2MessageQueue contract
pub mod message_queue {
    use super::*;
    use eth_types::U256;
    use std::{str::FromStr, sync::LazyLock};

    /// address of L2MessageQueue predeploy
    pub static ADDRESS: LazyLock<Address> =
        LazyLock::new(|| Address::from_str("0x5300000000000000000000000000000000000000").unwrap());
    /// the slot of withdraw root in L2MessageQueue
    pub static WITHDRAW_TRIE_ROOT_SLOT: U256 = U256::zero();
}

/// Helper for L1GasPriceOracle contract
pub mod l1_gas_price_oracle {
    use eth_types::{Address, U256};
    use std::{str::FromStr, sync::LazyLock};

    /// L1GasPriceOracle predeployed address
    pub static ADDRESS: LazyLock<Address> =
        LazyLock::new(|| Address::from_str("0x5300000000000000000000000000000000000002").unwrap());
    /// L1 base fee slot in L1GasPriceOracle
    pub static BASE_FEE_SLOT: LazyLock<U256> = LazyLock::new(|| U256::from(1));
    /// L1 overhead slot in L1GasPriceOracle
    pub static OVERHEAD_SLOT: LazyLock<U256> = LazyLock::new(|| U256::from(2));
    /// L1 scalar slot in L1GasPriceOracle
    pub static SCALAR_SLOT: LazyLock<U256> = LazyLock::new(|| U256::from(3));
    /// Bytecode before curie hardfork
    /// ```
    /// curl 127.0.0.1:8545   -X POST   -H "Content-Type: application/json" \  
    /// --data \
    ///   '{"method":"eth_getCode",
    /// "params":["0x5300000000000000000000000000000000000002","latest"]\
    /// ,"id":1,"jsonrpc":"2.0"}' \
    /// | jq .result
    /// ```
    pub static V1_BYTECODE: LazyLock<Vec<u8>> = LazyLock::new(|| 
        hex::decode(include_str!("./data/v1_l1_oracle_bytecode.txt")).unwrap()
    );
    /// Bytecode after curie hardfork
    pub static V2_BYTECODE: LazyLock<Vec<u8>> = LazyLock::new(|| 
        hex::decode(include_str!("./data/v2_l1_oracle_bytecode.txt")).unwrap()
    );
}
