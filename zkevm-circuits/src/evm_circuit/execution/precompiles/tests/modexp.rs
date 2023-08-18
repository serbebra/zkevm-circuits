use bus_mapping::{evm::PrecompileCallArgs, precompile::PrecompileCalls};
use eth_types::{bytecode, word, ToWord};
use once_cell::sync::Lazy;

pub static TEST_VECTOR: Lazy<Vec<PrecompileCallArgs>> = Lazy::new(|| {
    vec![
        PrecompileCallArgs {
            name: "modexp success",
            setup_code: bytecode! {
                // Base size
                PUSH1(0x1)
                PUSH1(0x00)
                MSTORE
                // Esize
                PUSH1(0x1)
                PUSH1(0x20)
                MSTORE
                // Msize
                PUSH1(0x1)
                PUSH1(0x40)
                MSTORE
                // B, E and M
                PUSH32(word!("0x08090A0000000000000000000000000000000000000000000000000000000000"))
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x0.into(),
            call_data_length: 0x63.into(),
            ret_offset: 0x9f.into(),
            ret_size: 0x01.into(),
            address: PrecompileCalls::Modexp.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "modexp success",
            setup_code: bytecode! {
                // Base size
                PUSH1(0x1)
                PUSH1(0x00)
                MSTORE
                // Esize
                PUSH1(0x3)
                PUSH1(0x20)
                MSTORE
                // Msize
                PUSH1(0x2)
                PUSH1(0x40)
                MSTORE
                // B, E and M
                PUSH32(word!("0x0800000901000000000000000000000000000000000000000000000000000000"))
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x0.into(),
            call_data_length: 0x66.into(),
            ret_offset: 0x9f.into(),
            ret_size: 0x01.into(),
            address: PrecompileCalls::Modexp.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "modexp success with padding 0",
            setup_code: bytecode! {
                // Base size
                PUSH1(0x1)
                PUSH1(0x00)
                MSTORE
                // Esize
                PUSH1(0x3)
                PUSH1(0x20)
                MSTORE
                // Msize
                PUSH1(0x2)
                PUSH1(0x40)
                MSTORE
                // B, E and M
                PUSH32(word!("0x0800000901000000000000000000000000000000000000000000000000000000"))
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x0.into(),
            call_data_length: 0x65.into(),
            ret_offset: 0x9f.into(),
            ret_size: 0x01.into(),
            address: PrecompileCalls::Modexp.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "modexp no input",
            setup_code: bytecode! {
                // just put something in memory
                PUSH1(0x1)
                PUSH1(0x00)
                MSTORE
            },
            call_data_offset: 0x0.into(),
            call_data_length: 0x0.into(),
            ret_offset: 0x9f.into(),
            ret_size: 0x01.into(),
            address: PrecompileCalls::Modexp.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "modexp success with garbage bytes",
            setup_code: bytecode! {
                // Base size
                PUSH1(0x1)
                PUSH1(0x00)
                MSTORE
                // Esize
                PUSH1(0x3)
                PUSH1(0x20)
                MSTORE
                // Msize
                PUSH1(0x2)
                PUSH1(0x40)
                MSTORE
                // B, E and M
                PUSH32(word!("0x0800000901000000000000000000000000000000000000000000000000000000"))
                PUSH1(0x60)
                MSTORE
                PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000009"))
                PUSH1(0x80)
                MSTORE
                PUSH32(word!("0xfcb51a0695d8f838b1ee009b3fbf66bda078cd64590202a864a8f3e8c4315c47"))
                PUSH1(0xA0)
                MSTORE
            },
            call_data_offset: 0x0.into(),
            call_data_length: 0xc0.into(),
            ret_offset: 0xe0.into(),
            ret_size: 0x01.into(),
            address: PrecompileCalls::Modexp.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "modexp zero modulus",
            setup_code: bytecode! {
                // Base size
                PUSH1(0x1)
                PUSH1(0x00)
                MSTORE
                // Esize
                PUSH1(0x2)
                PUSH1(0x20)
                MSTORE
                // Msize
                PUSH1(0x0)
                PUSH1(0x40)
                MSTORE
                // B, E and M
                PUSH32(word!("0x0800090000000000000000000000000000000000000000000000000000000000"))
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x0.into(),
            call_data_length: 0x63.into(),
            ret_offset: 0x9f.into(),
            ret_size: 0x01.into(),
            address: PrecompileCalls::Modexp.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "modexp length in u256",
            setup_code: bytecode! {
                // Base size
                PUSH1(0x20)
                PUSH1(0x00)
                MSTORE
                // Esize
                PUSH1(0x20)
                PUSH1(0x20)
                MSTORE
                // Msize
                PUSH1(0x20)
                PUSH1(0x40)
                MSTORE
                // B, E and M
                PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000008"))
                PUSH1(0x60)
                MSTORE
                PUSH32(word!("0x1000000000000000000000000000000000000000000000000000000000000009"))
                PUSH1(0x80)
                MSTORE
                PUSH32(word!("0xfcb51a0695d8f838b1ee009b3fbf66bda078cd64590202a864a8f3e8c4315c47"))
                PUSH1(0xA0)
                MSTORE
            },
            call_data_offset: 0x0.into(),
            call_data_length: 0xc0.into(),
            ret_offset: 0xe0.into(),
            ret_size: 0x01.into(),
            address: PrecompileCalls::Modexp.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "modexp length in u256 and result wrapped",
            setup_code: bytecode! {
                // Base size
                PUSH1(0x20)
                PUSH1(0x00)
                MSTORE
                // Esize
                PUSH1(0x20)
                PUSH1(0x20)
                MSTORE
                // Msize
                PUSH1(0x20)
                PUSH1(0x40)
                MSTORE
                // B, E and M
                PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000008"))
                PUSH1(0x60)
                MSTORE
                PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000064"))
                PUSH1(0x80)
                MSTORE
                PUSH32(word!("0xfcb51a0695d8f838b1ee009b3fbf66bda078cd64590202a864a8f3e8c4315c47"))
                PUSH1(0xA0)
                MSTORE
            },
            call_data_offset: 0x0.into(),
            call_data_length: 0xc0.into(),
            ret_offset: 0xe0.into(),
            ret_size: 0x01.into(),
            address: PrecompileCalls::Modexp.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "modexp length too large invalid",
            setup_code: bytecode! {
                // Base size
                PUSH1(0x1)
                PUSH1(0x00)
                MSTORE
                // Esize
                PUSH1(0x1)
                PUSH1(0x20)
                MSTORE
                // Msize
                PUSH1(0x21)
                PUSH1(0x40)
                MSTORE
                // B, E and M
                PUSH32(word!("0x08090A0000000000000000000000000000000000000000000000000000000000"))
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x0.into(),
            call_data_length: 0x63.into(),
            ret_offset: 0x9f.into(),
            ret_size: 0x01.into(),
            address: PrecompileCalls::Modexp.address().to_word(),
            gas: 100000.into(),
            ..Default::default()
        },
    ]
});
