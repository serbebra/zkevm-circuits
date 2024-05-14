use bus_mapping::{
    circuit_input_builder::{BuilderClient, CircuitsParams},
    rpc::GethClient,
};
use eth_types::{evm_types::OpcodeId, geth_types::TxType, Block, Transaction};
use ethers::prelude::{Middleware, Provider};
use integration_tests::{get_transport, log_init, START_BLOCK};
use log::*;
use std::{env, iter, path::PathBuf, time::Duration};

const DENCUN_BLOCK: u64 = 19424209;

// collect following txs:
// - mcopy opcode
// - tload opcode
// - tstore opcode
// - basefee opcode
// - type is 1559
// - type is 2930
#[tokio::test]
async fn collect_traces() {
    log_init();
    let mut total_txs = 0;
    let mut total_pending_txs = 0;
    let mut total_saving_txs = 0;

    let params = CircuitsParams {
        max_rws: 2_000_000,
        max_copy_rows: 2_000_000, // dynamic
        max_txs: 10,
        max_calldata: 1_000_000,
        max_inner_blocks: 8,
        max_bytecode: 1_000_000,
        max_mpt_rows: 200_000,
        max_poseidon_rows: 2_000_000,
        max_keccak_rows: 2_000_000,
        max_exp_steps: 5_000,
        max_evm_rows: 0,
        max_rlp_rows: 1_500_000,
        ..Default::default()
    };

    let transport = get_transport();
    let cli = BuilderClient::new(GethClient::new(transport.clone()), params)
        .await
        .unwrap();
    let base_dir = PathBuf::from(env::var("BASE_DIR").expect("BASE_DIR env var not found"));
    tokio::try_join!(
        tokio::fs::create_dir_all(base_dir.join("mcopy")),
        tokio::fs::create_dir_all(base_dir.join("tload")),
        tokio::fs::create_dir_all(base_dir.join("tstore")),
        tokio::fs::create_dir_all(base_dir.join("basefee")),
        tokio::fs::create_dir_all(base_dir.join("eip1559")),
        tokio::fs::create_dir_all(base_dir.join("eip2930")),
    )
    .expect("failed to create dir");

    let provider = Provider::new(transport);
    let mut current_block = *START_BLOCK as u64;
    if current_block < DENCUN_BLOCK {
        current_block = DENCUN_BLOCK;
    }

    loop {
        let mut backoff = Duration::from_secs(1);
        while provider.get_block_number().await.unwrap().as_u64() < current_block {
            if backoff == Duration::from_secs(1) {
                info!("waiting for block {}", current_block);
            }
            backoff *= 2;
            tokio::time::sleep(backoff).await;
        }

        let blk: Block<Transaction> = provider
            .get_block_with_txs(current_block)
            .await
            .expect("max retries exceeded")
            .expect("block not found");

        total_txs += blk.transactions.len();
        info!(
            "load {} txs from block#{current_block}, filtering {total_pending_txs}/{total_txs}, saving {total_saving_txs}/{total_txs}",
            blk.transactions.len(),
        );

        let mut saving_txs = vec![];

        let futs = blk.transactions.iter().filter_map(|tx| {
            let tx_type = TxType::get_tx_type(&tx);
            match tx_type {
                TxType::Eip1559 | TxType::Eip2930 => {
                    trace!("filter out tx#{} with type {:?}", tx.hash, tx_type);
                    let trace = cli.cli.trace_tx_by_hash_legacy(tx.hash).await.unwrap();
                    Some((tx.hash, trace))
                }
                TxType::PreEip155 => None,
                _ => {
                    total_pending_txs += 1;
                    let trace = cli.cli.trace_tx_by_hash_legacy(tx.hash).await.unwrap();
                    if trace.struct_logs.iter().any(|step| {
                        matches!(
                            step.op,
                            OpcodeId::MCOPY
                                | OpcodeId::TLOAD
                                | OpcodeId::TSTORE
                                | OpcodeId::BASEFEE
                        )
                    }) {
                        Some((tx.hash, trace))
                    } else {
                        None
                    }
                }
            }
        });

        for (tx_hash, geth_trace) in saving_txs {
            let mut eth_block = blk.clone();
            eth_block.transactions.retain(|t| t.hash == tx_hash);
            let trace_config = cli
                .get_trace_config(&eth_block, iter::once(&geth_trace), true)
                .await
                .expect(&format!("failed to get trace config for tx#{:x}", tx_hash));

            let serialized = tokio::task::spawn_blocking(move || {
                let block_trace = external_tracer::l2trace(&trace_config)
                    .expect(&format!("failed to get l2 trace for tx#{:x}", tx_hash));
                serde_json::to_vec_pretty(&block_trace).expect("failed to serialize")
            })
            .await
            .expect("failed to get l2 trace");

            for (opcode, dir) in [
                OpcodeId::MCOPY,
                OpcodeId::TLOAD,
                OpcodeId::TSTORE,
                OpcodeId::BASEFEE,
            ]
            .into_iter()
            .zip(["mcopy", "tload", "tstore", "basefee"])
            {
                if geth_trace.struct_logs.iter().any(|step| step.op == opcode) {
                    trace!("saving tx#{} to {}", tx_hash, dir);
                    let path = base_dir.join(dir).join(format!("{:x}.json", tx_hash));
                    tokio::fs::write(path, serialized.as_slice())
                        .await
                        .expect("failed to write file");
                }
            }

            let tx_type = TxType::get_tx_type(&eth_block.transactions[0]);
            for (dir, ty) in [("eip1559", TxType::Eip1559), ("eip2930", TxType::Eip2930)] {
                if tx_type == ty {
                    trace!("saving tx#{} to {}", tx_hash, dir);
                    let path = base_dir.join(dir).join(format!("{:x}.json", tx_hash));
                    tokio::fs::write(path, serialized.as_slice())
                        .await
                        .expect("failed to write file");
                }
            }
        }

        current_block += 1;
    }
}
