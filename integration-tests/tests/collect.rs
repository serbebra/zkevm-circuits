use bus_mapping::circuit_input_builder::{BuilderClient, CircuitsParams};
use eth_types::{evm_types::OpcodeId, geth_types::TxType, Block, GethExecTrace, Transaction, H256};
use ethers::prelude::Middleware;
use integration_tests::{get_client, get_provider, log_init, START_BLOCK};
use log::*;
use std::{env, iter, ops::Deref, path::PathBuf, sync::Arc, time::Duration};
use tokio::task::JoinSet;

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
    let (pending_txs_tx, pending_txs_rx) = async_channel::bounded(100);
    let (saving_txs_tx, saving_txs_rx) = async_channel::bounded(20);

    let total_saving_txs = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let mut set = JoinSet::new();
    // block loader
    set.spawn(load_transactions(
        pending_txs_tx.clone(),
        saving_txs_tx.clone(),
        total_saving_txs.clone(),
    ));
    // filter workers
    for i in 0..100 {
        set.spawn(filter_transaction(
            i,
            pending_txs_rx.clone(),
            saving_txs_tx.clone(),
            total_saving_txs.clone(),
        ));
    }

    // save workers
    for i in 0..10 {
        set.spawn(save_transaction(i, saving_txs_rx.clone()));
    }

    tokio::signal::ctrl_c().await.unwrap();
    info!("received ctrl-c, shutting down");
    pending_txs_tx.close();
    pending_txs_rx.close();
    saving_txs_tx.close();
    saving_txs_rx.close();

    while let Some(_) = set.join_next().await {}
}

#[derive(Clone)]
struct PartialTxWithBlock {
    tx_hash: H256,
    trace: Option<GethExecTrace>,
    blk: Arc<Block<Transaction>>,
}

impl PartialTxWithBlock {
    fn new(tx_hash: H256, blk: Arc<Block<Transaction>>) -> Self {
        Self {
            tx_hash,
            trace: None,
            blk,
        }
    }
}

async fn load_transactions(
    pending_txs_tx: async_channel::Sender<Box<PartialTxWithBlock>>,
    saving_txs_tx: async_channel::Sender<Box<PartialTxWithBlock>>,
    total_saving_txs: Arc<std::sync::atomic::AtomicUsize>,
) {
    let client = get_provider();
    let mut current_block = *START_BLOCK as u64;
    if current_block < DENCUN_BLOCK {
        current_block = DENCUN_BLOCK;
    }
    let mut total_pending_txs = 0;
    let mut total_txs = 0;
    loop {
        let mut backoff = Duration::from_secs(1);
        while client.get_block_number().await.unwrap().as_u64() < current_block {
            if backoff == Duration::from_secs(1) {
                info!("waiting for block {}", current_block);
            }
            backoff *= 2;
            tokio::time::sleep(backoff).await;
        }

        let blk: Block<Transaction> = client
            .get_block_with_txs(current_block)
            .await
            .expect("max retries exceeded")
            .expect("block not found");
        let blk = Arc::new(blk);

        {
            let total_saving_txs = total_saving_txs.load(std::sync::atomic::Ordering::Relaxed);
            info!(
                "load {} txs from block#{current_block}, filtering {total_pending_txs}/{total_txs}, saving {total_saving_txs}/{total_txs}",
                blk.transactions.len(),
            );
        }

        for tx in blk.transactions.iter() {
            total_txs += 1;
            let tx_type = TxType::get_tx_type(&tx);
            match tx_type {
                TxType::Eip1559 | TxType::Eip2930 => {
                    trace!("filter out tx#{} with type {:?}", tx.hash, tx_type);
                    if let Err(_) = saving_txs_tx
                        .send(Box::new(PartialTxWithBlock::new(tx.hash, blk.clone())))
                        .await
                    {
                        info!("saving_txs_tx closed, shutdown load_transactions");
                        total_saving_txs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                    continue;
                }
                TxType::PreEip155 => continue,
                _ => {
                    if let Err(_) = pending_txs_tx
                        .send(Box::new(PartialTxWithBlock::new(tx.hash, blk.clone())))
                        .await
                    {
                        info!("pending_txs_tx closed, shutdown load_transactions");
                        return;
                    }
                    total_pending_txs += 1;
                }
            }
        }

        current_block += 1;
    }
}

async fn filter_transaction(
    idx: usize,
    pending_txs_rx: async_channel::Receiver<Box<PartialTxWithBlock>>,
    saving_txs_tx: async_channel::Sender<Box<PartialTxWithBlock>>,
    total_saving_txs: Arc<std::sync::atomic::AtomicUsize>,
) {
    let client = get_client();
    while let Ok(mut tx) = pending_txs_rx.recv().await {
        let tx_hash = tx.tx_hash;
        let trace = client.trace_tx_by_hash_legacy(tx_hash).await.unwrap();
        if trace.struct_logs.iter().any(|step| {
            matches!(
                step.op,
                OpcodeId::MCOPY | OpcodeId::TLOAD | OpcodeId::TSTORE | OpcodeId::BASEFEE
            )
        }) {
            trace!("filter_transaction woker#{idx} found tx#{tx_hash} contains target opcode");
            tx.trace = Some(trace);
            saving_txs_tx.send(tx).await.expect("channel closed");
            total_saving_txs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    info!("filter_transaction worker#{idx} shutdown");
}

async fn save_transaction(
    idx: usize,
    saving_txs_rx: async_channel::Receiver<Box<PartialTxWithBlock>>,
) {
    let cli = get_client();
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
    let cli = BuilderClient::new(cli, params).await.unwrap();
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

    while let Ok(mut tx) = saving_txs_rx.recv().await {
        let tx_hash = tx.tx_hash;
        trace!("save_transaction worker#{idx} saving tx#{}", tx_hash);
        if tx.trace.is_none() {
            tx.trace = Some(
                cli.cli
                    .trace_tx_by_hash_legacy(tx_hash)
                    .await
                    .expect(&format!("failed to get trace for tx#{:x}", tx_hash)),
            );
        }
        let geth_trace = tx.trace.unwrap();
        let mut eth_block = tx.blk.deref().clone();
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
                trace!(
                    "save_transaction worker#{idx} saving tx#{} to {}",
                    tx.tx_hash,
                    dir
                );
                let path = base_dir.join(dir).join(format!("{:x}.json", tx.tx_hash));
                tokio::fs::write(path, serialized.as_slice())
                    .await
                    .expect("failed to write file");
            }
        }

        let tx_type = TxType::get_tx_type(&eth_block.transactions[0]);
        for (dir, ty) in [("eip1559", TxType::Eip1559), ("eip2930", TxType::Eip2930)] {
            if tx_type == ty {
                trace!(
                    "save_transaction worker#{idx} saving tx#{} to {}",
                    tx.tx_hash,
                    dir
                );
                let path = base_dir.join(dir).join(format!("{:x}.json", tx.tx_hash));
                tokio::fs::write(path, serialized.as_slice())
                    .await
                    .expect("failed to write file");
            }
        }
    }
    info!("save_transaction worker#{idx} shutdown");
}
