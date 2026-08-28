//! End-to-end mining flow over the real RPC surface: `getblocktemplate`
//! rendered JSON -> external-miner-style block assembly -> `submitblock` ->
//! tip advance, mempool drain, and a next template built on the new tip.
//!
//! The miner side of this test reads only the JSON template fields a real
//! miner sees (`previousblockhash`, `height`, `bits`, `curtime`,
//! `coinbasevalue`, `transactions[].data`, `default_witness_commitment`) — no
//! internal candidate state.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use bitcoin::absolute;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex as _;
use bitcoin::hex::FromHex;
use bitcoin::script::Builder;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    block,
};
use bitcoin_rs_node::{Config, MiningCoordinator, Network, state::NodeState};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::Handler;
use bitcoin_rs_rpc::context::{Context, ContextHandles, MiningControl};
use bitcoin_rs_utxo::UtxoSet;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

const SEED_BLOCKS: u32 = 100;
const SEED_BASE_TIME: u32 = 1_296_688_603;
const SEED_BLOCK_INTERVAL: u32 = 600;
const REGTEST_BITS: u32 = 0x207f_ffff;
const REGTEST_SUBSIDY_SATS: u64 = 50 * 100_000_000;
const MEMPOOL_TX_FEE_SATS: u64 = 10_000;
/// BIP141 witness reserved value committed by the mined coinbase.
const WITNESS_RESERVED: [u8; 32] = [0_u8; 32];

#[test]
fn template_mines_to_tip_and_drains_mempool() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

    // A spend of the height-1 seed coinbase matures exactly at height 101.
    let mempool_tx = seed_coinbase_spend();
    {
        let mempool = state.mempool();
        let mut guard = mempool.write();
        let vsize = u32::try_from(mempool_tx.vsize()).unwrap_or(u32::MAX);
        guard.insert_entry(bitcoin_rs_mempool::MempoolEntry::new(
            Arc::new(mempool_tx.clone()),
            vsize,
            MEMPOOL_TX_FEE_SATS,
            1,
            1,
        ))?;
    }

    let handler = mining_handler(&state);

    // --- getblocktemplate over the real RPC handler --------------------------
    let template = handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    let prev_hex = required_str(&template, "previousblockhash")?;
    let height = required_u64(&template, "height")?;
    assert_eq!(
        height,
        u64::from(SEED_BLOCKS + 1),
        "template height must extend the applied tip"
    );
    assert_eq!(
        prev_hex,
        block_hash_from_hash256(seed_tip_hash).to_string(),
        "template must build on the applied tip"
    );

    let template_txs = template
        .get("transactions")
        .and_then(|entry| entry.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    assert_eq!(template_txs.len(), 1, "the mempool tx must be selected");
    let template_txid = template_txs[0]
        .get("txid")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!("template transaction missing txid"))?;
    assert_eq!(
        template_txid,
        mempool_tx.compute_txid().to_string(),
        "the selected template tx must be the mempool tx"
    );

    // --- external-miner-style assembly from JSON fields only -----------------
    let block = assemble_from_template(&template, template_txs)?;

    // --- submitblock over the real RPC handler -------------------------------
    let hex = serialize(&block).to_lower_hex_string();
    let verdict = handler.dispatch("submitblock", &json!([hex]))?;
    assert!(
        verdict.is_null(),
        "submitblock of the mined template must be accepted, got: {verdict}"
    );

    // --- tip advanced, mempool drained, next template rebased ----------------
    let applied = state.applied_tip();
    let loaded_tip = applied.load_full();
    let Some(tip) = loaded_tip.as_ref() else {
        bail!("applied tip must exist after an accepted submission");
    };
    assert_eq!(
        tip.height,
        SEED_BLOCKS + 1,
        "tip height must advance by one"
    );
    assert_eq!(
        tip.hash,
        Hash256::from_le_bytes(block.block_hash().as_byte_array()),
        "tip hash must equal the submitted block hash"
    );
    assert_eq!(
        state.mempool().read().len(),
        0,
        "included tx must leave the mempool on block connect"
    );

    let next = handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    assert_eq!(
        required_str(&next, "previousblockhash")?,
        block.block_hash().to_string(),
        "next template must build on the submitted block"
    );
    assert_eq!(
        required_u64(&next, "height")?,
        u64::from(SEED_BLOCKS + 2),
        "next template height must extend the new tip"
    );
    Ok(())
}

/// Opens an isolated regtest `NodeState`; the returned guard keeps the data
/// directory alive for the whole test body (freed when the guard drops).
fn open_regtest() -> Result<(NodeState, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let mut config = Config::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p_listen.clear();
    let state = NodeState::open(config)?;
    Ok((state, dir))
}

fn apply_genesis(state: &NodeState) -> Result<()> {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    state.apply_block(&genesis)?;
    Ok(())
}

/// Mines `count` trivial-PoW regtest blocks through ordinary validation,
/// each coinbase paying an anyone-can-spend output.
fn seed_chain(state: &NodeState, count: u32) -> Result<Hash256> {
    let mut tip = current_tip(state)?;
    for height in 1..=count {
        let coinbase = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                // BIP34 height push plus one pad byte: consensus requires a
                // 2..=100 byte coinbase scriptSig (Core bad-cb-length).
                script_sig: Builder::new()
                    .push_int(i64::from(height))
                    .push_int(0)
                    .into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let mut block = Block {
            header: block::Header {
                version: block::Version::from_consensus(0x2000_0000),
                prev_blockhash: block_hash_from_hash256(tip.hash),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: SEED_BASE_TIME.saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
                bits: CompactTarget::from_consensus(REGTEST_BITS),
                nonce: 0,
            },
            txdata: vec![coinbase],
        };
        block.header.merkle_root = block
            .compute_merkle_root()
            .ok_or_else(|| anyhow::anyhow!("seed block must have a merkle root"))?;
        grind_pow(&mut block)?;
        state.apply_block(&block)?;
        tip = current_tip(state)?;
        assert_eq!(tip.height, height, "seed block must become the tip");
    }
    Ok(tip.hash)
}

fn current_tip(state: &NodeState) -> Result<bitcoin_rs_chain::TipSnapshot> {
    let applied = state.applied_tip();
    let Some(tip) = applied.load_full() else {
        bail!("applied tip must exist");
    };
    Ok((*tip).clone())
}

fn grind_pow(block: &mut Block) -> Result<()> {
    let target = block.header.target();
    loop {
        if block.header.validate_pow(target).is_ok() {
            return Ok(());
        }
        let Some(next) = block.header.nonce.checked_add(1) else {
            bail!("nonce exhausted while grinding block");
        };
        block.header.nonce = next;
    }
}

/// Assembles the submit-ready block from rendered template JSON fields
/// alone, the way an external miner would.
fn assemble_from_template(
    template: &sonic_rs::Value,
    template_txs: &[sonic_rs::Value],
) -> Result<Block> {
    let prev_hex = required_str(template, "previousblockhash")?;
    let height = required_u64(template, "height")?;
    let coinbase_value = required_u64(template, "coinbasevalue")?;
    let bits = u32::from_str_radix(&required_str(template, "bits")?, 16)?;
    let curtime = u32::try_from(required_u64(template, "curtime")?).unwrap_or(u32::MAX);
    let version = i32::try_from(required_u64(template, "version")?).unwrap_or(0);
    let commitment_script = ScriptBuf::from_bytes(Vec::<u8>::from_hex(&required_str(
        template,
        "default_witness_commitment",
    )?)?);
    assert!(
        commitment_script
            .as_bytes()
            .starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]),
        "default_witness_commitment must be the BIP141 commitment script"
    );

    let mut txs = Vec::with_capacity(template_txs.len());
    for entry in template_txs {
        let data = entry
            .get("data")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow::anyhow!("template transaction missing data hex"))?;
        txs.push(deserialize::<Transaction>(&Vec::<u8>::from_hex(data)?)?);
    }

    assemble_block(
        prev_hex.as_str(),
        u32::try_from(height).unwrap_or(u32::MAX),
        version,
        bits,
        curtime,
        coinbase_value,
        commitment_script,
        txs,
    )
}

/// Builds the transaction spending the height-1 seed coinbase (matured at
/// height 101) with a `MEMPOOL_TX_FEE_SATS` fee; the caller inserts it into
/// the mempool.
fn seed_coinbase_spend() -> Transaction {
    let seed_coinbase = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            // Must mirror the height-1 seed coinbase exactly (txid anchors
            // the mempool spend).
            script_sig: Builder::new().push_int(1).push_int(0).into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(seed_coinbase.compute_txid(), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS - MEMPOOL_TX_FEE_SATS),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

/// Wires the production RPC context exactly like `run()` does, with the real
/// mining coordinator installed as the `MiningControl`.
fn mining_handler(state: &NodeState) -> Handler {
    let coordinator = MiningCoordinator::new(
        state.config().network,
        state.applied_tip(),
        state.block_tree(),
        state.mempool(),
        state.apply_handles(),
        ScriptBuf::new(),
        state.shutdown(),
    )
    .with_mempool_update_wait(Duration::ZERO);
    let mining_control: Arc<dyn MiningControl> = Arc::new(coordinator);
    let ctx = Context::from_handles(ContextHandles {
        chain_tip: state.chain_tip(),
        applied_tip: state.applied_tip(),
        mempool: state.mempool(),
        blocks: state.blocks(),
        transactions: state.transactions(),
        utxo: Arc::new(UtxoSet::new()),
        coin_stats: state.coin_stats(),
        network: state.network(),
        network_active: state.network_active(),
        peers: state.peers(),
        peer_outbound: state.peer_outbound(),
        block_tree: state.block_tree(),
        chain_network: state.config().network,
        p2p_outbound_sender: Some(state.p2p_outbound_sender()),
        banned: state.banned_subnets(),
        added_nodes: Arc::new(parking_lot::RwLock::new(Vec::new())),
        tx_index: None,
        script_index: None,
    })
    .with_mining_control(mining_control);
    Handler::new(Arc::new(ctx))
}

fn assemble_block(
    prev_hex: &str,
    height: u32,
    version: i32,
    bits: u32,
    curtime: u32,
    coinbase_value: u64,
    commitment_script: ScriptBuf,
    txs: Vec<Transaction>,
) -> Result<Block> {
    let coinbase = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            // BIP34: the coinbase scriptSig begins with the serialized height.
            script_sig: Builder::new().push_int(i64::from(height)).into_script(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[WITNESS_RESERVED.to_vec()]),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(coinbase_value),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: commitment_script,
            },
        ],
    };

    let mut txdata = Vec::with_capacity(txs.len() + 1);
    txdata.push(coinbase);
    txdata.extend(txs);

    let mut block = Block {
        header: block::Header {
            version: block::Version::from_consensus(version),
            prev_blockhash: prev_hex
                .parse()
                .map_err(|err| anyhow::anyhow!("invalid previousblockhash: {err}"))?,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: curtime,
            bits: CompactTarget::from_consensus(bits),
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or_else(|| anyhow::anyhow!("block must have a merkle root"))?;
    grind_pow(&mut block)?;
    Ok(block)
}

fn block_hash_from_hash256(hash: Hash256) -> bitcoin::BlockHash {
    bitcoin::BlockHash::from_byte_array(*hash.as_byte_array())
}

fn required_str(value: &sonic_rs::Value, key: &str) -> Result<String> {
    let text = value
        .get(key)
        .and_then(|text| text.as_str())
        .ok_or_else(|| anyhow::anyhow!("template field {key} missing or not a string"))?;
    Ok(text.to_owned())
}

fn required_u64(value: &sonic_rs::Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(sonic_rs::JsonValueTrait::as_i64)
        .and_then(|number| u64::try_from(number).ok())
        .ok_or_else(|| anyhow::anyhow!("template field {key} missing or not a number"))
}
