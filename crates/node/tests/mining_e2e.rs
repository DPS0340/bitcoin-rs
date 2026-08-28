//! Mining E2E: template → external-style assembly → submitblock → tip.
//!
//! The test drives the production RPC handlers (`getblocktemplate`,
//! `submitblock`) exactly like an external miner: the block is assembled from
//! rendered template JSON fields only, then enters ordinary validation.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use bitcoin_rs_node::{Config, MiningCoordinator, Network, state::NodeState};
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_primitives::{
    Block, Hash256, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
    deserialize as native_deserialize,
};
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
        seed_tip_hash.to_string_be(),
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
        mempool_tx.txid().to_string(),
        "the selected template tx must be the mempool tx"
    );

    // --- external-miner-style assembly from JSON fields only -----------------
    let block = assemble_from_template(&template, template_txs)?;

    // --- submitblock over the real RPC handler -------------------------------
    let hex = hex_encode(&consensus_bytes(&block));
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
        Hash256::from(block.block_hash()),
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
    let genesis = Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    Ok(())
}

/// Mines `count` trivial-PoW regtest blocks through ordinary validation,
/// each coinbase paying an anyone-can-spend output.
fn seed_chain(state: &NodeState, count: u32) -> Result<Hash256> {
    let mut tip = current_tip(state)?;
    for height in 1..=count {
        let coinbase = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: null_prevout(),
                // BIP34 height push plus one pad byte: consensus requires a
                // 2..=100 byte coinbase scriptSig (Core bad-cb-length).
                script_sig: [script_push_int(i64::from(height)), script_push_int(0)].concat(),
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: REGTEST_SUBSIDY_SATS,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        };
        let mut block = Block {
            header: bitcoin_rs_primitives::Header {
                version: 0x2000_0000,
                prev_blockhash: bitcoin_rs_primitives::BlockHash::from(tip.hash),
                merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
                time: SEED_BASE_TIME.saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
                bits: REGTEST_BITS,
                nonce: 0,
            },
            txs: vec![coinbase],
        };
        block.header.merkle_root = compute_merkle_root(&block.txs)
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
    loop {
        if pow_is_met(block.header.bits, &block.header.compute_hash().into()) {
            return Ok(());
        }
        let Some(next) = block.header.nonce.checked_add(1) else {
            bail!("nonce exhausted while grinding block");
        };
        block.header.nonce = next;
    }
}

/// Returns true when the header hash, read as a little-endian integer, meets
/// the compact bits target (Core `CheckProofOfWork` shape).
fn pow_is_met(bits: u32, hash: &Hash256) -> bool {
    let exponent = usize::try_from(bits >> 24).unwrap_or(usize::MAX);
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 || mantissa & 0x0080_0000 != 0 || exponent > 32 {
        return false;
    }
    let shift = exponent.saturating_sub(3);
    // Little-endian target bytes: mantissa placed `shift` bytes from the
    // least-significant end (mantissa is masked below 2^24, so three bytes).
    let mantissa_le = mantissa.to_le_bytes();
    let mut target = [0_u8; 32];
    for (offset, byte) in mantissa_le.iter().take(3).enumerate() {
        let position = shift + offset;
        if position < 32 {
            target[position] = *byte;
        }
    }
    // Both sides are little-endian 32-byte integers: compare from the most
    // significant byte downward (Core `CheckProofOfWork`).
    let hash_le = hash.to_le_bytes();
    for index in (0..32).rev() {
        match hash_le[index].cmp(&target[index]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    true
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
    let commitment_script = hex_decode(&required_str(template, "default_witness_commitment")?)?;
    assert!(
        commitment_script.starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]),
        "default_witness_commitment must be the BIP141 commitment script"
    );

    let mut txs = Vec::with_capacity(template_txs.len());
    for entry in template_txs {
        let data = entry
            .get("data")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow::anyhow!("template transaction missing data hex"))?;
        txs.push(native_deserialize::<Tx>(&hex_decode(data)?)?);
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
fn seed_coinbase_spend() -> Tx {
    let seed_coinbase = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: null_prevout(),
            // Must mirror the height-1 seed coinbase exactly (txid anchors
            // the mempool spend).
            script_sig: [script_push_int(1), script_push_int(0)].concat(),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: REGTEST_SUBSIDY_SATS,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(seed_coinbase.txid(), 0),
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: REGTEST_SUBSIDY_SATS - MEMPOOL_TX_FEE_SATS,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
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
        Vec::new(),
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
    commitment_script: Vec<u8>,
    txs: Vec<Tx>,
) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: null_prevout(),
            // BIP34: the coinbase scriptSig begins with the serialized height.
            script_sig: script_push_int(i64::from(height)),
            sequence: 0xffff_ffff,
            witness: vec![WITNESS_RESERVED.to_vec()],
        }],
        outputs: vec![
            TxOut {
                value: coinbase_value,
                script_pubkey: vec![0x51],
            },
            TxOut {
                value: 0,
                script_pubkey: commitment_script,
            },
        ],
        lock_time: 0,
    };

    let mut block_txs = Vec::with_capacity(txs.len() + 1);
    block_txs.push(coinbase);
    block_txs.extend(txs);

    let mut block = Block {
        header: bitcoin_rs_primitives::Header {
            version,
            prev_blockhash: prev_hex
                .parse::<bitcoin_rs_primitives::BlockHash>()
                .map_err(|err| anyhow::anyhow!("invalid previousblockhash: {err}"))?,
            merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
            time: curtime,
            bits,
            nonce: 0,
        },
        txs: block_txs,
    };
    block.header.merkle_root = compute_merkle_root(&block.txs)
        .ok_or_else(|| anyhow::anyhow!("block must have a merkle root"))?;
    grind_pow(&mut block)?;
    Ok(block)
}

/// The one-input null-prevout coinbase outpoint (Core `COINBASE_OUTPOINT`).
fn null_prevout() -> OutPoint {
    OutPoint::new(Txid::default(), u32::MAX)
}

/// Minimal script push of a small integer, mirroring rust-bitcoin
/// `Builder::push_int`: `OP_0` for zero, `OP_N` for 1..=16, otherwise a
/// length-prefixed little-endian payload (BIP34 heights).
fn script_push_int(value: i64) -> Vec<u8> {
    match value {
        0 => vec![0x00],
        // `value` is pinned to 1..=16 by the match arm.
        1..=16 => vec![0x50 + u8::try_from(value).unwrap_or_default()],
        _ => {
            let mut payload = Vec::new();
            let mut magnitude = value.unsigned_abs();
            while magnitude > 0 {
                // Low byte only; the shift below consumes it fully.
                payload.push(u8::try_from(magnitude & 0xff).unwrap_or_default());
                magnitude >>= 8;
            }
            let mut out = Vec::with_capacity(payload.len() + 1);
            // A small-int push never exceeds 8 payload bytes.
            out.push(u8::try_from(payload.len()).unwrap_or_default());
            out.extend(payload);
            out
        }
    }
}

/// Native BIP141-style txid merkle fold with the odd-leaf duplication rule.
fn compute_merkle_root(txs: &[Tx]) -> Option<Hash256> {
    if txs.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pos in 0..level.len().div_ceil(2) {
            let left = level[2 * pos];
            let right = level[(2 * pos + 1).min(level.len() - 1)];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(*double_sha256(&pair).as_byte_array());
        }
        level = next;
    }
    Some(Hash256::from_le_bytes(&level[0]))
}

/// Encodes `bytes` as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// Decodes a hexadecimal string into bytes.
fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        bail!("hex string must have even length");
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0]).ok_or_else(|| anyhow::anyhow!("invalid hex"))?;
        let lo = hex_nibble(pair[1]).ok_or_else(|| anyhow::anyhow!("invalid hex"))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Decodes one ASCII hex nibble.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
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
