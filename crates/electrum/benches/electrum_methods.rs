//! End-to-end Electrum method benchmark.
//!
//! Drives the real `dispatch` entry point over an `IndexerHistoryReader` backed
//! by a populated `RocksDB` index, so the measured cost is what an Electrum
//! client actually pays — JSON parameter parsing, resolver work, and JSON
//! rendering included.
//!
//! This is the benchmark the G14 budget is written against: Electrum
//! `blockchain.scripthash.get_history` p95 <= 30 ms. `scripts/measure-g14-electrum-rss.sh`
//! remains the gate of record; this harness is the in-tree signal used while
//! iterating.
//!
//! Every group holds **both arms** of a refactor set over one identical
//! fixture. At the baseline commit both arms call the same path.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]
// A benchmark fixture that fails to build has no meaningful degraded mode: a
// dispatch returning `Err` would be timed as a fast early return and reported
// as a win. Panicking is the correct outcome, so `expect` is deliberate here
// and confined to fixture setup and the timed calls' error arms.
#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, Witness, absolute, block, transaction,
};
use bitcoin_rs_electrum::methods::IndexerHistoryReader;
use bitcoin_rs_electrum::{IndexHandle, MempoolHandle, dispatch};
use bitcoin_rs_index::{BlockSource, Indexer, ScriptHash};
use bitcoin_rs_storage::RocksDbStore;
use bitcoin_rs_storage::block_file::{BlockFilePosition, FlatFileBlockStore};
use criterion::{Criterion, criterion_group, criterion_main};
use hashbrown::HashMap;
use sonic_rs::{JsonContainerTrait as _, Value, json};

/// Filler transactions per fixture block (~250 KB serialized).
const TXS_PER_BLOCK: usize = 2_200;
/// First height a fixture block is placed at.
const BASE_HEIGHT: u32 = 100;

/// Block source over a real flat-file store, mirroring
/// `FlatFilePruneBodyStore`: a position lookup, then `load` for a whole body or
/// `load_range` for a slice. Both pay the real open/`fstat`/seek/read sequence,
/// so the reported cost is one a node can actually see.
#[derive(Clone)]
struct FlatFileBlockSource {
    files: Arc<FlatFileBlockStore>,
    positions: Arc<HashMap<u32, (BlockFilePosition, [u8; 32])>>,
}

impl core::fmt::Debug for FlatFileBlockSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FlatFileBlockSource")
            .finish_non_exhaustive()
    }
}

impl BlockSource for FlatFileBlockSource {
    fn block_at_height(&self, height: u32) -> Option<Block> {
        let (position, hash) = self.positions.get(&height)?;
        let bytes = self.files.load(*position, height, *hash).ok()??;
        deserialize::<Block>(&bytes).ok()
    }

    fn block_bytes_at_height(&self, height: u32, offset: u32, len: u32) -> Option<Vec<u8>> {
        let (position, hash) = self.positions.get(&height)?;
        self.files
            .load_range(*position, height, *hash, offset, len)
            .ok()?
    }
}

const fn next_u64(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

/// Fills `out` from whole LCG draws.
///
/// Taking one byte per draw would be a trap: in an LCG modulo 2^64 the low byte
/// evolves independently of the high bits, so `state & 0xff` has period 256 and
/// every generated script would collapse into 256 distinct values. That makes
/// filler scripts collide with the target and silently corrupts the fixture.
fn fill_bytes(seed: u64, out: &mut [u8]) {
    let mut state = seed;
    for chunk in out.chunks_mut(8) {
        let draw = next_u64(&mut state).to_le_bytes();
        chunk.copy_from_slice(&draw[..chunk.len()]);
    }
}

/// 22-byte P2WPKH-shaped script, so scripthash computation costs what it costs
/// on mainnet rather than on a toy script.
fn witness_script(seed: u64) -> ScriptBuf {
    let mut bytes = vec![0x00, 0x14];
    let mut program = [0_u8; 20];
    fill_bytes(seed, &mut program);
    bytes.extend_from_slice(&program);
    ScriptBuf::from_bytes(bytes)
}

fn filler_tx(seed: u64) -> Transaction {
    let mut txid_bytes = [0_u8; 32];
    fill_bytes(seed, &mut txid_bytes);
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(txid_bytes),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(5_000),
                script_pubkey: witness_script(seed ^ 0xa5a5_a5a5),
            },
            TxOut {
                value: Amount::from_sat(7_000),
                script_pubkey: witness_script(seed ^ 0x5a5a_5a5a),
            },
        ],
    }
}

fn target_tx(height: u32, target_script: &ScriptBuf) -> Transaction {
    let mut txid_bytes = [0_u8; 32];
    fill_bytes(
        u64::from(height).wrapping_mul(0x9e37_79b9_7f4a_7c15),
        &mut txid_bytes,
    );
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(txid_bytes),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(11_000),
            script_pubkey: target_script.clone(),
        }],
    }
}

fn empty_header() -> block::Header {
    block::Header {
        version: block::Version::ONE,
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: 0,
        bits: CompactTarget::from_consensus(0),
        nonce: 0,
    }
}

struct Fixture {
    // Held for their `Drop`: the RocksDB and block-file directories must outlive
    // the handle.
    _dir: tempfile::TempDir,
    _blocks_dir: tempfile::TempDir,
    index: IndexHandle,
    mempool: MempoolHandle,
    /// `[scripthash_hex]` params, pre-parsed once so the benchmark measures
    /// dispatch rather than `sonic_rs` fixture construction.
    params: Value,
}

/// Builds `heights` blocks with one transaction paying the target scripthash
/// planted at each block's midpoint, then wires the populated index into an
/// `IndexHandle` through the production `IndexerHistoryReader`.
fn build_fixture(heights: u32) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let blocks_dir = tempfile::tempdir().expect("blocks tempdir");
    let store = Arc::new(RocksDbStore::open(dir.path()).expect("open rocksdb"));
    let files = Arc::new(FlatFileBlockStore::open(blocks_dir.path()).expect("open block files"));
    let mut indexer = Indexer::new(Arc::clone(&store));

    let target_script = witness_script(0xdead_beef);
    let target = ScriptHash::from_script_bytes(target_script.as_bytes());

    let mut positions = HashMap::new();
    let midpoint = TXS_PER_BLOCK / 2;

    for index in 0..heights {
        let height = BASE_HEIGHT + index;
        let planted = target_tx(height, &target_script);

        let mut txdata = Vec::with_capacity(TXS_PER_BLOCK + 1);
        for slot in 0..TXS_PER_BLOCK {
            if slot == midpoint {
                txdata.push(planted.clone());
            }
            let seed = u64::from(height)
                .wrapping_mul(1_000_003)
                .wrapping_add(u64::try_from(slot).unwrap_or(0));
            txdata.push(filler_tx(seed));
        }

        let block = Block {
            header: empty_header(),
            txdata,
        };
        let bytes = serialize(&block);
        indexer
            .ingest_block(&bytes, height)
            .expect("ingest fixture block");
        let hash = block.block_hash().to_byte_array();
        let position = files
            .persist(None, height, hash, &bytes)
            .expect("persist fixture body");
        positions.insert(height, (position, hash));
    }

    let source = FlatFileBlockSource {
        files,
        positions: Arc::new(positions),
    };
    let reader = Arc::new(IndexerHistoryReader::new(Arc::new(indexer), source));
    let handle = IndexHandle::from_store(store).with_history_reader(reader);

    let hex = bitcoin_rs_electrum::methods::scripthash_hex(target);
    let params = json!([hex]);
    let mempool = MempoolHandle::default();

    // A fixture that resolves nothing would benchmark JSON plumbing over an
    // empty result and report a meaningless speedup. Prove it resolves first.
    let history = dispatch(
        "blockchain.scripthash.get_history",
        &handle,
        &mempool,
        &params,
    )
    .expect("fixture history dispatch succeeds");
    assert_eq!(
        history.as_array().map(sonic_rs::Array::len),
        Some(usize::try_from(heights).unwrap_or(0)),
        "fixture must return exactly one history entry per height"
    );

    Fixture {
        _dir: dir,
        _blocks_dir: blocks_dir,
        index: handle,
        mempool,
        params,
    }
}

/// Emits the paired `before`/`after` arms for one Electrum method.
///
/// Both arms call the same dispatch entry point; what differs is the resolver
/// underneath, which `dispatch` selects. The spread therefore reports the win
/// once a set lands under it, and the harness noise floor before that.
fn bench_method(c: &mut Criterion, method: &'static str, label: &str, fixture: &Fixture) {
    let Fixture {
        index,
        mempool,
        params,
        ..
    } = fixture;

    let mut group = c.benchmark_group(format!("{method}/{label}"));
    group.bench_function("before_scan", |b| {
        b.iter(|| {
            black_box(
                dispatch(black_box(method), index, mempool, params).expect("dispatch succeeds"),
            )
        });
    });
    group.bench_function("after_fast", |b| {
        b.iter(|| {
            black_box(
                dispatch(black_box(method), index, mempool, params).expect("dispatch succeeds"),
            )
        });
    });
    group.finish();
}

fn electrum_methods(c: &mut Criterion) {
    for heights in [1_u32, 8, 64] {
        let fixture = build_fixture(heights);
        let label = format!("heights_{heights}");
        // `get_history` is the method the G14 p95 budget is written against.
        bench_method(c, "blockchain.scripthash.get_history", &label, &fixture);
        // `subscribe` runs the same resolution then hashes the status; an
        // Electrum wallet issues one per address on connect, so it is the
        // highest-volume caller of this path.
        bench_method(c, "blockchain.scripthash.subscribe", &label, &fixture);
        bench_method(c, "blockchain.scripthash.get_balance", &label, &fixture);
        bench_method(c, "blockchain.scripthash.listunspent", &label, &fixture);
    }
}

criterion_group! {
    name = benches;
    // Resolution at 64 heights runs in the millisecond range, so the Criterion
    // default of 100 samples would put a single group in the tens of seconds.
    config = Criterion::default().sample_size(20);
    targets = electrum_methods
}
criterion_main!(benches);
