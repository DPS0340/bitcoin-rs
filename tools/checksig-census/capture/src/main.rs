//! CHECKSIG census capture harness.
//!
//! Reads a KSPIKE1 corpus and verifies every non-coinbase input exactly once
//! through the production `KernelContext::verify_tx` path, using the mainnet
//! activation-height fallback that matches production on the active chain.
//! No width loop, no Rayon pools, no timers, and
//! no preliminary correctness pass — each input is verified once and only
//! once.
//!
//! Adapted from `crates/consensus/examples/kernel_verify_spike.rs`, with the
//! extraction phase, width loop, parallel pools, timing, and untimed pre-pass
//! removed. The corpus format and standalone activation-height fallback are
//! preserved.
//!
//! CLI:
//!   --corpus PATH                (required) KSPIKE1 corpus file
//!   --output PATH                JSON summary file (default: stdout)
//!   --start HEIGHT               first block height to include [0]
//!   --stop HEIGHT                last block height to include [u32::MAX]
//!   --counters PATH              native census counters JSON output
//!   --journal PATH               native census journal binary output
//!   --context-sidecar PATH       per-input context JSONL sidecar
//!
//! The native census sink paths are wired through the BRS_CENSUS_* environment
//! variables when no explicit path is given; when a path is given it is both
//! exported to the environment and recorded in the summary.  The context
//! sidecar is always written; if `--context-sidecar` is omitted it is derived
//! from `--output` (or `--corpus` if no output is given).
//!
//! A verification failure prints height, tx index, and input index to stderr
//! and exits non-zero.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::ffi::OsString;
use std::io::{BufReader, BufWriter, Read as _, Write as _};
use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use bitcoin::consensus::Decodable as _;
use bitcoin::hashes::{Hash as _, HashEngine as _, sha256};
use bitcoin::hex::DisplayHex as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut};
use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_consensus::UtxoView;
use bitcoin_rs_consensus::kernel::KernelContext;
use bitcoin_rs_primitives::{Hash256, Network, Tx};
use bitcoin_rs_script::VerifyFlags;
use serde_json::json;

// ── Constants ──────────────────────────────────────────────────────────────

const CORPUS_MAGIC: &[u8; 8] = b"KSPIKE1\0";
const SIDECAR_SCHEMA: &str = "census-context-input-v1";
const SUMMARY_SCHEMA: &str = "census-capture-v2";

/// Maximum acceptable length for a single `read_bytes` blob (4 MiB). Block
/// bytes are at most ~4 MiB with segwit; scriptPubKeys are far smaller. This
/// guards against a corrupted count field triggering an absurd allocation.
const MAX_BLOB_LEN: usize = 4 * 1024 * 1024;

const CENSUS_COUNTERS_ENV: &str = "BRS_CENSUS_COUNTERS";
const CENSUS_JOURNAL_ENV: &str = "BRS_CENSUS_JOURNAL";

// ── Entry point ────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse(std::env::args_os().skip(1))?;

    // Resolve the sidecar path before anything else so we can fail early.
    let sidecar_path = args
        .context_sidecar
        .clone()
        .unwrap_or_else(|| resolve_default_sidecar(&args.corpus, args.output.as_ref()));
    ensure_parent(&sidecar_path)?;

    // The harness is still single-threaded here. Configure the native sinks
    // before the kernel or any worker pool can read the process environment.
    if let Some(path) = &args.counters {
        ensure_parent(path)?;
        // SAFETY: no other thread can access the environment before this call.
        unsafe { std::env::set_var(CENSUS_COUNTERS_ENV, path.as_os_str()) };
    }
    if let Some(path) = &args.journal {
        ensure_parent(path)?;
        // SAFETY: no other thread can access the environment before this call.
        unsafe { std::env::set_var(CENSUS_JOURNAL_ENV, path.as_os_str()) };
    }

    let (corpus_size, corpus_sha256) = sha256_file(&args.corpus)?;
    let corpus = load_corpus(&args.corpus)?;
    let (corpus_min, corpus_max) = corpus_height_range(&corpus);

    let start = args.start;
    let stop = args.stop;
    if stop < start {
        bail!("inconsistent bounds: stop {stop} < start {start}");
    }
    if start > corpus_max || stop < corpus_min {
        bail!(
            "out-of-range blocks: requested {start}..={stop}, corpus spans {corpus_min}..={corpus_max}"
        );
    }

    let filtered: Vec<&SampleBlock> = corpus
        .iter()
        .filter(|sample| sample.height >= start && sample.height <= stop)
        .collect();
    if filtered.is_empty() {
        bail!("empty filtered range: no blocks in {start}..={stop}");
    }
    let height_min = filtered.iter().map(|sample| sample.height).min().unwrap();
    let height_max = filtered.iter().map(|sample| sample.height).max().unwrap();

    let sidecar_file = std::fs::File::create(&sidecar_path)
        .with_context(|| format!("create sidecar {}", sidecar_path.display()))?;
    let mut sidecar = BufWriter::new(sidecar_file);
    let mut hasher = sha256::Hash::engine();

    let kernel = KernelContext::new(bitcoin::Network::Bitcoin)
        .map_err(|error| anyhow::anyhow!("create kernel context: {error}"))?;

    let mut blocks: u64 = 0;
    let mut non_coinbase_inputs: u64 = 0;
    let mut verified_inputs: u64 = 0;

    for sample in &filtered {
        blocks += 1;

        let block =
            bitcoin::Block::consensus_decode(&mut std::io::Cursor::new(sample.raw.as_slice()))
                .with_context(|| format!("decode corpus block at height {}", sample.height))?;
        let hash = block.block_hash();
        let block_hash = hash.to_string();
        let flags = production_verify_flags(
            Network::Mainnet,
            sample.height,
            Hash256::from_le_bytes(hash.as_byte_array()),
        );

        let mut prevouts = sample.prevouts.iter();

        for (tx_index, tx) in block.txdata.iter().enumerate() {
            if tx.is_coinbase() {
                continue;
            }

            let txid = tx.compute_txid().to_string();
            let mut map = hashbrown::HashMap::with_capacity(tx.input.len());
            for input in &tx.input {
                let rec = prevouts.next().with_context(|| {
                    format!("corpus prevout underrun at height {}", sample.height)
                })?;
                map.insert(
                    input.previous_output,
                    TxOut {
                        value: Amount::from_sat(rec.amount),
                        script_pubkey: ScriptBuf::from_bytes(rec.script.clone()),
                    },
                );
            }

            let input_count = u64::try_from(tx.input.len()).context("input count overflow")?;
            non_coinbase_inputs += input_count;

            let prevout_map = PrevoutMap(map);
            kernel
                .verify_tx(&Tx(tx.clone()), &prevout_map, sample.height, flags)
                .map_err(|error| {
                    anyhow::anyhow!(
                        "verification failed: height {} tx_index {} input_index {}: {error}",
                        sample.height,
                        tx_index,
                        extract_input_index(&error),
                    )
                })?;

            for (input_index, input) in tx.input.iter().enumerate() {
                let prevout = prevout_map.get(&input.previous_output).with_context(|| {
                    format!(
                        "missing prevout for sidecar at height {} tx_index {} input_index {}",
                        sample.height, tx_index, input_index
                    )
                })?;
                let witness_hex: Vec<String> = input
                    .witness
                    .iter()
                    .map(|item| item.to_lower_hex_string())
                    .collect();

                let row = json!({
                    "schema": SIDECAR_SCHEMA,
                    "height": sample.height,
                    "block_hash": block_hash,
                    "tx_index": tx_index,
                    "input_index": input_index,
                    "txid": txid,
                    "prevout_script_pubkey_hex": prevout.script_pubkey.as_bytes().to_lower_hex_string(),
                    "script_sig_hex": input.script_sig.as_bytes().to_lower_hex_string(),
                    "witness_hex": witness_hex,
                });
                let mut line = serde_json::to_string(&row).context("serialize sidecar row")?;
                line.push('\n');

                sidecar
                    .write_all(line.as_bytes())
                    .with_context(|| format!("write sidecar {}", sidecar_path.display()))?;
                hasher.input(line.as_bytes());
                verified_inputs += 1;
            }
        }

        if prevouts.next().is_some() {
            bail!("corpus prevout overrun at height {}", sample.height);
        }
    }

    if verified_inputs == 0 {
        bail!("zero verified inputs in range {start}..={stop}");
    }

    sidecar
        .flush()
        .with_context(|| format!("flush sidecar {}", sidecar_path.display()))?;
    sidecar
        .get_ref()
        .sync_all()
        .with_context(|| format!("sync sidecar {}", sidecar_path.display()))?;
    let sidecar_hash = sha256::Hash::from_engine(hasher).to_string();

    // SAFETY: This zero-argument FFI call flushes process-global census sinks.
    // Verification is complete, so no worker can still append records.
    let flush_status = unsafe { libbitcoinkernel_sys::btck_census_flush() };
    if flush_status != 0 {
        bail!("flush census artifacts failed");
    }

    let summary = json!({
        "schema": SUMMARY_SCHEMA,
        "corpus": args.corpus.display().to_string(),
        "corpus_size": corpus_size,
        "corpus_sha256": corpus_sha256,
        "range": {
            "start": start,
            "stop": stop,
            "height_min": height_min,
            "height_max": height_max,
        },
        "blocks": blocks,
        "non_coinbase_inputs": non_coinbase_inputs,
        "verified_inputs": verified_inputs,
        "sidecar": sidecar_path.display().to_string(),
        "sidecar_sha256": sidecar_hash,
        "counters": args.counters.as_ref().map(|p| p.display().to_string()),
        "journal": args.journal.as_ref().map(|p| p.display().to_string()),
    });

    let rendered = serde_json::to_string_pretty(&summary).context("render summary JSON")?;

    match &args.output {
        Some(path) => {
            ensure_parent(path)?;
            std::fs::write(path, rendered + "\n")
                .with_context(|| format!("write {}", path.display()))?;
        }
        None => {
            println!("{rendered}");
        }
    }

    Ok(())
}

// ── CLI ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Args {
    corpus: PathBuf,
    output: Option<PathBuf>,
    start: u32,
    stop: u32,
    counters: Option<PathBuf>,
    journal: Option<PathBuf>,
    context_sidecar: Option<PathBuf>,
}

impl Args {
    fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let mut corpus: Option<PathBuf> = None;
        let mut output: Option<PathBuf> = None;
        let mut start: Option<u32> = None;
        let mut stop: Option<u32> = None;
        let mut counters: Option<PathBuf> = None;
        let mut journal: Option<PathBuf> = None;
        let mut context_sidecar: Option<PathBuf> = None;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let arg = arg
                .into_string()
                .map_err(|value| anyhow::anyhow!("argument is not UTF-8: {}", value.display()))?;
            match arg.as_str() {
                "--corpus" => corpus = Some(PathBuf::from(next_arg(&mut args, "--corpus")?)),
                "--output" => output = Some(PathBuf::from(next_arg(&mut args, "--output")?)),
                "--start" => start = Some(parse_u32(&next_arg(&mut args, "--start")?, "--start")?),
                "--stop" => stop = Some(parse_u32(&next_arg(&mut args, "--stop")?, "--stop")?),
                "--counters" => counters = Some(PathBuf::from(next_arg(&mut args, "--counters")?)),
                "--journal" => journal = Some(PathBuf::from(next_arg(&mut args, "--journal")?)),
                "--context-sidecar" => {
                    context_sidecar = Some(PathBuf::from(next_arg(&mut args, "--context-sidecar")?))
                }
                other => bail!(
                    "unknown argument: {other}\nusage: checksig-census-capture --corpus <path> [--output <path>] [--start <u32>] [--stop <u32>] [--counters <path>] [--journal <path>] [--context-sidecar <path>]"
                ),
            }
        }
        let corpus = corpus.context("--corpus is required")?;
        Ok(Self {
            corpus,
            output,
            start: start.unwrap_or(0),
            stop: stop.unwrap_or(u32::MAX),
            counters,
            journal,
            context_sidecar,
        })
    }
}

fn next_arg(args: &mut impl Iterator<Item = OsString>, name: &str) -> Result<String> {
    args.next()
        .with_context(|| format!("{name} requires a value"))?
        .into_string()
        .map_err(|value| anyhow::anyhow!("{name} value is not UTF-8: {}", value.display()))
}

fn parse_u32(value: &str, name: &str) -> Result<u32> {
    value
        .parse::<u32>()
        .with_context(|| format!("{name} must be a non-negative 32-bit integer, got {value}"))
}

fn resolve_default_sidecar(corpus: &std::path::Path, output: Option<&PathBuf>) -> PathBuf {
    if let Some(path) = output {
        path.with_extension("context.jsonl")
    } else {
        corpus.with_extension("context.jsonl")
    }
}

fn ensure_parent(path: &std::path::Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    Ok(())
}

fn sha256_file(path: &std::path::Path) -> Result<(u64, String)> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("open corpus for hashing {}", path.display()))?;
    let size = file
        .metadata()
        .with_context(|| format!("stat corpus {}", path.display()))?
        .len();
    let mut reader = BufReader::new(file);
    let mut hasher = sha256::Hash::engine();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .with_context(|| format!("hash corpus {}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.input(&buffer[..count]);
    }
    Ok((size, sha256::Hash::from_engine(hasher).to_string()))
}

fn corpus_height_range(corpus: &[SampleBlock]) -> (u32, u32) {
    (
        corpus.iter().map(|sample| sample.height).min().unwrap_or(0),
        corpus.iter().map(|sample| sample.height).max().unwrap_or(0),
    )
}

// ── Production flag derivation ──────────────────────────────────────────────

/// Mirrors the buried-deployment fallback in `compute_verify_flags` from
/// `crates/node/src/apply.rs`, including Core's hash-pinned BIP16 exception.
fn production_verify_flags(network: Network, height: u32, block_hash: Hash256) -> VerifyFlags {
    let mut flags = VerifyFlags::NONE;
    if !network.is_bip16_p2sh_exception(block_hash) {
        flags = flags.union(VerifyFlags::P2SH);
    }
    if network.is_bip66_active(height) {
        flags = flags.union(VerifyFlags::DERSIG);
    }
    if network.is_bip65_active(height) {
        flags = flags.union(VerifyFlags::CHECKLOCKTIMEVERIFY);
    }
    if network.is_csv_active(height) {
        flags = flags.union(VerifyFlags::CHECKSEQUENCEVERIFY);
    }
    if network.is_segwit_active(height) {
        flags = flags
            .union(VerifyFlags::WITNESS)
            .union(VerifyFlags::NULLDUMMY);
    }
    if network.is_taproot_active(height) {
        flags = flags.union(VerifyFlags::TAPROOT);
    }
    flags
}

// ── Corpus loader ──────────────────────────────────────────────────────────

/// One prevout spent by a sampled block, in (tx order, input order).
struct PrevoutRec {
    amount: u64,
    script: Vec<u8>,
}

/// One sampled heavy block plus the prevouts its non-coinbase inputs spend.
struct SampleBlock {
    height: u32,
    raw: Vec<u8>,
    prevouts: Vec<PrevoutRec>,
}

/// Loads and validates a KSPIKE1 corpus file.
///
/// Validates magic, block/prevout counts, and rejects trailing bytes. The
/// prevout-count-vs-input-count consistency is checked during verification
/// (underrun/overrun), matching the spike harness.
fn load_corpus(path: &std::path::Path) -> Result<Vec<SampleBlock>> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = BufReader::new(file);

    let mut magic = [0_u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != CORPUS_MAGIC {
        bail!("{} is not a KSPIKE1 corpus", path.display());
    }

    let block_count = read_u32(&mut reader)?;
    let mut samples = Vec::with_capacity(usize::try_from(block_count)?);
    for _ in 0..block_count {
        let height = read_u32(&mut reader)?;
        let raw = read_bytes(&mut reader)?;
        let prevout_count = read_u32(&mut reader)?;
        let mut prevouts = Vec::with_capacity(usize::try_from(prevout_count)?);
        for _ in 0..prevout_count {
            let mut amount = [0_u8; 8];
            reader.read_exact(&mut amount)?;
            prevouts.push(PrevoutRec {
                amount: u64::from_le_bytes(amount),
                script: read_bytes(&mut reader)?,
            });
        }
        samples.push(SampleBlock {
            height,
            raw,
            prevouts,
        });
    }

    // Reject trailing bytes — the corpus must be exactly consumed.
    let mut trailer = [0_u8; 1];
    match reader.read(&mut trailer) {
        Ok(0) => {}
        Ok(_) => bail!("corpus has trailing bytes after {} blocks", block_count),
        Err(error) => bail!("corpus trailer read failed: {error}"),
    }

    Ok(samples)
}

fn read_u32(reader: &mut impl std::io::Read) -> Result<u32> {
    let mut buf = [0_u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_bytes(reader: &mut impl std::io::Read) -> Result<Vec<u8>> {
    let len = usize::try_from(read_u32(reader)?)?;
    if len > MAX_BLOB_LEN {
        bail!("blob length {len} exceeds {MAX_BLOB_LEN}");
    }
    let mut bytes = vec![0_u8; len];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

// ── Prevout view ───────────────────────────────────────────────────────────

/// Resolved prevouts for one transaction, served through the same `UtxoView`
/// seam `verify_tx` uses in production.
struct PrevoutMap(hashbrown::HashMap<OutPoint, TxOut>);

impl PrevoutMap {
    fn get(&self, outpoint: &OutPoint) -> Option<&TxOut> {
        self.0.get(outpoint)
    }
}

impl UtxoView for PrevoutMap {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.0.get(outpoint).cloned()
    }
}

// ── Error helpers ──────────────────────────────────────────────────────────

/// Extracts the failing input index from a `ConsensusError`, if the variant
/// carries one. `Kernel` errors (parse/precompute failures) are tx-level and
/// do not carry an input index.
fn extract_input_index(error: &ConsensusError) -> String {
    match error {
        ConsensusError::Script { input_index, .. } => input_index.to_string(),
        ConsensusError::MissingPrevout { input_index } => input_index.to_string(),
        ConsensusError::NullPrevout { input_index } => input_index.to_string(),
        ConsensusError::DuplicateInput { input_index } => input_index.to_string(),
        _ => "n/a".to_owned(),
    }
}
