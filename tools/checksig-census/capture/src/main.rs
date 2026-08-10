//! CHECKSIG census capture harness.
//!
//! Reads a KSPIKE1 corpus and verifies every non-coinbase input exactly once
//! through the production `KernelContext::verify_tx` path, using per-height
//! flags derived identically to `compute_verify_flags` in
//! `crates/node/src/apply.rs`. No width loop, no Rayon pools, no timers, and
//! no preliminary correctness pass — each input is verified once and only
//! once.
//!
//! Adapted from `crates/consensus/examples/kernel_verify_spike.rs`, with the
//! extraction phase, width loop, parallel pools, timing, and untimed pre-pass
//! removed. The corpus format and production flag derivation are preserved
//! exactly.
//!
//! CLI: `--corpus PATH [--output PATH]`. Emits a concise JSON summary to
//! `--output` if given, otherwise stdout. A verification failure prints
//! height, tx index, and input index to stderr and exits non-zero.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::ffi::OsString;
use std::io::{BufReader, Read as _};
use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use bitcoin::consensus::Decodable as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut};
use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_consensus::UtxoView;
use bitcoin_rs_consensus::kernel::KernelContext;
use bitcoin_rs_primitives::{Network, Tx};
use bitcoin_rs_script::VerifyFlags;
use serde_json::json;

// ── Constants ──────────────────────────────────────────────────────────────

const CORPUS_MAGIC: &[u8; 8] = b"KSPIKE1\0";
const SUMMARY_SCHEMA: u32 = 1;

/// Maximum acceptable length for a single `read_bytes` blob (4 MiB). Block
/// bytes are at most ~4 MiB with segwit; scriptPubKeys are far smaller. This
/// guards against a corrupted count field triggering an absurd allocation.
const MAX_BLOB_LEN: usize = 4 * 1024 * 1024;

// ── Entry point ────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse(std::env::args_os().skip(1))?;

    let corpus = load_corpus(&args.corpus)?;

    let kernel = KernelContext::new(bitcoin::Network::Bitcoin)
        .map_err(|error| anyhow::anyhow!("create kernel context: {error}"))?;

    let mut blocks: u64 = 0;
    let mut non_coinbase_inputs: u64 = 0;
    let mut verified_inputs: u64 = 0;

    for sample in &corpus {
        blocks += 1;

        let block =
            bitcoin::Block::consensus_decode(&mut std::io::Cursor::new(sample.raw.as_slice()))
                .with_context(|| format!("decode corpus block at height {}", sample.height))?;

        let flags = production_verify_flags(Network::Mainnet, sample.height);

        let mut prevouts = sample.prevouts.iter();

        for (tx_index, tx) in block.txdata.iter().enumerate() {
            if tx.is_coinbase() {
                continue;
            }

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

            verified_inputs += input_count;
        }

        if prevouts.next().is_some() {
            bail!("corpus prevout overrun at height {}", sample.height);
        }
    }
    // SAFETY: This zero-argument FFI call flushes process-global census sinks.
    // Verification is complete, so no worker can still append records.
    let flush_status = unsafe { libbitcoinkernel_sys::btck_census_flush() };
    if flush_status != 0 {
        bail!("flush census artifacts failed");
    }

    let summary = json!({
        "schema": SUMMARY_SCHEMA,
        "blocks": blocks,
        "non_coinbase_inputs": non_coinbase_inputs,
        "verified_inputs": verified_inputs,
    });

    let rendered = serde_json::to_string_pretty(&summary).context("render summary JSON")?;

    match &args.output {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
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
}

impl Args {
    fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let mut corpus: Option<PathBuf> = None;
        let mut output: Option<PathBuf> = None;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let arg = arg
                .into_string()
                .map_err(|value| anyhow::anyhow!("argument is not UTF-8: {}", value.display()))?;
            match arg.as_str() {
                "--corpus" => corpus = Some(PathBuf::from(next_arg(&mut args, "--corpus")?)),
                "--output" => output = Some(PathBuf::from(next_arg(&mut args, "--output")?)),
                other => bail!(
                    "unknown argument: {other}\nusage: checksig-census-capture \
                     --corpus <path> [--output <path>]"
                ),
            }
        }
        let corpus = corpus.context("--corpus is required")?;
        Ok(Self { corpus, output })
    }
}

fn next_arg(args: &mut impl Iterator<Item = OsString>, name: &str) -> Result<String> {
    args.next()
        .with_context(|| format!("{name} requires a value"))?
        .into_string()
        .map_err(|value| anyhow::anyhow!("{name} value is not UTF-8: {}", value.display()))
}

// ── Production flag derivation ──────────────────────────────────────────────

/// Mirrors `compute_verify_flags` in `crates/node/src/apply.rs`: P2SH is
/// always-on for supported validation paths; DERSIG/CLTV/CSV/WITNESS/TAPROOT
/// gate on activation height. Production resolves CSV/segwit through BIP9
/// contextual state with these same height predicates as fallback; at the
/// corpus heights (<= 150k, far below every activation) the two derivations
/// are identical and every flag except P2SH is off.
fn production_verify_flags(network: Network, height: u32) -> VerifyFlags {
    let mut flags = VerifyFlags::P2SH;
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
