#![allow(missing_docs)]
#![allow(clippy::print_stdout)]

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::ffi::OsString;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use bitcoin::{Block, BlockHash, Weight};
use bitcoin::consensus::Decodable as _;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin_rs_node::Network;
use bitcoin_rs_node::config::Config;
use bitcoin_rs_node::corpus::{CoreRestClient, CoreRestError, FetchedBlock, fetch_rest_block};
use bitcoin_rs_node::corpus::CorpusManifest;
use bitcoin_rs_node::state::NodeState;
use bitcoin_rs_storage::CoreFrameReader;
use serde_json::json;
use sha2::{Digest as _, Sha256};

/// Consensus-maximum serialized block size in bytes, derived from the
/// maximum block weight (BIP 141). No valid serialized block can be larger.
const MAX_SERIALIZED_BLOCK_SIZE: u32 = Weight::MAX_BLOCK.to_wu() as u32;

/// A reader that hashes every byte it yields.
///
/// Used so a Core-framed archive can be verified with a single streaming pass.
struct HashingReader<R> {
    inner: R,
    state: Sha256,
    bytes_read: u64,
}

impl<R: std::io::Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            state: Sha256::new(),
            bytes_read: 0,
        }
    }

    fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    fn digest(&self) -> [u8; 32] {
        let out = self.state.clone().finalize();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(out.as_ref());
        bytes
    }
}

impl<R: std::io::Read> std::io::Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.state.update(&buf[..n]);
            self.bytes_read = self
                .bytes_read
                .checked_add(u64::try_from(n).expect("read length fits u64"))
                .expect("bytes read do not overflow u64");
        }
        Ok(n)
    }
}

/// Proves a window's scripts in one dispatch, then applies its blocks in order.
///
/// Headers go in first because the batch reads median-time-past and softfork
/// state from the block tree, and a header-first peer would have put them there
/// Returns true once the accumulated window should be applied.
///
/// Applies the same byte cap production does, so a replay measures the window
/// production would actually form rather than a larger one. The byte total is
/// accumulated by the caller rather than re-summed here: the window holds up to
/// a thousand blocks and this runs once per block.
/// Totals the replay reports, gathered while it walks the prefix.
struct ReplayTotals {
    start_hash: Option<String>,
    stop_hash: Option<String>,
    tx_count: usize,
    block_bytes: usize,
    fetch_time: Duration,
    decode_time: Duration,
    elapsed: Duration,
}

/// Walks `start_height..=stop_height`, applying each window as it fills.
fn replay_prefix(
    args: &Args,
    manifest: Option<&CorpusManifest>,
    apply_handles: &bitcoin_rs_node::apply::ApplyHandles,
) -> Result<ReplayTotals> {
    let mut tx_count = 0_usize;
    let mut block_bytes = 0_usize;
    let mut fetch_time = Duration::ZERO;
    let mut decode_time = Duration::ZERO;
    let started = Instant::now();
    let mut start_hash = None;
    let mut stop_hash = None;
    let mut prev_hash: Option<BlockHash> = None;

    let window = args.window.max(1);
    let mut source = open_block_source(args, apply_handles.network, manifest)?;
    let mut window_blocks: Vec<Block> = Vec::new();
    let mut window_bytes: Vec<bytes::Bytes> = Vec::new();
    let mut window_bytes_held = 0_usize;
    for height in args.start_height..=args.stop_height {
        let fetch_started = Instant::now();
        let (hash, bytes) = source.fetch(height)?;
        fetch_time += fetch_started.elapsed();
        if height == args.start_height {
            start_hash = Some(hash.clone());
        }
        if height == args.stop_height {
            stop_hash = Some(hash.clone());
        }
        let decode_started = Instant::now();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let block = Block::consensus_decode(&mut cursor)
            .with_context(|| format!("decode block bytes at height {height}"))?;
        let consumed = cursor.position();
        if consumed != u64::try_from(bytes.len()).expect("block length fits u64") {
            bail!(
                "block payload at height {height} has {} trailing bytes",
                bytes.len() - usize::try_from(consumed).expect("decoded block length fits usize")
            );
        }
        decode_time += decode_started.elapsed();

        let actual_hash = block.block_hash();
        if actual_hash.to_string() != hash {
            bail!("block hash mismatch at height {height}: source {hash}, decoded {actual_hash}");
        }
        if height == 0 {
            if block.header.prev_blockhash != BlockHash::from_byte_array([0; 32]) {
                bail!(
                    "genesis block at height 0 has non-zero prev_blockhash {}",
                    block.header.prev_blockhash
                );
            }
            if actual_hash.to_string() != apply_handles.network.genesis_block_hash().to_string_be() {
                bail!(
                    "genesis block hash mismatch at height 0: expected {}, got {actual_hash}",
                    apply_handles.network.genesis_block_hash().to_string_be()
                );
            }
        } else if let Some(prev) = prev_hash {
            if block.header.prev_blockhash != prev {
                bail!(
                    "prev_blockhash mismatch at height {height}: expected {prev}, got {}",
                    block.header.prev_blockhash
                );
            }
        }
        prev_hash = Some(actual_hash);

        tx_count = tx_count.saturating_add(block.txdata.len());
        block_bytes = block_bytes.saturating_add(bytes.len());
        // Flushed BEFORE appending when this block would cross the byte cap,
        // which is what `window_len` does: it leaves the crossing block for the
        // next window. Appending first and checking after let a replay window
        // exceed the cap by a whole block, so its batch boundaries were not
        // production's and the timings near the cap were not comparable.
        if !window_blocks.is_empty()
            && window_bytes_held.saturating_add(bytes.len())
                > bitcoin_rs_node::apply::SCRIPT_BATCH_MAX_BYTES
        {
            apply_window(apply_handles, &mut window_blocks, &mut window_bytes)?;
            window_bytes_held = 0;
        }
        window_blocks.push(block);
        window_bytes_held = window_bytes_held.saturating_add(bytes.len());
        window_bytes.push(bytes::Bytes::from(bytes));
        if window_blocks.len() >= window {
            apply_window(apply_handles, &mut window_blocks, &mut window_bytes)?;
            window_bytes_held = 0;
        }
    }
    source.ensure_eof().with_context(|| "trailing data in Core-framed archive")?;
    apply_window(apply_handles, &mut window_blocks, &mut window_bytes)?;
    Ok(ReplayTotals {
        start_hash,
        stop_hash,
        tx_count,
        block_bytes,
        fetch_time,
        decode_time,
        elapsed: started.elapsed(),
    })
}

/// Inserts headers before applying a window.
///
/// Production receives headers before block bodies. The replay must do the
/// same or the window cannot prove and the driver measures the unbatched path.
fn apply_window(
    handles: &bitcoin_rs_node::apply::ApplyHandles,
    blocks: &mut Vec<Block>,
    raw: &mut Vec<bytes::Bytes>,
) -> Result<()> {
    if blocks.is_empty() {
        return Ok(());
    }
    let headers: Vec<bitcoin::block::Header> = blocks.iter().map(|block| block.header).collect();
    {
        let mut tree = handles.block_tree.write();
        bitcoin_rs_chain::header_sync::accept_headers(
            &mut tree,
            &headers,
            handles.network,
            bitcoin_rs_chain::current_unix_seconds(),
        )
        .context("accept window headers")?;
    }
    let borrowed: Vec<&Block> = blocks.iter().collect();
    bitcoin_rs_node::apply::apply_window(handles, &borrowed, raw).map_err(|error| {
        // Name the block that failed. Most `ApplyError`s carry no height or
        // hash, so a bare "apply window" leaves a 64-block range to search and
        // nothing to resume from. `applied` is the count that committed, so the
        // block at that index is the one that stopped it.
        let blame = borrowed.get(error.applied).map_or_else(
            || "unknown block".to_owned(),
            |block| format!("block {}", block.block_hash()),
        );
        anyhow::Error::new(error.source).context(format!(
            "apply window: {blame} failed after {} of {} blocks committed",
            error.applied,
            borrowed.len()
        ))
    })?;
    blocks.clear();
    raw.clear();
    Ok(())
}

#[derive(Debug)]
struct FileInputs {
    manifest: CorpusManifest,
    manifest_path: PathBuf,
    manifest_bytes_len: u64,
    manifest_sha: [u8; 32],
    blocks_path: PathBuf,
}

fn prepare_file_inputs(args: &Args) -> Result<FileInputs> {
    let blocks_path = args
        .blocks_file
        .as_ref()
        .expect("file mode checked before call");
    let manifest_path = args
        .corpus_manifest
        .as_ref()
        .expect("file mode checked before call");
    let (manifest, manifest_bytes) = CorpusManifest::load_with_bytes(manifest_path)
        .with_context(|| format!("load corpus manifest {}", manifest_path.display()))?;
    if manifest.network != Network::Mainnet {
        bail!(
            "corpus manifest network is {:?}, expected mainnet",
            manifest.network
        );
    }
    if manifest.genesis_hash != Network::Mainnet.genesis_block_hash() {
        bail!(
            "corpus manifest genesis hash {} does not match mainnet genesis {}",
            manifest.genesis_hash.to_string_be(),
            Network::Mainnet.genesis_block_hash().to_string_be()
        );
    }
    if manifest.start_height != 0 {
        bail!(
            "corpus manifest start height is {}, expected 0",
            manifest.start_height
        );
    }
    if manifest.stop_height != args.stop_height {
        bail!(
            "corpus manifest stop height {} does not match --stop-height {}",
            manifest.stop_height,
            args.stop_height
        );
    }
    let archive_size = std::fs::metadata(blocks_path)
        .with_context(|| format!("stat archive {}", blocks_path.display()))?
        .len();
    if archive_size != manifest.archive.size {
        bail!(
            "archive size {} does not match manifest {} for {}",
            archive_size,
            manifest.archive.size,
            blocks_path.display()
        );
    }
    let manifest_digest = Sha256::digest(&manifest_bytes);
    let mut manifest_sha = [0_u8; 32];
    manifest_sha.copy_from_slice(manifest_digest.as_ref());
    let manifest_bytes_len = manifest_bytes.len() as u64;
    Ok(FileInputs {
        manifest,
        manifest_path: manifest_path.clone(),
        manifest_bytes_len,
        manifest_sha,
        blocks_path: blocks_path.clone(),
    })
}

fn main() -> Result<()> {
    let args = Args::parse(std::env::args_os().skip(1))?;
    if args.stop_height < args.start_height {
        bail!("--stop-height must be greater than or equal to --start-height");
    }
    if args.start_height != 0 {
        bail!("mainnet prefix replay currently requires --start-height 0");
    }

    let mut config = Config::default_for_network(Network::Mainnet);
    config.data_dir.clone_from(&args.data_dir);
    config.storage_backend.clone_from(&args.storage_backend);
    config.p2p_listen.clear();
    config.dns_seeds_enabled = false;
    config.txindex = args.txindex;
    config.blockfilterindex = args.blockfilterindex;
    config.assume_valid_height = args.assume_valid_height;

    // In-memory recorder for the apply path's per-stage histograms; the bind
    // address only names the future exporter endpoint and is never served.
    let metrics_handle =
        bitcoin_rs_node::metrics::install_metrics(Some(([127, 0, 0, 1], 0).into()))
            .context("install metrics recorder")?;

    // Validate manifest identity, range, and archive size before opening state.
    // The single replay read validates every frame and the final archive digest.
    let file_mode = args.blocks_file.is_some();
    let file_inputs = if file_mode {
        Some(prepare_file_inputs(&args).context("prepare file-mode inputs")?)
    } else {
        None
    };

    let state = NodeState::open(config).context("open node state")?;
    let mut apply_handles = state.apply_handles();
    // Offline tool: no header sync loop ever runs, so a hash-pinned gate would
    // stay untrusted and silently force full verification when the configured
    // height equals the network anchor. Unpin the gate so `--assume-valid-height`
    // keeps its height-only shortcut semantics for every height.
    apply_handles.assume_valid_gate =
        Arc::new(bitcoin_rs_node::apply::AssumeValidGate::with_anchor(None));
    let ReplayTotals {
        start_hash,
        stop_hash,
        tx_count,
        block_bytes,
        fetch_time,
        decode_time,
        elapsed,
    } = replay_prefix(&args, file_inputs.as_ref().map(|f| &f.manifest), &apply_handles)?;
    // The full UTXO scan is opt-in and starts after the internal replay timer.
    // Performance custody runs must omit it because process wall and CPU still
    // include the scan; separate validation runs pass this option.
    if let Some(path) = args.validation_output.as_deref() {
        write_validation_artifact(path, &apply_handles, args.stop_height, stop_hash.as_deref())?;
    }
    let window = args.window.max(1);

    let block_count = args
        .stop_height
        .saturating_sub(args.start_height)
        .saturating_add(1);
    let stage_seconds = stage_decomposition(metrics_handle.clone());
    let snapshot = metrics_handle
        .as_ref()
        .map(bitcoin_rs_node::metrics::MetricsHandle::snapshot)
        .unwrap_or_default();
    let window_verify_success_total = counter_value(&snapshot, "node.window.verify_success_total");

    if file_mode {
        if window <= 1 {
            bail!("file custody requires --window > 1");
        }
        if window_verify_success_total == 0 {
            bail!("file custody requires at least one successful window verification dispatch");
        }
    }

    let checkpoint_generation = if file_mode {
        Some(state.publish_checkpoint().context("publish clean checkpoint")?)
    } else {
        None
    };

    let artifact = if file_mode {
        let inputs = file_inputs.as_ref().expect("file mode checked above");
        json!({
            "schema": "mainnet-prefix-replay-v2",
            "measurement_target": "mainnet-prefix-replay",
            "git_head": git_head().ok(),
            "network": "mainnet",
            "network_magic": inputs.manifest.network_magic.as_slice().to_lower_hex_string(),
            "genesis_hash": inputs.manifest.genesis_hash.to_string_be(),
            "corpus_manifest": {
                "schema": CorpusManifest::SCHEMA,
                "version": CorpusManifest::VERSION,
                "path": inputs.manifest_path,
                "bytes": inputs.manifest_bytes_len,
                "sha256": inputs.manifest_sha.as_slice().to_lower_hex_string(),
            },
            "archive": {
                "path": inputs.blocks_path,
                "bytes": inputs.manifest.archive.size,
                "sha256": inputs.manifest.archive.sha256.as_slice().to_lower_hex_string(),
            },
            "start_height": args.start_height,
            "start_hash": start_hash,
            "stop_height": args.stop_height,
            "stop_hash": stop_hash,
            "assume_valid_height": args.assume_valid_height,
            // The effective value, not the raw flag: `--window 0` normalises to 1.
            "window": window,
            "window_verify_success_total": window_verify_success_total,
            "checkpoint_generation": checkpoint_generation.expect("file mode checked above"),
            "storage_backend": args.storage_backend,
            "txindex": args.txindex,
            "blockfilterindex": args.blockfilterindex,
            "block_count": block_count,
            "tx_count": tx_count,
            "block_bytes": block_bytes,
            "elapsed_seconds": elapsed.as_secs_f64(),
            "blocks_per_second": f64::from(block_count) / elapsed.as_secs_f64(),
            "fetch_seconds": fetch_time.as_secs_f64(),
            "decode_seconds": decode_time.as_secs_f64(),
            "stage_seconds": stage_seconds,
            "rss_high_water_bytes": rss_high_water_bytes(),
            "block_source": "file",
            "data_dir": args.data_dir,
        })
    } else {
        let block_source = if args.rest_url.is_some() {
            "rest"
        } else {
            "bitcoin-cli"
        };
        json!({
            "schema": "mainnet-prefix-replay-v1",
            "measurement_target": "mainnet-prefix-replay",
            "git_head": git_head().ok(),
            "storage_backend": args.storage_backend,
            "txindex": args.txindex,
            "blockfilterindex": args.blockfilterindex,
            "assume_valid_height": args.assume_valid_height,
            "window": window,
            "start_height": args.start_height,
            "start_hash": start_hash,
            "stop_height": args.stop_height,
            "stop_hash": stop_hash,
            "block_count": block_count,
            "tx_count": tx_count,
            "block_bytes": block_bytes,
            "elapsed_seconds": elapsed.as_secs_f64(),
            "blocks_per_second": f64::from(block_count) / elapsed.as_secs_f64(),
            "fetch_seconds": fetch_time.as_secs_f64(),
            "decode_seconds": decode_time.as_secs_f64(),
            "stage_seconds": stage_seconds,
            "rss_high_water_bytes": rss_high_water_bytes(),
            "bitcoin_cli": args.bitcoin_cli,
            "bitcoin_cli_args": args.bitcoin_cli_args,
            "block_source": block_source,
            "rest_url": args.rest_url,
            "blocks_file": args.blocks_file,
            "data_dir": args.data_dir,
        })
    };
    let rendered = serde_json::to_string_pretty(&artifact).context("render artifact JSON")?;
    if let Some(output) = args.output {
        std::fs::write(&output, rendered + "\n")
            .with_context(|| format!("write {}", output.display()))?;
    } else {
        println!("{rendered}");
    }
    Ok(())
}

fn write_validation_artifact(
    path: &Path,
    handles: &bitcoin_rs_node::apply::ApplyHandles,
    stop_height: u32,
    stop_hash: Option<&str>,
) -> Result<()> {
    let stats = handles
        .utxo
        .with_stable_view(|view| bitcoin_rs_coinstats::scan_coin_stats(view, stop_height, true))
        .context("scan UTXO set for CoinStats validation")?;
    let utxo_hash = bitcoin_rs_utxo::aggregate_hash(&handles.utxo)
        .context("compute deterministic UTXO aggregate hash")?;
    let artifact = json!({
        "schema": "mainnet-prefix-replay-validation-v1",
        "stop_height": stop_height,
        "stop_hash": stop_hash,
        "utxo_hash_serialized_3": utxo_hash.to_string_be(),
        "muhash": stats.muhash.finalize_hash().to_string_be(),
        "utxo_count": stats.utxo_count,
        "total_amount": stats.total_amount,
    });
    let rendered =
        serde_json::to_string_pretty(&artifact).context("render validation artifact JSON")?;
    std::fs::write(path, rendered + "\n").with_context(|| format!("write {}", path.display()))
}

#[derive(Debug)]
struct Args {
    bitcoin_cli: String,
    bitcoin_cli_args: Vec<String>,
    rest_url: Option<String>,
    /// Path to a Core-framed archive (network magic + u32 LE length + block payload).
    blocks_file: Option<PathBuf>,
    /// Path to the validated corpus manifest for the Core-framed archive.
    corpus_manifest: Option<PathBuf>,
    assume_valid_height: u32,
    data_dir: PathBuf,
    output: Option<PathBuf>,
    validation_output: Option<PathBuf>,
    window: usize,
    start_height: u32,
    stop_height: u32,
    storage_backend: String,
    txindex: bool,
    blockfilterindex: bool,
}

impl Args {
    fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let mut parsed = Self {
            bitcoin_cli: "bitcoin-cli".to_owned(),
            bitcoin_cli_args: Vec::new(),
            rest_url: None,
            blocks_file: None,
            corpus_manifest: None,
            assume_valid_height: 0,
            data_dir: PathBuf::from(".bitcoin-rs-mainnet-prefix-replay"),
            output: None,
            validation_output: None,
            window: bitcoin_rs_node::apply::SCRIPT_BATCH_WINDOW,
            start_height: 0,
            stop_height: 0,
            storage_backend: "fjall".to_owned(),
            txindex: false,
            blockfilterindex: false,
        };
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let arg = arg
                .into_string()
                .map_err(|value| anyhow::anyhow!("argument is not UTF-8: {}", value.display()))?;
            match arg.as_str() {
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                "--bitcoin-cli" => parsed.bitcoin_cli = next_arg(&mut args, "--bitcoin-cli")?,
                "--rest-url" => parsed.rest_url = Some(next_arg(&mut args, "--rest-url")?),
                "--blocks-file" => {
                    parsed.blocks_file = Some(PathBuf::from(next_arg(&mut args, "--blocks-file")?));
                }
                "--corpus-manifest" => {
                    parsed.corpus_manifest =
                        Some(PathBuf::from(next_arg(&mut args, "--corpus-manifest")?));
                }
                "--assume-valid-height" => {
                    parsed.assume_valid_height =
                        parse_height(&next_arg(&mut args, "--assume-valid-height")?)?;
                }
                "--bitcoin-cli-arg" => {
                    parsed
                        .bitcoin_cli_args
                        .push(next_arg(&mut args, "--bitcoin-cli-arg")?);
                }
                "--data-dir" => parsed.data_dir = PathBuf::from(next_arg(&mut args, "--data-dir")?),
                "--output" => parsed.output = Some(PathBuf::from(next_arg(&mut args, "--output")?)),
                "--validation-output" => {
                    parsed.validation_output =
                        Some(PathBuf::from(next_arg(&mut args, "--validation-output")?));
                }
                "--window" => parsed.window = next_arg(&mut args, "--window")?.parse()?,
                "--start-height" => {
                    parsed.start_height = parse_height(&next_arg(&mut args, "--start-height")?)?;
                }
                "--stop-height" => {
                    parsed.stop_height = parse_height(&next_arg(&mut args, "--stop-height")?)?;
                }
                "--storage-backend" => {
                    parsed.storage_backend = next_arg(&mut args, "--storage-backend")?;
                }
                "--txindex" => parsed.txindex = true,
                "--blockfilterindex" => parsed.blockfilterindex = true,
                other => bail!("unknown argument: {other}"),
            }
        }
        if parsed.blocks_file.is_some() != parsed.corpus_manifest.is_some() {
            bail!("--blocks-file and --corpus-manifest must be provided together");
        }
        Ok(parsed)
    }
}

/// Every histogram the node recorded during the replay (apply stages, storage,
/// utxo — and anything added later), sorted by total time descending.
/// Deliberately unfiltered: a surprise entry in this list is diagnostic
/// signal, not noise.
fn counter_value(snapshot: &hashbrown::HashMap<String, bitcoin_rs_node::metrics::MetricValue>, name: &str) -> u64 {
    match snapshot.get(name) {
        Some(bitcoin_rs_node::metrics::MetricValue::Counter(value)) => *value,
        _ => 0,
    }
}

fn stage_decomposition(
    handle: Option<bitcoin_rs_node::metrics::MetricsHandle>,
) -> Vec<serde_json::Value> {
    let Some(handle) = handle else {
        return Vec::new();
    };
    let mut stages: Vec<(String, u64, f64)> = handle
        .snapshot()
        .into_iter()
        .filter_map(|(name, value)| match value {
            bitcoin_rs_node::metrics::MetricValue::Histogram { count, sum } => {
                Some((name, count, sum))
            }
            _ => None,
        })
        .collect();
    stages.sort_by(|a, b| b.2.total_cmp(&a.2));
    stages
        .into_iter()
        .map(|(name, count, sum)| json!({"stage": name, "count": count, "sum_seconds": sum}))
        .collect()
}

fn next_arg(args: &mut impl Iterator<Item = OsString>, name: &str) -> Result<String> {
    args.next()
        .with_context(|| format!("{name} requires a value"))?
        .into_string()
        .map_err(|value| anyhow::anyhow!("{name} value is not UTF-8: {}", value.display()))
}

fn parse_height(value: &str) -> Result<u32> {
    value
        .parse()
        .with_context(|| format!("parse height {value:?}"))
}

/// Where replay blocks come from: per-call `bitcoin-cli` spawns or a prefetch
/// thread reading ahead over a persistent REST socket.
/// Picks the block source, preferring a local Core-framed archive over REST.
///
/// The file source must win outright: building the REST source spawns a
/// prefetch thread, so choosing it first and discarding it would start an
/// HTTP pipeline the run never reads.
fn open_block_source<'a>(
    args: &'a Args,
    network: Network,
    manifest: Option<&CorpusManifest>,
) -> Result<BlockSource<'a>> {
    if let Some(path) = args.blocks_file.as_ref() {
        let manifest = manifest
            .with_context(|| "file mode requires a corpus manifest")?
            .clone();
        let file = std::fs::File::open(path)
            .with_context(|| format!("open Core-framed archive {}", path.display()))?;
        let reader = CoreFrameReader::new(
            HashingReader::new(BufReader::with_capacity(1 << 20, file)),
            network.magic(),
            MAX_SERIALIZED_BLOCK_SIZE,
        );
        return Ok(BlockSource::File {
            reader,
            manifest,
            next_index: 0,
        });
    }
    match &args.rest_url {
        Some(host) => Ok(BlockSource::Rest(spawn_prefetch(
            host,
            args.start_height,
            args.stop_height,
        )?)),
        None => Ok(BlockSource::Cli(args)),
    }
}

enum BlockSource<'a> {
    Cli(&'a Args),
    Rest(crossbeam_channel::Receiver<Result<FetchedBlock>>),
    /// Blocks read sequentially from a local Core-framed archive.
    ///
    /// Each frame is the Bitcoin Core `-loadblock` wire format:
    /// `network magic + u32 little-endian length + consensus block payload`.
    /// Core's `-loadblock` reads the same bytes, so this source removes the
    /// HTTP / second-process CPU overhead that a REST fetch adds.
    File {
        reader: CoreFrameReader<HashingReader<BufReader<std::fs::File>>>,
        manifest: CorpusManifest,
        next_index: usize,
    },
}

impl BlockSource<'_> {
    /// Returns `(block_hash_hex, raw_block_bytes)` for `height`.
    fn fetch(&mut self, height: u32) -> Result<FetchedBlock> {
        match self {
            Self::Cli(args) => {
                let hash = bitcoin_cli(args, ["getblockhash".to_owned(), height.to_string()])
                    .with_context(|| format!("get block hash at height {height}"))?;
                let block_hex =
                    bitcoin_cli(args, ["getblock".to_owned(), hash.clone(), "0".to_owned()])
                        .with_context(|| format!("get block {hash} at height {height}"))?;
                let bytes = Vec::<u8>::from_hex(block_hex.trim())
                    .with_context(|| format!("decode block hex at height {height}"))?;
                Ok((hash, bytes))
            }
            Self::Rest(receiver) => receiver
                .recv()
                .with_context(|| format!("prefetch thread gone before height {height}"))?,
            Self::File { reader, manifest, next_index } => {
                let offset = reader.offset();
                let record = reader
                    .next()
                    .with_context(|| format!("read Core frame at offset {offset} for height {height}"))?;
                let Some(record) = record else {
                    bail!("Core-framed archive ended at offset {offset} before height {height}");
                };
                let entry_index = *next_index;
                *next_index += 1;
                if entry_index != height as usize {
                    bail!("manifest entry index mismatch: expected {height}, got {entry_index}");
                }
                let entry = manifest
                    .entries
                    .get(entry_index)
                    .with_context(|| format!("manifest has no entry for height {height}"))?;
                if entry.height != height {
                    bail!(
                        "manifest entry height mismatch: expected {height}, got {}",
                        entry.height
                    );
                }
                if record.metadata.offset != entry.offset {
                    bail!(
                        "frame offset mismatch at height {height}: manifest {}, archive {}",
                        entry.offset,
                        record.metadata.offset
                    );
                }
                if record.metadata.len != entry.payload_length {
                    bail!(
                        "frame payload length mismatch at height {height}: manifest {}, archive {}",
                        entry.payload_length,
                        record.metadata.len
                    );
                }
                let bytes = record.payload;
                let header = bytes
                    .get(..80)
                    .with_context(|| format!("Core frame payload at height {height} is {} bytes, shorter than a block header", bytes.len()))?;
                let hash = bitcoin::BlockHash::from_byte_array(
                    bitcoin::hashes::sha256d::Hash::hash(header).to_byte_array(),
                );
                let expected = bitcoin::BlockHash::from_byte_array(*entry.hash.as_byte_array());
                if hash != expected {
                    bail!(
                        "frame header hash mismatch at height {height}: manifest {}, archive {}",
                        expected,
                        hash
                    );
                }
                Ok((hash.to_string(), bytes))
            }
        }
    }

    /// Fails if a Core-framed file source has more frames than the requested range
    /// or if the bytes consumed do not match the manifest's archive digest.
    fn ensure_eof(&mut self) -> Result<()> {
        match self {
            Self::File { reader, manifest, .. } => {
                let offset = reader.offset();
                match reader
                    .next()
                    .with_context(|| format!("trailing Core frame at offset {offset}"))?
                {
                    None => {
                        let hashing = reader.get_ref();
                        let archive_bytes = hashing.bytes_read();
                        if archive_bytes != manifest.archive.size {
                            bail!(
                                "archive size mismatch at EOF: manifest {}, read {}",
                                manifest.archive.size,
                                archive_bytes
                            );
                        }
                        let archive_digest = hashing.digest();
                        if archive_digest != manifest.archive.sha256 {
                            bail!(
                                "archive SHA-256 mismatch at EOF: manifest {}, read {}",
                                manifest.archive.sha256.as_slice().to_lower_hex_string(),
                                archive_digest.as_slice().to_lower_hex_string()
                            );
                        }
                        Ok(())
                    }
                    Some(record) => bail!(
                        "Core-framed archive has an extra frame at offset {} past --stop-height",
                        record.metadata.offset
                    ),
                }
            }
            _ => Ok(()),
        }
    }
}

/// Reads blocks ahead of the apply loop so fetch latency overlaps validation —
/// the serial round-trip-per-block fetch otherwise accounts for ~24% of replay
/// wall-clock (96s of 397s over 0..150k); a real node spends less waiting on
/// download or disk reads than other threads.
fn spawn_prefetch(
    host: &str,
    start_height: u32,
    stop_height: u32,
) -> Result<crossbeam_channel::Receiver<Result<FetchedBlock>>> {
    let mut client = CoreRestClient::connect(host).map_err(|e: CoreRestError| anyhow::Error::from(e))?;
    let (sender, receiver) = crossbeam_channel::bounded(32);
    std::thread::spawn(move || {
        for height in start_height..=stop_height {
            let item = fetch_rest_block(&mut client, height).map_err(|e: CoreRestError| anyhow::Error::from(e));
            let failed = item.is_err();
            // A send error means the apply loop dropped the receiver; stop.
            if sender.send(item).is_err() || failed {
                return;
            }
        }
    });
    Ok(receiver)
}

fn bitcoin_cli(args: &Args, command_args: impl IntoIterator<Item = String>) -> Result<String> {
    let output = Command::new(&args.bitcoin_cli)
        .args(&args.bitcoin_cli_args)
        .args(command_args)
        .output()
        .with_context(|| format!("run {}", args.bitcoin_cli))?;
    if !output.status.success() {
        bail!(
            "{} failed with status {}: {}",
            args.bitcoin_cli,
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8(output.stdout).context("bitcoin-cli stdout is not UTF-8")?;
    Ok(stdout.trim().to_owned())
}

fn git_head() -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .context("run git rev-parse")?;
    if !output.status.success() {
        bail!("git rev-parse failed with status {}", output.status);
    }
    Ok(String::from_utf8(output.stdout)
        .context("git stdout is not UTF-8")?
        .trim()
        .to_owned())
}

fn rss_high_water_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("VmHWM:") {
            let kib = value.split_whitespace().next()?.parse::<u64>().ok()?;
            return kib.checked_mul(1024);
        }
    }
    None
}

fn print_usage() {
    println!(
        "usage: mainnet_prefix_replay --stop-height <height> [--blocks-file <core-framed-archive> --corpus-manifest <manifest> | --rest-url <host:port> | --bitcoin-cli <path>] [--assume-valid-height <height>] [--bitcoin-cli-arg <arg>]... [--data-dir <path>] [--output <path>] [--validation-output <path>] [--txindex] [--blockfilterindex]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::serialize;
    use bitcoin_rs_node::corpus::{ArchiveInfo, CorpusEntry, CorpusManifest};
    use bitcoin_rs_primitives::Hash256;

    fn regtest_genesis_bytes() -> Vec<u8> {
        serialize(&bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest))
    }

    fn write_archive(magic: [u8; 4], payloads: &[&[u8]]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut writer = bitcoin_rs_storage::CoreFrameWriter::new(&mut buf, magic);
        for payload in payloads {
            writer.write(payload).unwrap();
        }
        buf
    }

    fn manifest_for_archive(network: Network, archive: &[u8], payloads: &[&[u8]]) -> CorpusManifest {
        let mut entries = Vec::new();
        let mut offset = 0_u64;
        for (height, payload) in payloads.iter().enumerate() {
            let header = payload.get(..80).expect("payload must include a block header");
            let hash = Hash256::from_le_bytes(
                &bitcoin::hashes::sha256d::Hash::hash(header).to_byte_array(),
            );
            entries.push(CorpusEntry {
                height: height as u32,
                hash,
                offset,
                payload_length: payload.len() as u32,
            });
            offset = offset
                .checked_add(bitcoin_rs_storage::CORE_FRAME_HEADER_LEN)
                .unwrap()
                .checked_add(payload.len() as u64)
                .unwrap();
        }
        let archive_digest = {
            use sha2::Digest as _;
            let digest = Sha256::digest(archive);
            let mut bytes = [0_u8; 32];
            bytes.copy_from_slice(digest.as_ref());
            bytes
        };
        CorpusManifest::new(
            network,
            ArchiveInfo::new(archive.len() as u64, archive_digest),
            entries,
        )
        .expect("test manifest is valid")
    }

    fn write_manifest(manifest: &CorpusManifest, path: &Path) {
        manifest.save(path).expect("save manifest")
    }

    fn args_for_file(archive_path: &Path, manifest_path: &Path) -> Args {
        let mut args = Args::parse(std::iter::empty::<OsString>()).unwrap();
        args.blocks_file = Some(archive_path.to_path_buf());
        args.corpus_manifest = Some(manifest_path.to_path_buf());
        args
    }

    #[test]
    fn file_source_reads_core_framed_blocks() {
        let magic = Network::Regtest.magic();
        let payload = regtest_genesis_bytes();
        let archive = write_archive(magic, &[&payload[..]]);
        let manifest = manifest_for_archive(Network::Regtest, &archive, &[&payload[..]]);

        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();
        let manifest_temp = tempfile::NamedTempFile::new().unwrap();
        write_manifest(&manifest, manifest_temp.path());

        let args = args_for_file(archive_temp.path(), manifest_temp.path());
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        let (hash, bytes) = source.fetch(0).unwrap();
        let expected = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
            .block_hash()
            .to_string();
        assert_eq!(hash, expected);
        assert_eq!(bytes, payload);
        let err = source.fetch(1).unwrap_err();
        assert!(err.to_string().contains("archive ended"), "{err}");
    }

    #[test]
    fn file_source_rejects_wrong_magic() {
        let archive = write_archive(Network::Mainnet.magic(), &[&regtest_genesis_bytes()[..]]);
        let manifest = manifest_for_archive(Network::Regtest, &archive, &[&regtest_genesis_bytes()[..]]);
        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();

        let args = args_for_file(archive_temp.path(), Path::new("/nonexistent/manifest.json"));
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        let err = source.fetch(0).unwrap_err();
        assert!(format!("{err:?}").to_lowercase().contains("wrong magic"), "{err:?}");
    }

    #[test]
    fn file_source_rejects_truncated_frame() {
        let magic = Network::Regtest.magic();
        let payload = regtest_genesis_bytes();
        let full_archive = write_archive(magic, &[&payload[..]]);
        let manifest = manifest_for_archive(Network::Regtest, &full_archive, &[&payload[..]]);
        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        let mut truncated = full_archive.clone();
        truncated.truncate(truncated.len() - 10);
        std::fs::write(archive_temp.path(), &truncated).unwrap();

        let args = args_for_file(archive_temp.path(), Path::new("/nonexistent/manifest.json"));
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        let err = source.fetch(0).unwrap_err();
        assert!(format!("{err:?}").to_lowercase().contains("partial payload"), "{err:?}");
    }

    #[test]
    fn file_source_rejects_old_length_only_file() {
        let payload = regtest_genesis_bytes();
        let magic = Network::Regtest.magic();
        let valid_archive = write_archive(magic, &[&payload[..]]);
        let manifest = manifest_for_archive(Network::Regtest, &valid_archive, &[&payload[..]]);
        let mut archive = Vec::new();
        archive.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        archive.extend_from_slice(&payload);
        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();

        let args = args_for_file(archive_temp.path(), Path::new("/nonexistent/manifest.json"));
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        let err = source.fetch(0).unwrap_err();
        assert!(format!("{err:?}").to_lowercase().contains("wrong magic"), "{err:?}");
    }

    #[test]
    fn file_source_rejects_extra_frames() {
        let magic = Network::Regtest.magic();
        let payload = regtest_genesis_bytes();
        // Archive with two frames, manifest expecting one.
        let two_frame_archive = write_archive(magic, &[&payload[..], &payload[..]]);
        let one_frame_archive = write_archive(magic, &[&payload[..]]);
        let manifest = manifest_for_archive(Network::Regtest, &one_frame_archive, &[&payload[..]]);
        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &two_frame_archive).unwrap();

        let args = args_for_file(archive_temp.path(), Path::new("/nonexistent/manifest.json"));
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        source.fetch(0).unwrap();
        let err = source.ensure_eof().unwrap_err();
        assert!(err.to_string().contains("extra frame"), "{err}");
    }

    #[test]
    fn file_source_rejects_hash_mismatch() {
        let magic = Network::Regtest.magic();
        let payload = regtest_genesis_bytes();
        let archive = write_archive(magic, &[&payload[..]]);
        let mut manifest = manifest_for_archive(Network::Regtest, &archive, &[&payload[..]]);
        manifest.entries[0].hash = Hash256::from_le_bytes(&[0xab; 32]);

        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();

        let args = args_for_file(archive_temp.path(), Path::new("/nonexistent/manifest.json"));
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        let err = source.fetch(0).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("hash mismatch"), "{err}");
    }

    #[test]
    fn file_source_rejects_offset_mismatch() {
        let magic = Network::Regtest.magic();
        let payload = regtest_genesis_bytes();
        let archive = write_archive(magic, &[&payload[..]]);
        let mut manifest = manifest_for_archive(Network::Regtest, &archive, &[&payload[..]]);
        manifest.entries[0].offset = 1;

        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();

        let args = args_for_file(archive_temp.path(), Path::new("/nonexistent/manifest.json"));
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        let err = source.fetch(0).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("offset mismatch"), "{err}");
    }

    #[test]
    fn file_source_rejects_length_mismatch() {
        let magic = Network::Regtest.magic();
        let payload = regtest_genesis_bytes();
        let archive = write_archive(magic, &[&payload[..]]);
        let mut manifest = manifest_for_archive(Network::Regtest, &archive, &[&payload[..]]);
        manifest.entries[0].payload_length = 1;

        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();

        let args = args_for_file(archive_temp.path(), Path::new("/nonexistent/manifest.json"));
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        let err = source.fetch(0).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("length mismatch"), "{err}");
    }

    #[test]
    fn file_source_rejects_archive_digest_mismatch() {
        let magic = Network::Regtest.magic();
        let payload = regtest_genesis_bytes();
        let archive = write_archive(magic, &[&payload[..]]);
        let mut manifest = manifest_for_archive(Network::Regtest, &archive, &[&payload[..]]);
        manifest.archive.sha256 = [0xcd; 32];

        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();

        let args = args_for_file(archive_temp.path(), Path::new("/nonexistent/manifest.json"));
        let mut source = open_block_source(&args, Network::Regtest, Some(&manifest)).unwrap();
        source.fetch(0).unwrap();
        let err = source.ensure_eof().unwrap_err();
        assert!(err.to_string().to_lowercase().contains("sha-256 mismatch"), "{err}");
    }

    #[test]
    fn file_mode_requires_paired_arguments() {
        let mut args = vec![OsString::from("--blocks-file"), OsString::from("/tmp/archive")];
        let err = Args::parse(args.drain(..)).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("must be provided together"), "{err}");
    }

    #[test]
    fn file_preflight_rejects_regtest_manifest() {
        let payload = regtest_genesis_bytes();
        let archive = write_archive(Network::Regtest.magic(), &[&payload[..]]);
        let manifest = manifest_for_archive(Network::Regtest, &archive, &[&payload[..]]);

        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();
        let manifest_temp = tempfile::NamedTempFile::new().unwrap();
        write_manifest(&manifest, manifest_temp.path());

        let mut args = Args::parse(std::iter::empty::<OsString>()).unwrap();
        args.stop_height = 0;
        args.blocks_file = Some(archive_temp.path().to_path_buf());
        args.corpus_manifest = Some(manifest_temp.path().to_path_buf());

        let err = prepare_file_inputs(&args).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("mainnet"), "{err}");
    }

    #[test]
    fn file_preflight_rejects_stop_height_mismatch() {
        let payload = regtest_genesis_bytes();
        let archive = write_archive(Network::Mainnet.magic(), &[&payload[..]]);
        let manifest = {
            let mut m = manifest_for_archive(Network::Mainnet, &archive, &[&payload[..]]);
            m
        };

        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive_temp.path(), &archive).unwrap();
        let manifest_temp = tempfile::NamedTempFile::new().unwrap();
        write_manifest(&manifest, manifest_temp.path());

        let mut args = Args::parse(std::iter::empty::<OsString>()).unwrap();
        args.stop_height = 1; // manifest has stop_height 0
        args.blocks_file = Some(archive_temp.path().to_path_buf());
        args.corpus_manifest = Some(manifest_temp.path().to_path_buf());

        let err = prepare_file_inputs(&args).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("stop height"), "{err}");
    }

    #[test]
    fn file_preflight_rejects_archive_size_mismatch() {
        let payload = regtest_genesis_bytes();
        let full_archive = write_archive(Network::Mainnet.magic(), &[&payload[..]]);
        let manifest = manifest_for_archive(Network::Mainnet, &full_archive, &[&payload[..]]);

        let archive_temp = tempfile::NamedTempFile::new().unwrap();
        let mut truncated = full_archive.clone();
        truncated.truncate(truncated.len() - 1);
        std::fs::write(archive_temp.path(), &truncated).unwrap();
        let manifest_temp = tempfile::NamedTempFile::new().unwrap();
        write_manifest(&manifest, manifest_temp.path());

        let mut args = Args::parse(std::iter::empty::<OsString>()).unwrap();
        args.stop_height = 0;
        args.blocks_file = Some(archive_temp.path().to_path_buf());
        args.corpus_manifest = Some(manifest_temp.path().to_path_buf());

        let err = prepare_file_inputs(&args).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("archive size"), "{err}");
    }
}
