#![allow(missing_docs)]
#![allow(clippy::print_stdout)]

use std::ffi::OsString;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use bitcoin::Block;
use bitcoin::consensus::Decodable as _;
use bitcoin::hex::FromHex as _;
use bitcoin_rs_node::Network;
use bitcoin_rs_node::config::Config;
use bitcoin_rs_node::state::NodeState;
use serde_json::json;

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
    apply_handles: &bitcoin_rs_node::apply::ApplyHandles,
) -> Result<ReplayTotals> {
    let mut tx_count = 0_usize;
    let mut block_bytes = 0_usize;
    let mut fetch_time = Duration::ZERO;
    let mut decode_time = Duration::ZERO;
    let started = Instant::now();
    let mut start_hash = None;
    let mut stop_hash = None;

    let window = args.window.max(1);
    let mut source = open_block_source(args)?;
    let mut window_blocks: Vec<Block> = Vec::with_capacity(window);
    let mut window_bytes: Vec<bytes::Bytes> = Vec::with_capacity(window);
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
        decode_time += decode_started.elapsed();
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
        if window_blocks.len() >= window || height == args.stop_height {
            apply_window(apply_handles, &mut window_blocks, &mut window_bytes)?;
            window_bytes_held = 0;
        }
    }
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

/// long before the bodies arrived. Without that the window can never prove and
/// the driver silently measures the unbatched path.
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
    bitcoin_rs_node::apply::apply_window(handles, blocks, raw).map_err(|error| {
        // Name the block that failed. Most `ApplyError`s carry no height or
        // hash, so a bare "apply window" leaves a 64-block range to search and
        // nothing to resume from. `applied` is the count that committed, so the
        // block at that index is the one that stopped it.
        let blame = blocks.get(error.applied).map_or_else(
            || "unknown block".to_owned(),
            |block| format!("block {}", block.block_hash()),
        );
        anyhow::Error::new(error.source).context(format!(
            "apply window: {blame} failed after {} of {} blocks committed",
            error.applied,
            blocks.len()
        ))
    })?;
    blocks.clear();
    raw.clear();
    Ok(())
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
    } = replay_prefix(&args, &apply_handles)?;
    let window = args.window.max(1);

    let block_count = args
        .stop_height
        .saturating_sub(args.start_height)
        .saturating_add(1);
    let stage_seconds = stage_decomposition(metrics_handle);
    let artifact = json!({
        "schema": "mainnet-prefix-replay-v1",
        "measurement_target": "mainnet-prefix-replay",
        "git_head": git_head().ok(),
        "storage_backend": args.storage_backend,
        "txindex": args.txindex,
        "blockfilterindex": args.blockfilterindex,
        "assume_valid_height": args.assume_valid_height,
        // The effective value, not the raw flag: `--window 0` normalises to 1.
        // Without this two artifacts from `--window 1` and `--window 64` are
        // indistinguishable by configuration, and those are exactly the two runs
        // the validation gate compares.
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
        "block_source": args.rest_url.as_ref().map_or("bitcoin-cli", |_| "rest"),
        "rest_url": args.rest_url,
        "data_dir": args.data_dir,
    });
    let rendered = serde_json::to_string_pretty(&artifact).context("render artifact JSON")?;
    if let Some(output) = args.output {
        std::fs::write(&output, rendered + "\n")
            .with_context(|| format!("write {}", output.display()))?;
    } else {
        println!("{rendered}");
    }
    Ok(())
}

#[derive(Debug)]
struct Args {
    bitcoin_cli: String,
    bitcoin_cli_args: Vec<String>,
    rest_url: Option<String>,
    blocks_file: Option<PathBuf>,
    assume_valid_height: u32,
    data_dir: PathBuf,
    output: Option<PathBuf>,
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
            assume_valid_height: 0,
            data_dir: PathBuf::from(".bitcoin-rs-mainnet-prefix-replay"),
            output: None,
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
        Ok(parsed)
    }
}

/// Every histogram the node recorded during the replay (apply stages, storage,
/// utxo — and anything added later), sorted by total time descending.
/// Deliberately unfiltered: a surprise entry in this list is diagnostic
/// signal, not noise.
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

/// Minimal keep-alive HTTP/1.1 client for the local `bitcoind -rest` interface.
///
/// Exists because spawning `bitcoin-cli` per block costs ~11 ms/call — 28 minutes of
/// pure harness overhead over a 150k-block replay window, drowning the measurement.
/// One persistent localhost connection brings the fetch cost below a millisecond.
struct RestClient {
    host: String,
    stream: BufReader<TcpStream>,
}

impl RestClient {
    /// Upper bound on an accepted response body. The largest legitimate body is
    /// one serialized block (≤4 MB by consensus weight); anything bigger means
    /// the URL points at something that is not a bitcoind REST endpoint.
    const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

    fn connect(host: &str) -> Result<Self> {
        let stream = TcpStream::connect(host).with_context(|| format!("connect to {host}"))?;
        // A stalled server must fail the replay loudly, not freeze a
        // multi-hour run inside a blocking read.
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        Ok(Self {
            host: host.to_owned(),
            stream: BufReader::new(stream),
        })
    }

    fn get(&mut self, path: &str) -> Result<Vec<u8>> {
        let first_err = match self.request(path) {
            Ok(body) => return Ok(body),
            Err(err) => err,
        };
        // The server may close a kept-alive connection between requests;
        // reconnect once before giving up, keeping the first failure's cause.
        *self =
            Self::connect(&self.host).with_context(|| format!("reconnect after: {first_err:#}"))?;
        self.request(path)
            .with_context(|| format!("retry after: {first_err:#}"))
    }

    fn request(&mut self, path: &str) -> Result<Vec<u8>> {
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
            self.host
        );
        self.stream.get_mut().write_all(request.as_bytes())?;
        let mut line = String::new();
        self.stream.read_line(&mut line)?;
        let status = line.trim_end().to_owned();
        let mut content_length: Option<usize> = None;
        loop {
            line.clear();
            self.stream.read_line(&mut line)?;
            let header = line.trim_end();
            if header.is_empty() {
                break;
            }
            if let Some(value) = header
                .to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(str::trim)
            {
                content_length = Some(value.parse().context("parse Content-Length")?);
            }
        }
        let length = content_length
            .with_context(|| format!("REST response without Content-Length: {status}"))?;
        if length > Self::MAX_BODY_BYTES {
            bail!("REST GET {path}: Content-Length {length} exceeds sane bound ({status})");
        }
        let mut body = vec![0_u8; length];
        // Drain the body before judging the status so a kept-alive connection
        // stays in sync after an HTTP error response.
        self.stream.read_exact(&mut body)?;
        let status_code = status.split_whitespace().nth(1);
        if status_code != Some("200") {
            bail!("REST GET {path} failed: {status}");
        }
        Ok(body)
    }
}

/// A fetched block: `(block_hash_hex, raw_block_bytes)`.
type FetchedBlock = (String, Vec<u8>);

/// Where replay blocks come from: per-call `bitcoin-cli` spawns or a prefetch
/// thread reading ahead over a persistent REST socket.
/// Picks the block source, preferring a local file over REST.
///
/// The file source must win outright: building the REST source spawns a
/// prefetch thread, so choosing it first and discarding it would start an
/// HTTP pipeline the run never reads.
fn open_block_source(args: &Args) -> Result<BlockSource<'_>> {
    if let Some(path) = args.blocks_file.as_ref() {
        return Ok(BlockSource::File(std::io::BufReader::with_capacity(
            1 << 20,
            std::fs::File::open(path)
                .with_context(|| format!("open blocks file {}", path.display()))?,
        )));
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
    /// Blocks read sequentially from a local length-prefixed file.
    ///
    /// Core's `-reindex-chainstate` reads its own `blk*.dat` files, so a REST
    /// fetch loads the replay with HTTP and a second process's CPU that Core
    /// never pays. This source removes that asymmetry for engine-to-engine
    /// comparisons.
    File(std::io::BufReader<std::fs::File>),
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
            Self::File(reader) => {
                use std::io::Read as _;
                let mut len_bytes = [0_u8; 4];
                reader
                    .read_exact(&mut len_bytes)
                    .with_context(|| format!("read block length at height {height}"))?;
                let len = usize::try_from(u32::from_le_bytes(len_bytes))
                    .with_context(|| format!("block length at height {height} exceeds usize"))?;
                let mut bytes = vec![0_u8; len];
                reader
                    .read_exact(&mut bytes)
                    .with_context(|| format!("read {len} block bytes at height {height}"))?;
                // Hash the 80-byte header directly. Deserializing the whole
                // block here would duplicate the decode the apply loop already
                // performs and would inflate this source against the REST one,
                // which gets the hash from the API for free.
                let header = bytes
                    .get(..80)
                    .with_context(|| format!("block at height {height} shorter than a header"))?;
                let hash = {
                    use bitcoin::hashes::Hash as _;
                    bitcoin::BlockHash::from_byte_array(
                        bitcoin::hashes::sha256d::Hash::hash(header).to_byte_array(),
                    )
                    .to_string()
                };
                Ok((hash, bytes))
            }
        }
    }
}

/// Reads blocks ahead of the apply loop so fetch latency overlaps validation —
/// the serial round-trip-per-block fetch otherwise accounts for ~24% of replay
/// wall-clock (96s of 397s over 0..150k), time a real node spends overlapped
/// with download or disk reads on other threads.
fn spawn_prefetch(
    host: &str,
    start_height: u32,
    stop_height: u32,
) -> Result<crossbeam_channel::Receiver<Result<FetchedBlock>>> {
    let mut client = RestClient::connect(host)?;
    let (sender, receiver) = crossbeam_channel::bounded(32);
    std::thread::spawn(move || {
        for height in start_height..=stop_height {
            let item = fetch_rest_block(&mut client, height);
            let failed = item.is_err();
            // A send error means the apply loop dropped the receiver; stop.
            if sender.send(item).is_err() || failed {
                return;
            }
        }
    });
    Ok(receiver)
}

fn fetch_rest_block(client: &mut RestClient, height: u32) -> Result<FetchedBlock> {
    let hash_bytes = client
        .get(&format!("/rest/blockhashbyheight/{height}.hex"))
        .with_context(|| format!("get block hash at height {height}"))?;
    let hash = String::from_utf8(hash_bytes)
        .context("block hash response is not UTF-8")?
        .trim()
        .to_owned();
    let bytes = client
        .get(&format!("/rest/block/{hash}.bin"))
        .with_context(|| format!("get block {hash} at height {height}"))?;
    Ok((hash, bytes))
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
        "usage: cargo run -p bitcoin-rs-node --example mainnet_prefix_replay --no-default-features --features fjall -- --stop-height <height> [--rest-url <host:port>] [--assume-valid-height <height>] [--bitcoin-cli <path>] [--bitcoin-cli-arg <arg>]... [--data-dir <path>] [--output <path>] [--txindex] [--blockfilterindex]"
    );
}
