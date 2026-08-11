//! Versioned corpus manifest and active-chain Core-frame exporter.
//!
//! A `CorpusManifest` names a single network, a single contiguous block range
//! `[0, stop]`, and the offset/length table for every block in the archive.
//! The manifest is the durable integrity contract; `export_active_chain_corpus`
//! streams the matching archive through [`bitcoin_rs_storage::CoreFrameWriter`]
//! and publishes it before the validated manifest.

use std::fs;
use std::io::{self, BufRead as _, BufReader, BufWriter, Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bitcoin::Block;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash as _;
use bitcoin::hashes::sha256d;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_primitives::{Hash256, Network};
use bitcoin_rs_rpc::BlockBodySource;
use bitcoin_rs_storage::{CORE_FRAME_HEADER_LEN, CoreFrameError, CoreFrameWriter};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub(crate) const SCHEMA: &str = "bitcoin-rs-corpus-manifest";
pub(crate) const VERSION: u32 = 1;
const MAGIC_HEX_LEN: usize = 8;
const HASH_HEX_LEN: usize = 64;
const SHA256_HEX_LEN: usize = 64;
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_HTTP_LINE_BYTES: u64 = 8 * 1024;
const REST_TIMEOUT: Duration = Duration::from_secs(30);
/// Consensus-maximum serialized block size in bytes.
pub(crate) const MAX_PAYLOAD_BYTES: u32 = 4_000_000;

/// A validated corpus manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorpusManifest {
    /// Bitcoin network the archive belongs to.
    pub network: Network,
    /// P2P message-start bytes for `network` in wire order.
    pub network_magic: [u8; 4],
    /// Genesis block hash for `network` in canonical displayed form.
    pub genesis_hash: Hash256,
    /// Inclusive start height; always `0` for a valid manifest.
    pub start_height: u32,
    /// Inclusive stop height.
    pub stop_height: u32,
    /// Archive payload metadata.
    pub archive: ArchiveInfo,
    /// One entry per height, contiguous from `start_height` to `stop_height`.
    pub entries: Vec<CorpusEntry>,
}

/// Archive-level metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveInfo {
    /// Total archive size in bytes.
    pub size: u64,
    /// SHA-256 digest of the entire archive.
    pub sha256: [u8; 32],
}

/// One block's position and identity inside the archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorpusEntry {
    /// Block height.
    pub height: u32,
    /// Block hash in canonical displayed Bitcoin form.
    pub hash: Hash256,
    /// Byte offset of the frame's magic in the archive.
    pub offset: u64,
    /// Length in bytes of the block's consensus-serialized payload.
    pub payload_length: u32,
}

/// Errors from manifest parsing, validation, or persistence.
#[derive(Debug, Error)]
pub enum CorpusError {
    /// Underlying I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// JSON parse or out-of-range integer failure.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// Top-level `schema` field did not match the expected value.
    #[error("schema mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Supported schema name.
        expected: &'static str,
        /// Schema name from the manifest.
        actual: String,
    },
    /// `version` field did not match the supported value.
    #[error("version mismatch: expected {expected}, got {actual}")]
    VersionMismatch {
        /// Supported schema version.
        expected: u32,
        /// Version from the manifest.
        actual: u32,
    },
    /// Network name is not one of the supported names.
    #[error("unknown network: {name}")]
    UnknownNetwork {
        /// Unrecognized network name.
        name: String,
    },
    /// Stored network magic does not match the configured network.
    #[error("network magic mismatch: expected {expected}, got {actual}")]
    NetworkMagicMismatch {
        /// Magic derived from the configured network.
        expected: String,
        /// Magic from the manifest.
        actual: String,
    },
    /// Stored genesis hash does not match the configured network.
    #[error("genesis hash mismatch for {network:?}: expected {expected}, got {actual}")]
    GenesisMismatch {
        /// Configured network.
        network: Network,
        /// Genesis hash derived from the network.
        expected: String,
        /// Genesis hash from the manifest.
        actual: String,
    },
    /// The manifest does not start at height 0.
    #[error("corpus must start at height 0, got {start}")]
    NonZeroStart {
        /// Declared start height.
        start: u32,
    },
    /// The manifest has no entries.
    #[error("empty corpus entries")]
    EmptyEntries,
    /// The inclusive stop height cannot be represented as a vector capacity.
    #[error("entry capacity for stop height {stop} does not fit this platform")]
    EntryCapacityOverflow {
        /// Declared inclusive stop height.
        stop: u32,
    },
    /// The entry count does not match the declared stop height.
    #[error("expected {expected} entries for stop height {stop}, got {count}")]
    EntryCountMismatch {
        /// Declared inclusive stop height.
        stop: u32,
        /// Entry count implied by the inclusive range.
        expected: u64,
        /// Actual number of entries.
        count: usize,
    },
    /// Heights are duplicated, gapped, or out of order.
    #[error("height mismatch at index {index}: expected {expected}, got {actual}")]
    HeightMismatch {
        /// Entry index in the manifest.
        index: usize,
        /// Contiguous height required at this index.
        expected: u32,
        /// Height stored in the entry.
        actual: u32,
    },
    /// An offset is not the expected continuation of the previous frame.
    #[error("offset mismatch at index {index}: expected {expected}, got {actual}")]
    OffsetMismatch {
        /// Entry index in the manifest.
        index: usize,
        /// Contiguous frame offset required at this index.
        expected: u64,
        /// Offset stored in the entry.
        actual: u64,
    },
    /// Computing the next frame end overflowed `u64`.
    #[error("offset arithmetic overflow at index {index}")]
    OffsetOverflow {
        /// Entry index whose frame end overflowed.
        index: usize,
    },
    /// A payload length exceeds the consensus maximum block size.
    #[error("oversized payload length {length} at index {index}")]
    OversizedPayload {
        /// Entry index in the manifest.
        index: usize,
        /// Declared payload length.
        length: u32,
    },
    /// The final frame end does not match the declared archive size.
    #[error("archive size mismatch: final frame ends at {computed}, manifest declares {declared}")]
    ArchiveSizeMismatch {
        /// Archive size implied by the final frame.
        computed: u64,
        /// Archive size stored in the manifest.
        declared: u64,
    },
    /// A hex string is not composed of lowercase hexadecimal characters.
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    /// A hash or digest is not exactly 64 lowercase hex characters.
    #[error("invalid hash length: expected {expected}, got {length}")]
    InvalidHashLength {
        /// Required hexadecimal string length.
        expected: usize,
        /// Actual string length.
        length: usize,
    },
    /// The network magic is not exactly 8 lowercase hex characters.
    #[error("invalid magic length: expected {MAGIC_HEX_LEN}, got {length}")]
    InvalidMagicLength {
        /// Actual string length.
        length: usize,
    },
    /// Archive and manifest resolve to the same destination.
    #[error("archive and manifest paths collide: {path}")]
    PathCollision {
        /// Colliding destination.
        path: PathBuf,
    },
    /// A final output already exists and will not be replaced.
    #[error("output already exists: {path}")]
    OutputExists {
        /// Existing destination.
        path: PathBuf,
    },
    /// An output path has no final file name.
    #[error("output path has no file name: {path}")]
    InvalidOutputPath {
        /// Invalid destination.
        path: PathBuf,
    },
    /// The requested stop height is beyond the active tip.
    #[error("stop height {stop} exceeds active tip {tip:?}")]
    StopAboveTip {
        /// Requested inclusive stop height.
        stop: u32,
        /// Active tip height, absent when the tree has no active tip.
        tip: Option<u32>,
    },
    /// The active-chain lookup returned an entry at the wrong height.
    #[error("noncontiguous active entry: requested height {expected}, got {actual}")]
    NoncontiguousActiveEntry {
        /// Requested height.
        expected: u32,
        /// Height stored in the returned node.
        actual: u32,
    },
    /// The active chain has no entry at a required height.
    #[error("missing active-chain entry at height {height}")]
    MissingActiveEntry {
        /// Missing height.
        height: u32,
    },
    /// The durable block-body source has no bytes for an active block.
    #[error("missing block body at height {height} for {hash}")]
    MissingBody {
        /// Active-chain height.
        height: u32,
        /// Expected active-chain hash.
        hash: Hash256,
    },
    /// Stored consensus bytes did not decode as one complete block.
    #[error("invalid block body at height {height}: {source}")]
    InvalidBody {
        /// Active-chain height.
        height: u32,
        /// Consensus decoding failure.
        #[source]
        source: bitcoin::consensus::encode::Error,
    },
    /// The stored body's block hash differs from the active-chain hash.
    #[error("block body hash mismatch at height {height}: expected {expected}, got {actual}")]
    BodyHashMismatch {
        /// Active-chain height.
        height: u32,
        /// Active-chain hash.
        expected: Hash256,
        /// Decoded body's hash.
        actual: Hash256,
    },
    /// Core-frame streaming failed.
    #[error("Core frame error: {0}")]
    CoreFrame(#[from] CoreFrameError),
    /// Core REST transport or protocol failure.
    #[error("Core REST error: {0}")]
    Rest(#[from] CoreRestError),
    /// A REST payload is too short to contain a block header.
    #[error("REST block payload at height {height} is only {len} bytes; expected at least 80")]
    RestShortPayload {
        /// Requested height.
        height: u32,
        /// Received payload length.
        len: usize,
    },
    /// The hash reported by Core differs from the payload header hash.
    #[error(
        "REST block hash mismatch at height {height}: reported {reported}, computed {computed}"
    )]
    RestHashMismatch {
        /// Requested height.
        height: u32,
        /// Hash returned by `blockhashbyheight`.
        reported: String,
        /// Hash computed from the received header.
        computed: String,
    },
    /// The first REST block is not the configured network's genesis block.
    #[error("REST genesis mismatch: expected {expected}, got {actual}")]
    RestGenesisMismatch {
        /// Configured network genesis.
        expected: String,
        /// Received height-zero hash.
        actual: String,
    },
    /// Consecutive REST blocks do not form one chain.
    #[error(
        "REST chain discontinuity at height {height}: expected parent {expected_prev}, got {actual_prev}"
    )]
    RestContinuity {
        /// Discontinuous block height.
        height: u32,
        /// Previously fetched block hash.
        expected_prev: String,
        /// Parent named by this block.
        actual_prev: String,
    },
    /// A temporary output name could not be reserved.
    #[error("could not reserve a sibling temporary file for {path}")]
    TempNameExhausted {
        /// Final destination.
        path: PathBuf,
    },
}

/// Errors from the synchronous Bitcoin Core REST client.
#[derive(Debug, Error)]
pub enum CoreRestError {
    /// Opening the TCP connection failed.
    #[error("connect to {host}: {source}")]
    Connect {
        /// REST host in `host:port` form.
        host: String,
        /// Socket error.
        #[source]
        source: io::Error,
    },
    /// Reading or writing the REST connection failed.
    #[error("REST I/O error: {0}")]
    Io(#[from] io::Error),
    /// The response status was not HTTP 200.
    #[error("REST GET {path} failed: {status}")]
    HttpStatus {
        /// Requested path.
        path: String,
        /// Complete status line.
        status: String,
    },
    /// No Content-Length header was present.
    #[error("REST response without Content-Length: {status}")]
    MissingContentLength {
        /// Complete status line.
        status: String,
    },
    /// Content-Length was not a non-negative decimal integer.
    #[error("invalid Content-Length {value:?}")]
    InvalidContentLength {
        /// Header value.
        value: String,
    },
    /// A status or header line exceeded the protocol bound.
    #[error("REST response line exceeds {MAX_HTTP_LINE_BYTES} bytes")]
    OversizedHeaderLine,
    /// A response body exceeded the configured safety bound.
    #[error("REST GET {path}: Content-Length {len} exceeds sane bound")]
    OversizedBody {
        /// Requested path.
        path: String,
        /// Declared response length.
        len: usize,
    },
    /// The block-hash response was not UTF-8.
    #[error("block hash response is not UTF-8")]
    NonUtf8Hash,
    /// The block-hash response was not a canonical hash.
    #[error("invalid block hash hex: {0}")]
    InvalidHashHex(String),
}

/// Minimal synchronous keep-alive client for Bitcoin Core's REST interface.
pub struct CoreRestClient {
    host: String,
    stream: BufReader<TcpStream>,
}

impl CoreRestClient {
    /// Opens a bounded blocking connection to `host` in `host:port` form.
    pub fn connect(host: &str) -> Result<Self, CoreRestError> {
        let stream = TcpStream::connect(host).map_err(|source| CoreRestError::Connect {
            host: host.to_owned(),
            source,
        })?;
        stream.set_read_timeout(Some(REST_TIMEOUT))?;
        stream.set_write_timeout(Some(REST_TIMEOUT))?;
        Ok(Self {
            host: host.to_owned(),
            stream: BufReader::new(stream),
        })
    }

    /// Fetches one bounded response, reconnecting once if the keep-alive socket failed.
    pub fn get(&mut self, path: &str) -> Result<Vec<u8>, CoreRestError> {
        match self.request(path) {
            Ok(body) => Ok(body),
            // A keep-alive socket may close between requests; retry once for I/O
            // failures only. Protocol/logic errors are final.
            Err(CoreRestError::Io(_)) => {
                *self = Self::connect(&self.host)?;
                self.request(path)
            }
            Err(other) => Err(other),
        }
    }

    fn request(&mut self, path: &str) -> Result<Vec<u8>, CoreRestError> {
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
            self.host
        );
        self.stream.get_mut().write_all(request.as_bytes())?;
        let status = read_http_line(&mut self.stream)?;
        let mut content_length = None;
        loop {
            let header = read_http_line(&mut self.stream)?;
            if header.is_empty() {
                break;
            }
            if let Some(value) = header
                .to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(str::trim)
            {
                let length = value
                    .parse()
                    .map_err(|_| CoreRestError::InvalidContentLength {
                        value: value.to_owned(),
                    })?;
                content_length = Some(length);
            }
        }
        let length = content_length.ok_or_else(|| CoreRestError::MissingContentLength {
            status: status.clone(),
        })?;
        if length > MAX_BODY_BYTES {
            return Err(CoreRestError::OversizedBody {
                path: path.to_owned(),
                len: length,
            });
        }
        let mut body = vec![0_u8; length];
        self.stream.read_exact(&mut body)?;
        if status.split_whitespace().nth(1) != Some("200") {
            return Err(CoreRestError::HttpStatus {
                path: path.to_owned(),
                status,
            });
        }
        Ok(body)
    }
}

fn read_http_line(stream: &mut BufReader<TcpStream>) -> Result<String, CoreRestError> {
    let mut bytes = Vec::new();
    let read = stream
        .take(MAX_HTTP_LINE_BYTES + 1)
        .read_until(b'\n', &mut bytes)?;
    if read == 0 {
        return Err(CoreRestError::Io(io::ErrorKind::UnexpectedEof.into()));
    }
    let max_line = usize::try_from(MAX_HTTP_LINE_BYTES).unwrap_or(usize::MAX);
    if read > max_line || !bytes.ends_with(b"\n") {
        return Err(CoreRestError::OversizedHeaderLine);
    }
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    String::from_utf8(bytes).map_err(|_| CoreRestError::OversizedHeaderLine)
}

/// A fetched block's canonical displayed hash and raw consensus bytes.
pub type FetchedBlock = (String, Vec<u8>);

/// Fetches a height's hash and raw block bytes from Bitcoin Core REST.
pub fn fetch_rest_block(
    client: &mut CoreRestClient,
    height: u32,
) -> Result<FetchedBlock, CoreRestError> {
    let hash_bytes = client.get(&format!("/rest/blockhashbyheight/{height}.hex"))?;
    let hash = String::from_utf8(hash_bytes)
        .map_err(|_| CoreRestError::NonUtf8Hash)?
        .trim()
        .to_owned();
    Hash256::from_str_be(&hash).map_err(|_| CoreRestError::InvalidHashHex(hash.clone()))?;
    let bytes = client.get(&format!("/rest/block/{hash}.bin"))?;
    Ok((hash, bytes))
}

struct CorpusBlock {
    hash: Hash256,
    payload: Vec<u8>,
}

trait CorpusBlockSource {
    fn next_block(&mut self, height: u32) -> Result<CorpusBlock, CorpusError>;
}

struct BlockTreeSource<'a> {
    tree: &'a BlockTree,
    body: &'a dyn BlockBodySource,
}

impl CorpusBlockSource for BlockTreeSource<'_> {
    fn next_block(&mut self, height: u32) -> Result<CorpusBlock, CorpusError> {
        let node = self
            .tree
            .active_node_at_height(height)
            .ok_or(CorpusError::MissingActiveEntry { height })?;
        if node.height != height {
            return Err(CorpusError::NoncontiguousActiveEntry {
                expected: height,
                actual: node.height,
            });
        }
        let hash = node.hash;
        let payload = self
            .body
            .block_body(height, hash)
            .ok_or(CorpusError::MissingBody { height, hash })?;
        Ok(CorpusBlock { hash, payload })
    }
}

struct RestCorpusSource {
    fetcher: Box<dyn FnMut(u32) -> Result<FetchedBlock, CoreRestError>>,
    network: Network,
    prev: Option<Hash256>,
}

impl CorpusBlockSource for RestCorpusSource {
    fn next_block(&mut self, height: u32) -> Result<CorpusBlock, CorpusError> {
        let (reported, payload) = (self.fetcher)(height)?;
        if payload.len() < 80 {
            return Err(CorpusError::RestShortPayload {
                height,
                len: payload.len(),
            });
        }
        let hash = Hash256::from_str_be(&reported)
            .map_err(|_| CoreRestError::InvalidHashHex(reported.clone()))?;
        let computed = Hash256::from_le_bytes(sha256d::Hash::hash(&payload[..80]).as_byte_array());
        if computed != hash {
            return Err(CorpusError::RestHashMismatch {
                height,
                reported,
                computed: computed.to_string_be(),
            });
        }
        let mut actual_prev_bytes = [0_u8; 32];
        actual_prev_bytes.copy_from_slice(&payload[4..36]);
        let actual_prev = Hash256::from_le_bytes(&actual_prev_bytes);
        if height == 0 {
            let expected = self.network.genesis_block_hash();
            if computed != expected {
                return Err(CorpusError::RestGenesisMismatch {
                    expected: expected.to_string_be(),
                    actual: computed.to_string_be(),
                });
            }
        } else if self.prev != Some(actual_prev) {
            return Err(CorpusError::RestContinuity {
                height,
                expected_prev: self
                    .prev
                    .map_or_else(String::new, bitcoin_rs_primitives::Hash256::to_string_be),
                actual_prev: actual_prev.to_string_be(),
            });
        }
        self.prev = Some(computed);
        Ok(CorpusBlock { hash, payload })
    }
}

/// Streams heights `0..=stop_height` directly from Bitcoin Core REST.
pub fn export_corpus_from_rest(
    rest_url: &str,
    network: Network,
    stop_height: u32,
    archive_path: impl AsRef<Path>,
    manifest_path: impl AsRef<Path>,
) -> Result<CorpusManifest, CorpusError> {
    let (archive_path, manifest_path) =
        prepare_corpus_destinations(archive_path.as_ref(), manifest_path.as_ref())?;
    let mut client = CoreRestClient::connect(rest_url)?;
    let mut source = RestCorpusSource {
        fetcher: Box::new(move |height| fetch_rest_block(&mut client, height)),
        network,
        prev: None,
    };
    write_corpus_archive(
        &mut source,
        network,
        stop_height,
        &archive_path,
        &manifest_path,
    )
}

/// Exports heights `0..=stop_height` from an opened production node state.
///
/// The archive contains Bitcoin Core `-loadblock` frames. Stored consensus body
/// bytes are decoded only to verify their hash and are written without
/// re-encoding. The archive is durably published before the validated manifest.
pub fn export_active_chain_corpus(
    state: &crate::state::NodeState,
    network: Network,
    stop_height: u32,
    archive_path: impl AsRef<Path>,
    manifest_path: impl AsRef<Path>,
) -> Result<CorpusManifest, CorpusError> {
    let block_tree = state.block_tree();
    let block_tree = block_tree.read();
    let body_source = state.block_body_source();
    export_from_sources(
        &block_tree,
        body_source.as_ref(),
        network,
        stop_height,
        archive_path.as_ref(),
        manifest_path.as_ref(),
    )
}

pub(crate) fn export_from_sources(
    block_tree: &BlockTree,
    body_source: &dyn BlockBodySource,
    network: Network,
    stop_height: u32,
    archive_path: &Path,
    manifest_path: &Path,
) -> Result<CorpusManifest, CorpusError> {
    let (archive_path, manifest_path) = prepare_corpus_destinations(archive_path, manifest_path)?;
    let tip = block_tree.tip_height();
    match tip {
        Some(tip_height) if stop_height <= tip_height => {}
        _ => {
            return Err(CorpusError::StopAboveTip {
                stop: stop_height,
                tip,
            });
        }
    }
    let mut source = BlockTreeSource {
        tree: block_tree,
        body: body_source,
    };
    write_corpus_archive(
        &mut source,
        network,
        stop_height,
        &archive_path,
        &manifest_path,
    )
}

fn prepare_corpus_destinations(
    archive_path: &Path,
    manifest_path: &Path,
) -> Result<(PathBuf, PathBuf), CorpusError> {
    let archive_path = prepare_destination(archive_path)?;
    let manifest_path = prepare_destination(manifest_path)?;
    if archive_path == manifest_path {
        return Err(CorpusError::PathCollision { path: archive_path });
    }
    Ok((archive_path, manifest_path))
}

fn write_corpus_archive(
    source: &mut dyn CorpusBlockSource,
    network: Network,
    stop_height: u32,
    archive_path: &Path,
    manifest_path: &Path,
) -> Result<CorpusManifest, CorpusError> {
    ensure_absent(archive_path)?;
    ensure_absent(manifest_path)?;

    let (mut archive_temp, archive_file) = TempFile::create(archive_path)?;
    let mut hashing_writer = HashingWriter::new(BufWriter::new(archive_file));
    let entry_capacity = usize::try_from(u64::from(stop_height) + 1)
        .map_err(|_| CorpusError::EntryCapacityOverflow { stop: stop_height })?;
    let mut entries = Vec::with_capacity(entry_capacity);
    let archive_size;
    {
        let mut frames = CoreFrameWriter::new(&mut hashing_writer, network.magic());
        for height in 0..=stop_height {
            let CorpusBlock { hash, payload } = source.next_block(height)?;
            let block: Block = deserialize(&payload)
                .map_err(|source| CorpusError::InvalidBody { height, source })?;
            let actual = Hash256::from_le_bytes(block.block_hash().as_byte_array());
            if actual != hash {
                return Err(CorpusError::BodyHashMismatch {
                    height,
                    expected: hash,
                    actual,
                });
            }
            let metadata = frames.write(&payload)?;
            entries.push(CorpusEntry {
                height,
                hash,
                offset: metadata.offset,
                payload_length: metadata.len,
            });
        }
        archive_size = frames.offset();
    }
    let (mut buf, hasher) = hashing_writer.into_parts();
    buf.flush()?;
    let file = buf
        .into_inner()
        .map_err(std::io::IntoInnerError::into_error)?;
    file.sync_all()?;
    let archive_digest: [u8; 32] = hasher.finalize().into();
    drop(file);
    let stored_size = fs::metadata(archive_temp.path())?.len();
    if stored_size != archive_size {
        return Err(CorpusError::ArchiveSizeMismatch {
            computed: archive_size,
            declared: stored_size,
        });
    }

    let manifest = CorpusManifest::new(
        network,
        ArchiveInfo::new(archive_size, archive_digest),
        entries,
    )?;
    let manifest_bytes = serde_json::to_vec(&CorpusManifestV1::from(&manifest))?;
    let (mut manifest_temp, mut manifest_file) = TempFile::create(manifest_path)?;
    manifest_file.write_all(&manifest_bytes)?;
    manifest_file.flush()?;
    manifest_file.sync_all()?;
    drop(manifest_file);

    ensure_absent(archive_path)?;
    ensure_absent(manifest_path)?;
    archive_temp.publish(archive_path)?;
    sync_parent(archive_path)?;
    manifest_temp.publish(manifest_path)?;
    sync_parent(manifest_path)?;
    Ok(manifest)
}

struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
}

impl<W> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn into_parts(self) -> (W, Sha256) {
        (self.inner, self.hasher)
    }
}

impl<W: io::Write> io::Write for HashingWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.hasher.update(&bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct TempFile {
    path: PathBuf,
    armed: bool,
}

impl TempFile {
    fn create(target: &Path) -> Result<(Self, fs::File), CorpusError> {
        static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
        let file_name = target
            .file_name()
            .ok_or_else(|| CorpusError::InvalidOutputPath {
                path: target.to_owned(),
            })?;
        for _ in 0..128 {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let mut temp_name = file_name.to_os_string();
            temp_name.push(format!(".tmp.{}.{id}", std::process::id()));
            let path = target.with_file_name(temp_name);
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => {
                    return Ok((Self { path, armed: true }, file));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(CorpusError::TempNameExhausted {
            path: target.to_owned(),
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn publish(&mut self, target: &Path) -> Result<(), CorpusError> {
        rename_noreplace(&self.path, target).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                CorpusError::OutputExists {
                    path: target.to_owned(),
                }
            } else {
                CorpusError::Io(error)
            }
        })?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn prepare_destination(path: &Path) -> Result<PathBuf, CorpusError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| CorpusError::InvalidOutputPath {
            path: path.to_owned(),
        })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    Ok(fs::canonicalize(parent)?.join(file_name))
}

fn ensure_absent(path: &Path) -> Result<(), CorpusError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(CorpusError::OutputExists {
            path: path.to_owned(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn sync_parent(path: &Path) -> io::Result<()> {
    fs::File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        from,
        rustix::fs::CWD,
        to,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(Into::into)
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
)))]
fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    fs::hard_link(from, to)?;
    fs::remove_file(from)
}

impl CorpusManifest {
    /// Schema identifier for the v1 manifest.
    pub const SCHEMA: &'static str = SCHEMA;
    /// Version number for the v1 manifest.
    pub const VERSION: u32 = VERSION;

    /// Constructs and validates a manifest from its constituent parts.
    ///
    /// `network_magic` and `genesis_hash` are derived from `network`; the
    /// caller is responsible for ensuring `entries` are contiguous and the
    /// archive size matches the final frame.
    pub fn new(
        network: Network,
        archive: ArchiveInfo,
        entries: Vec<CorpusEntry>,
    ) -> Result<Self, CorpusError> {
        let start_height = 0;
        let stop_height = match entries.len() {
            0 => return Err(CorpusError::EmptyEntries),
            n => u32::try_from(n - 1).map_err(|_| CorpusError::OffsetOverflow { index: 0 })?,
        };

        let manifest = Self {
            network,
            network_magic: network.magic(),
            genesis_hash: network.genesis_block_hash(),
            start_height,
            stop_height,
            archive,
            entries,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Loads a manifest from a JSON file and validates every field.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, CorpusError> {
        let bytes = fs::read(path.as_ref())?;
        Self::from_bytes(&bytes)
    }

    /// Parses and validates a manifest from its in-memory JSON bytes.
    ///
    /// Keeps the read and the parse in one call so a caller can hash the same
    /// bytes it validated, avoiding a second file read.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CorpusError> {
        let wire: CorpusManifestV1 = serde_json::from_slice(bytes)?;
        wire.try_into()
    }

    /// Validates a manifest from a path and returns the parsed manifest plus
    /// the raw bytes that produced it, so the caller can compute the manifest
    /// file's own digest without reading it a second time.
    pub fn load_with_bytes(path: impl AsRef<Path>) -> Result<(Self, Vec<u8>), CorpusError> {
        let bytes = fs::read(path.as_ref())?;
        let manifest = Self::from_bytes(&bytes)?;
        Ok((manifest, bytes))
    }

    /// Saves this manifest to `path` atomically via a temp file, fsync, and
    /// rename, followed by a parent-directory fsync.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), CorpusError> {
        self.validate()?;
        let wire = CorpusManifestV1::from(self);
        let bytes = serde_json::to_vec(&wire)?;

        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let tmp = path.with_extension("tmp");

        {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp)?;
            file.write_all(&bytes)?;
            file.flush()?;
            file.sync_all()?;
        }

        fs::rename(&tmp, path)?;
        fs::File::open(parent)?.sync_all()?;

        Ok(())
    }

    /// Re-validates the in-memory manifest.
    pub fn validate(&self) -> Result<(), CorpusError> {
        if self.start_height != 0 {
            return Err(CorpusError::NonZeroStart {
                start: self.start_height,
            });
        }
        if self.network_magic != self.network.magic() {
            return Err(CorpusError::NetworkMagicMismatch {
                expected: hex_encode(&self.network.magic()),
                actual: hex_encode(&self.network_magic),
            });
        }
        if self.genesis_hash != self.network.genesis_block_hash() {
            return Err(CorpusError::GenesisMismatch {
                network: self.network,
                expected: self.network.genesis_block_hash().to_string_be(),
                actual: self.genesis_hash.to_string_be(),
            });
        }

        if self.entries.is_empty() {
            return Err(CorpusError::EmptyEntries);
        }

        let expected_count = u64::from(self.stop_height)
            .checked_add(1)
            .ok_or(CorpusError::OffsetOverflow { index: 0 })?;
        let entry_count =
            u64::try_from(self.entries.len()).map_err(|_| CorpusError::EntryCountMismatch {
                stop: self.stop_height,
                expected: expected_count,
                count: self.entries.len(),
            })?;
        if entry_count != expected_count {
            return Err(CorpusError::EntryCountMismatch {
                stop: self.stop_height,
                expected: expected_count,
                count: self.entries.len(),
            });
        }

        let mut expected_offset = 0_u64;
        let last_index = self.entries.len().saturating_sub(1);
        for (index, entry) in self.entries.iter().enumerate() {
            let height_offset = u32::try_from(index).map_err(|_| CorpusError::HeightMismatch {
                index,
                expected: self.stop_height,
                actual: entry.height,
            })?;
            let expected_height = self.start_height.wrapping_add(height_offset);
            if entry.height != expected_height {
                return Err(CorpusError::HeightMismatch {
                    index,
                    expected: expected_height,
                    actual: entry.height,
                });
            }
            if entry.payload_length > MAX_PAYLOAD_BYTES {
                return Err(CorpusError::OversizedPayload {
                    index,
                    length: entry.payload_length,
                });
            }
            if index == 0 {
                if entry.offset != 0 {
                    return Err(CorpusError::OffsetMismatch {
                        index,
                        expected: 0,
                        actual: entry.offset,
                    });
                }
            } else if entry.offset != expected_offset {
                return Err(CorpusError::OffsetMismatch {
                    index,
                    expected: expected_offset,
                    actual: entry.offset,
                });
            }

            expected_offset = entry
                .offset
                .checked_add(CORE_FRAME_HEADER_LEN)
                .and_then(|o| o.checked_add(u64::from(entry.payload_length)))
                .ok_or(CorpusError::OffsetOverflow { index })?;

            if index == last_index && expected_offset != self.archive.size {
                return Err(CorpusError::ArchiveSizeMismatch {
                    computed: expected_offset,
                    declared: self.archive.size,
                });
            }
        }

        Ok(())
    }
}

impl ArchiveInfo {
    /// Constructs archive metadata from the file size and SHA-256 digest.
    pub const fn new(size: u64, sha256: [u8; 32]) -> Self {
        Self { size, sha256 }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CorpusManifestV1 {
    schema: String,
    version: u32,
    network: String,
    network_magic: String,
    genesis_hash: String,
    range: RangeV1,
    archive: ArchiveInfoV1,
    entries: Vec<CorpusEntryV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RangeV1 {
    start_height: u32,
    stop_height: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArchiveInfoV1 {
    size: u64,
    sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CorpusEntryV1 {
    height: u32,
    hash: String,
    offset: u64,
    payload_length: u32,
}

impl TryFrom<CorpusManifestV1> for CorpusManifest {
    type Error = CorpusError;

    fn try_from(wire: CorpusManifestV1) -> Result<Self, Self::Error> {
        if wire.schema != SCHEMA {
            return Err(CorpusError::SchemaMismatch {
                expected: SCHEMA,
                actual: wire.schema,
            });
        }
        if wire.version != VERSION {
            return Err(CorpusError::VersionMismatch {
                expected: VERSION,
                actual: wire.version,
            });
        }

        let network = parse_network_name(&wire.network)?;

        let magic = decode_magic(&wire.network_magic)?;
        if magic != network.magic() {
            return Err(CorpusError::NetworkMagicMismatch {
                expected: hex_encode(&network.magic()),
                actual: wire.network_magic,
            });
        }

        let genesis = parse_hash256(&wire.genesis_hash)?;
        let expected_genesis = network.genesis_block_hash();
        if genesis != expected_genesis {
            return Err(CorpusError::GenesisMismatch {
                network,
                expected: expected_genesis.to_string_be(),
                actual: wire.genesis_hash,
            });
        }

        if wire.range.start_height != 0 {
            return Err(CorpusError::NonZeroStart {
                start: wire.range.start_height,
            });
        }

        let archive = ArchiveInfo {
            size: wire.archive.size,
            sha256: decode_sha256(&wire.archive.sha256)?,
        };

        let mut entries = Vec::with_capacity(wire.entries.len());
        for wire_entry in wire.entries {
            entries.push(CorpusEntry {
                height: wire_entry.height,
                hash: parse_hash256(&wire_entry.hash)?,
                offset: wire_entry.offset,
                payload_length: wire_entry.payload_length,
            });
        }

        let manifest = Self {
            network,
            network_magic: magic,
            genesis_hash: genesis,
            start_height: wire.range.start_height,
            stop_height: wire.range.stop_height,
            archive,
            entries,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

impl From<&CorpusManifest> for CorpusManifestV1 {
    fn from(manifest: &CorpusManifest) -> Self {
        Self {
            schema: SCHEMA.to_owned(),
            version: VERSION,
            network: network_name(manifest.network).to_owned(),
            network_magic: hex_encode(&manifest.network_magic),
            genesis_hash: manifest.genesis_hash.to_string_be(),
            range: RangeV1 {
                start_height: manifest.start_height,
                stop_height: manifest.stop_height,
            },
            archive: ArchiveInfoV1 {
                size: manifest.archive.size,
                sha256: hex_encode(&manifest.archive.sha256),
            },
            entries: manifest
                .entries
                .iter()
                .map(|entry| CorpusEntryV1 {
                    height: entry.height,
                    hash: entry.hash.to_string_be(),
                    offset: entry.offset,
                    payload_length: entry.payload_length,
                })
                .collect(),
        }
    }
}

fn network_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet3 => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

fn parse_network_name(name: &str) -> Result<Network, CorpusError> {
    match name {
        "mainnet" => Ok(Network::Mainnet),
        "testnet" => Ok(Network::Testnet3),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(CorpusError::UnknownNetwork {
            name: name.to_owned(),
        }),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn is_lower_hex(s: &str, expected_len: usize) -> Result<(), CorpusError> {
    if s.len() != expected_len {
        return Err(CorpusError::InvalidHashLength {
            expected: expected_len,
            length: s.len(),
        });
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CorpusError::InvalidHex(s.to_owned()));
    }
    Ok(())
}

fn decode_hex<const N: usize>(s: &str) -> Result<[u8; N], CorpusError> {
    is_lower_hex(s, N.saturating_mul(2))?;
    let mut out = [0_u8; N];
    for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
        let hi = decode_nibble(pair[0]);
        let lo = decode_nibble(pair[1]);
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn decode_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

fn decode_magic(s: &str) -> Result<[u8; 4], CorpusError> {
    if s.len() != MAGIC_HEX_LEN {
        return Err(CorpusError::InvalidMagicLength { length: s.len() });
    }
    decode_hex::<4>(s)
}

fn decode_sha256(s: &str) -> Result<[u8; 32], CorpusError> {
    is_lower_hex(s, SHA256_HEX_LEN)?;
    decode_hex::<32>(s)
}

fn parse_hash256(s: &str) -> Result<Hash256, CorpusError> {
    is_lower_hex(s, HASH_HEX_LEN)?;
    Hash256::from_str_be(s).map_err(|_| CorpusError::InvalidHex(s.to_owned()))
}

#[cfg(test)]
// Test fixtures fail at the assertion site; production parsing stays fallible.
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use hashbrown::HashMap;
    use std::io::{BufRead as _, BufReader, Cursor, Write as _};
    use std::net::TcpListener;
    use std::thread;
    use std::{fs, path::Path};

    use bitcoin::Block;
    use bitcoin::block::{Header as BlockHeader, Version};
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
    use bitcoin_rs_chain::{BlockTree, NodeStatus};
    use bitcoin_rs_primitives::{Hash256, Network};
    use bitcoin_rs_rpc::BlockBodySource;
    use bitcoin_rs_storage::CoreFrameReader;
    use sha2::{Digest as _, Sha256};

    use super::{
        ArchiveInfo, BlockTreeSource, CoreRestClient, CoreRestError, CorpusEntry, CorpusError,
        CorpusManifest, CorpusManifestV1, HASH_HEX_LEN, MAX_BODY_BYTES, MAX_PAYLOAD_BYTES,
        RestCorpusSource, SCHEMA, VERSION, export_from_sources, write_corpus_archive,
    };

    fn sample_archive() -> ArchiveInfo {
        ArchiveInfo::new(22, [1; 32])
    }

    fn sample_entries() -> Vec<CorpusEntry> {
        vec![
            CorpusEntry {
                height: 0,
                hash: Hash256::from_le_bytes(&[0; 32]),
                offset: 0,
                payload_length: 2,
            },
            CorpusEntry {
                height: 1,
                hash: Hash256::from_le_bytes(&[1; 32]),
                offset: 10,
                payload_length: 4,
            },
        ]
    }

    fn sample_manifest() -> CorpusManifest {
        CorpusManifest::new(Network::Regtest, sample_archive(), sample_entries()).unwrap()
    }

    #[test]
    fn roundtrip_saves_and_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corpus-manifest-v1.json");

        let manifest = sample_manifest();
        manifest.save(&path).unwrap();
        let loaded = CorpusManifest::load(&path).unwrap();

        assert_eq!(loaded, manifest);
    }

    #[test]
    fn rejects_wrong_schema() {
        let json = r#"{"schema":"other","version":1,"network":"regtest","network_magic":"fabfb5da","genesis_hash":"0000000000000000000000000000000000000000000000000000000000000000","range":{"start_height":0,"stop_height":0},"archive":{"size":8,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"},"entries":[{"height":0,"hash":"0000000000000000000000000000000000000000000000000000000000000000","offset":0,"payload_length":0}]}"#;
        let err = CorpusManifest::try_from(serde_json::from_str::<CorpusManifestV1>(json).unwrap())
            .unwrap_err();
        assert!(matches!(err, CorpusError::SchemaMismatch { .. }));
    }

    #[test]
    fn rejects_wrong_version() {
        let json = r#"{"schema":"bitcoin-rs-corpus-manifest","version":2,"network":"regtest","network_magic":"fabfb5da","genesis_hash":"0000000000000000000000000000000000000000000000000000000000000000","range":{"start_height":0,"stop_height":0},"archive":{"size":8,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"},"entries":[{"height":0,"hash":"0000000000000000000000000000000000000000000000000000000000000000","offset":0,"payload_length":0}]}"#;
        let err = CorpusManifest::try_from(serde_json::from_str::<CorpusManifestV1>(json).unwrap())
            .unwrap_err();
        assert!(matches!(err, CorpusError::VersionMismatch { .. }));
    }

    #[test]
    fn rejects_unknown_network() {
        let manifest = sample_manifest();
        // Inject a bad network name through the wire path by hand-editing JSON.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        manifest.save(&path).unwrap();

        let text = fs::read_to_string(&path)
            .unwrap()
            .replace("regtest", "unknown");
        fs::write(&path, text).unwrap();

        let err = CorpusManifest::load(&path).unwrap_err();
        assert!(matches!(err, CorpusError::UnknownNetwork { .. }));
    }

    #[test]
    fn rejects_network_magic_mismatch() {
        let mut manifest = sample_manifest();
        manifest.network_magic = [0xde, 0xad, 0xbe, 0xef];
        manifest.network = Network::Regtest;
        manifest.genesis_hash = Network::Regtest.genesis_block_hash();
        let err = manifest.save(Path::new("/dev/null")).unwrap_err();
        assert!(matches!(err, CorpusError::NetworkMagicMismatch { .. }));
    }

    #[test]
    fn rejects_genesis_mismatch() {
        let mut manifest = sample_manifest();
        manifest.genesis_hash = Hash256::from_le_bytes(&[0xff; 32]);
        let err = manifest.save(Path::new("/dev/null")).unwrap_err();
        assert!(matches!(err, CorpusError::GenesisMismatch { .. }));
    }

    #[test]
    fn rejects_nonzero_start() {
        let mut wire = CorpusManifestV1::from(&sample_manifest());
        wire.range.start_height = 1;
        let err = CorpusManifest::try_from(wire).unwrap_err();
        assert!(matches!(err, CorpusError::NonZeroStart { .. }));
    }

    #[test]
    fn rejects_empty_entries() {
        let err = CorpusManifest::new(Network::Regtest, sample_archive(), Vec::new()).unwrap_err();
        assert!(matches!(err, CorpusError::EmptyEntries));
    }

    #[test]
    fn rejects_gapped_heights() {
        let mut entries = sample_entries();
        entries[1].height = 2;
        let err = CorpusManifest::new(Network::Regtest, sample_archive(), entries).unwrap_err();
        assert!(matches!(err, CorpusError::HeightMismatch { .. }));
    }

    #[test]
    fn rejects_duplicate_heights() {
        let mut entries = sample_entries();
        entries[1].height = 0;
        let err = CorpusManifest::new(Network::Regtest, sample_archive(), entries).unwrap_err();
        assert!(matches!(err, CorpusError::HeightMismatch { .. }));
    }

    #[test]
    fn rejects_nonzero_first_offset() {
        let mut entries = sample_entries();
        entries[0].offset = 1;
        let err = CorpusManifest::new(Network::Regtest, sample_archive(), entries).unwrap_err();
        assert!(matches!(err, CorpusError::OffsetMismatch { .. }));
    }

    #[test]
    fn rejects_inconsistent_offset() {
        let mut entries = sample_entries();
        entries[1].offset = 11;
        let err = CorpusManifest::new(Network::Regtest, sample_archive(), entries).unwrap_err();
        assert!(matches!(err, CorpusError::OffsetMismatch { .. }));
    }

    #[test]
    fn rejects_oversized_payload() {
        let mut entries = sample_entries();
        entries[0].payload_length = MAX_PAYLOAD_BYTES + 1;
        let err = CorpusManifest::new(Network::Regtest, sample_archive(), entries).unwrap_err();
        assert!(matches!(err, CorpusError::OversizedPayload { .. }));
    }

    #[test]
    fn rejects_archive_size_mismatch() {
        let entries = sample_entries();
        let archive = ArchiveInfo::new(13, [1; 32]);
        let err = CorpusManifest::new(Network::Regtest, archive, entries).unwrap_err();
        assert!(matches!(err, CorpusError::ArchiveSizeMismatch { .. }));
    }

    #[test]
    fn rejects_invalid_magic_length() {
        let manifest = sample_manifest();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        manifest.save(&path).unwrap();

        let text = fs::read_to_string(&path).unwrap().replace(
            "\"network_magic\":\"fabfb5da\"",
            "\"network_magic\":\"fabfb5\"",
        );
        fs::write(&path, text).unwrap();

        let err = CorpusManifest::load(&path).unwrap_err();
        assert!(matches!(err, CorpusError::InvalidMagicLength { .. }));
    }

    #[test]
    fn rejects_invalid_hex() {
        let mut wire = CorpusManifestV1::from(&sample_manifest());
        wire.entries[0].hash = "g".repeat(HASH_HEX_LEN);
        let err = CorpusManifest::try_from(wire).unwrap_err();
        assert!(matches!(err, CorpusError::InvalidHex { .. }));
    }

    #[test]
    fn rejects_invalid_hash_length() {
        let mut wire = CorpusManifestV1::from(&sample_manifest());
        wire.archive.sha256.pop();
        let err = CorpusManifest::try_from(wire).unwrap_err();
        assert!(matches!(err, CorpusError::InvalidHashLength { .. }));
    }

    #[test]
    fn rejects_out_of_range_version_integer() {
        let json = r#"{"schema":"bitcoin-rs-corpus-manifest","version":4294967296,"network":"regtest","network_magic":"fabfb5da","genesis_hash":"0000000000000000000000000000000000000000000000000000000000000000","range":{"start_height":0,"stop_height":0},"archive":{"size":8,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"},"entries":[{"height":0,"hash":"0000000000000000000000000000000000000000000000000000000000000000","offset":0,"payload_length":0}]}"#;
        assert!(serde_json::from_str::<CorpusManifestV1>(json).is_err());
    }

    #[test]
    fn rejects_out_of_range_payload_length_integer() {
        let json = r#"{"schema":"bitcoin-rs-corpus-manifest","version":1,"network":"regtest","network_magic":"fabfb5da","genesis_hash":"0000000000000000000000000000000000000000000000000000000000000000","range":{"start_height":0,"stop_height":0},"archive":{"size":8,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"},"entries":[{"height":0,"hash":"0000000000000000000000000000000000000000000000000000000000000000","offset":0,"payload_length":4294967296}]}"#;
        assert!(serde_json::from_str::<CorpusManifestV1>(json).is_err());
    }

    #[test]
    fn single_entry_archive_size_is_frame_length() {
        let entries = vec![CorpusEntry {
            height: 0,
            hash: Hash256::from_le_bytes(&[0; 32]),
            offset: 0,
            payload_length: 10,
        }];
        let archive = ArchiveInfo::new(18, [0; 32]);
        let manifest = CorpusManifest::new(Network::Regtest, archive, entries).unwrap();
        assert_eq!(manifest.stop_height, 0);
        assert_eq!(manifest.archive.size, 18);
    }

    #[test]
    fn boundary_max_u32_stop_height_roundtrips() {
        // One entry at height u32::MAX is not practical to allocate, so just
        // validate the wire form for the boundary value.
        let json = format!(
            r#"{{"schema":"{}","version":{},"network":"regtest","network_magic":"fabfb5da","genesis_hash":"0000000000000000000000000000000000000000000000000000000000000000","range":{{"start_height":0,"stop_height":{}}},"archive":{{"size":8,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}},"entries":[{{"height":{},"hash":"0000000000000000000000000000000000000000000000000000000000000000","offset":0,"payload_length":0}}]}}"#,
            SCHEMA,
            VERSION,
            u32::MAX,
            u32::MAX
        );
        assert!(serde_json::from_str::<CorpusManifestV1>(&json).is_ok());
    }

    fn block_hash256(block: &Block) -> Hash256 {
        Hash256::from_le_bytes(block.block_hash().as_byte_array())
    }

    fn make_test_chain(stop: u32) -> (BlockTree, Vec<Block>) {
        let mut tree = BlockTree::new();
        let mut blocks = Vec::new();
        let mut prev_hash = BlockHash::all_zeros();
        for height in 0..=stop {
            let header = BlockHeader {
                version: Version::ONE,
                prev_blockhash: prev_hash,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_000_000 + height * 600,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            let next_hash = header.block_hash();
            tree.insert_header(header, NodeStatus::HeaderValid)
                .expect("test chain inserts must succeed");
            let block = Block {
                header,
                txdata: Vec::new(),
            };
            blocks.push(block);
            prev_hash = next_hash;
        }
        (tree, blocks)
    }

    struct MockBodySource {
        bodies: HashMap<(u32, Hash256), Vec<u8>>,
    }

    impl MockBodySource {
        fn empty() -> Self {
            Self {
                bodies: HashMap::new(),
            }
        }

        fn from_blocks(blocks: &[Block]) -> Self {
            let mut bodies = HashMap::new();
            for (height, block) in blocks.iter().enumerate() {
                let hash = block_hash256(block);
                let height = u32::try_from(height).expect("test chain height fits u32");
                bodies.insert((height, hash), serialize(block));
            }
            Self { bodies }
        }
    }

    impl BlockBodySource for MockBodySource {
        fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
            self.bodies.get(&(height, hash)).cloned()
        }
    }

    fn sha256_of(bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher.finalize().into()
    }

    #[test]
    fn exports_active_chain_corpus() -> Result<(), CorpusError> {
        let (tree, blocks) = make_test_chain(2);
        let body_source = MockBodySource::from_blocks(&blocks);
        let dir = tempfile::tempdir()?;
        let archive_path = dir.path().join("archive.dat");
        let manifest_path = dir.path().join("manifest.json");

        let manifest = export_from_sources(
            &tree,
            &body_source,
            Network::Regtest,
            2,
            &archive_path,
            &manifest_path,
        )?;

        assert_eq!(manifest.network, Network::Regtest);
        assert_eq!(manifest.start_height, 0);
        assert_eq!(manifest.stop_height, 2);
        assert_eq!(manifest.entries.len(), 3);

        let archive_bytes = fs::read(&archive_path)?;
        assert_eq!(
            u64::try_from(archive_bytes.len()).expect("archive length fits u64"),
            manifest.archive.size
        );
        assert_eq!(sha256_of(&archive_bytes), manifest.archive.sha256);

        assert_eq!(&archive_bytes[..4], Network::Regtest.magic());
        let payload_len = u32::from_le_bytes([
            archive_bytes[4],
            archive_bytes[5],
            archive_bytes[6],
            archive_bytes[7],
        ]);
        assert_eq!(
            payload_len,
            u32::try_from(serialize(&blocks[0]).len()).expect("payload length fits u32")
        );

        let mut reader = CoreFrameReader::new(
            Cursor::new(archive_bytes.as_slice()),
            Network::Regtest.magic(),
            MAX_PAYLOAD_BYTES,
        );
        for (i, block) in blocks.iter().enumerate() {
            let record = reader
                .read_next()?
                .ok_or_else(|| std::io::Error::other("expected a frame"))?;
            let expected = serialize(block);
            assert_eq!(record.payload, expected, "payload mismatch at height {i}");
            let entry = &manifest.entries[i];
            assert_eq!(
                entry.height,
                u32::try_from(i).expect("test height fits u32")
            );
            assert_eq!(entry.hash, block_hash256(block));
            assert_eq!(entry.offset, record.metadata.offset);
            assert_eq!(entry.payload_length, record.metadata.len);
            assert_eq!(
                entry.payload_length,
                u32::try_from(expected.len()).expect("payload length fits u32")
            );
        }
        assert!(reader.read_next()?.is_none());

        let loaded = CorpusManifest::load(&manifest_path)?;
        assert_eq!(loaded, manifest);
        Ok(())
    }

    #[test]
    fn rejects_stop_above_active_tip() -> Result<(), CorpusError> {
        let (tree, blocks) = make_test_chain(1);
        let body_source = MockBodySource::from_blocks(&blocks);
        let dir = tempfile::tempdir()?;
        let archive_path = dir.path().join("archive.dat");
        let manifest_path = dir.path().join("manifest.json");

        let err = export_from_sources(
            &tree,
            &body_source,
            Network::Regtest,
            5,
            &archive_path,
            &manifest_path,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            CorpusError::StopAboveTip {
                stop: 5,
                tip: Some(1),
            }
        ));
        assert!(!archive_path.exists());
        assert!(!manifest_path.exists());
        Ok(())
    }

    #[test]
    fn rejects_missing_body_before_manifest() -> Result<(), CorpusError> {
        let (tree, blocks) = make_test_chain(1);
        let hash0 = block_hash256(&blocks[0]);
        let mut source = MockBodySource::from_blocks(&blocks);
        source.bodies.remove(&(0, hash0));

        let dir = tempfile::tempdir()?;
        let archive_path = dir.path().join("archive.dat");
        let manifest_path = dir.path().join("manifest.json");

        let err = export_from_sources(
            &tree,
            &source,
            Network::Regtest,
            0,
            &archive_path,
            &manifest_path,
        )
        .unwrap_err();

        assert!(matches!(err, CorpusError::MissingBody { height: 0, .. }));
        assert!(!manifest_path.exists());
        Ok(())
    }

    #[test]
    fn rejects_body_hash_mismatch_before_manifest() -> Result<(), CorpusError> {
        let (tree, blocks) = make_test_chain(1);
        let hash1 = block_hash256(&blocks[1]);
        let mut source = MockBodySource::from_blocks(&blocks);
        // Replace the body at height 1 with the serialized block from height 0;
        // it decodes cleanly but its hash does not match the active chain.
        source.bodies.insert((1, hash1), serialize(&blocks[0]));

        let dir = tempfile::tempdir()?;
        let archive_path = dir.path().join("archive.dat");
        let manifest_path = dir.path().join("manifest.json");

        let err = export_from_sources(
            &tree,
            &source,
            Network::Regtest,
            1,
            &archive_path,
            &manifest_path,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            CorpusError::BodyHashMismatch { height: 1, .. }
        ));
        assert!(!manifest_path.exists());
        Ok(())
    }

    #[test]
    fn rejects_archive_manifest_path_collision() {
        let tree = BlockTree::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("same.dat");

        let err = export_from_sources(
            &tree,
            &MockBodySource::empty(),
            Network::Regtest,
            0,
            &path,
            &path,
        )
        .unwrap_err();

        assert!(matches!(err, CorpusError::PathCollision { .. }));
        assert!(!path.exists());
    }

    #[test]
    fn rejects_existing_archive_output() -> Result<(), CorpusError> {
        let (tree, blocks) = make_test_chain(0);
        let body_source = MockBodySource::from_blocks(&blocks);
        let dir = tempfile::tempdir()?;
        let archive_path = dir.path().join("archive.dat");
        let manifest_path = dir.path().join("manifest.json");
        fs::write(&archive_path, b"do not overwrite")?;

        let err = export_from_sources(
            &tree,
            &body_source,
            Network::Regtest,
            0,
            &archive_path,
            &manifest_path,
        )
        .unwrap_err();

        assert!(matches!(err, CorpusError::OutputExists { .. }));
        assert_eq!(fs::read(&archive_path)?, b"do not overwrite");
        assert!(!manifest_path.exists());
        Ok(())
    }

    #[test]
    fn write_corpus_archive_matches_export_from_sources() -> Result<(), CorpusError> {
        let (tree, blocks) = make_test_chain(2);
        let body_source = MockBodySource::from_blocks(&blocks);
        let dir = tempfile::tempdir()?;
        let archive_path = dir.path().join("archive.dat");
        let manifest_path = dir.path().join("manifest.json");

        let direct = export_from_sources(
            &tree,
            &body_source,
            Network::Regtest,
            2,
            &archive_path,
            &manifest_path,
        )?;
        let direct_archive = fs::read(&archive_path)?;
        let direct_manifest = fs::read(&manifest_path)?;

        // Remove the published files and rerun through the shared writer only.
        fs::remove_file(&archive_path)?;
        fs::remove_file(&manifest_path)?;

        let mut source = BlockTreeSource {
            tree: &tree,
            body: &body_source,
        };
        let via_writer = write_corpus_archive(
            &mut source,
            Network::Regtest,
            2,
            &archive_path,
            &manifest_path,
        )?;
        let writer_archive = fs::read(&archive_path)?;
        let writer_manifest = fs::read(&manifest_path)?;

        assert_eq!(direct, via_writer);
        assert_eq!(direct_archive, writer_archive);
        assert_eq!(direct_manifest, writer_manifest);
        Ok(())
    }

    fn make_rest_blocks(stop: u32) -> (Vec<Block>, Vec<(String, Vec<u8>)>) {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let mut blocks = vec![genesis.clone()];
        let mut records = vec![(genesis.block_hash().to_string(), serialize(&genesis))];
        let mut prev_hash = genesis.block_hash();
        for height in 1..=stop {
            let header = BlockHeader {
                version: Version::ONE,
                prev_blockhash: prev_hash,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_000_000 + height * 600,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            let next_hash = header.block_hash();
            let block = Block {
                header,
                txdata: Vec::new(),
            };
            records.push((next_hash.to_string(), serialize(&block)));
            blocks.push(block);
            prev_hash = next_hash;
        }
        (blocks, records)
    }

    fn make_regtest_tree(blocks: &[Block]) -> BlockTree {
        let mut tree = BlockTree::new();
        for block in blocks {
            tree.insert_header(block.header, NodeStatus::HeaderValid)
                .expect("regtest chain inserts must succeed");
        }
        tree
    }

    fn make_rest_source(records: Vec<(String, Vec<u8>)>, network: Network) -> RestCorpusSource {
        let mut iter = records.into_iter();
        RestCorpusSource {
            fetcher: Box::new(move |height| {
                let (hash, payload) = iter.next().ok_or_else(|| CoreRestError::HttpStatus {
                    path: format!("/rest/blockhashbyheight/{height}.hex"),
                    status: "HTTP/1.1 404 Not Found".to_owned(),
                })?;
                Ok((hash, payload))
            }),
            network,
            prev: None,
        }
    }

    #[test]
    fn rest_corpus_source_matches_blocktree_output() -> Result<(), CorpusError> {
        let (blocks, records) = make_rest_blocks(2);
        let tree = make_regtest_tree(&blocks);
        let body_source = MockBodySource::from_blocks(&blocks);
        let dir = tempfile::tempdir()?;
        let archive_path = dir.path().join("archive.dat");
        let manifest_path = dir.path().join("manifest.json");

        let mut rest = make_rest_source(records, Network::Regtest);
        let rest_manifest = write_corpus_archive(
            &mut rest,
            Network::Regtest,
            2,
            &archive_path,
            &manifest_path,
        )?;
        let rest_archive = fs::read(&archive_path)?;

        fs::remove_file(&archive_path)?;
        fs::remove_file(&manifest_path)?;

        let direct = export_from_sources(
            &tree,
            &body_source,
            Network::Regtest,
            2,
            &archive_path,
            &manifest_path,
        )?;
        let direct_archive = fs::read(&archive_path)?;

        assert_eq!(rest_manifest, direct);
        assert_eq!(rest_archive, direct_archive);
        Ok(())
    }

    #[test]
    fn rest_corpus_rejects_genesis_mismatch() -> Result<(), CorpusError> {
        let (_, records) = make_rest_blocks(0);
        // Use mainnet expectation; the real regtest genesis will not match.
        let mut source = make_rest_source(records, Network::Mainnet);
        let dir = tempfile::tempdir()?;
        let archive = dir.path().join("archive.dat");
        let manifest = dir.path().join("manifest.json");

        let err = write_corpus_archive(&mut source, Network::Mainnet, 0, &archive, &manifest)
            .unwrap_err();

        assert!(matches!(err, CorpusError::RestGenesisMismatch { .. }));
        assert!(!archive.exists());
        assert!(!manifest.exists());
        assert!(no_tmp_files(&dir));
        Ok(())
    }

    #[test]
    fn rest_corpus_rejects_continuity_break() -> Result<(), CorpusError> {
        let (_, mut records) = make_rest_blocks(2);
        // Make height 2 claim a bogus parent while keeping a valid header hash.
        let mut tampered = bitcoin::consensus::deserialize::<Block>(&records[2].1).unwrap();
        tampered.header.prev_blockhash = BlockHash::from_byte_array([0xff; 32]);
        tampered.header.nonce += 1; // re-mine to a new hash
        let new_hash = tampered.block_hash().to_string();
        records[2] = (new_hash, serialize(&tampered));

        let mut source = make_rest_source(records, Network::Regtest);
        let dir = tempfile::tempdir()?;
        let archive = dir.path().join("archive.dat");
        let manifest = dir.path().join("manifest.json");

        let err = write_corpus_archive(&mut source, Network::Regtest, 2, &archive, &manifest)
            .unwrap_err();

        assert!(matches!(err, CorpusError::RestContinuity { height: 2, .. }));
        assert!(!archive.exists());
        assert!(!manifest.exists());
        assert!(no_tmp_files(&dir));
        Ok(())
    }

    #[test]
    fn rest_corpus_rejects_hash_mismatch() -> Result<(), CorpusError> {
        let (_, mut records) = make_rest_blocks(1);
        // Reported hash stays the same but payload is the genesis block;
        // computed hash will differ.
        records[1].1 = records[0].1.clone();

        let mut source = make_rest_source(records, Network::Regtest);
        let dir = tempfile::tempdir()?;
        let archive = dir.path().join("archive.dat");
        let manifest = dir.path().join("manifest.json");

        let err = write_corpus_archive(&mut source, Network::Regtest, 1, &archive, &manifest)
            .unwrap_err();

        assert!(matches!(err, CorpusError::RestHashMismatch { .. }));
        assert!(!archive.exists());
        assert!(!manifest.exists());
        assert!(no_tmp_files(&dir));
        Ok(())
    }

    #[test]
    fn rest_corpus_rejects_short_payload() -> Result<(), CorpusError> {
        let (_, mut records) = make_rest_blocks(0);
        records[0].1 = vec![0; 79];
        let mut source = make_rest_source(records, Network::Regtest);
        let dir = tempfile::tempdir()?;
        let archive = dir.path().join("archive.dat");
        let manifest = dir.path().join("manifest.json");

        let err = write_corpus_archive(&mut source, Network::Regtest, 0, &archive, &manifest)
            .unwrap_err();

        assert!(matches!(err, CorpusError::RestShortPayload { .. }));
        assert!(!archive.exists());
        assert!(!manifest.exists());
        assert!(no_tmp_files(&dir));
        Ok(())
    }

    fn no_tmp_files(dir: &tempfile::TempDir) -> bool {
        dir.path()
            .read_dir()
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .all(|e| {
                let name = e.file_name();
                let s = name.to_string_lossy();
                !s.contains(".tmp.")
            })
    }

    fn http_response(status: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {}\r\nContent-Length: {}\r\n\r\n",
            status,
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn http_no_content_length(status: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {status}\r\n\r\n").into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn http_oversized_content_length() -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        )
        .into_bytes()
    }

    fn serve_http(responses: Vec<Vec<u8>>) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            for response in responses {
                // consume one request
                let mut line = String::new();
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line.trim().is_empty() {
                        break;
                    }
                }
                reader.get_mut().write_all(&response).unwrap();
                reader.get_mut().flush().unwrap();
            }
        });
        (addr, handle)
    }

    #[test]
    fn core_rest_client_gets_body_and_rejects_non_200() {
        let body = b"hello".to_vec();
        let ok = http_response("200 OK", &body);
        let not_found = http_response("404 Not Found", b"missing");
        let (addr, _handle) = serve_http(vec![ok, not_found]);

        let mut client = CoreRestClient::connect(&addr).unwrap();
        assert_eq!(client.get("/a").unwrap(), body);

        let err = client.get("/b").unwrap_err();
        assert!(
            matches!(err, CoreRestError::HttpStatus { status, .. } if status.starts_with("HTTP/1.1 404"))
        );
    }

    #[test]
    fn core_rest_client_rejects_missing_content_length() {
        let body = b"hello".to_vec();
        let (addr, _handle) = serve_http(vec![http_no_content_length("200 OK", &body)]);

        let mut client = CoreRestClient::connect(&addr).unwrap();
        let err = client.get("/a").unwrap_err();
        assert!(matches!(err, CoreRestError::MissingContentLength { .. }));
    }

    #[test]
    fn core_rest_client_rejects_oversized_content_length() {
        let (addr, _handle) = serve_http(vec![http_oversized_content_length()]);

        let mut client = CoreRestClient::connect(&addr).unwrap();
        let err = client.get("/a").unwrap_err();
        assert!(matches!(err, CoreRestError::OversizedBody { .. }));
    }

    fn serve_http_with_close_then_response(
        response: Vec<u8>,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = thread::spawn(move || {
            // first connection: accept, read request, drop.
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                if line.trim().is_empty() {
                    break;
                }
            }
            drop(reader);

            // second connection: serve the real response.
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&response).unwrap();
            stream.flush().unwrap();
        });
        (addr, handle)
    }

    #[test]
    fn core_rest_client_reconnects_once() {
        let response = http_response("200 OK", b"body");
        let (addr, _handle) = serve_http_with_close_then_response(response);

        let mut client = CoreRestClient::connect(&addr).unwrap();
        let body = client.get("/a").unwrap();
        assert_eq!(body, b"body");
    }
}
