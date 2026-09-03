//! Versioned corpus manifest and active-chain Core-frame exporter.
//!
//! A `CorpusManifest` names a single network, a single contiguous block range
//! `[0, stop]`, and the offset/length table for every block in the archive.
//! The manifest is the durable integrity contract; `export_active_chain_corpus`
//! streams the matching archive through [`bitcoin_rs_storage::CoreFrameWriter`]
//! and publishes it before the validated manifest.

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::{self, BufRead as _, BufReader, BufWriter, Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Network, deserialize};
use bitcoin_rs_rpc::context::BlockBodySource;
use bitcoin_rs_storage::{CORE_FRAME_HEADER_LEN, CoreFrameError, CoreFrameWriter};
use cap_fs_ext::{
    FollowSymlinks, MetadataExt as CapMetadataExt, OpenOptionsFollowExt as _,
    OpenOptionsSyncExt as _,
};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub(crate) const SCHEMA: &str = "bitcoin-rs-corpus-manifest";
pub(crate) const VERSION: u32 = 2;
/// Schema identifier emitted by the active-chain corpus exporter.
pub const EXPORTER_SCHEMA: &str = "bitcoin-rs-active-chain-exporter";
/// Version of the active-chain corpus exporter contract.
pub const EXPORTER_VERSION: u32 = 1;
/// Schema identifier required by the checksig census consumer.
pub const CHECKSIG_CENSUS_SCHEMA: &str = "classify-corpus-v2";
/// Version of the checksig census contract.
pub const CHECKSIG_CENSUS_VERSION: u32 = 2;
/// Schema identifier required for backend reopen proofs.
pub const REOPEN_PROOF_SCHEMA: &str = "verify-replay-durability-proof-v1";
/// Version of the backend reopen-proof contract.
pub const REOPEN_PROOF_VERSION: u32 = 1;
/// Backends whose reopen proof a custody manifest must bind, exactly once each.
const REQUIRED_REOPEN_BACKENDS: [&str; 3] = ["fjall", "rocksdb", "redb"];
const MAGIC_HEX_LEN: usize = 8;
const HASH_HEX_LEN: usize = 64;
const SHA256_HEX_LEN: usize = 64;
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_HTTP_LINE_BYTES: u64 = 8 * 1024;
const REST_TIMEOUT: Duration = Duration::from_secs(30);
/// Consensus-maximum serialized block size in bytes.
pub(crate) const MAX_PAYLOAD_BYTES: u32 = 4_000_000;
/// Serialized-block payloads below this many bytes cannot hold a header.
pub(crate) const MIN_PAYLOAD_BYTES: u32 = 80;
/// Single-read ceiling for a corpus manifest, matching the Python loader.
///
/// Derived from the schema and the largest recognized product: Cmodern is
/// frozen at stop height 709,635, so its manifest carries 709,636 entries.
/// The worst-case v2 entry object (u32 height, 64-hex hash, u64 offset,
/// u32 payload at their widest decimal renderings) is 153 bytes, so the
/// entries array alone is at most 709,636 * 153 + 709,635 separators, and
/// the bounded top-level/proof allowance covers the remaining fixed fields.
/// That total is under 128 MiB, which therefore admits every recognized
/// product while still rejecting unbounded input before allocation.
pub(crate) const MAX_MANIFEST_BYTES: u64 = 128 * 1024 * 1024;

/// Returns true when a serialized manifest of `len` bytes fits the shared
/// schema-derived ceiling. Applied by the exporter before publication and
/// by the loader before allocation so neither side can accept what the
/// other rejects.
pub(crate) const fn manifest_bound_ok(len: u64) -> bool {
    len <= MAX_MANIFEST_BYTES
}
/// Frozen product identity: corpus id, stop height, and stop hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProductIdentity {
    /// Inclusive stop height the product corpus is frozen at, or the
    /// unforced `0` used by synthetic unit fixtures.
    pub stop_height: u32,
    /// Canonical displayed hash of the frozen stop block, or the
    /// unforced `""` used by synthetic unit fixtures.
    pub stop_hash: &'static str,
}

/// Frozen product identities the custody contract recognizes.
///
/// Production accepts exactly these two product corpora; both pin mainnet,
/// and the stop hashes match the census classifier's frozen tips so Rust
/// and Python enforce the same identities.
pub(crate) const PRODUCT_IDENTITIES: [(&str, ProductIdentity); 2] = [
    (
        "C150",
        ProductIdentity {
            stop_height: 150_000,
            stop_hash: "0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b",
        },
    ),
    (
        "Cmodern",
        ProductIdentity {
            stop_height: 709_635,
            stop_hash: "00000000000000000001f9ee4f69cbc75ce61db5178175c2ad021fe1df5bad8f",
        },
    ),
];

/// Synthetic corpus id used only by unit fixtures so structural tests can
/// exercise the validator without a 150,001-entry product chain. Compiled
/// out of production builds: `product_identity` resolves it under
/// `#[cfg(test)]` exclusively, so release binaries accept only C150 and
/// Cmodern.
#[cfg(test)]
const FIXTURE_CORPUS_ID: &str = "CFIXTURE";

/// Unforced identity paired with [`FIXTURE_CORPUS_ID`].
#[cfg(test)]
const FIXTURE_IDENTITY: ProductIdentity = ProductIdentity {
    stop_height: 0,
    stop_hash: "",
};

/// Looks up the frozen identity for a product corpus id.
pub(crate) fn product_identity(corpus_id: &str) -> Option<ProductIdentity> {
    if let Some((_, identity)) = PRODUCT_IDENTITIES
        .iter()
        .find(|(name, _)| *name == corpus_id)
    {
        return Some(*identity);
    }
    #[cfg(test)]
    if corpus_id == FIXTURE_CORPUS_ID {
        return Some(FIXTURE_IDENTITY);
    }
    None
}

/// A schema name and version pair a custody consumer must support exactly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedSchema {
    /// Schema identifier.
    pub schema: String,
    /// Schema version.
    pub version: u32,
}

/// An external proof file bound by backend, path, size, and SHA-256.
///
/// Fields are private: a `CustodyFile` only ever comes from a verified load,
/// so no caller can assemble one from unproven parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyFile {
    /// Storage backend the proof covers.
    backend: String,
    /// Path of the proof artifact at custody time.
    path: String,
    /// Proof file size in bytes.
    size: u64,
    /// SHA-256 digest of the proof file.
    sha256: [u8; 32],
}

impl CustodyFile {
    /// Storage backend this proof covers.
    pub fn backend(&self) -> &str {
        &self.backend
    }

    /// Path the proof was loaded from at custody time.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Measured proof size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// SHA-256 of the exact bytes that were parsed.
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

/// Validates that a product corpus id pins mainnet and the frozen product
/// tip. `tip` carries the manifest's claimed `(stop_height, tip_hash)` when
/// known so the same check guards construction, structural validation, and
/// wire ingestion.
fn validate_product_identity(
    corpus_id: &str,
    network: Network,
    tip: Option<(u32, Hash256)>,
) -> Result<(), CorpusError> {
    let identity = product_identity(corpus_id).ok_or_else(|| {
        CorpusError::InvalidCustody(format!(
            "corpus_id must be C150 or Cmodern, got {}",
            bounded_fact("corpus_id", corpus_id)
        ))
    })?;
    // Unit-fixture identity: skips network and frozen-tip enforcement so
    // structural tests can use small regtest chains. Only reachable in
    // test builds; production resolves only C150/Cmodern above.
    if identity.stop_height == 0 && identity.stop_hash.is_empty() {
        return Ok(());
    }
    if network != Network::Mainnet {
        return Err(CorpusError::InvalidCustody(format!(
            "{corpus_id} is a mainnet product corpus; got network {network:?}"
        )));
    }
    if let Some((stop_height, tip_hash)) = tip {
        if stop_height != identity.stop_height {
            return Err(CorpusError::InvalidCustody(format!(
                "{corpus_id} is frozen at stop height {}; got {stop_height}",
                identity.stop_height
            )));
        }
        let expected = Hash256::from_str_be(identity.stop_hash).map_err(|_| {
            CorpusError::InvalidCustody("compiled-in product tip is invalid hex".to_owned())
        })?;
        if tip_hash != expected {
            return Err(CorpusError::InvalidCustody(format!(
                "{corpus_id} is frozen at tip {}; got {}",
                identity.stop_hash,
                tip_hash.to_string_be()
            )));
        }
    }
    Ok(())
}

/// Operator-supplied custody that cannot be inferred from archive bytes.
///
/// Every export must claim one of the two product corpus identities, name
/// the Bitcoin Core version the chain was exported from, and bind one
/// reopen proof per supported storage backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportCustody {
    /// `C150` or `Cmodern`.
    pub corpus_id: String,
    /// Bitcoin Core version string: 3-15 bytes, 2-4 dot-separated
    /// components, each 1-3 ASCII digits, e.g. `31.1.0`.
    pub core_version: String,
    /// Exactly one proof per supported storage backend.
    pub reopen_proofs: Vec<CustodyFile>,
}

impl ExportCustody {
    /// Constructs and validates custody fail-closed.
    pub fn new(
        corpus_id: impl Into<String>,
        core_version: impl Into<String>,
        reopen_proofs: Vec<CustodyFile>,
    ) -> Result<Self, CorpusError> {
        let custody = Self {
            corpus_id: corpus_id.into(),
            core_version: core_version.into(),
            reopen_proofs,
        };
        validate_custody(
            &custody.corpus_id,
            &custody.core_version,
            &custody.reopen_proofs,
        )?;
        Ok(custody)
    }

    fn validate(&self) -> Result<(), CorpusError> {
        validate_custody(&self.corpus_id, &self.core_version, &self.reopen_proofs)
    }
}

fn validate_custody(
    corpus_id: &str,
    core_version: &str,
    reopen_proofs: &[CustodyFile],
) -> Result<(), CorpusError> {
    // Membership resolves through the product table so a production build
    // accepts only C150/Cmodern; test builds additionally resolve the
    // cfg-gated fixture identity for synthetic chains.
    if product_identity(corpus_id).is_none() {
        return Err(CorpusError::InvalidCustody(format!(
            "corpus_id must be C150 or Cmodern, got {}",
            bounded_fact("corpus_id", corpus_id)
        )));
    }
    let mut component_count = 0;
    let valid_core_version = (3..=15).contains(&core_version.len())
        && core_version.split('.').all(|component| {
            component_count += 1;
            (1..=3).contains(&component.len())
                && component.bytes().all(|byte| byte.is_ascii_digit())
        })
        && (2..=4).contains(&component_count);
    if !valid_core_version {
        return Err(CorpusError::InvalidCustody(format!(
            "core_version must be 3-15 bytes with 2-4 dot-separated 1-3 digit components, got {}",
            bounded_fact("core_version", core_version)
        )));
    }
    if reopen_proofs.len() != REQUIRED_REOPEN_BACKENDS.len() {
        return Err(CorpusError::InvalidCustody(format!(
            "exactly {} reopen proofs are required, got {}",
            REQUIRED_REOPEN_BACKENDS.len(),
            reopen_proofs.len()
        )));
    }
    if let Some(proof) = reopen_proofs
        .iter()
        .find(|proof| !REQUIRED_REOPEN_BACKENDS.contains(&proof.backend.as_str()))
    {
        return Err(CorpusError::InvalidCustody(format!(
            "unsupported reopen proof backend {}",
            bounded_fact("backend", &proof.backend)
        )));
    }
    for backend in REQUIRED_REOPEN_BACKENDS {
        let matches: Vec<&CustodyFile> = reopen_proofs
            .iter()
            .filter(|proof| proof.backend == backend)
            .collect();
        if matches.len() != 1 {
            return Err(CorpusError::InvalidCustody(format!(
                "exactly one {backend} reopen proof is required, got {}",
                matches.len()
            )));
        }
        let proof = matches[0];
        if proof.path.trim().is_empty() {
            return Err(CorpusError::InvalidCustody(format!(
                "{backend} reopen proof requires a nonempty path"
            )));
        }
        if proof.size == 0 {
            return Err(CorpusError::InvalidCustody(format!(
                "{backend} reopen proof requires a nonzero size"
            )));
        }
        if proof.sha256 == [0; 32] {
            return Err(CorpusError::InvalidCustody(format!(
                "{backend} reopen proof requires a nonzero sha256 binding"
            )));
        }
    }
    Ok(())
}

/// Single-read ceiling for one reopen-proof artifact. The real producer
/// (`verify_replay_durability.rs`) renders a few kilobytes of pretty JSON;
/// anything larger is not a durability proof.
pub(crate) const PROOF_MAX_BYTES: u64 = 64 * 1024;

/// Parsed `verify-replay-durability-proof-v1` artifact. Field-for-field the
/// serialization of `Proof` in `verify_replay_durability.rs`; unknown keys
/// are rejected so a proof cannot smuggle extra claims.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReopenProofFile {
    schema: String,
    version: u32,
    network: String,
    backend: String,
    validation: ReopenValidationDigest,
    before: ReopenInvariants,
    after: ReopenInvariants,
    checkpoint_generation: u64,
    durable_body_roundtrip: bool,
    durable_undo_roundtrip: bool,
    mutated_copy_only: bool,
    reopen_count: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReopenValidationDigest {
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReopenInvariants {
    tip_height: u32,
    tip_hash: String,
    utxo_count: u64,
    total_amount: u64,
    muhash: String,
    utxo_hash_serialized_3: String,
    tx_count: u64,
    bogo_size: u64,
}

/// Fails closed unless `condition` holds, wrapping the refusal as a custody
/// error.
fn require(condition: bool, message: String) -> Result<(), CorpusError> {
    if condition {
        Ok(())
    } else {
        Err(CorpusError::InvalidCustody(message))
    }
}

/// Verifies the shared-artifact bindings one parsed reopen proof claims:
/// the exact bytes this export loaded, the state those bytes commit to, and
/// the frozen product identity the export names.
fn verify_reopen_proof_bindings(
    proof: &ReopenProofFile,
    label: &str,
    corpus_id: &str,
    identity: ProductIdentity,
    validation: &ValidationArtifact,
) -> Result<(), CorpusError> {
    // The unforced fixture identity (synthetic unit chains) carries no pin;
    // production identities always do. The shared-artifact tip binding
    // below still enforces proof/artifact consistency either way.
    if !(identity.stop_height == 0 && identity.stop_hash.is_empty()) {
        require(
            proof.before.tip_height == identity.stop_height
                && proof.before.tip_hash == identity.stop_hash,
            format!(
                "{label} tip {}/{} does not match the {corpus_id} custody identity",
                proof.before.tip_height,
                bounded_fact("tip_hash", &proof.before.tip_hash)
            ),
        )?;
    }
    // The shared artifact is bound twice: by the exact bytes the export
    // loaded, and by the state those bytes commit to. Binding only the
    // digest would let a proof name the right file and claim a different
    // tip.
    require(
        proof.validation.size_bytes == validation.size,
        format!(
            "{label} binds a {}-byte validation artifact; this export binds {}",
            proof.validation.size_bytes, validation.size
        ),
    )?;
    require(
        proof.validation.sha256 == validation.sha256_hex,
        format!(
            "{label} binds validation digest {}; this export binds {}",
            bounded_fact("sha256", &proof.validation.sha256),
            validation.sha256_hex
        ),
    )?;
    require(
        proof.before.tip_height == validation.stop_height
            && proof.before.tip_hash == validation.stop_hash,
        format!(
            "{label} tip {}/{} does not match the shared validation tip {}/{}",
            proof.before.tip_height,
            bounded_fact("tip_hash", &proof.before.tip_hash),
            validation.stop_height,
            validation.stop_hash
        ),
    )?;
    require(
        proof.before.muhash == validation.muhash
            && proof.before.utxo_hash_serialized_3 == validation.utxo_hash_serialized_3
            && proof.before.utxo_count == validation.utxo_count
            && proof.before.total_amount == validation.total_amount,
        format!("{label} state commitment does not match the shared validation artifact"),
    )
}

/// Loads one `verify-replay-durability-proof-v1` artifact and binds its
///
/// The file is opened once with the custody input contract (no-follow,
/// non-blocking, close-on-exec), read exactly to its statted length from
/// that same descriptor and proven not to have moved under the read,
/// rejected if any object repeats a key, and parsed with an exact-key
/// schema. Every semantic claim is then verified against the export: the
/// backend, a successful durable-reopen outcome, the corpus product
/// identity, and the one shared validation artifact — bound by exact bytes
/// and by state, the same artifact every backend proof in this export must
/// name.
pub fn load_reopen_proof(
    corpus_id: &str,
    backend: &str,
    path: &Path,
    validation: &ValidationArtifact,
) -> Result<CustodyFile, CorpusError> {
    let identity = product_identity(corpus_id).ok_or_else(|| {
        CorpusError::InvalidCustody(format!(
            "corpus_id must be C150 or Cmodern, got {}",
            bounded_fact("corpus_id", corpus_id)
        ))
    })?;
    if !REQUIRED_REOPEN_BACKENDS.contains(&backend) {
        return Err(CorpusError::InvalidCustody(format!(
            "unsupported reopen proof backend {}",
            bounded_fact("backend", backend)
        )));
    }

    let label = format!("{backend} reopen proof");
    let bytes = read_custody_document(path, PROOF_MAX_BYTES, &label)?;
    let size = u64::try_from(bytes.len())
        .map_err(|_| CorpusError::InvalidCustody(format!("{label} length does not fit u64")))?;
    let sha256: [u8; 32] = Sha256::digest(&bytes).into();

    let proof: ReopenProofFile = serde_json::from_slice(&bytes).map_err(|error| {
        CorpusError::InvalidCustody(format!(
            "{label} {} is not a bounded {REOPEN_PROOF_SCHEMA} document: {}",
            bounded_diagnostic_path(path),
            bounded_fact("serde", &error.to_string())
        ))
    })?;
    require(
        proof.schema == REOPEN_PROOF_SCHEMA,
        format!(
            "{label} schema is {}, expected {REOPEN_PROOF_SCHEMA:?}",
            bounded_fact("schema", &proof.schema)
        ),
    )?;
    require(
        proof.version == REOPEN_PROOF_VERSION,
        format!(
            "{label} version must be {REOPEN_PROOF_VERSION}, got {}",
            proof.version
        ),
    )?;
    require(
        proof.network == "mainnet",
        format!(
            "{label} network is {}, expected \"mainnet\"",
            bounded_fact("network", &proof.network)
        ),
    )?;
    require(
        proof.backend == backend,
        format!(
            "{label} names backend {}",
            bounded_fact("backend", &proof.backend)
        ),
    )?;
    require(
        proof.before == proof.after,
        format!("{label} pre/post reorg invariants differ"),
    )?;
    verify_reopen_proof_bindings(&proof, &label, corpus_id, identity, validation)?;
    require(
        proof.durable_body_roundtrip && proof.durable_undo_roundtrip && proof.mutated_copy_only,
        format!("{label} durability invariants are not all true"),
    )?;
    require(
        proof.reopen_count >= 2,
        format!(
            "{label} records {} reopens; at least 2 are required",
            proof.reopen_count
        ),
    )?;
    require(
        proof.checkpoint_generation > 0,
        format!("{label} has no checkpoint generation"),
    )?;

    Ok(CustodyFile {
        backend: backend.to_owned(),
        path: path.to_string_lossy().into_owned(),
        size,
        sha256,
    })
}

/// True when `s` is exactly 64 ASCII zeros.
fn set_is_zero_hex(s: &str) -> bool {
    s.bytes().all(|byte| byte == b'0')
}

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
    /// Product corpus identity this archive claims: `C150` or `Cmodern`.
    pub corpus_id: String,
    /// Bitcoin Core version the source chain was exported from.
    pub core_version: String,
    /// Exporter schema identity and version.
    pub exporter: VersionedSchema,
    /// Checksig-census schema identity and version consumers must support.
    pub checksig_census: VersionedSchema,
    /// One storage-backend reopen proof per supported backend.
    pub reopen_proofs: Vec<CustodyFile>,
    /// Displayed hash of the final entry; binds the claimed source tip.
    pub source_tip_hash: Hash256,
    /// SHA-256 of the canonical preimage: this manifest with a zeroed digest.
    pub manifest_sha256: [u8; 32],
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

/// Maximum preview characters a bounded fact shows before fingerprinting.
const BOUNDED_PREVIEW_CHARS: usize = 24;

/// Renders a bounded, escaped fact about a rejected hostile value: the
/// field name, byte length, at most [`BOUNDED_PREVIEW_CHARS`] printable-ASCII
/// preview characters (controls, ESC sequences, and bidi controls escaped),
/// and for longer values a SHA-256 fingerprint. Raw rejected values are
/// never stored in error variants.
fn bounded_fact(field: &str, value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars().take(BOUNDED_PREVIEW_CHARS) {
        match ch {
            c if c.is_ascii_graphic() && !c.is_ascii_control() => escaped.push(c),
            c => escaped.push_str(&format!("\\u{{{:04x}}}", u32::from(c))),
        }
    }
    if value.chars().count() > BOUNDED_PREVIEW_CHARS {
        let digest = Sha256::digest(value.as_bytes());
        escaped.push_str(&format!("…sha256={}", hex_encode(&digest)));
    }
    format!("{field}:{}:{escaped}", value.len())
}

/// Renders an operator-supplied path as one bounded, escaped diagnostic fact.
///
/// A fully safe path — printable ASCII including ordinary spaces, at most
/// [`BOUNDED_PREVIEW_CHARS`] characters, no lossy non-UTF-8 replacement —
/// keeps its exact string. Anything hostile or over the bound renders in
/// the `path:<len>:<escaped>…[sha256]` form so it cannot forge terminal or
/// log structure.
pub fn bounded_diagnostic_path(path: &Path) -> String {
    let lossy = path.to_string_lossy();
    let safe = !lossy.contains('\u{FFFD}')
        && lossy.chars().count() <= BOUNDED_PREVIEW_CHARS
        && lossy.chars().all(|ch| ch.is_ascii_graphic() || ch == ' ');
    if safe {
        lossy.into_owned()
    } else {
        bounded_fact("path", &lossy)
    }
}

/// Recursive JSON shape check that rejects repeated object keys.
///
/// `serde_json` keeps the last value for a repeated key, so one external
/// document could carry one value for a validator and another for a reader.
/// Custody, replay, counter, proof, and manifest reads run this check before
/// any typed parse; trusted in-process performance inputs do not, because
/// they never cross a trust boundary.
struct DuplicateKeyCheck;

impl<'de> Deserialize<'de> for DuplicateKeyCheck {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(DuplicateKeyVisitor)
    }
}

struct DuplicateKeyVisitor;

impl<'de> Visitor<'de> for DuplicateKeyVisitor {
    type Value = DuplicateKeyCheck;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value whose objects have unique keys")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        DuplicateKeyCheck::deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<DuplicateKeyCheck>()?.is_some() {}
        Ok(DuplicateKeyCheck)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen: HashSet<String> = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            map.next_value::<DuplicateKeyCheck>()?;
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "duplicate key {}",
                    bounded_fact("key", &key)
                )));
            }
        }
        Ok(DuplicateKeyCheck)
    }
}

/// Rejects an external JSON document that repeats an object key or carries
/// trailing content after the top-level value.
fn reject_duplicate_keys(bytes: &[u8], label: &str) -> Result<(), CorpusError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    DuplicateKeyCheck::deserialize(&mut deserializer).map_err(|error| {
        CorpusError::ExternalDocument {
            label: label.to_owned(),
            detail: bounded_fact("detail", &error.to_string()),
        }
    })?;
    deserializer
        .end()
        .map_err(|error| CorpusError::ExternalDocument {
            label: label.to_owned(),
            detail: bounded_fact("detail", &error.to_string()),
        })
}

/// Identity of an open file, captured from its own descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    timestamps: FileTimestamps,
}

/// Metadata timestamps used to detect changes while a held file is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileTimestamps {
    #[cfg(unix)]
    mtime: (i64, i64),
    #[cfg(unix)]
    ctime: (i64, i64),
    #[cfg(windows)]
    last_write: u64,
    #[cfg(windows)]
    creation: u64,
}

#[cfg(unix)]
fn file_timestamps(metadata: &cap_std::fs::Metadata) -> FileTimestamps {
    use cap_std::fs::MetadataExt as _;

    FileTimestamps {
        mtime: (metadata.mtime(), metadata.mtime_nsec()),
        ctime: (metadata.ctime(), metadata.ctime_nsec()),
    }
}

#[cfg(windows)]
fn file_timestamps(metadata: &cap_std::fs::Metadata) -> FileTimestamps {
    use cap_std::fs::MetadataExt as _;

    FileTimestamps {
        last_write: metadata.last_write_time(),
        creation: metadata.creation_time(),
    }
}
#[cfg(not(any(unix, windows)))]
fn file_timestamps(_: &cap_std::fs::Metadata) -> FileTimestamps {
    FileTimestamps {}
}

/// An open file's identity and whether it is a regular file.
#[derive(Clone, Copy, Debug)]
struct FileFacts {
    identity: FileIdentity,
    is_file: bool,
}

/// Reads one capability file's facts from its held handle.
fn capability_file_facts(file: &File) -> Result<FileFacts, CorpusError> {
    Ok(capability_facts_from_metadata(&file.metadata()?))
}

/// Builds facts from capability metadata captured through one held handle.
fn capability_facts_from_metadata(metadata: &cap_std::fs::Metadata) -> FileFacts {
    FileFacts {
        identity: FileIdentity {
            dev: CapMetadataExt::dev(metadata),
            ino: CapMetadataExt::ino(metadata),
            size: metadata.len(),
            timestamps: file_timestamps(metadata),
        },
        is_file: metadata.file_type().is_file(),
    }
}

/// Reads one standard file's facts from its own descriptor, never from its
/// path: `dev` and `ino` cannot change under a retained descriptor, so a
/// single predicate serves both the retained-descriptor reads and the
/// descriptor-relative reopen proofs.
fn file_facts(file: &fs::File) -> Result<FileFacts, CorpusError> {
    let metadata = file.metadata()?;
    Ok(FileFacts {
        identity: FileIdentity {
            dev: CapMetadataExt::dev(&metadata),
            ino: CapMetadataExt::ino(&metadata),
            size: metadata.len(),
            timestamps: std_file_timestamps(&metadata),
        },
        is_file: metadata.file_type().is_file(),
    })
}

#[cfg(unix)]
fn std_file_timestamps(metadata: &fs::Metadata) -> FileTimestamps {
    use std::os::unix::fs::MetadataExt as _;

    FileTimestamps {
        mtime: (metadata.mtime(), metadata.mtime_nsec()),
        ctime: (metadata.ctime(), metadata.ctime_nsec()),
    }
}

#[cfg(windows)]
fn std_file_timestamps(metadata: &fs::Metadata) -> FileTimestamps {
    use std::os::windows::fs::MetadataExt as _;

    FileTimestamps {
        last_write: metadata.last_write_time(),
        creation: metadata.creation_time(),
    }
}
#[cfg(not(any(unix, windows)))]
fn std_file_timestamps(_: &fs::Metadata) -> FileTimestamps {
    FileTimestamps {}
}

/// Windows reparse-point attribute shared by symlinks, junctions, and other
/// link tags; the no-follow open reports such an object as an opened reparse
/// point rather than failing, so the attribute check is the rejection.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Opens an external custody input through a held parent-directory capability.
///
/// The final component is never followed, a FIFO can never block the open,
/// and a non-regular object is rejected from the held handle's own metadata
/// before the capability file is converted for existing streaming callers.
pub fn open_custody_input(path: &Path, label: &str) -> Result<fs::File, CorpusError> {
    let reject = |detail: String| CorpusError::BoundedRead {
        label: label.to_owned(),
        path: bounded_diagnostic_path(path),
        detail,
    };
    let name = path
        .file_name()
        .ok_or_else(|| reject("has no final path component".to_owned()))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dir = Dir::open_ambient_dir(parent, ambient_authority())?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = dir.open_with(name, &options).map_err(|error| {
        let is_symlink = dir
            .symlink_metadata(name)
            .is_ok_and(|metadata| metadata.file_type().is_symlink());
        if is_symlink {
            reject("is a symbolic link".to_owned())
        } else {
            CorpusError::Io(error)
        }
    })?;
    let metadata = file.metadata()?;
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt as _;

        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(reject("is a reparse point".to_owned()));
        }
    }
    if !capability_facts_from_metadata(&metadata).is_file {
        return Err(reject("is not a regular file".to_owned()));
    }
    Ok(file.into_std())
}

/// Reads exactly the bytes the file's own metadata declares, from one open
/// descriptor, and proves the file did not move under the read.
///
/// The statted length is consumed exactly, one extra byte is probed — a
/// non-empty probe means the file grew — and `dev`, `ino`, `size`, `mtime`,
/// and `ctime` are compared after the last read. A short read, a grown file,
/// or drifted metadata is a rejected custody input, never a truncated parse.
fn read_exact_bounded(
    file: &mut fs::File,
    max: u64,
    label: &str,
    path: &Path,
) -> Result<Vec<u8>, CorpusError> {
    let before = file_facts(file)?;
    let declared = before.identity.size;
    read_declared_bounded(file, before, declared, max, label, path)
}

/// Variant of [`read_exact_bounded`] whose declared length the caller
/// supplies, so a length captured before the call can be proven to still
/// hold. A file that grew past its declared length trips the one-byte
/// probe; a file that shrank trips the short-read check; drifted metadata
/// trips the post-read identity comparison.
fn read_declared_bounded(
    file: &mut fs::File,
    before: FileFacts,
    declared_size: u64,
    max: u64,
    label: &str,
    path: &Path,
) -> Result<Vec<u8>, CorpusError> {
    let reject = |detail: String| CorpusError::BoundedRead {
        label: label.to_owned(),
        path: bounded_diagnostic_path(path),
        detail,
    };
    if !before.is_file {
        return Err(reject("is not a regular file".to_owned()));
    }
    let size = declared_size;
    if size == 0 {
        return Err(reject("is empty".to_owned()));
    }
    if size > max {
        return Err(reject(format!(
            "is {size} bytes; the bounded ceiling is {max}"
        )));
    }
    let len = usize::try_from(size)
        .map_err(|_| reject(format!("is {size} bytes; too large for this platform")))?;
    let mut bytes = vec![0_u8; len];
    file.read_exact(&mut bytes)
        .map_err(|error| reject(format!("short read of its {size} declared bytes: {error}")))?;
    let mut probe = [0_u8; 1];
    if file.read(&mut probe)? != 0 {
        return Err(reject(format!("grew past its declared {size} bytes")));
    }
    let after = file_facts(file)?;
    if after.identity != before.identity {
        return Err(reject(
            "changed identity or metadata during the read".to_owned(),
        ));
    }
    Ok(bytes)
}

/// Opens, exactly reads, and duplicate-key screens one external custody
/// document.
///
/// The contract: no-follow open, exact statted length from one descriptor,
/// an identity re-check after the last read, and repeated-key rejection
/// before any typed parse. Every custody, proof, and validation read —
/// including the ones the custody tools perform — goes through here.
pub fn read_custody_document(path: &Path, max: u64, label: &str) -> Result<Vec<u8>, CorpusError> {
    let mut file = open_custody_input(path, label)?;
    let bytes = read_exact_bounded(&mut file, max, label, path)?;
    reject_duplicate_keys(&bytes, label)?;
    Ok(bytes)
}

/// Schema of the shared replay validation artifact.
pub const VALIDATION_SCHEMA: &str = "mainnet-prefix-replay-validation-v1";

/// Single-read ceiling for one validation artifact. The producer renders a
/// handful of scalar commitments; anything larger is not a validation record.
pub const VALIDATION_MAX_BYTES: u64 = 64 * 1024;

/// Field-for-field the serialization the replay writes. Unknown keys are
/// rejected so a validation artifact cannot smuggle extra claims.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationFile {
    schema: String,
    stop_height: u32,
    stop_hash: String,
    utxo_hash_serialized_3: String,
    muhash: String,
    utxo_count: u64,
    total_amount: u64,
}

/// The one validation artifact an export binds, loaded once and shared by
/// every backend proof.
///
/// A per-backend validation path would let three proofs each bind a different
/// state and still pass. One artifact, bound to all three by exact bytes and
/// by state, cannot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationArtifact {
    path: String,
    size: u64,
    sha256: [u8; 32],
    sha256_hex: String,
    stop_height: u32,
    stop_hash: String,
    utxo_hash_serialized_3: String,
    muhash: String,
    utxo_count: u64,
    total_amount: u64,
}

impl ValidationArtifact {
    /// Diagnostic-safe rendering of the loaded path: verbatim when it is
    /// short printable ASCII, bounded/escaped otherwise.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Measured artifact size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// SHA-256 of the exact bytes that were parsed.
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Frozen stop height the artifact commits to.
    pub fn stop_height(&self) -> u32 {
        self.stop_height
    }

    /// Frozen stop hash the artifact commits to.
    pub fn stop_hash(&self) -> &str {
        &self.stop_hash
    }
}

/// Loads the shared validation artifact and binds it to the product identity.
///
/// The bytes are read exactly once under the bounded-read contract, screened
/// for repeated keys, parsed with an exact-key schema, and checked against the
/// frozen product tip before any backend proof is allowed to name them.
pub fn load_validation_artifact(
    corpus_id: &str,
    path: &Path,
) -> Result<ValidationArtifact, CorpusError> {
    let identity = product_identity(corpus_id).ok_or_else(|| {
        CorpusError::InvalidCustody(format!(
            "corpus_id must be C150 or Cmodern, got {}",
            bounded_fact("corpus_id", corpus_id)
        ))
    })?;
    let label = "validation artifact";
    let bytes = read_custody_document(path, VALIDATION_MAX_BYTES, label)?;
    let size = u64::try_from(bytes.len())
        .map_err(|_| CorpusError::InvalidCustody(format!("{label} length does not fit u64")))?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let file: ValidationFile = serde_json::from_slice(&bytes).map_err(|error| {
        CorpusError::InvalidCustody(format!(
            "{label} {} is not a bounded {VALIDATION_SCHEMA} document: {}",
            bounded_diagnostic_path(path),
            bounded_fact("serde", &error.to_string())
        ))
    })?;
    if file.schema != VALIDATION_SCHEMA {
        return Err(CorpusError::InvalidCustody(format!(
            "{label} schema is {}, expected {VALIDATION_SCHEMA:?}",
            bounded_fact("schema", &file.schema)
        )));
    }
    for (field, value) in [
        ("stop_hash", &file.stop_hash),
        ("utxo_hash_serialized_3", &file.utxo_hash_serialized_3),
        ("muhash", &file.muhash),
    ] {
        is_lower_hex(value, SHA256_HEX_LEN).map_err(|_| {
            CorpusError::InvalidCustody(format!(
                "{label} {} is not 64 lowercase hex characters",
                bounded_fact(field, value)
            ))
        })?;
        if set_is_zero_hex(value) {
            return Err(CorpusError::InvalidCustody(format!(
                "{label} field {field} is all zeros"
            )));
        }
    }
    // The unit fixture identity carries no frozen tip; production identities
    // pin both, so the artifact must land on the exact frozen product tip.
    if !(identity.stop_height == 0 && identity.stop_hash.is_empty())
        && (file.stop_height != identity.stop_height || file.stop_hash != identity.stop_hash)
    {
        return Err(CorpusError::InvalidCustody(format!(
            "{label} tip {}/{} does not match the {corpus_id} custody identity {}/{}",
            file.stop_height,
            bounded_fact("stop_hash", &file.stop_hash),
            identity.stop_height,
            identity.stop_hash
        )));
    }
    if file.utxo_count == 0 || file.total_amount == 0 {
        return Err(CorpusError::InvalidCustody(format!(
            "{label} records an empty UTXO set"
        )));
    }
    Ok(ValidationArtifact {
        path: bounded_diagnostic_path(path),
        size,
        sha256: digest,
        sha256_hex: hex_encode(&digest),
        stop_height: file.stop_height,
        stop_hash: file.stop_hash,
        utxo_hash_serialized_3: file.utxo_hash_serialized_3,
        muhash: file.muhash,
        utxo_count: file.utxo_count,
        total_amount: file.total_amount,
    })
}

/// Fixed post-link verification buffer size: exactly 1 MiB.
const VERIFY_BUFFER_BYTES: usize = 1024 * 1024;

/// One reusable 1 MiB buffer for streamed post-link verification.
///
/// Published objects include multi-gigabyte archives, so verification never
/// buffers a whole file; one allocation serves every entry in a publication.
struct VerifyBuffer(Box<[u8]>);

impl VerifyBuffer {
    fn new() -> Self {
        Self(vec![0_u8; VERIFY_BUFFER_BYTES].into_boxed_slice())
    }
}

/// One published directory entry, retaining the destination path and the
/// descriptor for the inode this publication wrote.
struct PublishedEntry {
    target: PathBuf,
    file: fs::File,
}

impl PublishedEntry {}

/// Reports published entries as named orphans when a multi-entry publication
/// does not complete.
///
/// The guard is armed the moment its first entry is linked into place and is
/// disarmed only once every recorded entry is durable. An armed drop never
/// pathname-unlinks a published entry: an inode verified through a descriptor
/// can be redirected by a concurrent rename before the unlink lands, which
/// would delete a substitute. Each entry is therefore left in place as a
/// named orphan and reported for operator cleanup.
///
/// The manifest — the durable integrity contract — is always the last entry
/// published, so an orphan archive alone can never validate a corpus.
struct PublicationGuard {
    entries: Vec<PublishedEntry>,
    armed: bool,
}

impl PublicationGuard {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            armed: true,
        }
    }

    fn record(&mut self, entry: PublishedEntry) {
        self.entries.push(entry);
    }

    /// Disarms the guard once every recorded entry is durable.
    fn commit(mut self) {
        self.armed = false;
    }
}

impl Drop for PublicationGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for entry in &self.entries {
            warn_orphaned_entry(&entry.target, file_facts(&entry.file));
        }
    }
}

/// Emits the armed-orphan warning unconditionally: a failed publication must
/// always report its orphan for operator cleanup, even when the written
/// descriptor can no longer be statted. A live descriptor names the written
/// device/inode; a failed stat carries a bounded metadata error instead.
fn warn_orphaned_entry(target: &Path, facts: Result<FileFacts, CorpusError>) {
    let path = bounded_diagnostic_path(target);
    match facts {
        Ok(facts) => tracing::warn!(
            target: "corpus",
            dev = facts.identity.dev,
            ino = facts.identity.ino,
            "failed corpus publication left an orphan output for operator cleanup: {}",
            path
        ),
        Err(error) => tracing::warn!(
            target: "corpus",
            metadata_error = %bounded_fact("metadata", &error.to_string()),
            "failed corpus publication left an orphan output for operator cleanup: {}",
            path
        ),
    }
}

/// Ordered durability steps one publication performs.
///
/// Recorded only under `cfg(test)`, so the data-fsync-before-retain-before-
/// link-before-directory-fsync order is proven by observing the real
/// publication path rather than asserted in a comment. Release builds carry
/// neither the log nor the recording calls.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DurabilityStep {
    DataSync,
    RetainDescriptor,
    Link,
    DirSync,
}

#[cfg(test)]
thread_local! {
    static DURABILITY_LOG: std::cell::RefCell<Vec<DurabilityStep>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn record_durability(step: DurabilityStep) {
    DURABILITY_LOG.with(|log| log.borrow_mut().push(step));
}

#[cfg(test)]
fn durability_log_reset() {
    DURABILITY_LOG.with(|log| log.borrow_mut().clear());
}

#[cfg(test)]
fn durability_log_take() -> Vec<DurabilityStep> {
    DURABILITY_LOG.with(|log| std::mem::take(&mut *log.borrow_mut()))
}

// One armed failure at a named step, consumed by the first matching check.
//
// The publication path performs every fallible preparation before the link
// that makes a destination name visible, so proving that order needs one
// step to fail on demand. Keyed by the same step vocabulary the log
// records, so no second test-only state model exists.
#[cfg(test)]
thread_local! {
    static DURABILITY_FAULT: std::cell::Cell<Option<DurabilityStep>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn durability_fault_arm(step: DurabilityStep) {
    DURABILITY_FAULT.with(|fault| fault.set(Some(step)));
}

/// Fails once when `step` is armed, disarming so one arm injects one failure.
#[cfg(test)]
fn durability_fault_check(step: DurabilityStep) -> io::Result<()> {
    DURABILITY_FAULT.with(|fault| {
        if fault.get() != Some(step) {
            return Ok(());
        }
        fault.set(None);
        Err(io::Error::other(format!("injected {step:?} failure")))
    })
}

/// Publishes `bytes` at `path` through the one crash-safe publication path.
///
/// The bytes are written to one create-new scratch name inside the pinned
/// destination directory, synced, linked into place with the kernel's
/// no-replace hard link without touching any existing entry, verified
/// through a capability-relative no-follow reopen proving device, inode,
/// and streamed digest, and made durable by a directory sync.
///
/// This is the only publisher. Tools and examples call it instead of growing
/// their own weaker copies.
pub fn publish_artifact(path: impl AsRef<Path>, bytes: &[u8]) -> Result<(), CorpusError> {
    let path = path.as_ref();
    #[cfg(not(unix))]
    {
        // Durable publication is a Unix-only capability on this surface:
        // refuse before any scratch allocation or directory mutation.
        let _ = (path, bytes);
        return Err(CorpusError::UnsupportedPlatform);
    }
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let dest = PinnedDestination::pin(path)?;
        dest.ensure_absent()?;

        let mut temp = OutputTemp::create(&dest)?;
        temp.file.write_all(bytes)?;
        temp.sync_data()?;
        dest.ensure_absent()?;

        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let mut buffer = VerifyBuffer::new();
        let mut guard = PublicationGuard::new();
        temp.publish(&digest, &mut guard, &mut buffer)?;
        guard.commit();
        Ok(())
    }
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
    /// A custody binding is missing, unsupported, or contradictory.
    #[error("invalid corpus custody: {0}")]
    InvalidCustody(String),
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
    #[error("archive and manifest paths collide: {}", bounded_diagnostic_path(.path))]
    PathCollision {
        /// Colliding destination.
        path: PathBuf,
    },
    /// A final output already exists and will not be replaced.
    #[error("output already exists: {}", bounded_diagnostic_path(.path))]
    OutputExists {
        /// Existing destination.
        path: PathBuf,
    },
    /// An output path has no final file name.
    #[error("output path has no file name: {}", bounded_diagnostic_path(.path))]
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
        source: bitcoin_rs_primitives::DecodeError,
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
    /// An external custody document could not be opened under the bounded
    /// input contract, or moved, grew, or shrank while being read.
    #[error("{label} {path} {detail}")]
    BoundedRead {
        /// Which custody input was being read.
        label: String,
        /// Bounded, escaped rendering of the input path.
        path: String,
        /// Why the read was rejected.
        detail: String,
    },
    /// An external JSON document repeats an object key or is not one value,
    /// so different readers could disagree about its contents.
    #[error("{label} was rejected: {detail}")]
    ExternalDocument {
        /// Which custody input was parsed.
        label: String,
        /// Why the document was rejected.
        detail: String,
    },
    /// A temporary output name could not be reserved.
    #[error("could not reserve a sibling temporary file for {}", bounded_diagnostic_path(.path))]
    TempNameExhausted {
        /// Final destination.
        path: PathBuf,
    },
    /// Durable corpus publication is implemented for Unix only; other targets
    /// refuse before any scratch allocation or directory mutation.
    #[error("corpus artifact publication is not supported on this platform")]
    UnsupportedPlatform,
    /// Two entries claim the same block hash.
    #[error("duplicate entry hash at index {index}")]
    DuplicateEntryHash {
        /// Entry index whose hash repeats an earlier entry.
        index: usize,
    },
    /// A manifest exceeds the bounded single-read ceiling.
    #[error("manifest {} is {len} bytes; the bounded ceiling is {max}", bounded_diagnostic_path(.path))]
    ManifestTooLarge {
        /// Manifest path that was rejected.
        path: PathBuf,
        /// Declared file size in bytes.
        len: u64,
        /// Maximum accepted manifest size in bytes.
        max: u64,
    },
    /// An entry payload is too short to hold a serialized block header.
    #[error(
        "payload length {length} at index {index} is below the {MIN_PAYLOAD_BYTES}-byte header minimum"
    )]
    ShortPayload {
        /// Entry index in the manifest.
        index: usize,
        /// Declared payload length.
        length: u32,
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
    #[error("invalid block hash hex: {len} bytes, sha256 {sha256}")]
    InvalidHashHex {
        /// Byte length of the rejected value.
        len: usize,
        /// SHA-256 fingerprint of the rejected value.
        sha256: String,
    },
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
    Hash256::from_str_be(&hash).map_err(|_| CoreRestError::InvalidHashHex {
        len: hash.len(),
        sha256: hex_encode(&Sha256::digest(hash.as_bytes())),
    })?;
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
            .block_body(height, BlockHash::from(hash))
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
        let hash = Hash256::from_str_be(&reported).map_err(|_| CoreRestError::InvalidHashHex {
            len: reported.len(),
            sha256: hex_encode(&Sha256::digest(reported.as_bytes())),
        })?;
        let computed = double_sha256(&payload[..80]);
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
    custody: ExportCustody,
    archive_path: impl AsRef<Path>,
    manifest_path: impl AsRef<Path>,
) -> Result<CorpusManifest, CorpusError> {
    let (archive_dest, manifest_dest) =
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
        custody,
        &archive_dest,
        &manifest_dest,
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
    custody: ExportCustody,
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
        custody,
        archive_path.as_ref(),
        manifest_path.as_ref(),
    )
}

pub(crate) fn export_from_sources(
    block_tree: &BlockTree,
    body_source: &dyn BlockBodySource,
    network: Network,
    stop_height: u32,
    custody: ExportCustody,
    archive_path: &Path,
    manifest_path: &Path,
) -> Result<CorpusManifest, CorpusError> {
    let (archive_dest, manifest_dest) = prepare_corpus_destinations(archive_path, manifest_path)?;
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
        custody,
        &archive_dest,
        &manifest_dest,
    )
}

/// One publication destination pinned to one held directory capability.
///
/// The parent directory is opened once, up front, and every later step —
/// the no-clobber precheck, alias-collision detection, scratch creation,
/// the no-replace hard link, the reopened identity/digest proof, the
/// directory sync, and scratch cleanup — resolves names against that held
/// capability. No filesystem call after `pin` ever re-resolves the
/// operator-supplied parent path, so renaming or substituting that path
/// cannot redirect, split, or relocate a publication in progress.
struct PinnedDestination {
    /// The held parent-directory capability every later operation uses.
    dir: Arc<Dir>,
    /// Ordinary read-only handle to `.` opened relative to `dir`; unlike
    /// `cap-std`'s `O_PATH` capability, this descriptor can durably sync entries.
    #[cfg(unix)]
    sync_handle: Arc<std::fs::File>,
    /// The validated final name inside that directory.
    name: std::ffi::OsString,
    /// Canonical parent joined with the final name. Display-only: never a
    /// filesystem argument.
    display_path: PathBuf,
    /// Device and inode of the pinned directory itself, captured from the
    /// held capability at pin time for alias collision detection.
    dir_identity: (u64, u64),
}

impl PinnedDestination {
    /// Pins a publication destination: opens the destination's parent
    /// directory, captures its identity, and holds the capability for the
    /// whole publication. `path` is consumed only to split parent and final
    /// name; nothing re-reads it afterwards.
    fn pin(path: &Path) -> Result<Self, CorpusError> {
        let name = path
            .file_name()
            .ok_or_else(|| CorpusError::InvalidOutputPath {
                path: path.to_owned(),
            })?
            .to_os_string();
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let dir = Arc::new(Dir::open_ambient_dir(parent, ambient_authority())?);
        #[cfg(unix)]
        let sync_handle = Arc::new(dir.open(".")?.into_std());
        let dir_identity = directory_identity(&dir)?;
        // Display only: the canonical walk cannot redirect the pinned
        // directory; the held capability decides where publication lands.
        let display_path = parent.canonicalize().map_err(CorpusError::Io)?.join(&name);
        Ok(Self {
            dir,
            #[cfg(unix)]
            sync_handle,
            name,
            display_path,
            dir_identity,
        })
    }

    /// Pins a destination onto an already-held directory capability: the
    /// same-lexical-parent second destination of one publication reuses the
    /// first destination's directory, so no swap of the shared parent path
    /// between the two pins can split the pair across two directories.
    /// `path` contributes only the final name and the display path.
    fn pin_with_dir(path: &Path, pinned: &Self) -> Result<Self, CorpusError> {
        let name = path
            .file_name()
            .ok_or_else(|| CorpusError::InvalidOutputPath {
                path: path.to_owned(),
            })?
            .to_os_string();
        let dir_identity = pinned.dir_identity;
        let display_path = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .canonicalize()
            .map_err(CorpusError::Io)?
            .join(&name);
        Ok(Self {
            dir: Arc::clone(&pinned.dir),
            #[cfg(unix)]
            sync_handle: Arc::clone(&pinned.sync_handle),
            name,
            display_path,
            dir_identity,
        })
    }

    /// The display-only destination path for operator-facing diagnostics.
    fn display(&self) -> &Path {
        &self.display_path
    }

    /// Makes the published directory entry durable through the ordinary
    /// directory handle opened from this already-pinned capability.
    #[cfg(unix)]
    fn sync_parent(&self) -> Result<(), CorpusError> {
        #[cfg(test)]
        durability_fault_check(DurabilityStep::DirSync)?;
        self.sync_handle.sync_all()?;
        Ok(())
    }

    /// Whether two destinations name the same final entry in one directory,
    /// detected by directory device/inode plus final name. Paths cannot
    /// answer this: one directory reached by two spellings, or renamed
    /// between two canonicalisation calls, compares unequal as paths while
    /// still being one destination.
    fn collides_with(&self, other: &Self) -> bool {
        self.dir_identity == other.dir_identity && self.name == other.name
    }

    /// Test-only resolution assertion: whether two destinations were pinned
    /// onto one directory, independent of their final names.
    #[cfg(test)]
    fn pins_the_same_directory(&self, other: &Self) -> bool {
        self.dir_identity == other.dir_identity
    }

    /// No-clobber precheck: rejects any existing directory entry at the
    /// destination, including a dangling symlink (the final component is
    /// never followed). Resolved against the held capability, so a parent
    /// substituted after the pin cannot move this check. The authoritative
    /// guard remains the kernel's `EEXIST` at the no-replace link inside
    /// `OutputTemp::publish`.
    fn ensure_absent(&self) -> Result<(), CorpusError> {
        match self.dir.symlink_metadata(&self.name) {
            Ok(_) => Err(CorpusError::OutputExists {
                path: self.display_path.clone(),
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(CorpusError::Io(error)),
        }
    }
}

/// Captures a held directory's device/inode identity from its own handle.
fn directory_identity(dir: &Dir) -> Result<(u64, u64), CorpusError> {
    let metadata = dir.dir_metadata()?;
    Ok((
        CapMetadataExt::dev(&metadata),
        CapMetadataExt::ino(&metadata),
    ))
}

/// Pins both output destinations up front — before custody validation or
/// any block streaming — and rejects an archive/manifest alias collision
/// before anything is written. Collision detection compares directory
/// identity (device and inode) plus the final name, so one directory
/// reached through two spellings is still caught.
fn prepare_corpus_destinations(
    archive_path: &Path,
    manifest_path: &Path,
) -> Result<(PinnedDestination, PinnedDestination), CorpusError> {
    let archive_dest = PinnedDestination::pin(archive_path)?;
    // Test-only boundary hook: runs at the exact between-pins moment, so a
    // test can swap the shared parent path before the manifest pin.
    #[cfg(test)]
    run_between_pins_hook();
    let manifest_dest = if same_lexical_parent(archive_path, manifest_path) {
        // One held directory descriptor serves both destinations: the
        // manifest is pinned onto the archive's already-open directory, so
        // a swap of the shared parent path between the two pins cannot
        // split the pair across two directories.
        PinnedDestination::pin_with_dir(manifest_path, &archive_dest)?
    } else {
        PinnedDestination::pin(manifest_path)?
    };
    if archive_dest.collides_with(&manifest_dest) {
        return Err(CorpusError::PathCollision {
            path: archive_dest.display_path,
        });
    }
    Ok((archive_dest, manifest_dest))
}

/// Whether two destinations share one lexical parent directory. Lexical
/// only: the reused-descriptor decision covers callers that spell both
/// outputs under one parent; different spellings fall back to independent
/// pins, which remain correct on their own.
fn same_lexical_parent(a: &Path, b: &Path) -> bool {
    let parent = |path: &Path| {
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    };
    parent(a) == parent(b)
}

// Test-only between-pins boundary for `prepare_corpus_destinations`.
// Armed by a test, the hook runs once after the archive pin and before the
// manifest pin — the exact window where a shared-parent path swap could
// otherwise split the pair. Compiled out of release builds.
#[cfg(test)]
thread_local! {
    static BETWEEN_PINS_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn arm_between_pins_hook(hook: impl FnOnce() + 'static) {
    BETWEEN_PINS_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_between_pins_hook() {
    BETWEEN_PINS_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

fn write_corpus_archive(
    source: &mut dyn CorpusBlockSource,
    network: Network,
    stop_height: u32,
    custody: ExportCustody,
    archive_dest: &PinnedDestination,
    manifest_dest: &PinnedDestination,
) -> Result<CorpusManifest, CorpusError> {
    // Capability-relative no-clobber prechecks: rejected before any scratch
    // name exists, against the held directory capabilities. The authoritative
    // guard stays the kernel's EEXIST at the no-replace link.
    archive_dest.ensure_absent()?;
    manifest_dest.ensure_absent()?;
    custody.validate()?;
    // Validate the frozen product identity before any reservation so an
    // operator-controlled stop height can never drive the entry allocation.
    let identity = product_identity(&custody.corpus_id).ok_or_else(|| {
        CorpusError::InvalidCustody(format!(
            "corpus_id must be C150 or Cmodern, got {}",
            bounded_fact("corpus_id", &custody.corpus_id)
        ))
    })?;
    // Fixture identity has no frozen height (test builds only); production
    // identities must hit theirs exactly so the entry reservation below is
    // bounded by a compiled-in constant.
    if !(identity.stop_height == 0 && identity.stop_hash.is_empty())
        && stop_height != identity.stop_height
    {
        return Err(CorpusError::InvalidCustody(format!(
            "{} is frozen at stop height {}; got {stop_height}",
            bounded_fact("corpus_id", &custody.corpus_id),
            identity.stop_height
        )));
    }

    let mut archive_temp = OutputTemp::create(archive_dest)?;
    let mut hashing_writer = HashingWriter::new(BufWriter::new(&mut archive_temp.file));
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
            let actual = Hash256::from(block.block_hash());
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
    buf.into_inner()
        .map_err(std::io::IntoInnerError::into_error)?;
    archive_temp.sync_data()?;
    let archive_digest: [u8; 32] = hasher.finalize().into();
    let stored_size = archive_temp.file.metadata()?.len();
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
        custody,
    )?;
    let manifest_bytes = serde_json::to_vec(&CorpusManifestV2::from(&manifest))?;
    let manifest_len =
        u64::try_from(manifest_bytes.len()).map_err(|_| CorpusError::ManifestTooLarge {
            path: manifest_dest.display().to_owned(),
            len: u64::MAX,
            max: MAX_MANIFEST_BYTES,
        })?;
    if !manifest_bound_ok(manifest_len) {
        return Err(CorpusError::ManifestTooLarge {
            path: manifest_dest.display().to_owned(),
            len: manifest_len,
            max: MAX_MANIFEST_BYTES,
        });
    }
    let mut manifest_temp = OutputTemp::create(manifest_dest)?;
    manifest_temp.file.write_all(&manifest_bytes)?;
    manifest_temp.sync_data()?;

    let mut guard = PublicationGuard::new();
    let mut buffer = VerifyBuffer::new();
    archive_temp.publish(&archive_digest, &mut guard, &mut buffer)?;
    manifest_temp.publish(
        &Sha256::digest(&manifest_bytes).into(),
        &mut guard,
        &mut buffer,
    )?;
    guard.commit();
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

/// Scratch output bound to one named inode inside one pinned destination.
///
/// The scratch is one create-new sibling name opened without following its
/// final component against the held directory capability, so it has no
/// pre-existing entry to race and no parent path to re-resolve. Publication
/// links the written name into place with the kernel's inherently
/// no-replace hard link, then reopens the final name no-follow and proves
/// its device, inode, and content digest equal the written object.
/// Publication therefore cannot succeed on substituted bytes, and every
/// cleanup removes only the relative scratch name through the held
/// capability.
struct OutputTemp<'d> {
    dest: &'d PinnedDestination,
    file: fs::File,
    scratch: std::ffi::OsString,
    armed: bool,
}

impl<'d> OutputTemp<'d> {
    /// Creates the scratch file inside the pinned directory. The parent
    /// path is never opened here: every operation resolves against the held
    /// capability.
    fn create(dest: &'d PinnedDestination) -> Result<Self, CorpusError> {
        #[cfg(not(unix))]
        {
            // Durable publication is a Unix-only capability on this surface;
            // refuse before any scratch name is generated or created.
            let _ = dest;
            return Err(CorpusError::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
            let mut attempts = 0_u32;
            let (file, scratch) = loop {
                if attempts >= 128 {
                    return Err(CorpusError::TempNameExhausted {
                        path: dest.display().to_owned(),
                    });
                }
                attempts += 1;
                let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
                let mut scratch = dest.name.clone();
                scratch.push(format!(".tmp.{}.{id}", std::process::id()));
                let mut options = OpenOptions::new();
                options
                    .write(true)
                    .create_new(true)
                    .follow(FollowSymlinks::No);
                match dest.dir.open_with(&scratch, &options) {
                    Ok(file) => break (file.into_std(), scratch),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
            };
            Ok(Self {
                dest,
                file,
                scratch,
                armed: true,
            })
        }
    }

    /// Flushes and syncs the written file so its bytes are durable before
    /// any directory entry can name them.
    fn sync_data(&mut self) -> Result<(), CorpusError> {
        self.file.flush()?;
        self.file.sync_all()?;
        #[cfg(test)]
        record_durability(DurabilityStep::DataSync);
        Ok(())
    }

    /// Links the written file into place, records the entry in the
    /// publication guard, and proves the published object is the written
    /// bytes through a capability-relative no-follow reopen: same device and
    /// inode as the retained written descriptor and a streamed digest equal
    /// to `expected_digest` over one reusable fixed buffer, then syncs the
    /// held directory capability so the new entry is durable.
    ///
    /// Every fallible preparation runs before the link. Once the link makes a
    /// destination name visible, only moves of already-owned values separate
    /// it from `guard.record`, so a published entry can never go unrecorded —
    /// and an unrecorded entry is an orphan no drop can report.
    ///
    /// The entry is recorded before verification so a failure after the link
    /// still retains the entry in the guard, which reports it as a named
    /// orphan on an armed drop.
    fn publish(
        mut self,
        expected_digest: &[u8; 32],
        guard: &mut PublicationGuard,
        buffer: &mut VerifyBuffer,
    ) -> Result<(), CorpusError> {
        #[cfg(not(unix))]
        {
            // Unreachable: `create` refuses publication on non-Unix targets
            // before a scratch exists, so no name can ever be linked here.
            let _ = (expected_digest, guard, buffer);
            return Err(CorpusError::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            // Every fallible preparation happens here, before any operation
            // can make a destination name visible. A failure now leaves only
            // the scratch name, which the armed drop removes.
            #[cfg(test)]
            durability_fault_check(DurabilityStep::RetainDescriptor)?;
            let retained = self.file.try_clone()?;
            let published_target = self.dest.display().to_owned();
            #[cfg(test)]
            record_durability(DurabilityStep::RetainDescriptor);

            // Hard links never replace: the kernel rejects an existing
            // destination with EEXIST, which is the authoritative collision
            // guard. Both names resolve through the same held capability.
            if let Err(error) = self.dest.dir.hard_link(
                self.scratch.as_os_str(),
                &self.dest.dir,
                self.dest.name.as_os_str(),
            ) {
                return Err(if error.kind() == io::ErrorKind::AlreadyExists {
                    CorpusError::OutputExists {
                        path: published_target,
                    }
                } else {
                    CorpusError::Io(error)
                });
            }
            #[cfg(test)]
            record_durability(DurabilityStep::Link);
            // Infallible: nothing between the visible name and this record
            // can fail. The only remaining fallible step is the best-effort
            // scratch cleanup after this record, so a published entry can
            // never go unrecorded.
            guard.record(PublishedEntry {
                target: published_target,
                file: retained,
            });
            // The final entry is already linked and recorded, so this
            // cleanup is best-effort; a leftover scratch name is inert and
            // never un-publishes the entry.
            let _ = self.dest.dir.remove_file(&self.scratch);
            self.armed = false;
            self.verify_published(expected_digest, buffer)?;
            self.armed = false;
            Ok(())
        }
    }

    /// Proves the published name is the written object: a capability
    /// no-follow reopen, a regular-file and device/inode identity check
    /// against the retained written descriptor, one streamed digest over
    /// the reusable buffer, and a directory sync through the held
    /// capability. No parent path is opened or re-resolved.
    #[cfg(unix)]
    fn verify_published(
        &self,
        expected_digest: &[u8; 32],
        buffer: &mut VerifyBuffer,
    ) -> Result<(), CorpusError> {
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No).nonblock(true);
        // A successful no-replace link proved this name is ours, so the
        // reopen cannot report a pre-existing destination.
        let mut published = self.dest.dir.open_with(&self.dest.name, &options)?;
        let published_facts = capability_file_facts(&published)?;
        if !published_facts.is_file {
            return Err(CorpusError::InvalidCustody(format!(
                "published output {} is not a regular file",
                bounded_diagnostic_path(self.dest.display())
            )));
        }
        let written_facts = file_facts(&self.file)?;
        if published_facts.identity.dev != written_facts.identity.dev
            || published_facts.identity.ino != written_facts.identity.ino
        {
            return Err(CorpusError::InvalidCustody(format!(
                "published output {} is not the written inode",
                bounded_diagnostic_path(self.dest.display())
            )));
        }
        let mut hasher = Sha256::new();
        loop {
            let read = published.read(&mut buffer.0)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer.0[..read]);
        }
        let digest: [u8; 32] = hasher.finalize().into();
        if &digest != expected_digest {
            return Err(CorpusError::InvalidCustody(format!(
                "published output {} content differs from the written object",
                bounded_diagnostic_path(self.dest.display())
            )));
        }
        self.dest.sync_parent()?;
        #[cfg(test)]
        record_durability(DurabilityStep::DirSync);
        Ok(())
    }
}

impl Drop for OutputTemp<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Cleanup resolves the scratch name through the held directory
            // capability. The parent pathname was never re-opened after the
            // pin, so a rename or symlink swap of that path cannot redirect
            // this removal, while a pathname cleanup could delete an
            // attacker-supplied file placed at the substituted path.
            let _ = self.dest.dir.remove_file(&self.scratch);
        }
    }
}

/// Opens a manifest file once and reads exactly the bytes its metadata
/// declares under the shared bounded-read contract.
///
/// The manifest keeps its own typed ceiling error, and the read itself is
/// exact: a file that grows, shrinks, or changes metadata while being read is
/// rejected instead of parsed.
fn read_manifest_bounded(path: &Path) -> Result<Vec<u8>, CorpusError> {
    let mut file = open_custody_input(path, "corpus manifest")?;
    // The bounded-open contract already rejected non-regular objects; the
    // metadata ceiling is the manifest's own typed bound.
    let facts = file_facts(&file)?;
    if facts.identity.size > MAX_MANIFEST_BYTES {
        return Err(CorpusError::ManifestTooLarge {
            path: path.to_owned(),
            len: facts.identity.size,
            max: MAX_MANIFEST_BYTES,
        });
    }
    read_exact_bounded(&mut file, MAX_MANIFEST_BYTES, "corpus manifest", path)
}

impl CorpusManifest {
    /// Schema identifier for the manifest schema.
    pub const SCHEMA: &'static str = SCHEMA;
    /// Version number for the manifest schema.
    pub const VERSION: u32 = VERSION;

    /// Constructs and validates a manifest from its constituent parts.
    ///
    /// `network_magic` and `genesis_hash` are derived from `network`; the
    /// caller is responsible for ensuring `entries` are contiguous and the
    /// archive size matches the final frame. Custody bindings are validated
    /// fail-closed and the canonical manifest digest is computed here. The
    /// product corpus id additionally pins the network to mainnet and the
    /// stop height/hash to the frozen product tip before anything is built.
    pub fn new(
        network: Network,
        archive: ArchiveInfo,
        entries: Vec<CorpusEntry>,
        custody: ExportCustody,
    ) -> Result<Self, CorpusError> {
        custody.validate()?;
        validate_product_identity(
            &custody.corpus_id,
            network,
            entries.last().map(|entry| (entry.height, entry.hash)),
        )?;
        let start_height = 0;
        let stop_height = match entries.len() {
            0 => return Err(CorpusError::EmptyEntries),
            n => u32::try_from(n - 1).map_err(|_| CorpusError::OffsetOverflow { index: 0 })?,
        };

        let mut manifest = Self {
            corpus_id: custody.corpus_id,
            core_version: custody.core_version,
            exporter: VersionedSchema {
                schema: EXPORTER_SCHEMA.to_owned(),
                version: EXPORTER_VERSION,
            },
            checksig_census: VersionedSchema {
                schema: CHECKSIG_CENSUS_SCHEMA.to_owned(),
                version: CHECKSIG_CENSUS_VERSION,
            },
            reopen_proofs: custody.reopen_proofs,
            source_tip_hash: entries
                .last()
                .map(|entry| entry.hash)
                .ok_or(CorpusError::EmptyEntries)?,
            manifest_sha256: [0; 32],
            network,
            network_magic: network.magic(),
            genesis_hash: network.genesis_block_hash(),
            start_height,
            stop_height,
            archive,
            entries,
        };
        manifest.validate_unguarded()?;
        manifest.manifest_sha256 = manifest.canonical_sha256()?;
        Ok(manifest)
    }

    /// Computes the manifest digest over the canonical preimage: this exact
    /// wire serialization with `manifest_sha256` zeroed.
    fn canonical_sha256(&self) -> Result<[u8; 32], CorpusError> {
        let mut preimage = self.clone();
        preimage.manifest_sha256 = [0; 32];
        let bytes = serde_json::to_vec(&CorpusManifestV2::from(&preimage))?;
        Ok(Sha256::digest(bytes).into())
    }

    /// Loads a manifest from a JSON file and validates every field.
    ///
    /// The read is bounded: the file is opened, sized via its metadata, and
    /// rejected before allocation when it exceeds [`MAX_MANIFEST_BYTES`].
    pub fn load(path: impl AsRef<Path>) -> Result<Self, CorpusError> {
        let bytes = read_manifest_bounded(path.as_ref())?;
        Self::from_bytes(&bytes)
    }

    /// Parses and validates a manifest from its in-memory JSON bytes.
    ///
    /// Keeps the read and the parse in one call so a caller can hash the same
    /// bytes it validated, avoiding a second file read.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CorpusError> {
        // A manifest is an external custody document: repeated object keys
        // would let one document show different readers different values.
        reject_duplicate_keys(bytes, "corpus manifest")?;
        let wire: CorpusManifestV2 =
            serde_json::from_slice(bytes).map_err(|error| CorpusError::ExternalDocument {
                label: "corpus manifest".to_owned(),
                detail: bounded_fact("serde", &error.to_string()),
            })?;
        wire.try_into()
    }

    /// Validates a manifest from a path and returns the parsed manifest plus
    /// the raw bytes that produced it, so the caller can compute the manifest
    /// file's own digest without reading it a second time.
    pub fn load_with_bytes(path: impl AsRef<Path>) -> Result<(Self, Vec<u8>), CorpusError> {
        let bytes = read_manifest_bounded(path.as_ref())?;
        let manifest = Self::from_bytes(&bytes)?;
        Ok((manifest, bytes))
    }

    /// Saves this manifest to `path` through [`publish_artifact`]: the one
    /// crash-safe publication path — one create-new scratch name inside the
    /// pinned destination, data sync, a no-replace hard link, a
    /// capability-relative no-follow reopen proving device/inode/digest, and
    /// a directory sync. An existing destination is never replaced.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), CorpusError> {
        self.validate()?;
        let wire = CorpusManifestV2::from(self);
        let bytes = serde_json::to_vec(&wire)?;
        publish_artifact(path, &bytes)
    }

    /// Re-validates the in-memory manifest, including the canonical digest.
    pub fn validate(&self) -> Result<(), CorpusError> {
        self.validate_unguarded()?;
        let computed = self.canonical_sha256()?;
        if self.manifest_sha256 != computed {
            return Err(CorpusError::InvalidCustody(format!(
                "manifest_sha256 mismatch: declared {}, computed {}",
                hex_encode(&self.manifest_sha256),
                hex_encode(&computed)
            )));
        }
        Ok(())
    }

    /// Validates every structural and custody binding except the canonical
    /// digest, which cannot be checked before it has been computed.
    fn validate_unguarded(&self) -> Result<(), CorpusError> {
        validate_custody(&self.corpus_id, &self.core_version, &self.reopen_proofs)?;
        validate_product_identity(
            &self.corpus_id,
            self.network,
            Some((self.stop_height, self.source_tip_hash)),
        )?;
        if self.archive.sha256 == [0; 32] {
            return Err(CorpusError::InvalidCustody(
                "archive.sha256 must be a nonzero digest".to_owned(),
            ));
        }
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
        self.validate_entries()?;

        Ok(())
    }

    /// Validates entry count, height contiguity, payload bounds, hash
    /// uniqueness, frame offsets, and the final archive size.
    fn validate_entries(&self) -> Result<(), CorpusError> {
        if self.entries.is_empty() {
            return Err(CorpusError::EmptyEntries);
        }
        if self.entries.last().map(|entry| entry.hash) != Some(self.source_tip_hash) {
            return Err(CorpusError::InvalidCustody(
                "source_tip_hash must equal the final entry hash".to_owned(),
            ));
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

        let mut seen_hashes = std::collections::HashSet::with_capacity(self.entries.len());
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
            if entry.payload_length < MIN_PAYLOAD_BYTES {
                return Err(CorpusError::ShortPayload {
                    index,
                    length: entry.payload_length,
                });
            }
            if !seen_hashes.insert(entry.hash) {
                return Err(CorpusError::DuplicateEntryHash { index });
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
pub(crate) struct CorpusManifestV2 {
    schema: String,
    version: u32,
    corpus_id: String,
    core_version: String,
    exporter: VersionedSchema,
    checksig_census: VersionedSchema,
    reopen_proofs: Vec<CustodyFileV2>,
    manifest_sha256: String,
    source_tip_hash: String,
    network: String,
    network_magic: String,
    genesis_hash: String,
    range: RangeV1,
    archive: ArchiveInfoV1,
    entries: Vec<CorpusEntryV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyFileV2 {
    schema: String,
    version: u32,
    backend: String,
    path: String,
    size: u64,
    sha256: String,
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

impl TryFrom<CorpusManifestV2> for CorpusManifest {
    type Error = CorpusError;

    fn try_from(wire: CorpusManifestV2) -> Result<Self, Self::Error> {
        if wire.schema != SCHEMA {
            return Err(CorpusError::SchemaMismatch {
                expected: SCHEMA,
                actual: bounded_fact("schema", &wire.schema),
            });
        }
        if wire.version != VERSION {
            return Err(CorpusError::VersionMismatch {
                expected: VERSION,
                actual: wire.version,
            });
        }
        validate_versioned(
            &wire.exporter,
            EXPORTER_SCHEMA,
            EXPORTER_VERSION,
            "exporter",
        )?;
        validate_versioned(
            &wire.checksig_census,
            CHECKSIG_CENSUS_SCHEMA,
            CHECKSIG_CENSUS_VERSION,
            "checksig_census",
        )?;
        let reopen_proofs = wire
            .reopen_proofs
            .iter()
            .map(|proof| {
                if proof.schema != REOPEN_PROOF_SCHEMA || proof.version != REOPEN_PROOF_VERSION {
                    return Err(CorpusError::InvalidCustody(format!(
                        "unsupported reopen proof schema/version: expected \
                         {REOPEN_PROOF_SCHEMA}/v{REOPEN_PROOF_VERSION}, got {}/v{}",
                        bounded_fact("schema", &proof.schema),
                        proof.version
                    )));
                }
                Ok(CustodyFile {
                    backend: proof.backend.clone(),
                    path: proof.path.clone(),
                    size: proof.size,
                    sha256: decode_sha256(&proof.sha256)?,
                })
            })
            .collect::<Result<Vec<CustodyFile>, CorpusError>>()?;
        validate_custody(&wire.corpus_id, &wire.core_version, &reopen_proofs)?;

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
            corpus_id: wire.corpus_id,
            core_version: wire.core_version,
            exporter: wire.exporter,
            checksig_census: wire.checksig_census,
            reopen_proofs,
            source_tip_hash: parse_hash256(&wire.source_tip_hash)?,
            manifest_sha256: decode_sha256(&wire.manifest_sha256)?,
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

/// Rejects any schema name/version pair the consumer does not support exactly.
fn validate_versioned(
    schema: &VersionedSchema,
    expected_schema: &str,
    expected_version: u32,
    label: &str,
) -> Result<(), CorpusError> {
    if schema.schema != expected_schema || schema.version != expected_version {
        return Err(CorpusError::InvalidCustody(format!(
            "unsupported {label} schema/version: expected {expected_schema}/v{expected_version}, \
             got {}/v{}",
            bounded_fact("schema", &schema.schema),
            schema.version
        )));
    }
    Ok(())
}

impl From<&CorpusManifest> for CorpusManifestV2 {
    fn from(manifest: &CorpusManifest) -> Self {
        Self {
            schema: SCHEMA.to_owned(),
            version: VERSION,
            corpus_id: manifest.corpus_id.clone(),
            core_version: manifest.core_version.clone(),
            exporter: manifest.exporter.clone(),
            checksig_census: manifest.checksig_census.clone(),
            reopen_proofs: manifest
                .reopen_proofs
                .iter()
                .map(|proof| CustodyFileV2 {
                    schema: REOPEN_PROOF_SCHEMA.to_owned(),
                    version: REOPEN_PROOF_VERSION,
                    backend: proof.backend.clone(),
                    path: proof.path.clone(),
                    size: proof.size,
                    sha256: hex_encode(&proof.sha256),
                })
                .collect(),
            manifest_sha256: hex_encode(&manifest.manifest_sha256),
            source_tip_hash: manifest.source_tip_hash.to_string_be(),
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
            name: bounded_fact("network", name),
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
        return Err(CorpusError::InvalidHex(bounded_fact("hex", s)));
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
    Hash256::from_str_be(s).map_err(|_| CorpusError::InvalidHex(bounded_fact("hash", s)))
}

#[cfg(test)]
// Test fixtures fail at the assertion site; production parsing stays fallible.
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use hashbrown::HashMap;
    use std::io::{BufRead as _, BufReader, Cursor, ErrorKind, Write as _};
    use std::net::TcpListener;
    use std::thread;
    use std::{fs, path::Path};

    use bitcoin_rs_chain::{BlockTree, NodeStatus};
    use bitcoin_rs_primitives::{
        Block, BlockHash, Hash256, Header, Network, consensus_bytes, deserialize,
    };
    use bitcoin_rs_rpc::context::BlockBodySource;
    use bitcoin_rs_storage::CoreFrameReader;
    use sha2::{Digest as _, Sha256};

    use super::{
        ArchiveInfo, BlockTreeSource, CHECKSIG_CENSUS_SCHEMA, CHECKSIG_CENSUS_VERSION,
        CoreRestClient, CoreRestError, CorpusEntry, CorpusError, CorpusManifest, CorpusManifestV2,
        CustodyFile, DurabilityStep, EXPORTER_SCHEMA, EXPORTER_VERSION, ExportCustody,
        FIXTURE_CORPUS_ID, HASH_HEX_LEN, MAX_BODY_BYTES, MAX_PAYLOAD_BYTES, OutputTemp,
        PinnedDestination, PublicationGuard, PublishedEntry, REOPEN_PROOF_SCHEMA,
        REOPEN_PROOF_VERSION, RestCorpusSource, SCHEMA, VALIDATION_MAX_BYTES, VALIDATION_SCHEMA,
        VERSION, ValidationArtifact, VerifyBuffer, arm_between_pins_hook, bounded_diagnostic_path,
        durability_fault_arm, durability_log_reset, durability_log_take, export_from_sources,
        file_facts, load_reopen_proof, load_validation_artifact, open_custody_input,
        prepare_corpus_destinations, publish_artifact, read_custody_document,
        read_declared_bounded, read_exact_bounded, reject_duplicate_keys, warn_orphaned_entry,
        write_corpus_archive,
    };

    fn sample_archive() -> ArchiveInfo {
        ArchiveInfo::new(176, [1; 32])
    }

    fn sample_entries() -> Vec<CorpusEntry> {
        vec![
            CorpusEntry {
                height: 0,
                hash: Hash256::from_le_bytes(&[0; 32]),
                offset: 0,
                payload_length: 80,
            },
            CorpusEntry {
                height: 1,
                hash: Hash256::from_le_bytes(&[1; 32]),
                offset: 88,
                payload_length: 80,
            },
        ]
    }

    fn sample_proofs() -> Vec<CustodyFile> {
        ["fjall", "rocksdb", "redb"]
            .map(|backend| CustodyFile {
                backend: backend.to_owned(),
                path: format!("/tmp/synthetic/{backend}-reopen-proof.json"),
                size: 3,
                sha256: [1; 32],
            })
            .to_vec()
    }

    fn sample_custody() -> ExportCustody {
        // Fixture identity: resolves only under cfg(test), skips frozen
        // range/network pinning, and keeps unit chains two blocks long.
        ExportCustody::new("CFIXTURE", "31.1.0", sample_proofs()).unwrap()
    }

    // One-line minimal v2 manifest; digests are placeholders and validation
    // only completes when the schema/version under test passes its check.
    fn minimal_v2_json(schema: &str, version: impl std::fmt::Display) -> String {
        let hash = "0".repeat(64);
        let proof = |backend: &str| {
            format!(
                r#"{{"schema":"{REOPEN_PROOF_SCHEMA}","version":{REOPEN_PROOF_VERSION},"backend":"{backend}","path":"/tmp/synthetic/{backend}-reopen-proof.json","size":3,"sha256":"1111111111111111111111111111111111111111111111111111111111111111"}}"#
            )
        };
        format!(
            r#"{{"schema":"{schema}","version":{version},"corpus_id":"{FIXTURE_CORPUS_ID}","core_version":"31.1.0","exporter":{{"schema":"{EXPORTER_SCHEMA}","version":{EXPORTER_VERSION}}},"checksig_census":{{"schema":"{CHECKSIG_CENSUS_SCHEMA}","version":{CHECKSIG_CENSUS_VERSION}}},"reopen_proofs":[{fjall},{rocksdb},{redb}],"manifest_sha256":"{hash}","source_tip_hash":"{hash}","network":"regtest","network_magic":"fabfb5da","genesis_hash":"{hash}","range":{{"start_height":0,"stop_height":0}},"archive":{{"size":8,"sha256":"{hash}"}},"entries":[{{"height":0,"hash":"{hash}","offset":0,"payload_length":80}}]}}"#,
            fjall = proof("fjall"),
            rocksdb = proof("rocksdb"),
            redb = proof("redb"),
        )
    }

    fn sample_manifest() -> CorpusManifest {
        CorpusManifest::new(
            Network::Mainnet,
            ArchiveInfo::new(176, [1; 32]),
            vec![
                CorpusEntry {
                    height: 0,
                    hash: Hash256::from_str_be(
                        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                    )
                    .unwrap(),
                    offset: 0,
                    payload_length: 80,
                },
                CorpusEntry {
                    height: 1,
                    hash: Hash256::from_le_bytes(&[1; 32]),
                    offset: 88,
                    payload_length: 80,
                },
            ],
            sample_custody(),
        )
        .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn roundtrip_saves_and_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corpus-manifest-v2.json");

        let manifest = sample_manifest();
        manifest.save(&path).unwrap();
        let loaded = CorpusManifest::load(&path).unwrap();

        assert_eq!(loaded, manifest);
    }

    #[test]
    fn custody_rejects_unknown_corpus_id() {
        let err = ExportCustody::new("C999", "31.1.0", sample_proofs()).unwrap_err();
        assert!(matches!(err, CorpusError::InvalidCustody(_)));
    }

    #[test]
    fn custody_rejects_empty_core_version() {
        let err = ExportCustody::new("C150", "  ", sample_proofs()).unwrap_err();
        assert!(matches!(err, CorpusError::InvalidCustody(_)));
    }

    #[test]
    fn custody_accepts_core_version_grammar_variants() {
        for version in [
            "31.1.0",
            "31.1",
            "0.15.0.1",
            "0.0",
            "1.1",
            "123.123.123.123",
        ] {
            ExportCustody::new("C150", version, sample_proofs())
                .unwrap_or_else(|error| panic!("{version} must be accepted: {error}"));
        }
    }

    #[test]
    fn custody_rejects_core_version_grammar_variants() {
        for version in [
            "",
            " ",
            "31",
            "31.",
            ".1",
            "31..1",
            "31.1.",
            "v31.1",
            "+31.1",
            "31.-1",
            "31.1.0 ",
            " 31.1.0",
            "31.1\t",
            "31.1\n",
            "٣١.١",
            "31.1.0.1.2",
            "1234.1",
            "31.1.0.1.2.3.4.5.6.7.8.9.0.1.2.3",
        ] {
            let error = ExportCustody::new("C150", version, sample_proofs()).unwrap_err();
            assert!(
                matches!(error, CorpusError::InvalidCustody(_)),
                "{version:?} must be rejected"
            );
        }
    }

    #[test]
    fn custody_error_bounds_hostile_core_version() {
        let hostile = format!("31.1.0\n\u{1b}[31m\u{202e}{}", "v".repeat(300));
        let error = ExportCustody::new("C150", hostile.as_str(), sample_proofs()).unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("core_version:"), "actual: {rendered}");
        assert!(rendered.contains("sha256="), "no fingerprint: {rendered}");
        assert!(!rendered.contains('\n'), "raw newline: {rendered:?}");
        assert!(!rendered.contains('\u{1b}'), "raw escape: {rendered:?}");
        assert!(!rendered.contains('\u{202e}'), "raw bidi: {rendered:?}");
        assert!(!rendered.contains(&"v".repeat(40)), "raw run: {rendered:?}");
        assert!(rendered.len() < 512, "unbounded: {}", rendered.len());
    }

    #[test]
    fn custody_rejects_missing_backend_proof() {
        let mut proofs = sample_proofs();
        proofs.remove(1);
        let err = ExportCustody::new("C150", "31.1.0", proofs).unwrap_err();
        assert!(matches!(err, CorpusError::InvalidCustody(_)));
    }

    #[test]
    fn custody_rejects_duplicate_backend_proof() {
        let mut proofs = sample_proofs();
        proofs[1].backend = "fjall".to_owned();
        let err = ExportCustody::new("Cmodern", "31.1.0", proofs).unwrap_err();
        assert!(matches!(err, CorpusError::InvalidCustody(_)));
    }

    #[test]
    fn custody_rejects_stub_proof_binding() {
        let mut proofs = sample_proofs();
        proofs[2].sha256 = [0; 32];
        let err = ExportCustody::new("C150", "31.1.0", proofs).unwrap_err();
        assert!(matches!(err, CorpusError::InvalidCustody(_)));
    }

    #[cfg(unix)]
    #[test]
    fn roundtrip_rejects_tampered_corpus_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        sample_manifest().save(&path).unwrap();
        let text = fs::read_to_string(&path)
            .unwrap()
            .replace("CFIXTURE", "C999");
        fs::write(&path, text).unwrap();
        let err = CorpusManifest::load(&path).unwrap_err();
        assert!(matches!(err, CorpusError::InvalidCustody(_)));
    }

    #[test]
    fn wire_rejects_unsupported_exporter_schema() {
        let mut wire = CorpusManifestV2::from(&sample_manifest());
        wire.exporter.schema = "other".to_owned();
        let err = CorpusManifest::try_from(wire).unwrap_err();
        assert!(matches!(err, CorpusError::InvalidCustody(_)));
    }

    #[test]
    fn wire_rejects_unsupported_census_version() {
        let mut wire = CorpusManifestV2::from(&sample_manifest());
        wire.checksig_census.version = 9;
        let err = CorpusManifest::try_from(wire).unwrap_err();
        assert!(matches!(err, CorpusError::InvalidCustody(_)));
    }

    #[test]
    fn wire_rejects_reopen_proof_schema_drift() {
        let mut wire = CorpusManifestV2::from(&sample_manifest());
        wire.reopen_proofs[0].schema = "other".to_owned();
        let err = CorpusManifest::try_from(wire).unwrap_err();
        assert!(matches!(err, CorpusError::InvalidCustody(_)));
    }

    #[test]
    fn wire_rejects_zero_manifest_digest() {
        let mut wire = CorpusManifestV2::from(&sample_manifest());
        wire.manifest_sha256 = "0".repeat(64);
        let err = CorpusManifest::try_from(wire).unwrap_err();
        assert!(matches!(err, CorpusError::InvalidCustody(_)));
    }

    #[test]
    fn wire_rejects_source_tip_mismatch() {
        let mut wire = CorpusManifestV2::from(&sample_manifest());
        wire.source_tip_hash = "f".repeat(64);
        let err = CorpusManifest::try_from(wire).unwrap_err();
        assert!(matches!(err, CorpusError::InvalidCustody(_)));
    }

    #[test]
    fn wire_rejects_core_version_grammar_drift() {
        let mut wire = CorpusManifestV2::from(&sample_manifest());
        wire.core_version = "31".to_owned();
        let error = CorpusManifest::try_from(wire).unwrap_err();
        assert!(matches!(error, CorpusError::InvalidCustody(_)));
    }

    #[test]
    fn manifest_digest_binds_canonical_preimage() {
        let manifest = sample_manifest();
        let mut preimage = CorpusManifestV2::from(&manifest);
        preimage.manifest_sha256 = "0".repeat(64);
        let bytes = serde_json::to_vec(&preimage).unwrap();
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        assert_eq!(digest, manifest.manifest_sha256);
    }

    #[test]
    fn rejects_wrong_schema() {
        let json = minimal_v2_json("other", VERSION);
        let err =
            CorpusManifest::try_from(serde_json::from_str::<CorpusManifestV2>(&json).unwrap())
                .unwrap_err();
        assert!(matches!(err, CorpusError::SchemaMismatch { .. }));
    }

    #[test]
    fn rejects_wrong_version() {
        let json = minimal_v2_json(SCHEMA, 3);
        let err =
            CorpusManifest::try_from(serde_json::from_str::<CorpusManifestV2>(&json).unwrap())
                .unwrap_err();
        assert!(matches!(err, CorpusError::VersionMismatch { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_unknown_network() {
        let manifest = sample_manifest();
        // Inject a bad network name through the wire path by hand-editing JSON.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        manifest.save(&path).unwrap();

        let text = fs::read_to_string(&path)
            .unwrap()
            .replace("mainnet", "unknown");
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
        let mut wire = CorpusManifestV2::from(&sample_manifest());
        wire.range.start_height = 1;
        let err = CorpusManifest::try_from(wire).unwrap_err();
        assert!(matches!(err, CorpusError::NonZeroStart { .. }));
    }

    #[test]
    fn rejects_empty_entries() {
        let err = CorpusManifest::new(
            Network::Regtest,
            sample_archive(),
            Vec::new(),
            sample_custody(),
        )
        .unwrap_err();
        assert!(matches!(err, CorpusError::EmptyEntries));
    }

    #[test]
    fn rejects_gapped_heights() {
        let mut entries = sample_entries();
        entries[1].height = 2;
        let err = CorpusManifest::new(
            Network::Regtest,
            sample_archive(),
            entries,
            sample_custody(),
        )
        .unwrap_err();
        assert!(matches!(err, CorpusError::HeightMismatch { .. }));
    }

    #[test]
    fn rejects_duplicate_heights() {
        let mut entries = sample_entries();
        entries[1].height = 0;
        let err = CorpusManifest::new(
            Network::Regtest,
            sample_archive(),
            entries,
            sample_custody(),
        )
        .unwrap_err();
        assert!(matches!(err, CorpusError::HeightMismatch { .. }));
    }

    #[test]
    fn rejects_nonzero_first_offset() {
        let mut entries = sample_entries();
        entries[0].offset = 1;
        let err = CorpusManifest::new(
            Network::Regtest,
            sample_archive(),
            entries,
            sample_custody(),
        )
        .unwrap_err();
        assert!(matches!(err, CorpusError::OffsetMismatch { .. }));
    }

    #[test]
    fn rejects_inconsistent_offset() {
        let mut entries = sample_entries();
        entries[1].offset = 11;
        let err = CorpusManifest::new(
            Network::Regtest,
            sample_archive(),
            entries,
            sample_custody(),
        )
        .unwrap_err();
        assert!(matches!(err, CorpusError::OffsetMismatch { .. }));
    }

    #[test]
    fn rejects_oversized_payload() {
        let mut entries = sample_entries();
        entries[0].payload_length = MAX_PAYLOAD_BYTES + 1;
        let err = CorpusManifest::new(
            Network::Regtest,
            sample_archive(),
            entries,
            sample_custody(),
        )
        .unwrap_err();
        assert!(matches!(err, CorpusError::OversizedPayload { .. }));
    }

    #[test]
    fn rejects_archive_size_mismatch() {
        let entries = sample_entries();
        let archive = ArchiveInfo::new(13, [1; 32]);
        let err =
            CorpusManifest::new(Network::Regtest, archive, entries, sample_custody()).unwrap_err();
        assert!(matches!(err, CorpusError::ArchiveSizeMismatch { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_invalid_magic_length() {
        let manifest = sample_manifest();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        manifest.save(&path).unwrap();

        let text = fs::read_to_string(&path).unwrap().replace(
            "\"network_magic\":\"f9beb4d9\"",
            "\"network_magic\":\"f9beb4\"",
        );
        fs::write(&path, text).unwrap();

        let err = CorpusManifest::load(&path).unwrap_err();
        assert!(matches!(err, CorpusError::InvalidMagicLength { .. }));
    }

    #[test]
    fn rejects_invalid_hex() {
        let mut wire = CorpusManifestV2::from(&sample_manifest());
        wire.entries[0].hash = "g".repeat(HASH_HEX_LEN);
        let err = CorpusManifest::try_from(wire).unwrap_err();
        assert!(matches!(err, CorpusError::InvalidHex { .. }));
    }

    #[test]
    fn rejects_invalid_hash_length() {
        let mut wire = CorpusManifestV2::from(&sample_manifest());
        wire.archive.sha256.pop();
        let err = CorpusManifest::try_from(wire).unwrap_err();
        assert!(matches!(err, CorpusError::InvalidHashLength { .. }));
    }

    #[test]
    fn rejects_out_of_range_version_integer() {
        let json = minimal_v2_json(SCHEMA, "4294967296");
        assert!(serde_json::from_str::<CorpusManifestV2>(&json).is_err());
    }

    #[test]
    fn rejects_out_of_range_payload_length_integer() {
        let json = minimal_v2_json(SCHEMA, VERSION)
            .replace("\"payload_length\":80", "\"payload_length\":4294967296");
        assert!(serde_json::from_str::<CorpusManifestV2>(&json).is_err());
    }

    #[test]
    fn single_entry_archive_size_is_frame_length() {
        let entries = vec![CorpusEntry {
            height: 0,
            hash: Hash256::from_le_bytes(&[0; 32]),
            offset: 0,
            payload_length: 80,
        }];
        let archive = ArchiveInfo::new(88, [1; 32]);
        let manifest =
            CorpusManifest::new(Network::Regtest, archive, entries, sample_custody()).unwrap();
        assert_eq!(manifest.stop_height, 0);
        assert_eq!(manifest.archive.size, 88);
    }

    #[test]
    fn boundary_max_u32_stop_height_roundtrips() {
        // One entry at height u32::MAX is not practical to allocate, so just
        // validate the wire form for the boundary value.
        let json = format!(
            r#"{{"schema":"{SCHEMA}","version":{VERSION},"corpus_id":"C150","core_version":"31.1.0","exporter":{{"schema":"{EXPORTER_SCHEMA}","version":{EXPORTER_VERSION}}},"checksig_census":{{"schema":"{CHECKSIG_CENSUS_SCHEMA}","version":{CHECKSIG_CENSUS_VERSION}}},"reopen_proofs":[],"manifest_sha256":"0000000000000000000000000000000000000000000000000000000000000000","source_tip_hash":"0000000000000000000000000000000000000000000000000000000000000000","network":"regtest","network_magic":"fabfb5da","genesis_hash":"0000000000000000000000000000000000000000000000000000000000000000","range":{{"start_height":0,"stop_height":{}}},"archive":{{"size":8,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}},"entries":[{{"height":{},"hash":"0000000000000000000000000000000000000000000000000000000000000000","offset":0,"payload_length":0}}]}}"#,
            u32::MAX,
            u32::MAX
        );
        assert!(serde_json::from_str::<CorpusManifestV2>(&json).is_ok());
    }

    fn block_hash256(block: &Block) -> Hash256 {
        block.block_hash().0
    }

    fn make_test_chain(stop: u32) -> (BlockTree, Vec<Block>) {
        let mut tree = BlockTree::new();
        let mut blocks = Vec::new();
        let mut prev_hash = BlockHash::default();
        for height in 0..=stop {
            let header = Header {
                version: 1,
                prev_blockhash: prev_hash,
                merkle_root: Hash256::default(),
                time: 1_000_000 + height * 600,
                bits: 0x207f_ffff,
                nonce: 0,
            };
            let next_hash = header.compute_hash();
            tree.insert_header(header, NodeStatus::HeaderValid)
                .expect("test chain inserts must succeed");
            let block = Block {
                header,
                txs: Vec::new(),
            };
            blocks.push(block);
            prev_hash = next_hash;
        }
        (tree, blocks)
    }

    struct MockBodySource {
        bodies: HashMap<(u32, BlockHash), Vec<u8>>,
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
                let hash = block.block_hash();
                let height = u32::try_from(height).expect("test chain height fits u32");
                bodies.insert((height, hash), consensus_bytes(block));
            }
            Self { bodies }
        }
    }

    impl BlockBodySource for MockBodySource {
        fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
            self.bodies.get(&(height, hash)).cloned()
        }
    }

    fn sha256_of(bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher.finalize().into()
    }

    #[cfg(unix)]
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
            sample_custody(),
            &archive_path,
            &manifest_path,
        )?;

        assert_eq!(manifest.network, Network::Regtest);
        assert_eq!(manifest.corpus_id, "CFIXTURE");
        assert_eq!(manifest.stop_height, 2);
        assert_eq!(manifest.entries.len(), 3);
        assert_eq!(manifest.core_version, "31.1.0");
        assert_eq!(manifest.reopen_proofs.len(), 3);
        assert_ne!(manifest.manifest_sha256, [0; 32]);
        assert_eq!(manifest.source_tip_hash, manifest.entries[2].hash);

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
            u32::try_from(consensus_bytes(&blocks[0]).len()).expect("payload length fits u32")
        );

        let mut reader = CoreFrameReader::new(
            Cursor::new(archive_bytes.as_slice()),
            Network::Regtest.magic(),
            MAX_PAYLOAD_BYTES,
        );
        for (i, block) in blocks.iter().enumerate() {
            let record = reader
                .next_record()?
                .ok_or_else(|| std::io::Error::other("expected a frame"))?;
            let expected = consensus_bytes(block);
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
        assert!(reader.next_record()?.is_none());

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
            sample_custody(),
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

    #[cfg(unix)]
    #[test]
    fn rejects_missing_body_before_manifest() -> Result<(), CorpusError> {
        let (tree, blocks) = make_test_chain(1);
        let hash0 = blocks[0].block_hash();
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
            sample_custody(),
            &archive_path,
            &manifest_path,
        )
        .unwrap_err();

        assert!(matches!(err, CorpusError::MissingBody { height: 0, .. }));
        assert!(!manifest_path.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_body_hash_mismatch_before_manifest() -> Result<(), CorpusError> {
        let (tree, blocks) = make_test_chain(1);
        let hash1 = blocks[1].block_hash();
        let mut source = MockBodySource::from_blocks(&blocks);
        // Replace the body at height 1 with the serialized block from height 0;
        // it decodes cleanly but its hash does not match the active chain.
        source
            .bodies
            .insert((1, hash1), consensus_bytes(&blocks[0]));

        let dir = tempfile::tempdir()?;
        let archive_path = dir.path().join("archive.dat");
        let manifest_path = dir.path().join("manifest.json");

        let err = export_from_sources(
            &tree,
            &source,
            Network::Regtest,
            1,
            sample_custody(),
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
            sample_custody(),
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
            sample_custody(),
            &archive_path,
            &manifest_path,
        )
        .unwrap_err();

        assert!(matches!(err, CorpusError::OutputExists { .. }));
        assert_eq!(fs::read(&archive_path)?, b"do not overwrite");
        assert!(!manifest_path.exists());
        Ok(())
    }

    #[cfg(unix)]
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
            sample_custody(),
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
        let (archive_dest, manifest_dest) =
            prepare_corpus_destinations(&archive_path, &manifest_path)?;
        let via_writer = write_corpus_archive(
            &mut source,
            Network::Regtest,
            2,
            sample_custody(),
            &archive_dest,
            &manifest_dest,
        )?;
        let writer_archive = fs::read(&archive_path)?;
        let writer_manifest = fs::read(&manifest_path)?;

        assert_eq!(direct, via_writer);
        assert_eq!(direct_archive, writer_archive);
        assert_eq!(direct_manifest, writer_manifest);
        Ok(())
    }

    fn make_rest_blocks(stop: u32) -> (Vec<Block>, Vec<(String, Vec<u8>)>) {
        let genesis = Network::Regtest.genesis_block();
        let mut blocks = vec![genesis.clone()];
        let mut records = vec![(genesis.block_hash().to_string(), consensus_bytes(&genesis))];
        let mut prev_hash = genesis.block_hash();
        for height in 1..=stop {
            let header = Header {
                version: 1,
                prev_blockhash: prev_hash,
                merkle_root: Hash256::default(),
                time: 1_000_000 + height * 600,
                bits: 0x207f_ffff,
                nonce: 0,
            };
            let next_hash = header.compute_hash();
            let block = Block {
                header,
                txs: Vec::new(),
            };
            records.push((next_hash.to_string(), consensus_bytes(&block)));
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

    #[cfg(unix)]
    #[test]
    fn rest_corpus_source_matches_blocktree_output() -> Result<(), CorpusError> {
        let (blocks, records) = make_rest_blocks(2);
        let tree = make_regtest_tree(&blocks);
        let body_source = MockBodySource::from_blocks(&blocks);
        let dir = tempfile::tempdir()?;
        let archive_path = dir.path().join("archive.dat");
        let manifest_path = dir.path().join("manifest.json");

        let mut rest = make_rest_source(records, Network::Regtest);
        let (archive_dest, manifest_dest) =
            prepare_corpus_destinations(&archive_path, &manifest_path)?;
        let rest_manifest = write_corpus_archive(
            &mut rest,
            Network::Regtest,
            2,
            sample_custody(),
            &archive_dest,
            &manifest_dest,
        )?;
        let rest_archive = fs::read(&archive_path)?;

        fs::remove_file(&archive_path)?;
        fs::remove_file(&manifest_path)?;

        let direct = export_from_sources(
            &tree,
            &body_source,
            Network::Regtest,
            2,
            sample_custody(),
            &archive_path,
            &manifest_path,
        )?;
        let direct_archive = fs::read(&archive_path)?;

        assert_eq!(rest_manifest, direct);
        assert_eq!(rest_archive, direct_archive);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rest_corpus_rejects_genesis_mismatch() -> Result<(), CorpusError> {
        let (_, records) = make_rest_blocks(0);
        // Use mainnet expectation; the real regtest genesis will not match.
        let mut source = make_rest_source(records, Network::Mainnet);
        let dir = tempfile::tempdir()?;
        let archive = dir.path().join("archive.dat");
        let manifest = dir.path().join("manifest.json");

        let (archive_dest, manifest_dest) = prepare_corpus_destinations(&archive, &manifest)?;
        let err = write_corpus_archive(
            &mut source,
            Network::Mainnet,
            0,
            sample_custody(),
            &archive_dest,
            &manifest_dest,
        )
        .unwrap_err();

        assert!(matches!(err, CorpusError::RestGenesisMismatch { .. }));
        assert!(!archive.exists());
        assert!(!manifest.exists());
        assert!(no_tmp_files(&dir));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rest_corpus_rejects_continuity_break() -> Result<(), CorpusError> {
        let (_, mut records) = make_rest_blocks(2);
        // Make height 2 claim a bogus parent while keeping a valid header hash.
        let mut tampered = deserialize::<Block>(&records[2].1).unwrap();
        tampered.header.prev_blockhash = BlockHash(Hash256::from_le_bytes(&[0xff; 32]));
        tampered.header.nonce += 1; // re-mine to a new hash
        let new_hash = tampered.block_hash().to_string();
        records[2] = (new_hash, consensus_bytes(&tampered));

        let mut source = make_rest_source(records, Network::Regtest);
        let dir = tempfile::tempdir()?;
        let archive = dir.path().join("archive.dat");
        let manifest = dir.path().join("manifest.json");
        let (archive_dest, manifest_dest) = prepare_corpus_destinations(&archive, &manifest)?;
        let err = write_corpus_archive(
            &mut source,
            Network::Regtest,
            2,
            sample_custody(),
            &archive_dest,
            &manifest_dest,
        )
        .unwrap_err();

        assert!(matches!(err, CorpusError::RestContinuity { height: 2, .. }));
        assert!(!archive.exists());
        assert!(!manifest.exists());
        assert!(no_tmp_files(&dir));
        Ok(())
    }

    #[cfg(unix)]
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
        let (archive_dest, manifest_dest) = prepare_corpus_destinations(&archive, &manifest)?;
        let err = write_corpus_archive(
            &mut source,
            Network::Regtest,
            1,
            sample_custody(),
            &archive_dest,
            &manifest_dest,
        )
        .unwrap_err();

        assert!(matches!(err, CorpusError::RestHashMismatch { .. }));
        assert!(!archive.exists());
        assert!(!manifest.exists());
        assert!(no_tmp_files(&dir));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rest_corpus_rejects_short_payload() -> Result<(), CorpusError> {
        let (_, mut records) = make_rest_blocks(0);
        records[0].1 = vec![0; 79];
        let mut source = make_rest_source(records, Network::Regtest);
        let dir = tempfile::tempdir()?;
        let archive = dir.path().join("archive.dat");
        let manifest = dir.path().join("manifest.json");
        let (archive_dest, manifest_dest) = prepare_corpus_destinations(&archive, &manifest)?;
        let err = write_corpus_archive(
            &mut source,
            Network::Regtest,
            0,
            sample_custody(),
            &archive_dest,
            &manifest_dest,
        )
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

    // ── Issue #42 custody-mechanics regressions ─────────────────────────

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn validation_doc(stop_height: u32, stop_hash: &str) -> String {
        format!(
            "{{\"schema\": \"{VALIDATION_SCHEMA}\", \"stop_height\": \
             {stop_height}, \"stop_hash\": \"{stop_hash}\", \
             \"utxo_hash_serialized_3\": \"{}\", \"muhash\": \"{}\", \
             \"utxo_count\": 2, \"total_amount\": 200}}\n",
            "cd".repeat(32),
            "ab".repeat(32),
        )
    }

    fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> fs::File {
        let path = dir.join(name);
        fs::write(&path, bytes).unwrap();
        fs::File::open(&path).unwrap()
    }

    #[test]
    fn bounded_read_rejects_growth_and_metadata_drift() {
        let dir = temp_dir();

        // Growth: a byte appended after the descriptor was sized makes the
        // one-byte probe fail closed.
        let grown = dir.path().join("grown.json");
        fs::write(&grown, b"{\"a\": 1}").unwrap();
        let mut grown_file = fs::File::open(&grown).unwrap();
        {
            use std::io::Write as _;
            let mut handle = fs::OpenOptions::new().append(true).open(&grown).unwrap();
            handle.write_all(b"\n").unwrap();
        }
        // The descriptor saw eight bytes when it was sized; the appended
        // ninth byte must trip the one-byte growth probe.
        let grown_facts = file_facts(&grown_file).unwrap();
        let error = read_declared_bounded(&mut grown_file, grown_facts, 8, 64, "grown", &grown)
            .unwrap_err();
        assert!(error.to_string().contains("grew past"));

        // Metadata drift: an mtime bump between fstat and the post-read
        // comparison fails closed even when the bytes match exactly.
        let path = dir.path().join("doc.json");
        fs::write(&path, b"{\"a\": 1}").unwrap();
        let mut file = fs::File::open(&path).unwrap();
        let before = file_facts(&file).unwrap();
        let bytes =
            read_declared_bounded(&mut file, before, before.identity.size, 64, "doc", &path)
                .unwrap();
        assert_eq!(bytes, b"{\"a\": 1}");
        file.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(2))
            .unwrap();
        // A fresh descriptor starts at offset zero; the captured identity
        // predates the touch, so the post-read comparison must fail closed
        // against it.
        let mut file = fs::File::open(&path).unwrap();
        let error =
            read_declared_bounded(&mut file, before, before.identity.size, 64, "doc", &path)
                .unwrap_err();
        assert!(
            error.to_string().contains("changed identity or metadata"),
            "actual error: {error}"
        );

        // An empty external document is rejected before any parse.
        let empty = dir.path().join("empty.json");
        fs::write(&empty, b"").unwrap();
        let mut empty_file = fs::File::open(&empty).unwrap();
        let error = read_exact_bounded(&mut empty_file, 64, "empty", &empty).unwrap_err();
        assert!(error.to_string().contains("is empty"));
    }

    #[test]
    fn duplicate_keys_rejected_in_external_documents() {
        let error = reject_duplicate_keys(br#"{"a": 1, "a": 2}"#, "doc").unwrap_err();
        let rendered = error.to_string();
        // The detail is bounded and escaped, so the rejection names the
        // duplicate without echoing the document.
        assert!(rendered.contains("duplicate"), "actual: {rendered:?}");
        assert!(rendered.contains("detail:"), "actual: {rendered:?}");
        let nested = br#"{"outer": {"b": 1, "b": 2}}"#;
        assert!(reject_duplicate_keys(nested, "doc").is_err());
        let in_list = br#"{"list": [{"c": 1, "c": 0}]}"#;
        assert!(reject_duplicate_keys(in_list, "doc").is_err());
    }

    #[test]
    fn validation_artifact_missing_schema_and_tip_are_rejected() {
        let dir = temp_dir();
        // Missing file.
        let error =
            load_validation_artifact("CFIXTURE", &dir.path().join("nope.json")).unwrap_err();
        assert!(matches!(error, CorpusError::Io(error) if error.kind() == ErrorKind::NotFound));
        // Wrong schema.
        let path = dir.path().join("wrong-schema.json");
        fs::write(
            &path,
            validation_doc(1, &"a".repeat(64))
                .replace("mainnet-prefix-replay-validation-v1", "other-v9"),
        )
        .unwrap();
        assert!(load_validation_artifact("CFIXTURE", &path).is_err());
        // Zero hash field.
        let path = dir.path().join("zero-hash.json");
        fs::write(
            &path,
            validation_doc(1, &"a".repeat(64)).replace(&"ab".repeat(32), &"0".repeat(64)),
        )
        .unwrap();
        assert!(load_validation_artifact("CFIXTURE", &path).is_err());
        // Production identity pins the frozen tip; a fixture tip mismatches.
        let path = dir.path().join("tip.json");
        fs::write(&path, validation_doc(1, &"a".repeat(64))).unwrap();
        let error = load_validation_artifact("C150", &path).unwrap_err();
        assert!(error.to_string().contains("custody identity"));
    }

    fn proof_doc(validation: &ValidationArtifact, muhash: &str) -> String {
        let invariants = format!(
            "{{\"tip_height\": {h}, \"tip_hash\": \"{t}\", \"utxo_count\": 2, \
             \"total_amount\": 200, \"muhash\": \"{m}\", \
             \"utxo_hash_serialized_3\": \"{}\", \"tx_count\": 0, \
             \"bogo_size\": 0}}",
            "cd".repeat(32),
            h = validation.stop_height,
            t = validation.stop_hash,
            m = muhash,
        );
        format!(
            "{{\"schema\": \"{REOPEN_PROOF_SCHEMA}\", \"version\": 1, \
             \"network\": \"mainnet\", \"backend\": \"fjall\", \
             \"validation\": {{\"size_bytes\": {s}, \"sha256\": \"{d}\"}}, \
             \"before\": {inv}, \"after\": {inv}, \
             \"checkpoint_generation\": 1, \"durable_body_roundtrip\": true, \
             \"durable_undo_roundtrip\": true, \"mutated_copy_only\": true, \
             \"reopen_count\": 2}}\n",
            s = validation.size,
            d = validation.sha256_hex,
            inv = invariants,
        )
    }

    #[test]
    fn reopen_proof_binds_shared_validation_by_bytes_and_state() {
        let dir = temp_dir();
        let validation_path = dir.path().join("validation.json");
        fs::write(&validation_path, validation_doc(1, &"aa".repeat(32))).unwrap();
        let validation = load_validation_artifact("CFIXTURE", &validation_path).unwrap();

        // A proof bound to the loaded artifact's exact bytes and state loads.
        let proof_path = dir.path().join("fjall-reopen-proof.json");
        fs::write(&proof_path, proof_doc(&validation, &"ab".repeat(32))).unwrap();
        let custody = load_reopen_proof("CFIXTURE", "fjall", &proof_path, &validation).unwrap();
        assert_eq!(custody.backend(), "fjall");
        assert_eq!(custody.sha256().len(), 32);

        // Drifting the bound digest fails the exact-bytes half.
        let drift = dir.path().join("hash-drift.json");
        fs::write(
            &drift,
            proof_doc(&validation, &"ab".repeat(32))
                .replace(&validation.sha256_hex, &"22".repeat(32)),
        )
        .unwrap();
        let error = load_reopen_proof("CFIXTURE", "fjall", &drift, &validation).unwrap_err();
        assert!(error.to_string().contains("binds validation digest"));

        // Drifting the committed state fails the state half.
        let drift = dir.path().join("state-drift.json");
        fs::write(&drift, proof_doc(&validation, &"ff".repeat(32))).unwrap();
        let error = load_reopen_proof("CFIXTURE", "fjall", &drift, &validation).unwrap_err();
        assert!(error.to_string().contains("state commitment"));
    }

    #[cfg(unix)]
    #[test]
    fn publish_artifact_is_no_replace_and_committed_files_survive() {
        let dir = temp_dir();
        let first = dir.path().join("archive.json");
        let second = dir.path().join("manifest.json");
        publish_artifact(&first, b"first\n").unwrap();
        publish_artifact(&second, b"second\n").unwrap();
        // The committed pair survives.
        assert_eq!(fs::read(&first).unwrap(), b"first\n");
        assert_eq!(fs::read(&second).unwrap(), b"second\n");
        // No-replace: republishing an existing name fails without clobber.
        let error = publish_artifact(&first, b"again\n").unwrap_err();
        assert!(matches!(error, CorpusError::OutputExists { .. }));
        assert_eq!(fs::read(&first).unwrap(), b"first\n");
        // No scratch names are left behind.
        let residue: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp."))
            .collect();
        assert!(residue.is_empty(), "residue: {residue:?}");
    }

    /// Captures `corpus` warnings through a real `tracing` fmt subscriber
    /// writing into memory, so tests observe the actual diagnostic sink
    /// rather than a test-only mirror of it.
    fn capture_corpus_warnings(emit: impl FnOnce()) -> String {
        use parking_lot::Mutex;
        use std::sync::Arc;

        struct SharedWriter(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for SharedWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer({
                let buffer = buffer.clone();
                move || SharedWriter(buffer.clone())
            })
            .finish();
        tracing::subscriber::with_default(subscriber, emit);
        let warnings = buffer.lock().clone();
        String::from_utf8(warnings).expect("utf-8 warnings")
    }

    #[test]
    fn armed_guard_warns_bounded_orphan_paths_without_unlinking() {
        let dir = temp_dir();
        let target = dir.path().join("owned.json");
        let written = write_file(dir.path(), "owned.json", b"written");
        let mut guard = PublicationGuard::new();
        guard.record(PublishedEntry {
            target: target.clone(),
            file: written.try_clone().unwrap(),
        });
        drop(written);
        let rendered = capture_corpus_warnings(|| drop(guard));
        // The real warn sink names the orphan (verbatim when the path is
        // safe, bounded otherwise), and the orphan policy never unlinks the
        // published entry.
        assert!(
            rendered.contains("failed corpus publication left an orphan output"),
            "actual: {rendered}"
        );
        assert!(rendered.contains("dev="), "dev: {rendered}");
        assert!(rendered.contains("ino="), "ino: {rendered}");
        assert_eq!(fs::read(&target).unwrap(), b"written");
    }

    #[cfg(unix)]
    #[test]
    fn armed_guard_escapes_hostile_orphan_names() {
        let dir = temp_dir();
        let hostile = format!("a\n\u{1b}[31m\u{202e}{}", "x".repeat(180));
        let written = write_file(dir.path(), &hostile, b"orphan");
        let mut guard = PublicationGuard::new();
        guard.record(PublishedEntry {
            target: dir.path().join(&hostile),
            file: written.try_clone().unwrap(),
        });
        drop(written);
        let rendered = capture_corpus_warnings(|| drop(guard));
        assert_eq!(rendered.lines().count(), 1, "multiline: {rendered:?}");
        assert!(rendered.contains("sha256="), "no fingerprint: {rendered}");
        assert!(!rendered.contains('\u{1b}'), "raw escape: {rendered:?}");
        assert!(!rendered.contains('\u{202e}'), "raw bidi: {rendered:?}");
        assert!(!rendered.contains(&"x".repeat(40)), "raw run: {rendered:?}");
    }

    #[test]
    fn bounded_diagnostic_path_preserves_safe_paths() {
        assert_eq!(
            bounded_diagnostic_path(Path::new("/tmp/archive.dat")),
            "/tmp/archive.dat"
        );
        assert_eq!(bounded_diagnostic_path(Path::new("a b c.dat")), "a b c.dat");
        // Over the preview bound, even printable ASCII is bounded.
        let long = format!("/tmp/{}", "a".repeat(60));
        let rendered = bounded_diagnostic_path(Path::new(&long));
        assert!(rendered.starts_with("path:"), "{rendered}");
        assert!(rendered.contains("sha256="), "{rendered}");
        // A control character forces the bounded form.
        let rendered = bounded_diagnostic_path(Path::new("a\nb"));
        assert!(rendered.starts_with("path:"), "{rendered}");
        assert!(rendered.contains("\\u{000a}"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn bounded_diagnostic_path_bounds_non_utf8_paths() {
        use std::os::unix::ffi::OsStrExt as _;

        let rendered =
            bounded_diagnostic_path(Path::new(std::ffi::OsStr::from_bytes(b"/tmp/x\xff.bin")));
        assert!(rendered.starts_with("path:"), "{rendered}");
        assert!(!rendered.contains('\u{FFFD}'), "{rendered}");
    }

    #[test]
    fn orphan_warning_emits_metadata_error_when_facts_fail() {
        let hostile = "/tmp/own\n\u{1b}[31med.json".to_owned();
        let rendered = capture_corpus_warnings(|| {
            warn_orphaned_entry(
                Path::new(&hostile),
                Err(CorpusError::Io(std::io::Error::from_raw_os_error(9))),
            );
        });
        // The warning is emitted unconditionally: the failed stat becomes a
        // bounded metadata_error next to the bounded path.
        assert!(
            rendered.contains("failed corpus publication left an orphan output"),
            "actual: {rendered}"
        );
        assert!(rendered.contains("metadata_error"), "actual: {rendered}");
        assert!(rendered.contains("path:"), "bounded: {rendered}");
        assert_eq!(rendered.lines().count(), 1, "multiline: {rendered:?}");
        assert!(!rendered.contains('\u{1b}'), "raw escape: {rendered:?}");
    }

    #[cfg(unix)]
    #[test]
    fn publication_guard_leaves_armed_entries_as_reported_orphans() {
        let dir = temp_dir();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        publish_artifact(&first, b"one\n").unwrap();
        publish_artifact(&second, b"two\n").unwrap();

        // An armed drop must NOT delete published entries: they stay as
        // named orphans for operator cleanup.
        let file = fs::File::open(&first).unwrap();
        let mut guard = PublicationGuard::new();
        guard.record(PublishedEntry {
            target: first.clone(),
            file: file.try_clone().unwrap(),
        });
        drop(file);
        drop(guard);
        assert!(first.exists());
        assert_eq!(fs::read(&first).unwrap(), b"one\n");

        // A committed guard leaves its entries in place.
        let file = fs::File::open(&second).unwrap();
        let mut guard = PublicationGuard::new();
        guard.record(PublishedEntry {
            target: second.clone(),
            file: file.try_clone().unwrap(),
        });
        drop(file);
        guard.commit();
        assert!(second.exists());
        assert_eq!(fs::read(&second).unwrap(), b"two\n");
    }

    #[test]
    fn core_rest_client_reconnects_once() {
        let response = http_response("200 OK", b"body");
        let (addr, _handle) = serve_http_with_close_then_response(response);

        let mut client = CoreRestClient::connect(&addr).unwrap();
        let body = client.get("/a").unwrap();
        assert_eq!(body, b"body");
    }

    #[test]
    fn custody_read_is_bound_to_the_held_descriptor() {
        let dir = temp_dir();
        let path = dir.path().join("doc.json");
        fs::write(&path, b"{\"a\": 1}").unwrap();

        let mut held = open_custody_input(&path, "doc").unwrap();
        let held_facts = file_facts(&held).unwrap();

        // Substitute the pathname with a different inode carrying different
        // bytes while the descriptor is held.
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"{\"a\": 2, \"b\": 3}").unwrap();

        // The held descriptor still yields the bytes it was opened on, and
        // two reads of one descriptor agree on identity.
        let bytes = read_exact_bounded(&mut held, 64, "doc", &path).unwrap();
        assert_eq!(bytes, b"{\"a\": 1}");
        // Only device and inode are stable under a retained descriptor:
        // unlinking the pathname bumps the inode's ctime, so comparing whole
        // identities here would assert a false invariant. The production
        // check inside `read_exact_bounded` brackets one read, where every
        // field including ctime must hold still.
        let after = file_facts(&held).unwrap().identity;
        assert_eq!(
            (after.dev, after.ino),
            (held_facts.identity.dev, held_facts.identity.ino)
        );

        // The pathname now resolves to a different inode entirely, so the
        // bytes read above cannot have come from it.
        let replaced = open_custody_input(&path, "doc").unwrap();
        assert_ne!(
            file_facts(&replaced).unwrap().identity.ino,
            held_facts.identity.ino
        );
    }

    #[cfg(unix)]
    #[test]
    fn custody_open_rejects_symlinks_and_nonregular_inputs() {
        let dir = temp_dir();
        let target = dir.path().join("real.json");
        fs::write(&target, b"{}").unwrap();

        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink("real.json", &link).unwrap();
        let error = read_custody_document(&link, 64, "doc").unwrap_err();
        assert!(
            error.to_string().contains("is a symbolic link"),
            "actual error: {error}"
        );

        // The capability can open a directory without following a final
        // symlink; the held-file type guard rejects it before allocation.
        let error = read_custody_document(dir.path(), 64, "doc").unwrap_err();
        assert!(
            error.to_string().contains("is not a regular file"),
            "actual error: {error}"
        );
    }

    #[test]
    fn bounded_ceiling_applies_before_allocation() {
        let dir = temp_dir();
        let path = dir.path().join("sparse.json");
        let file = fs::File::create(&path).unwrap();
        // Eight sparse gigabytes: rejected from the statted length, so no
        // buffer is ever sized to it. An allocate-then-read loader would not
        // return promptly here.
        file.set_len(8 * 1024 * 1024 * 1024).unwrap();
        drop(file);
        let error = read_custody_document(&path, VALIDATION_MAX_BYTES, "doc").unwrap_err();
        assert!(
            error.to_string().contains("the bounded ceiling is 65536"),
            "actual error: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn publication_retains_and_syncs_before_linking_and_directory_after() {
        let dir = temp_dir();
        durability_log_reset();
        publish_artifact(dir.path().join("artifact.json"), b"payload\n").unwrap();
        assert_eq!(
            durability_log_take(),
            vec![
                DurabilityStep::DataSync,
                DurabilityStep::RetainDescriptor,
                DurabilityStep::Link,
                DurabilityStep::DirSync,
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn retained_descriptor_failure_precedes_the_link_and_names_nothing() {
        let dir = temp_dir();
        let target = dir.path().join("artifact.json");
        durability_log_reset();
        durability_fault_arm(DurabilityStep::RetainDescriptor);

        let error = publish_artifact(&target, b"payload\n").unwrap_err();
        assert!(matches!(error, CorpusError::Io(_)), "error: {error}");
        // The run stopped after the data fsync: the link never ran, so no
        // destination name was ever visible to go unrecorded.
        assert_eq!(durability_log_take(), vec![DurabilityStep::DataSync]);
        assert!(fs::symlink_metadata(&target).is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);

        // The one-shot fault disarmed itself, so the same path still works.
        durability_log_reset();
        publish_artifact(&target, b"payload\n").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"payload\n");
    }

    #[cfg(unix)]
    #[test]
    fn directory_sync_failure_leaves_a_reported_orphan() {
        let dir = temp_dir();
        let target = dir.path().join("orphan.json");
        durability_log_reset();
        durability_fault_arm(DurabilityStep::DirSync);

        let warnings = capture_corpus_warnings(|| {
            let error = publish_artifact(&target, b"payload\n").unwrap_err();
            assert!(matches!(error, CorpusError::Io(_)), "error: {error}");
        });
        assert_eq!(
            durability_log_take(),
            vec![
                DurabilityStep::DataSync,
                DurabilityStep::RetainDescriptor,
                DurabilityStep::Link,
            ]
        );
        assert_eq!(fs::read(&target).unwrap(), b"payload\n");
        assert!(warnings.contains("orphan output"), "warnings: {warnings}");

        let recovered = dir.path().join("recovered.json");
        publish_artifact(&recovered, b"recovered\n").unwrap();
        assert_eq!(fs::read(recovered).unwrap(), b"recovered\n");
    }

    #[cfg(unix)]
    #[test]
    fn publish_kernel_guard_rejects_existing_name_without_replacement() {
        let dir = temp_dir();
        let target = dir.path().join("raced.json");
        // The name is occupied before the scratch inode is linked, so the
        // only guard left is the kernel's EEXIST at the no-replace link.
        write_file(dir.path(), "raced.json", b"original");
        let dest = PinnedDestination::pin(&target).unwrap();
        let mut temp = OutputTemp::create(&dest).unwrap();
        temp.file.write_all(b"intruder").unwrap();
        temp.sync_data().unwrap();
        let digest: [u8; 32] = Sha256::digest(b"intruder").into();
        let mut guard = PublicationGuard::new();
        let mut buffer = VerifyBuffer::new();
        let error = temp.publish(&digest, &mut guard, &mut buffer).unwrap_err();
        assert!(
            matches!(error, CorpusError::OutputExists { .. }),
            "actual error: {error}"
        );
        // The occupant is untouched: nothing was replaced or truncated.
        assert_eq!(fs::read(&target).unwrap(), b"original");
    }

    #[cfg(unix)]
    #[test]
    fn pinned_parent_substitution_cannot_redirect_or_split_publication() {
        let root = temp_dir();
        let pinned = root.path().join("pinned");
        let decoy = root.path().join("decoy");
        fs::create_dir(&pinned).unwrap();
        fs::create_dir(&decoy).unwrap();
        let live = root.path().join("live");
        std::os::unix::fs::symlink(&pinned, &live).unwrap();

        // Both parents are pinned up front, exactly as an export pins them
        // before streaming a multi-gigabyte archive.
        let (archive, manifest) =
            prepare_corpus_destinations(&live.join("archive.dat"), &live.join("manifest.json"))
                .unwrap();

        // The parent path is redirected at another directory afterwards.
        fs::remove_file(&live).unwrap();
        std::os::unix::fs::symlink(&decoy, &live).unwrap();

        for (dest, bytes) in [
            (&archive, b"archive\n".as_slice()),
            (&manifest, b"manifest\n".as_slice()),
        ] {
            let mut temp = OutputTemp::create(dest).unwrap();
            temp.file.write_all(bytes).unwrap();
            temp.sync_data().unwrap();
            let digest: [u8; 32] = Sha256::digest(bytes).into();
            let mut guard = PublicationGuard::new();
            let mut buffer = VerifyBuffer::new();
            temp.publish(&digest, &mut guard, &mut buffer).unwrap();
            guard.commit();
        }

        // Every entry landed in the pinned directory, so a substituted
        // parent can neither redirect a publication nor split one pair
        // across two directories.
        assert_eq!(fs::read(pinned.join("archive.dat")).unwrap(), b"archive\n");
        assert_eq!(
            fs::read(pinned.join("manifest.json")).unwrap(),
            b"manifest\n"
        );
        assert!(!decoy.join("archive.dat").exists());
        assert!(!decoy.join("manifest.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn alias_collision_is_detected_by_directory_identity_not_path_spelling() {
        let root = temp_dir();
        let out = root.path().join("out");
        fs::create_dir(&out).unwrap();

        // One directory entry, two spellings: the destinations compare
        // unequal as paths.
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(&out, &alias).unwrap();
        let archive = out.join("same.dat");
        let manifest = alias.join("same.dat");
        assert_ne!(archive, manifest);
        let error = match prepare_corpus_destinations(&archive, &manifest) {
            Ok(_) => panic!("expected PathCollision for alias destinations"),
            Err(error) => error,
        };
        assert!(
            matches!(error, CorpusError::PathCollision { .. }),
            "actual error: {error}"
        );
        assert!(!archive.exists());

        // A parent renamed between the two pins leaves the destinations with
        // unequal canonical paths while they still name one entry in one
        // directory. Only the pinned device and inode see it.
        let first = PinnedDestination::pin(&out.join("same.dat")).unwrap();
        let renamed = root.path().join("moved");
        fs::rename(&out, &renamed).unwrap();
        let second = PinnedDestination::pin(&renamed.join("same.dat")).unwrap();
        assert_ne!(first.display(), second.display());
        assert!(first.collides_with(&second));

        // Distinct names in one directory are not a collision.
        let other = PinnedDestination::pin(&renamed.join("other.dat")).unwrap();
        assert!(!second.collides_with(&other));
    }

    #[cfg(unix)]
    #[test]
    fn hostile_names_and_documents_never_reach_diagnostics_raw() {
        let dir = temp_dir();
        // A hostile output name carrying a newline, an ESC colour sequence, a
        // bidi override, and a long run that must not be echoed whole.
        let hostile = format!("a\n\u{1b}[31m\u{202e}{}", "x".repeat(180));
        let target = dir.path().join(&hostile);
        fs::write(&target, b"occupied").unwrap();

        let dest = PinnedDestination::pin(&target).unwrap();
        let rendered = dest.ensure_absent().unwrap_err().to_string();
        assert!(!rendered.contains('\n'), "raw control: {rendered:?}");
        assert!(!rendered.contains('\u{1b}'), "raw escape: {rendered:?}");
        assert!(!rendered.contains('\u{202e}'), "raw bidi: {rendered:?}");
        assert!(!rendered.contains(&"x".repeat(40)), "raw run: {rendered:?}");
        assert!(rendered.contains("sha256="), "no fingerprint: {rendered:?}");
        assert!(rendered.len() < 512, "unbounded: {}", rendered.len());

        // A rejected external document is bounded the same way: a serde
        // rejection is attacker-shaped text, not a trusted internal string.
        let mut hostile_doc = br#"{"a": 1, "a": ""#.to_vec();
        hostile_doc.resize(hostile_doc.len() + 4096, b'y');
        hostile_doc.extend_from_slice(br#""}"#);
        let rendered = reject_duplicate_keys(&hostile_doc, "doc")
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("duplicate"), "actual: {rendered:?}");
        assert!(!rendered.contains(&"y".repeat(40)), "raw run: {rendered:?}");
        assert!(rendered.len() < 512, "unbounded: {}", rendered.len());

        // A rejected manifest schema name is bounded the same way: the
        // wire schema is attacker-derived, so its rendering escapes
        // controls and carries the length bound.
        let hostile_schema = format!("a\n\u{1b}[31m{}", "s".repeat(300));
        let escaped = serde_json::to_string(&hostile_schema).unwrap();
        let err = CorpusManifest::try_from(
            serde_json::from_str::<CorpusManifestV2>(&minimal_v2_json(
                escaped.trim_matches('"'),
                2,
            ))
            .unwrap(),
        )
        .unwrap_err();
        match err {
            CorpusError::SchemaMismatch { actual, .. } => {
                assert!(!actual.contains('\n'), "raw control: {actual:?}");
                assert!(!actual.contains('\u{1b}'), "raw escape: {actual:?}");
                assert!(actual.contains("sha256="), "no fingerprint: {actual:?}");
                assert!(actual.len() < 200, "unbounded: {}", actual.len());
            }
            other => panic!("expected SchemaMismatch, got {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn shared_parent_pin_reuses_one_descriptor_across_parent_swap() {
        let root = temp_dir();
        let pinned = root.path().join("pinned");
        let decoy = root.path().join("decoy");
        fs::create_dir(&pinned).unwrap();
        fs::create_dir(&decoy).unwrap();
        let live = root.path().join("live");
        std::os::unix::fs::symlink(&pinned, &live).unwrap();

        // Arm the between-pins hook: the instant the archive destination is
        // pinned, the shared parent path is swapped at the decoy — before
        // the manifest destination is pinned. Only reusing the archive's
        // held descriptor can keep the manifest in the pinned directory.
        let swap_live = live.clone();
        let decoy_for_hook = decoy.clone();
        arm_between_pins_hook(move || {
            fs::remove_file(&swap_live).unwrap();
            std::os::unix::fs::symlink(&decoy_for_hook, &swap_live).unwrap();
        });

        let (archive, manifest) =
            prepare_corpus_destinations(&live.join("a.dat"), &live.join("m.json")).unwrap();

        // Both destinations must have been pinned onto the original pinned
        // directory, despite the path now naming the decoy.
        assert!(
            archive.pins_the_same_directory(&manifest),
            "manifest pin did not reuse the archive's held directory"
        );

        // Publishing through either destination lands in the pinned
        // directory; the decoy stays empty.
        for (dest, bytes) in [
            (&archive, b"a\n".as_slice()),
            (&manifest, b"m\n".as_slice()),
        ] {
            let mut temp = OutputTemp::create(dest).unwrap();
            temp.file.write_all(bytes).unwrap();
            temp.sync_data().unwrap();
            let digest: [u8; 32] = Sha256::digest(bytes).into();
            let mut guard = PublicationGuard::new();
            let mut buffer = VerifyBuffer::new();
            temp.publish(&digest, &mut guard, &mut buffer).unwrap();
            guard.commit();
        }
        assert_eq!(fs::read(pinned.join("a.dat")).unwrap(), b"a\n");
        assert_eq!(fs::read(pinned.join("m.json")).unwrap(), b"m\n");
        assert!(!decoy.join("a.dat").exists());
        assert!(!decoy.join("m.json").exists());
    }

    /// A typed manifest parse failure is an attacker-shaped rendering path:
    /// an unknown key carrying a newline, an ESC sequence, a bidi override,
    /// and a long run must surface only through the bounded external-document
    /// error, never as raw serde text.
    #[test]
    fn manifest_typed_parse_error_is_bounded() {
        let hostile_key = format!("a\n\u{1b}[31m\u{202e}{}", "k".repeat(300));
        // JSON-escape the key so the document parses and the typed
        // unknown-field rejection is what carries the hostile text.
        let escaped_key = serde_json::to_string(&hostile_key).unwrap();
        let doc = format!(r#"{{"schema":"{SCHEMA}","version":{VERSION},{escaped_key}:1}}"#);
        let error = CorpusManifest::from_bytes(doc.as_bytes()).unwrap_err();
        let rendered = error.to_string();
        assert!(
            matches!(error, CorpusError::ExternalDocument { .. }),
            "expected ExternalDocument, got {error}"
        );
        assert!(!rendered.contains('\n'), "raw newline: {rendered:?}");
        assert!(!rendered.contains('\u{1b}'), "raw escape: {rendered:?}");
        assert!(!rendered.contains('\u{202e}'), "raw bidi: {rendered:?}");
        assert!(!rendered.contains(&"k".repeat(40)), "raw run: {rendered:?}");
        assert!(rendered.contains("sha256="), "no fingerprint: {rendered:?}");
        assert!(rendered.len() < 512, "unbounded: {}", rendered.len());
    }

    /// Durable publication is a Unix-only capability on this surface. Other
    /// targets must refuse before any scratch name is generated or the
    /// destination directory is touched.
    #[cfg(not(unix))]
    #[test]
    fn non_unix_publication_refuses_before_any_mutation() {
        let dir = temp_dir();
        let before = fs::read_dir(dir.path()).unwrap().count();

        let target = dir.path().join("artifact.json");
        let error = publish_artifact(&target, b"payload\n").unwrap_err();
        assert!(
            matches!(error, CorpusError::UnsupportedPlatform),
            "expected UnsupportedPlatform, got {error}"
        );

        let manifest_path = dir.path().join("manifest.json");
        let error = sample_manifest().save(&manifest_path).unwrap_err();
        assert!(
            matches!(error, CorpusError::UnsupportedPlatform),
            "expected UnsupportedPlatform, got {error}"
        );

        let dest = PinnedDestination::pin(&target).unwrap();
        let error = OutputTemp::create(&dest).unwrap_err();
        assert!(
            matches!(error, CorpusError::UnsupportedPlatform),
            "expected UnsupportedPlatform, got {error}"
        );

        // Neither output nor scratch was created: the directory is untouched.
        let after = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(after, before, "directory was mutated");
        assert!(!target.exists());
        assert!(!manifest_path.exists());
        let residue: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp."))
            .collect();
        assert!(residue.is_empty(), "residue: {residue:?}");
    }
}
