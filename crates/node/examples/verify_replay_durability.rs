//! Untimed durability and reorg-custody verification for a manifest-replayed state.
//!
//! `--data-dir` must point to a disposable copy made by the trial controller. This
//! executable deliberately mutates that copy; it must never receive the original
//! timed-trial store.
//!
//! Custody: `--data-dir` is anchored once with a no-follow directory
//! descriptor, and every `NodeState` open resolves through that held inode
//! (a `/proc/self/fd` magic link), so a pathname swapped in mid-run cannot
//! substitute bytes. `--output` is anchored the same way: its parent must
//! already exist and is resolved once with no-follow descriptors, refused
//! if that walk reaches the anchored data directory or sits on a different
//! mount than the store (descriptor `statx` mount IDs, failing closed), and
//! the proof is published only through the retained descriptor with a
//! post-fsync no-follow identity proof against the still-held unnamed
//! inode. `--self-test-anchor` proves these properties on
//! any host without a store.

#![allow(missing_docs)]
#![allow(clippy::print_stdout)]

use std::ffi::{OsStr, OsString};
use std::io::{self, Write as _};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail, ensure};
use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_node::Network;
use bitcoin_rs_node::config::NodeConfig;
use bitcoin_rs_node::state::NodeState;
use bitcoin_rs_primitives::Hash256;
use rustix::fs::{AtFlags, Mode, OFlags, StatxFlags};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};

const VALIDATION_SCHEMA: &str = "mainnet-prefix-replay-validation-v1";
const PROOF_SCHEMA: &str = "verify-replay-durability-proof-v1";

struct ValidationCustody {
    value: Validation,
    size_bytes: u64,
    sha256: String,
}

fn read_validation(path: &Path) -> Result<ValidationCustody> {
    let bytes = bitcoin_rs_node::corpus::read_custody_document(
        path,
        bitcoin_rs_node::corpus::VALIDATION_MAX_BYTES,
        "replay validation",
    )
    .with_context(|| format!("read validation file {}", bounded_path_context(path)))?;
    let size_bytes =
        u64::try_from(bytes.len()).context("validation file length does not fit u64")?;
    let sha256 = Sha256::digest(&bytes).as_slice().to_lower_hex_string();
    let value: Validation = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parse strict validation JSON {}",
            bounded_path_context(path)
        )
    })?;
    value.validate()?;
    Ok(ValidationCustody {
        value,
        size_bytes,
        sha256,
    })
}

fn main() -> Result<()> {
    let raw_args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if raw_args.iter().any(|arg| arg == "--self-test-anchor") {
        ensure!(
            raw_args.len() == 1,
            "--self-test-anchor takes no other arguments"
        );
        return anchor_self_test();
    }
    let args = Args::parse(raw_args)?;

    let ValidationCustody {
        value: validation,
        size_bytes: validation_file_size,
        sha256: validation_file_sha256,
    } = read_validation(&args.validation)?;

    let anchor = AnchoredDir::open(&args.data_dir).with_context(|| {
        format!(
            "anchor disposable copy {} with one no-follow directory descriptor",
            bounded_path_context(&args.data_dir)
        )
    })?;

    // Anchor the output before any state open or data-directory mutation:
    // an unusable --output must not cost the replay run, and the
    // publication target must be fixed before this executable starts
    // mutating the disposable copy.
    let output = AnchoredOutput::prepare(&anchor, &args.output)?;

    let before = {
        let state = open_anchored_state(&anchor, &args).with_context(|| {
            format!(
                "open checkpointed mainnet state in disposable copy {} using {}",
                bounded_path_context(&args.data_dir),
                bounded_os_component(OsStr::new(&args.storage_backend))
            )
        })?;
        let captured =
            capture_invariants(&state).context("capture invariants before reorg probe")?;
        captured
            .invariants
            .ensure_matches_validation(&validation)
            .context("checkpointed state does not match replay validation")?;
        captured
    };

    let checkpoint_generation = verify_durable_reorg(&anchor, &args, &validation, &before)?;
    anchor
        .reverify()
        .context("anchored directory identity changed across the destructive reorg")?;

    let after = {
        let state = open_anchored_state(&anchor, &args).with_context(|| {
            format!(
                "reopen post-reorg checkpoint in disposable copy {}",
                bounded_path_context(&args.data_dir)
            )
        })?;
        capture_invariants(&state)
            .context("capture invariants after final checkpoint reopen")?
            .invariants
    };
    after
        .ensure_matches_validation(&validation)
        .context("post-reorg checkpoint does not match replay validation")?;
    ensure!(
        after == before.invariants,
        "post-reorg invariants differ from the pre-reorg checkpoint: before={:?}, after={after:?}",
        before.invariants
    );

    let proof = Proof {
        schema: PROOF_SCHEMA,
        version: 1,
        network: "mainnet",
        backend: &args.storage_backend,
        validation: ValidationFileProof {
            size_bytes: validation_file_size,
            sha256: &validation_file_sha256,
        },
        before: &before.invariants,
        after: &after,
        checkpoint_generation,
        durable_body_roundtrip: true,
        durable_undo_roundtrip: true,
        mutated_copy_only: true,
        reopen_count: 2,
    };
    let rendered = serde_json::to_vec_pretty(&proof).context("render durability proof JSON")?;
    output.publish(&rendered).with_context(|| {
        format!(
            "publish durability proof {}",
            bounded_path_context(&args.output)
        )
    })?;

    println!(
        "wrote durability proof {}",
        bounded_path_context(&args.output)
    );
    Ok(())
}

fn verify_durable_reorg(
    anchor: &AnchoredDir,
    args: &Args,
    validation: &Validation,
    before: &CapturedInvariants,
) -> Result<u64> {
    let state = open_anchored_state(anchor, args).with_context(|| {
        format!(
            "reopen checkpointed state for durability probe in {}",
            bounded_path_context(&args.data_dir)
        )
    })?;
    let mut handles = state.apply_handles();
    // Full verification, same as the timed trial that produced the validation artifact.
    handles.assume_valid_height = 0;
    handles.assume_valid_gate =
        Arc::new(bitcoin_rs_node::apply::AssumeValidGate::with_anchor(None));

    let (original_tip_id, parent_id, parent_hash) = {
        let tree = state.block_tree();
        let tree = tree.read();
        let original_tip_id = tree.lookup(before.tip_hash).with_context(|| {
            format!(
                "resolve original tip {} in reopened block tree",
                before.tip_hash
            )
        })?;
        let parent_id = tree
            .parent_id(original_tip_id)
            .context("resolve original tip parent in reopened block tree")?
            .context("validation names a genesis-only state; no parent exists")?;
        let parent_hash = tree
            .node(parent_id)
            .context("resolve original tip parent node in reopened block tree")?
            .hash;
        (original_tip_id, parent_id, parent_hash)
    };

    bitcoin_rs_node::reorg::switch_to_branch(&handles, parent_id, |_| None, |_| {})
        .context("switch durable state from original tip to its parent")?;
    ensure_applied_tip(&state, validation.stop_height - 1, parent_hash)
        .context("verify applied parent after durable disconnect")?;

    bitcoin_rs_node::reorg::switch_to_branch(&handles, original_tip_id, |_| None, |_| {})
        .context("switch durable state from parent back to original tip")?;
    ensure_applied_tip(&state, validation.stop_height, before.tip_hash)
        .context("verify applied original tip after durable reconnect")?;

    state
        .publish_checkpoint()
        .context("publish clean checkpoint after durable reconnect")
}

fn node_config(args: &Args) -> NodeConfig {
    let mut config = NodeConfig::default_for_network(Network::Mainnet);
    config.storage_backend.clone_from(&args.storage_backend);
    config.p2p_listen.clear();
    config.dns_seeds_enabled = false;
    config.txindex = false;
    // Mirror the timed-trial replay default: full script verification on every block.
    config.assume_valid_height = 0;
    config
}

/// One no-follow descriptor anchoring the disposable data directory.
///
/// `NodeState` keeps re-opening block files by pathname for its whole
/// lifetime, so a validated `--data-dir` pathname must never be re-resolved:
/// a swapped name could substitute a different store. Every state open goes
/// through [`AnchoredDir::state_path`], a `/proc/self/fd` magic link the
/// kernel resolves to the anchored inode on each `open(2)`.
struct AnchoredDir {
    fd: OwnedFd,
    operator_path: PathBuf,
    dev: u64,
    ino: u64,
}

impl AnchoredDir {
    /// Open `path` one component at a time, refusing symlinks throughout.
    fn open(path: &Path) -> Result<Self> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let start = if path.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        };
        let mut fd = rustix::fs::open(start, flags, Mode::empty())
            .with_context(|| format!("open data-directory walk root {}", start.display()))?;
        let mut walked = start.to_path_buf();

        for (index, component) in path.components().enumerate() {
            let name = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => name,
                Component::ParentDir => {
                    bail!(
                        "data-directory path contains forbidden parent component at #{index}: {}",
                        bounded_path_context(&walked)
                    )
                }
                Component::Prefix(_) => {
                    bail!(
                        "data-directory path contains unsupported platform prefix at #{index}: {}",
                        bounded_path_context(&walked)
                    )
                }
            };
            walked.push(name);
            fd = rustix::fs::openat(&fd, name, flags, Mode::empty()).with_context(|| {
                format!(
                    "open data-directory component #{index} no-follow: {}",
                    bounded_path_context(&walked)
                )
            })?;
        }

        let stat = rustix::fs::fstat(&fd)
            .with_context(|| format!("fstat anchored {}", bounded_path_context(path)))?;
        Ok(Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
            fd,
            operator_path: path.to_path_buf(),
        })
    }

    /// Path that re-opens inside the anchored inode whatever the name says.
    fn state_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.fd.as_raw_fd()))
    }

    /// Stable identity of the anchored directory.
    fn identity(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }

    /// Prove the held descriptor still is the anchored directory: device and
    /// inode stay stable across destructive operations and the descriptor
    /// cannot have been silently recycled.
    fn reverify(&self) -> Result<()> {
        let stat = rustix::fs::fstat(&self.fd).with_context(|| {
            format!(
                "re-verify anchored directory {}",
                bounded_path_context(&self.operator_path)
            )
        })?;
        let dev = stat.st_dev;
        let ino = stat.st_ino;
        ensure!(
            (dev, ino) == self.identity(),
            "anchored directory {} changed identity: held (dev {}, ino {}), descriptor now (dev {dev}, ino {ino})",
            bounded_path_context(&self.operator_path),
            self.dev,
            self.ino
        );
        Ok(())
    }

    /// Reject a pathname that no longer resolves to the anchored directory.
    fn ensure_same_directory(&self, path: &Path) -> Result<()> {
        let fresh = Self::open(path)?;
        ensure!(
            fresh.identity() == self.identity(),
            "pathname {} re-opened a substitute directory: held (dev {}, ino {}), pathname (dev {}, ino {})",
            bounded_path_context(path),
            self.dev,
            self.ino,
            fresh.dev,
            fresh.ino
        );
        Ok(())
    }
}

/// A proof output anchored to one held output-parent descriptor.
///
/// Why: `--output` is operator-supplied, and a pathname publisher re-opens
/// the parent by name at publication time, so a name swapped in mid-run
/// could redirect the proof. Worse, an output placed at or beneath the
/// anchored data directory would put this executable's deliberate
/// mutations on its own evidence path. [`AnchoredOutput`] requires an
/// existing parent, resolves it once with no-follow descriptors, refuses
/// any output whose walk reaches the anchored data directory by
/// device/inode or whose parent sits on another mount, and publishes only
/// through the retained descriptor.
struct AnchoredOutput<'a> {
    /// The anchored data directory: publication must never reach it.
    anchor: &'a AnchoredDir,
    /// The held output-parent descriptor every publication step uses.
    parent_fd: OwnedFd,
    /// The final leaf name, resolved only relative to `parent_fd`.
    leaf: OsString,
    /// Leaf state at preparation; publication must still find exactly it.
    initial_leaf: Option<(u64, u64)>,
    /// Operator-supplied spelling, for bounded diagnostics only.
    operator_output: PathBuf,
}

impl<'a> AnchoredOutput<'a> {
    /// Resolves an existing output parent once and refuses clobber of an
    /// existing leaf. Runs before any `NodeState` open or data-directory
    /// mutation so an unusable output costs nothing.
    fn prepare(anchor: &'a AnchoredDir, output: &Path) -> Result<Self> {
        let leaf = output
            .file_name()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "output path has no final component: {}",
                    bounded_path_context(output)
                )
            })?
            .to_os_string();
        let parent = output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent_fd = Self::resolve_parent(anchor, parent)?;
        ensure_same_mount(anchor, &parent_fd, output)?;
        let initial_leaf = Self::leaf_state(&parent_fd, &leaf, output)?;
        if let Some((dev, ino)) = initial_leaf {
            bail!(
                "output already exists (dev {dev}, ino {ino}); refusing to clobber: {}",
                bounded_path_context(output)
            );
        }
        Ok(Self {
            anchor,
            parent_fd,
            leaf,
            initial_leaf,
            operator_output: output.to_path_buf(),
        })
    }

    /// Walks the existing parent pathname with no-follow descriptors. Every
    /// directory the walk opens — the root included — is compared against the
    /// anchored data directory's device/inode. Missing components are refused:
    /// proof publication never creates operator-supplied directory structure.
    fn resolve_parent(anchor: &AnchoredDir, parent: &Path) -> Result<OwnedFd> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let start = if parent.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        };
        let mut fd = rustix::fs::open(start, flags, Mode::empty())
            .with_context(|| format!("open output walk root {}", bounded_path_context(start)))?;
        let mut walked = start.to_path_buf();
        // The root is the deepest existing ancestor when the parent adds
        // no components, so it gets the same identity check.
        ensure_outside_anchor(anchor, &fd, &walked)?;

        for (index, component) in parent.components().enumerate() {
            let name = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => name,
                Component::ParentDir => bail!(
                    "output path contains forbidden parent component at #{index}: {}",
                    bounded_path_context(&walked)
                ),
                Component::Prefix(_) => bail!(
                    "output path contains unsupported platform prefix at #{index}: {}",
                    bounded_path_context(&walked)
                ),
            };
            walked.push(name);
            fd = rustix::fs::openat(&fd, name, flags, Mode::empty()).map_err(|error| {
                anyhow::anyhow!(
                    "open existing output-parent component #{index} no-follow: {error}: {}",
                    bounded_path_context(&walked)
                )
            })?;
            ensure_outside_anchor(anchor, &fd, &walked)?;
        }
        Ok(fd)
    }

    /// Publishes `bytes` at the prepared leaf through the retained
    /// descriptor; no pathname is re-resolved. The ancestry proof is redone
    /// from the held fd, the mount equality is re-proved, and the retained
    /// unnamed inode stays live through the parent fsync: after that sync
    /// the published leaf is re-statted no-follow and must still be that
    /// inode. Directory descriptors preserve identity, not namespace
    /// immutability; a process that can rename the parent can still move it
    /// between any userspace check and `linkat`.
    fn publish(&self, bytes: &[u8]) -> Result<()> {
        self.publish_with_post_fsync(bytes, |_, _| Ok(()))
    }

    /// Publication seam used only by the built-in custody self-test. It is
    /// private and accepts no operator input, so production publication has no
    /// exposed fault-injection hook.
    fn publish_with_post_fsync_substitution_for_self_test(&self, bytes: &[u8]) -> Result<()> {
        self.publish_with_post_fsync(bytes, |parent_fd, leaf| {
            rustix::fs::unlinkat(parent_fd, leaf, AtFlags::empty())
                .context("self-test unlink published leaf after parent fsync")?;
            let substitute = rustix::fs::openat(
                parent_fd,
                leaf,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .context("self-test create substituted leaf after parent fsync")?;
            let mut substitute = std::fs::File::from(substitute);
            substitute
                .write_all(b"post-fsync-substitute")
                .context("self-test write substituted leaf")?;
            substitute
                .sync_all()
                .context("self-test sync substituted leaf")?;
            Ok(())
        })
    }

    fn publish_with_post_fsync(
        &self,
        bytes: &[u8],
        after_parent_fsync: impl FnOnce(&OwnedFd, &OsStr) -> Result<()>,
    ) -> Result<()> {
        // Renaming a directory re-parents its held descriptor's inode, so
        // the ancestry proof is redone from the held fd, never a pathname.
        ensure_ancestry_outside_anchor(self.anchor, &self.parent_fd, &self.operator_output)?;
        ensure_same_mount(self.anchor, &self.parent_fd, &self.operator_output)?;
        let now = Self::leaf_state(&self.parent_fd, &self.leaf, &self.operator_output)?;
        ensure!(
            now == self.initial_leaf,
            "output leaf changed after preparation (was {:?}, now {now:?}); refusing substitution: {}",
            self.initial_leaf,
            bounded_path_context(&self.operator_output)
        );

        let (written, written_identity) = self.write_and_link(bytes)?;
        rustix::fs::fsync(&self.parent_fd).with_context(|| {
            format!(
                "sync output-parent directory: {}",
                bounded_path_context(&self.operator_output)
            )
        })?;
        after_parent_fsync(&self.parent_fd, &self.leaf)?;

        let published = rustix::fs::statat(&self.parent_fd, &self.leaf, AtFlags::SYMLINK_NOFOLLOW)
            .with_context(|| {
                format!(
                    "re-stat published output after parent fsync no-follow: {}",
                    bounded_path_context(&self.operator_output)
                )
            })?;
        ensure!(
            (published.st_dev, published.st_ino) == written_identity,
            "post-fsync output identity differs from the still-held written inode; refusing substitution: {}",
            bounded_path_context(&self.operator_output)
        );
        drop(written);
        Ok(())
    }

    /// Writes and syncs one unnamed inode in the held parent and hard links it
    /// to the leaf without replacement. The returned file keeps that inode
    /// alive until publication has been directory-synced and re-verified.
    fn write_and_link(&self, bytes: &[u8]) -> Result<(std::fs::File, (u64, u64))> {
        let written = rustix::fs::openat(
            &self.parent_fd,
            ".",
            OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .with_context(|| {
            format!(
                "create unnamed output inode in held parent: {}",
                bounded_path_context(&self.operator_output)
            )
        })?;
        let mut written = std::fs::File::from(written);
        written
            .write_all(bytes)
            .context("write unnamed output bytes")?;
        written.sync_all().context("sync unnamed output bytes")?;
        let written_stat = rustix::fs::fstat(&written).context("fstat unnamed output")?;
        // Keep the unavoidable namespace race window to one syscall. The
        // early check above prevents any output mutation when reparenting
        // is already visible.
        ensure_ancestry_outside_anchor(self.anchor, &self.parent_fd, &self.operator_output)?;
        rustix::fs::linkat(
            &written,
            "",
            &self.parent_fd,
            self.leaf.as_os_str(),
            AtFlags::EMPTY_PATH,
        )
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                anyhow::anyhow!(
                    "output appeared after preparation; refusing to clobber: {}",
                    bounded_path_context(&self.operator_output)
                )
            } else {
                error.into()
            }
        })?;
        Ok((written, (written_stat.st_dev, written_stat.st_ino)))
    }

    /// No-follow stat of the final leaf relative to the held parent:
    /// `Some` identity when any entry, a symlink included, is present.
    fn leaf_state(parent_fd: &OwnedFd, leaf: &OsStr, output: &Path) -> Result<Option<(u64, u64)>> {
        match rustix::fs::statat(parent_fd, leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some((stat.st_dev, stat.st_ino))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => bail!(
                "stat output leaf no-follow: {error}: {}",
                bounded_path_context(output)
            ),
        }
    }
}

/// Reads a held descriptor's mount identity without resolving a pathname.
/// Mount identity is mandatory for this custody contract; unsupported or
/// incomplete `statx` results fail closed.
fn descriptor_mount_id(fd: &OwnedFd, role: &str, path: &Path) -> Result<u64> {
    let stat =
        rustix::fs::statx(fd, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID).with_context(|| {
            format!(
                "statx {role} mount identity: {}",
                bounded_path_context(path)
            )
        })?;
    ensure!(
        StatxFlags::from_bits_retain(stat.stx_mask).contains(StatxFlags::MNT_ID),
        "statx omitted {role} mount identity; refusing publication: {}",
        bounded_path_context(path)
    );
    Ok(stat.stx_mnt_id)
}

/// The source store and proof parent must occupy the same mount. Ordinary file
/// descriptors retain inodes, not mount topology, so this check complements —
/// rather than replaces — the descriptor ancestry and final identity proofs.
fn ensure_same_mount(anchor: &AnchoredDir, output_parent: &OwnedFd, output: &Path) -> Result<()> {
    let source_mount = descriptor_mount_id(&anchor.fd, "source", &anchor.operator_path)?;
    let output_mount = descriptor_mount_id(output_parent, "output-parent", output)?;
    ensure!(
        source_mount == output_mount,
        "source and output parent are on different mounts ({source_mount} != {output_mount}); refusing publication: {}",
        bounded_path_context(output)
    );
    Ok(())
}

/// Rejects a walked directory that is the anchored data directory itself.
/// The walk resolved each component for real, so reaching that inode means
/// the output equals or descends from the data directory — never a lexical
/// guess.
fn ensure_outside_anchor(anchor: &AnchoredDir, fd: &OwnedFd, walked: &Path) -> Result<()> {
    let stat = rustix::fs::fstat(fd)
        .with_context(|| format!("fstat output-parent walk: {}", bounded_path_context(walked)))?;
    ensure!(
        (stat.st_dev, stat.st_ino) != anchor.identity(),
        "output path is at or beneath the anchored data directory: {}",
        bounded_path_context(walked)
    );
    Ok(())
}

/// Walks upward from a held directory descriptor to the filesystem root,
/// refusing when any directory on the current ancestry chain is the
/// anchored data directory. Descriptor-relative: this catches a parent
/// directory renamed beneath the data directory after preparation, which
/// no pathname re-resolution would see the same way.
fn ensure_ancestry_outside_anchor(anchor: &AnchoredDir, fd: &OwnedFd, output: &Path) -> Result<()> {
    let mut current = fd.try_clone().context("clone output-parent descriptor")?;
    loop {
        let stat = rustix::fs::fstat(&current)
            .with_context(|| format!("fstat output ancestry: {}", bounded_path_context(output)))?;
        ensure!(
            (stat.st_dev, stat.st_ino) != anchor.identity(),
            "output parent ancestry reached the anchored data directory: {}",
            bounded_path_context(output)
        );
        let parent = rustix::fs::openat(
            &current,
            "..",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| {
            format!(
                "walk output ancestry upward: {}",
                bounded_path_context(output)
            )
        })?;
        let parent_stat = rustix::fs::fstat(&parent).context("fstat output ancestry root")?;
        // The filesystem root's parent is itself: the walk is complete.
        if (parent_stat.st_dev, parent_stat.st_ino) == (stat.st_dev, stat.st_ino) {
            return Ok(());
        }
        current = parent;
    }
}

/// Bounded context for an anchor error: enough to identify the failing
/// component without embedding an unbounded attacker-supplied path.
fn bounded_path_context(path: &Path) -> String {
    const MAX_COMPONENTS: usize = 8;
    let mut components = path.components();
    let mut names = Vec::with_capacity(MAX_COMPONENTS);
    for component in components.by_ref().take(MAX_COMPONENTS) {
        names.push(match component {
            Component::RootDir => "/".to_string(),
            Component::CurDir => ".".to_string(),
            Component::ParentDir => "..".to_string(),
            Component::Prefix(prefix) => bounded_os_component(prefix.as_os_str()),
            Component::Normal(name) => bounded_os_component(name),
        });
    }
    let suffix = if components.next().is_some() {
        "/…"
    } else {
        ""
    };
    format!("{}{suffix}", names.join("/"))
}

/// Escapes only a bounded prefix so one invalid argument cannot allocate or
/// print in proportion to attacker-controlled input.
fn bounded_os_component(value: &OsStr) -> String {
    use std::os::unix::ffi::OsStrExt as _;

    const MAX_BYTES: usize = 96;
    let bytes = value.as_bytes();
    let prefix = &bytes[..bytes.len().min(MAX_BYTES)];
    let mut rendered = String::with_capacity(MAX_BYTES);
    for &byte in prefix {
        rendered.extend(std::ascii::escape_default(byte).map(char::from));
    }
    if bytes.len() > MAX_BYTES {
        rendered.push('…');
    }
    rendered
}

/// A node state whose backing directory is the anchored inode.
///
/// Holding the anchor by reference makes "the anchor outlives every state
/// opened from it" a compile-time fact: dropping the anchor would close the
/// descriptor behind `state_path()` while `NodeState` still re-opens block
/// files through it.
struct AnchoredState<'a> {
    state: NodeState,
    _anchor: &'a AnchoredDir,
}

impl core::ops::Deref for AnchoredState<'_> {
    type Target = NodeState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

fn open_anchored_state<'a>(anchor: &'a AnchoredDir, args: &Args) -> Result<AnchoredState<'a>> {
    let mut config = node_config(args);
    config.data_dir = anchor.state_path();
    let state = NodeState::open(config, None)?;
    Ok(AnchoredState {
        state,
        _anchor: anchor,
    })
}

struct AnchorSelfTestEvidence {
    held: (u64, u64),
    rejection: String,
}

struct OutputSelfTestEvidence {
    nested_rejection: String,
    swapped_publication: String,
    post_fsync_substitution_rejection: String,
}

/// Swap the data-dir pathname out from under a held anchor and prove the
/// anchor stays authoritative while the swapped pathname is rejected,
/// then prove the output custody cases against the same anchor.
fn anchor_self_test() -> Result<()> {
    let scratch = tempfile::Builder::new()
        .prefix("verify-replay-durability-anchor-")
        .tempdir()
        .context("create anchor self-test scratch")?;
    let store = scratch.path().join("store");
    std::fs::create_dir_all(&store)?;
    std::fs::write(store.join("marker.bin"), b"original-custody-store")?;
    let anchor = AnchoredDir::open(&store)?;

    let evidence = anchor_self_test_in(scratch.path(), &anchor)?;
    println!("  pathname re-open rejected: {}", evidence.rejection);
    let output = output_self_test_in(scratch.path(), &anchor)?;
    println!(
        "  nested data-dir output rejected: {}",
        output.nested_rejection
    );
    println!(
        "  swapped output-parent stayed on the retained descriptor: {}",
        output.swapped_publication
    );
    println!(
        "  post-fsync leaf substitution rejected: {}",
        output.post_fsync_substitution_rejection
    );
    println!(
        "anchor self-test: held (dev {}, ino {}) stayed authoritative across the pathname swap",
        evidence.held.0, evidence.held.1
    );
    println!("ANCHOR-SELF-TEST-OK");
    Ok(())
}

fn anchor_self_test_in(base: &Path, anchor: &AnchoredDir) -> Result<AnchorSelfTestEvidence> {
    let held = anchor.identity();

    // The anchored store's now-stale pathname: renamed away below.
    let store = base.join("store");
    // Destructive operation: the original directory moves away and a
    // substitute takes its name.
    let moved = base.join("store.moved");
    std::fs::rename(&store, &moved)?;
    let substitute = base.join("store");
    std::fs::create_dir_all(&substitute)?;
    std::fs::write(substitute.join("decoy.bin"), b"substitute-store")?;

    anchor
        .reverify()
        .context("anchor identity drifted across the pathname swap")?;
    ensure!(anchor.identity() == held, "held identity changed");

    // Opens through the held anchor land in the original inode, never in the
    // substitute now sitting at the old name.
    std::fs::write(anchor.state_path().join("probe.bin"), b"anchored-write")?;
    ensure!(
        moved.join("probe.bin").is_file(),
        "anchored write missed the moved original store"
    );
    ensure!(
        !substitute.join("probe.bin").exists(),
        "anchored write leaked into the substitute directory"
    );
    let marker = std::fs::read(anchor.state_path().join("marker.bin"))?;
    ensure!(
        marker.as_slice() == b"original-custody-store",
        "anchor no longer reads the original store bytes"
    );

    // A fresh pathname open of the swapped name resolves to the substitute
    // and is rejected on device/inode identity.
    let rejection = match anchor.ensure_same_directory(&substitute) {
        Ok(()) => bail!("pathname re-open accepted a substitute directory"),
        Err(err) => err.to_string(),
    };

    // The constructor itself refuses a symlinked final component.
    let link = base.join("store.link");
    std::os::unix::fs::symlink(&moved, &link)?;
    ensure!(
        AnchoredDir::open(&link).is_err(),
        "anchor accepted a symlinked pathname"
    );

    // The walk refuses a symlink at an intermediate component too: a real
    // directory whose child name is a link out of the scratch tree.
    let outer = base.join("walk");
    std::fs::create_dir_all(&outer)?;
    let escape = base.join("outside");
    std::fs::create_dir_all(escape.join("deeper"))?;
    let midway = outer.join("hop");
    std::os::unix::fs::symlink(&escape, &midway)?;
    ensure!(
        AnchoredDir::open(&midway.join("deeper")).is_err(),
        "anchor accepted a symlinked intermediate directory"
    );

    Ok(AnchorSelfTestEvidence { held, rejection })
}

/// Proves the output custody cases against a live anchor: an absent
/// nested output path beneath the data directory is refused before its
/// missing parents or leaf are created, and a parent pathname swapped
/// after preparation cannot redirect publication away from the retained
/// descriptor.
fn output_self_test_in(base: &Path, anchor: &AnchoredDir) -> Result<OutputSelfTestEvidence> {
    // Case 1: the walk reaches the anchored inode at `store.moved`
    // itself, so both missing components and the leaf must never be
    // created.
    let nested = base.join("store.moved").join("reports").join("deep");
    let nested_target = nested.join("proof.json");
    let nested_rejection = match AnchoredOutput::prepare(anchor, &nested_target) {
        Ok(_) => bail!("an output beneath the data directory was accepted"),
        Err(error) => error.to_string(),
    };
    ensure!(
        !base.join("store.moved").join("reports").exists(),
        "rejected data-dir output created its missing parent components"
    );
    ensure!(
        !nested_target.exists(),
        "rejected data-dir output created its leaf"
    );

    // Case 2: the output parent pathname is replaced after preparation,
    // and the substitute plants a decoy leaf at the old name.
    let outdir = base.join("out");
    std::fs::create_dir_all(&outdir)?;
    let out = AnchoredOutput::prepare(anchor, &outdir.join("proof.json"))?;
    let original = base.join("out.original");
    std::fs::rename(&outdir, &original)?;
    std::fs::create_dir_all(&outdir)?;
    std::fs::write(outdir.join("proof.json"), b"substitute-decoy")?;

    out.publish(b"published-through-retained-descriptor")?;
    let landed = std::fs::read(original.join("proof.json"))?;
    ensure!(
        landed.as_slice() == b"published-through-retained-descriptor",
        "publication did not land in the original output-parent directory"
    );
    let decoy = std::fs::read(outdir.join("proof.json"))?;
    ensure!(
        decoy.as_slice() == b"substitute-decoy",
        "publication clobbered the substitute at the swapped pathname"
    );

    // Case 3: substitute the linked leaf only after its parent fsync. The
    // still-live unnamed inode identity must make this deterministic tampering
    // visible to the final no-follow re-stat.
    let post_sync_dir = base.join("post-sync");
    std::fs::create_dir_all(&post_sync_dir)?;
    let post_sync = AnchoredOutput::prepare(anchor, &post_sync_dir.join("proof.json"))?;
    let post_fsync_substitution_rejection =
        match post_sync.publish_with_post_fsync_substitution_for_self_test(b"original-proof") {
            Ok(()) => bail!("post-fsync output substitution was accepted"),
            Err(error) => error.to_string(),
        };
    ensure!(
        std::fs::read(post_sync_dir.join("proof.json"))?.as_slice() == b"post-fsync-substitute",
        "self-test did not substitute the published leaf at the intended seam"
    );

    Ok(OutputSelfTestEvidence {
        nested_rejection,
        swapped_publication: "published via the retained descriptor, not the swapped pathname"
            .to_string(),
        post_fsync_substitution_rejection,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Validation {
    schema: String,
    stop_height: u32,
    #[serde(deserialize_with = "deserialize_lower_hash")]
    stop_hash: Hash256,
    #[serde(deserialize_with = "deserialize_lower_hash")]
    utxo_hash_serialized_3: Hash256,
    #[serde(deserialize_with = "deserialize_lower_hash")]
    muhash: Hash256,
    utxo_count: u64,
    total_amount: u64,
}

impl Validation {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == VALIDATION_SCHEMA,
            "unsupported validation schema {:?}; expected {VALIDATION_SCHEMA:?}",
            self.schema
        );
        ensure!(
            self.stop_height > 0,
            "validation stop_height must be greater than zero; genesis-only validation is unsupported"
        );
        Ok(())
    }
}

fn deserialize_lower_hash<'de, D>(deserializer: D) -> core::result::Result<Hash256, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(serde::de::Error::custom(
            "hash must be exactly 64 lowercase hexadecimal characters",
        ));
    }
    Hash256::from_str_be(&value).map_err(serde::de::Error::custom)
}

#[derive(Debug)]
struct CapturedInvariants {
    tip_hash: Hash256,
    invariants: Invariants,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct Invariants {
    tip_height: u32,
    tip_hash: String,
    utxo_count: u64,
    total_amount: u64,
    muhash: String,
    utxo_hash_serialized_3: String,
    tx_count: u64,
    bogo_size: u64,
}

impl Invariants {
    fn ensure_matches_validation(&self, expected: &Validation) -> Result<()> {
        ensure!(
            self.tip_height == expected.stop_height,
            "tip height mismatch: expected {}, found {}",
            expected.stop_height,
            self.tip_height
        );
        ensure!(
            self.tip_hash == expected.stop_hash.to_string_be(),
            "tip hash mismatch: expected {}, found {}",
            expected.stop_hash,
            self.tip_hash
        );
        ensure!(
            self.utxo_count == expected.utxo_count,
            "UTXO count mismatch: expected {}, found {}",
            expected.utxo_count,
            self.utxo_count
        );
        ensure!(
            self.total_amount == expected.total_amount,
            "total amount mismatch: expected {}, found {} sat",
            expected.total_amount,
            self.total_amount
        );
        ensure!(
            self.muhash == expected.muhash.to_string_be(),
            "MuHash mismatch: expected {}, found {}",
            expected.muhash,
            self.muhash
        );
        ensure!(
            self.utxo_hash_serialized_3 == expected.utxo_hash_serialized_3.to_string_be(),
            "aggregate UTXO hash mismatch: expected {}, found {}",
            expected.utxo_hash_serialized_3,
            self.utxo_hash_serialized_3
        );
        Ok(())
    }
}

fn capture_invariants(state: &NodeState) -> Result<CapturedInvariants> {
    let applied = state
        .applied_tip()
        .load_full()
        .context("checkpoint has no applied tip")?;
    let tip_height = applied.height;
    let tip_hash = applied.hash;
    drop(applied);

    let utxo = state.utxo();
    let stats = utxo
        .with_stable_view(|view| bitcoin_rs_utxo::stats::scan_coin_stats(view, tip_height, true))
        .context("scan full UTXO coin statistics with MuHash")?;
    ensure!(
        stats.height == tip_height,
        "coin-stat height mismatch: applied tip is {tip_height}, scan reports {}",
        stats.height
    );
    let aggregate = bitcoin_rs_utxo::aggregate_hash(&utxo)
        .context("compute deterministic aggregate UTXO hash")?;
    drop(utxo);

    Ok(CapturedInvariants {
        tip_hash,
        invariants: Invariants {
            tip_height,
            tip_hash: tip_hash.to_string_be(),
            utxo_count: stats.utxo_count,
            total_amount: stats.total_amount,
            muhash: stats.muhash.finalize_hash().to_string_be(),
            utxo_hash_serialized_3: aggregate.to_string_be(),
            tx_count: stats.tx_count,
            bogo_size: stats.bogo_size,
        },
    })
}

fn ensure_applied_tip(
    state: &NodeState,
    expected_height: u32,
    expected_hash: Hash256,
) -> Result<()> {
    let applied = state
        .applied_tip()
        .load_full()
        .context("state has no applied tip after branch switch")?;
    ensure!(
        applied.height == expected_height,
        "applied height mismatch: expected {expected_height}, found {}",
        applied.height
    );
    ensure!(
        applied.hash == expected_hash,
        "applied hash mismatch: expected {expected_hash}, found {}",
        applied.hash
    );
    Ok(())
}

#[derive(Serialize)]
struct Proof<'a> {
    schema: &'static str,
    version: u32,
    network: &'static str,
    backend: &'a str,
    validation: ValidationFileProof<'a>,
    before: &'a Invariants,
    after: &'a Invariants,
    checkpoint_generation: u64,
    durable_body_roundtrip: bool,
    durable_undo_roundtrip: bool,
    mutated_copy_only: bool,
    reopen_count: u8,
}

#[derive(Serialize)]
struct ValidationFileProof<'a> {
    size_bytes: u64,
    sha256: &'a str,
}

#[derive(Debug)]
struct Args {
    data_dir: PathBuf,
    storage_backend: String,
    validation: PathBuf,
    output: PathBuf,
}

impl Args {
    fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let mut data_dir = None;
        let mut storage_backend = None;
        let mut validation = None;
        let mut output = None;
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            let arg = arg.into_string().map_err(|value| {
                anyhow::anyhow!(
                    "argument is not UTF-8: {}",
                    bounded_path_context(Path::new(&value))
                )
            })?;
            match arg.as_str() {
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                "--data-dir" => set_once(
                    &mut data_dir,
                    PathBuf::from(next_arg(&mut args, "--data-dir")?),
                    "--data-dir",
                )?,
                "--storage-backend" => set_once(
                    &mut storage_backend,
                    next_arg(&mut args, "--storage-backend")?,
                    "--storage-backend",
                )?,
                "--validation" => set_once(
                    &mut validation,
                    PathBuf::from(next_arg(&mut args, "--validation")?),
                    "--validation",
                )?,
                "--output" => set_once(
                    &mut output,
                    PathBuf::from(next_arg(&mut args, "--output")?),
                    "--output",
                )?,
                other => {
                    bail!(
                        "unknown argument {}; --data-dir must name a disposable copy",
                        bounded_os_component(OsStr::new(other))
                    )
                }
            }
        }

        Ok(Self {
            data_dir: data_dir.context(
                "missing --data-dir <disposable-copy>; the controller must copy the timed-trial store",
            )?,
            storage_backend: storage_backend.context("missing --storage-backend <backend>")?,
            validation: validation.context("missing --validation <path>")?,
            output: output.context("missing --output <path>")?,
        })
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<()> {
    ensure!(slot.is_none(), "duplicate argument {name}");
    *slot = Some(value);
    Ok(())
}

fn next_arg(args: &mut impl Iterator<Item = OsString>, name: &str) -> Result<String> {
    args.next()
        .with_context(|| format!("{name} requires a value"))?
        .into_string()
        .map_err(|value| {
            anyhow::anyhow!(
                "{name} value is not UTF-8: {}",
                bounded_path_context(Path::new(&value))
            )
        })
}

fn print_usage() {
    println!(
        "Usage: verify_replay_durability --data-dir <disposable-copy> --storage-backend <backend> \\\n\
         --validation <mainnet-prefix-replay-validation-v1.json> --output <proof.json>\n\
         Usage: verify_replay_durability --self-test-anchor\n\
         WARNING: --data-dir is mutated and must be a controller-created copy of the timed-trial store."
    );
}
