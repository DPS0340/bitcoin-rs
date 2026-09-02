use std::io::{self, Read, Write};
use std::path::Path;
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

use bitcoin_rs_primitives::Network;
#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
use cap_fs_ext::OpenOptionsMaybeDirExt;
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};
use serde::{Deserialize, Serialize};

/// Name of the datadir-wide clean-cutover schema marker.
pub(crate) const CURRENT_SCHEMA_FILE: &str = "CURRENT_SCHEMA";
const CURRENT_SCHEMA_TEMP_PREFIX: &str = ".CURRENT_SCHEMA.";
const CURRENT_SCHEMA_TEMP_SUFFIX: &str = ".tmp";
const CURRENT_SCHEMA_MAX_BYTES: u64 = 512;
// This epoch is the single source of truth for the current persistent format.
// Its record also binds the datadir to the resolved chain and storage backend;
// increment it for a schema-breaking change and provide no converter.
const CURRENT_SCHEMA_VERSION: u32 = 1;
static CURRENT_SCHEMA_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct DatadirIdentity {
    network: String,
    genesis_hash: String,
    p2p_magic: String,
    storage_backend: String,
}

impl DatadirIdentity {
    pub(crate) fn for_network(network: Network, p2p_magic: [u8; 4], storage_backend: &str) -> Self {
        let network_name = match network {
            Network::Mainnet => "mainnet",
            Network::Testnet3 => "testnet",
            Network::Testnet4 => "testnet4",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        };
        Self {
            network: network_name.to_owned(),
            genesis_hash: network.genesis_block_hash().to_string_be(),
            p2p_magic: hex_encode(&p2p_magic),
            storage_backend: storage_backend.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CurrentSchemaMarker {
    schema: u32,
    network: String,
    genesis_hash: String,
    p2p_magic: String,
    storage_backend: String,
}

pub(crate) fn open_data_dir(path: &Path) -> io::Result<Dir> {
    Dir::open_ambient_dir(path, ambient_authority())
}

/// Opens the current datadir epoch, initializing it only for a genuinely empty
/// directory. A non-empty directory without the marker is an unsupported
/// legacy datadir and must be explicitly removed and resynced by the operator.
pub(crate) fn ensure_current_schema(data: &Dir, expected: &DatadirIdentity) -> io::Result<()> {
    match read_file(data, CURRENT_SCHEMA_FILE, CURRENT_SCHEMA_MAX_BYTES) {
        Ok(bytes) => validate_current_schema(&bytes, expected),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut has_other_entry = false;
            for entry in data.entries()? {
                let entry = entry?;
                if !entry
                    .file_name()
                    .to_str()
                    .is_some_and(is_current_schema_temp)
                {
                    has_other_entry = true;
                }
            }
            if has_other_entry {
                // Another opener may have published CURRENT_SCHEMA after the
                // initial read but before this directory scan completed.
                // Recheck once before classifying the non-empty directory as
                // an incompatible legacy datadir.
                return match read_file(data, CURRENT_SCHEMA_FILE, CURRENT_SCHEMA_MAX_BYTES) {
                    Ok(bytes) => validate_current_schema(&bytes, expected),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        Err(incompatible_schema(
                            "datadir has no CURRENT_SCHEMA marker and is not empty",
                        ))
                    }
                    Err(error) => Err(error),
                };
            }
            // Temporary marker files are reserved crash residue. They are
            // ignored rather than removed: another opener may still be using
            // one of them. A successful publication makes them harmless, and
            // the unique name prevents one opener from truncating another's
            // partially written marker.
            let (temp_name, mut marker) = create_current_schema_temp(data)?;
            let bytes = current_schema_bytes(expected)?;
            marker.write_all(&bytes)?;
            marker.sync_all()?;
            drop(marker);
            match data.hard_link(&temp_name, data, CURRENT_SCHEMA_FILE) {
                Ok(()) => {
                    data.remove_file(&temp_name)?;
                    sync_dir(data)
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    // Another opener won publication. Its marker is the only
                    // authoritative result; validate it before continuing.
                    data.remove_file(&temp_name)?;
                    validate_current_schema(
                        &read_file(data, CURRENT_SCHEMA_FILE, CURRENT_SCHEMA_MAX_BYTES)?,
                        expected,
                    )
                }
                Err(error) => Err(error),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::InvalidData => Err(incompatible_schema(
            format!("invalid CURRENT_SCHEMA: {error}"),
        )),
        Err(error) => Err(error),
    }
}

fn validate_current_schema(bytes: &[u8], expected: &DatadirIdentity) -> io::Result<()> {
    let marker: CurrentSchemaMarker = serde_json::from_slice(bytes)
        .map_err(|error| incompatible_schema(format!("invalid CURRENT_SCHEMA: {error}")))?;
    if marker.schema != CURRENT_SCHEMA_VERSION {
        return Err(incompatible_schema(format!(
            "CURRENT_SCHEMA epoch {} is not the current epoch {CURRENT_SCHEMA_VERSION}",
            marker.schema
        )));
    }
    let mut canonical = serde_json::to_vec(&marker)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    canonical.push(b'\n');
    if bytes != canonical.as_slice() {
        return Err(incompatible_schema(
            "CURRENT_SCHEMA is not in the canonical format",
        ));
    }
    let actual = DatadirIdentity {
        network: marker.network,
        genesis_hash: marker.genesis_hash,
        p2p_magic: marker.p2p_magic,
        storage_backend: marker.storage_backend,
    };
    if actual != *expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "CURRENT_SCHEMA datadir identity does not match configuration (on-disk: {actual:?}, configured: {expected:?}); use the matching network, P2P magic, and storage backend or choose another datadir"
            ),
        ));
    }
    Ok(())
}

pub(crate) fn current_schema_bytes(expected: &DatadirIdentity) -> io::Result<Vec<u8>> {
    let marker = CurrentSchemaMarker {
        schema: CURRENT_SCHEMA_VERSION,
        network: expected.network.clone(),
        genesis_hash: expected.genesis_hash.clone(),
        p2p_magic: expected.p2p_magic.clone(),
        storage_backend: expected.storage_backend.clone(),
    };
    let mut bytes = serde_json::to_vec(&marker)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn create_current_schema_temp(data: &Dir) -> io::Result<(String, File)> {
    loop {
        let counter = CURRENT_SCHEMA_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!(
            "{CURRENT_SCHEMA_TEMP_PREFIX}{}-{counter}{CURRENT_SCHEMA_TEMP_SUFFIX}",
            process::id()
        );
        match create_file(data, &name) {
            Ok(file) => return Ok((name, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
}

fn is_current_schema_temp(name: &str) -> bool {
    (name == ".CURRENT_SCHEMA.tmp")
        || (name.starts_with(CURRENT_SCHEMA_TEMP_PREFIX)
            && name.ends_with(CURRENT_SCHEMA_TEMP_SUFFIX))
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

fn incompatible_schema(reason: impl Into<String>) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "{}; remove or replace the datadir and restart to perform a full resync",
            reason.into()
        ),
    )
}

pub(crate) struct CheckpointRoot {
    dir: Dir,
}

impl CheckpointRoot {
    pub(crate) fn dir(&self) -> &Dir {
        &self.dir
    }
    pub(crate) fn open_existing(data: &Dir, name: &str) -> io::Result<Option<Self>> {
        match data.open_dir_nofollow(name) {
            Ok(dir) => Ok(Some(Self { dir })),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn open_or_create(data: &Dir, name: &str) -> io::Result<Self> {
        match data.open_dir_nofollow(name) {
            Ok(dir) => Ok(Self { dir }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match data.create_dir(name) {
                    Ok(()) => sync_dir(data)?,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
                Ok(Self {
                    dir: data.open_dir_nofollow(name)?,
                })
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn open_dir(&self, name: &str) -> io::Result<Dir> {
        self.dir.open_dir_nofollow(name)
    }

    pub(crate) fn create_dir(&self, name: &str) -> io::Result<Dir> {
        self.dir.create_dir(name)?;
        self.dir.open_dir_nofollow(name)
    }

    pub(crate) fn create_file(&self, name: &str) -> io::Result<File> {
        create_file(&self.dir, name)
    }

    pub(crate) fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.dir.rename(from, &self.dir, to)
    }

    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    ))]
    pub(crate) fn rename_noreplace(&self, from: &str, to: &str) -> io::Result<()> {
        rustix::fs::renameat_with(
            self.dir(),
            from,
            self.dir(),
            to,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(Into::into)
    }

    pub(crate) fn sync(&self) -> io::Result<()> {
        sync_dir(&self.dir)
    }

    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    ))]
    pub(crate) fn entry_exists(&self, name: &str) -> io::Result<bool> {
        match self.dir.symlink_metadata(name) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn entries(&self) -> io::Result<cap_std::fs::ReadDir> {
        self.dir.entries()
    }

    pub(crate) fn remove_file(&self, name: &str) -> io::Result<()> {
        self.dir.remove_file(name)
    }

    pub(crate) fn remove_dir(&self, name: &str) -> io::Result<()> {
        self.dir.remove_dir(name)
    }
}

pub(crate) fn create_file(dir: &Dir, name: &str) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    dir.open_with(name, &options)
}

pub(crate) fn open_file(dir: &Dir, name: &str) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = dir.open_with(name, &options)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("checkpoint entry {name:?} is not a regular file"),
        ));
    }
    Ok(file)
}

pub(crate) fn read_file(dir: &Dir, name: &str, limit: u64) -> io::Result<Vec<u8>> {
    let mut file = open_file(dir, name)?;
    let length = file.metadata()?.len();
    if length > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("checkpoint entry {name:?} exceeds its size bound"),
        ));
    }
    let capacity = usize::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "checkpoint file is too large"))?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).ok() != Some(length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("checkpoint entry {name:?} changed while it was read"),
        ));
    }
    Ok(bytes)
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
pub(crate) fn sync_dir(dir: &Dir) -> io::Result<()> {
    // cap-std directory capabilities use O_PATH on Linux; reopen "." read-only
    // so fsync has an I/O-capable descriptor without leaving this capability.
    let mut options = OpenOptions::new();
    options
        .read(true)
        .maybe_dir(true)
        .follow(FollowSymlinks::No);
    dir.open_with(".", &options)?.sync_all()
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
)))]
pub(crate) fn sync_dir(_dir: &Dir) -> io::Result<()> {
    // Windows does not support flushing a directory handle with the access
    // mode used by cap-std. File contents are still flushed by File::sync_all.
    Ok(())
}

pub(crate) fn remove_known_dir(root: &CheckpointRoot, name: &str) -> io::Result<()> {
    let dir = root.open_dir(name)?;
    for entry in dir.entries()? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let file_type = entry.file_type()?;
        if file_type.is_file() {
            dir.remove_file(file_name)?;
        }
    }
    root.remove_dir(name)
}
