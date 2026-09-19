//! Failpoint-aware checkpoint writes and filesystem durability barriers.

use super::CURRENT_FILE;
use super::CheckpointError;
use super::CheckpointFailpoint;
use super::fs::CheckpointRoot;
use super::fs::sync_dir;
use cap_std::fs::Dir;
use cap_std::fs::File;
use std::io::Write;

pub(crate) fn injected_io(
    configured: Option<CheckpointFailpoint>,
    boundary: CheckpointFailpoint,
) -> std::io::Result<()> {
    if configured == Some(boundary) {
        return Err(std::io::Error::from_raw_os_error(28));
    }
    Ok(())
}

pub(crate) fn write_file(
    file: &mut File,
    bytes: &[u8],
    configured: Option<CheckpointFailpoint>,
    boundary: CheckpointFailpoint,
) -> Result<(), CheckpointError> {
    injected_io(configured, boundary)?;
    file.write_all(bytes)?;
    Ok(())
}

pub(crate) fn sync_file(
    file: &File,
    configured: Option<CheckpointFailpoint>,
    boundary: CheckpointFailpoint,
) -> Result<(), CheckpointError> {
    injected_io(configured, boundary)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn sync_checkpoint_dir(
    dir: &Dir,
    configured: Option<CheckpointFailpoint>,
    boundary: CheckpointFailpoint,
) -> Result<(), CheckpointError> {
    injected_io(configured, boundary)?;
    sync_dir(dir)?;
    Ok(())
}

pub(crate) fn sync_root(
    root: &CheckpointRoot,
    configured: Option<CheckpointFailpoint>,
    boundary: CheckpointFailpoint,
) -> Result<(), CheckpointError> {
    injected_io(configured, boundary)?;
    root.sync()?;
    Ok(())
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
pub(crate) fn rename_generation(
    root: &CheckpointRoot,
    from: &str,
    to: &str,
    configured: Option<CheckpointFailpoint>,
    boundary: CheckpointFailpoint,
) -> Result<(), CheckpointError> {
    injected_io(configured, boundary)?;
    root.rename_noreplace(from, to)?;
    Ok(())
}

pub(crate) fn rename_current(
    root: &CheckpointRoot,
    from: &str,
    configured: Option<CheckpointFailpoint>,
    boundary: CheckpointFailpoint,
) -> Result<(), CheckpointError> {
    injected_io(configured, boundary)?;
    root.rename(from, CURRENT_FILE)?;
    Ok(())
}
