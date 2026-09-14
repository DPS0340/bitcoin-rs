use super::*;
use bitcoin_rs_storage::FjallStore;
use bitcoin_rs_storage::FlatFileBlockStore;
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::block_body::IndexedBlockBodyStore;
use std::cell::Cell;
use std::sync::Arc;

fn identity(height: u32) -> BlockIdentity {
    let mut hash = [0_u8; 32];
    hash[0..4].copy_from_slice(&height.to_le_bytes());
    BlockIdentity {
        height,
        hash,
        parent_hash: [0_u8; 32],
    }
}

fn body_store(
    dir: &std::path::Path,
) -> Result<IndexedBlockBodyStore<FjallStore>, Box<dyn std::error::Error>> {
    let index = Arc::new(FjallStore::open(dir.join("index"))?);
    let files = Arc::new(FlatFileBlockStore::open(dir)?);
    Ok(IndexedBlockBodyStore::new(index, files))
}

/// The store's prefetched-position cursor is consumed strictly in request
/// order: every `load_block_body` advances it. `load_body_prefix` must retain
/// every body it loads, so `identities` advances by exactly the positions the
/// cursor consumed (#1032).
#[test]
fn byte_cap_retains_every_body_the_cursor_consumed() -> Result<(), Box<dyn std::error::Error>> {
    // Three bodies of just over half the cap: the second reaches the cap.
    let size = PREPARE_CHUNK_BYTES / 2 + 1;
    let identities: Vec<BlockIdentity> = (0..3).map(identity).collect();

    let temp = tempfile::tempdir()?;
    let store = body_store(temp.path())?;
    for identity in &identities {
        store.persist_block_body(
            identity.height,
            Hash256::from_le_bytes(&identity.hash),
            &vec![0_u8; size],
        )?;
    }
    let requests: Vec<(u32, Hash256)> = identities
        .iter()
        .map(|identity| (identity.height, Hash256::from_le_bytes(&identity.hash)))
        .collect();
    let mut reader = store.reader()?;
    reader.prefetch_positions(&requests)?;

    let first = load_body_prefix(reader.as_mut(), &identities, &|| false)?
        .ok_or(StorageError::InvalidOperation("body missing"))?;
    assert_eq!(first.len(), 2);

    let rest = load_body_prefix(reader.as_mut(), &identities[first.len()..], &|| false)?
        .ok_or(StorageError::InvalidOperation("body missing"))?;
    assert_eq!(rest.len(), 1);

    // The cursor consumed all three prefetched positions; identities and the
    // reader are aligned.
    assert!(matches!(
        reader.load_block_body(
            identities[2].height,
            Hash256::from_le_bytes(&identities[2].hash)
        ),
        Err(StorageError::InvalidOperation(
            "prefetched body positions are exhausted"
        ))
    ));
    Ok(())
}

#[test]
fn count_cap_bounds_the_prefix() -> Result<(), Box<dyn std::error::Error>> {
    let count = u32::try_from(PREPARE_CHUNK_BLOCKS)
        .map_err(|_| StorageError::InvalidOperation("cap exceeds u32"))?;
    let identities: Vec<BlockIdentity> = (0..=count).map(identity).collect();

    let temp = tempfile::tempdir()?;
    let store = body_store(temp.path())?;
    for identity in &identities {
        store.persist_block_body(
            identity.height,
            Hash256::from_le_bytes(&identity.hash),
            &[0_u8],
        )?;
    }
    let requests: Vec<(u32, Hash256)> = identities
        .iter()
        .map(|identity| (identity.height, Hash256::from_le_bytes(&identity.hash)))
        .collect();
    let mut reader = store.reader()?;
    reader.prefetch_positions(&requests)?;

    let first = load_body_prefix(reader.as_mut(), &identities, &|| false)?
        .ok_or(StorageError::InvalidOperation("body missing"))?;
    assert_eq!(first.len(), PREPARE_CHUNK_BLOCKS);

    // Exactly `PREPARE_CHUNK_BLOCKS` positions were consumed; the next cursor
    // entry is identities[256].
    let next = reader.load_block_body(
        identities[PREPARE_CHUNK_BLOCKS].height,
        Hash256::from_le_bytes(&identities[PREPARE_CHUNK_BLOCKS].hash),
    )?;
    assert!(next.is_some());
    Ok(())
}

/// A mid-load shutdown keeps the bodies already read: the returned prefix is
/// still exactly the positions the cursor consumed.
#[test]
fn shutdown_keeps_the_prefix_aligned_with_the_cursor() -> Result<(), Box<dyn std::error::Error>> {
    let identities: Vec<BlockIdentity> = (0..3).map(identity).collect();

    let temp = tempfile::tempdir()?;
    let store = body_store(temp.path())?;
    for identity in &identities {
        store.persist_block_body(
            identity.height,
            Hash256::from_le_bytes(&identity.hash),
            &[0_u8],
        )?;
    }
    let requests: Vec<(u32, Hash256)> = identities
        .iter()
        .map(|identity| (identity.height, Hash256::from_le_bytes(&identity.hash)))
        .collect();
    let mut reader = store.reader()?;
    reader.prefetch_positions(&requests)?;

    // Shutdown is polled before each load; it fires on the second poll, so
    // only the first body is retained.
    let polls = Cell::new(0_u32);
    let should_stop = || {
        polls.set(polls.get() + 1);
        polls.get() >= 2
    };
    let prefix = load_body_prefix(reader.as_mut(), &identities, &should_stop)?
        .ok_or(StorageError::InvalidOperation("body missing"))?;
    assert_eq!(prefix.len(), 1);

    // The cursor sits at exactly position 1: loading identities[1] succeeds.
    let next = reader.load_block_body(
        identities[1].height,
        Hash256::from_le_bytes(&identities[1].hash),
    )?;
    assert!(next.is_some());
    Ok(())
}
