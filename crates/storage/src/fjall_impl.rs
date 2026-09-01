use std::path::Path;

use bytes::Bytes;
use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode, Readable};

use crate::{ColumnFamily, KvSnapshot, KvStore, StorageError, WriteBatch, WriteCondition};

/// Fjall's default block-cache capacity for unbudgeted opens.
const FJALL_DEFAULT_CACHE_BYTES: u64 = 32 * 1024 * 1024;

/// Fjall-backed key-value store.
pub struct FjallStore {
    db: Database,
    keyspaces: Vec<Keyspace>,
    // Non-reentrant: public mutators hold this lock while calling the lock-free batch helper.
    write_lock: parking_lot::Mutex<()>,
}

impl FjallStore {
    /// Opens or creates a Fjall store at `path` with one keyspace per column family.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::open_with_cache(path, FJALL_DEFAULT_CACHE_BYTES)
    }

    /// Opens or creates a Fjall store with an explicit block-cache capacity.
    ///
    /// `cache_bytes` sizes fjall's shared block cache and is configured
    /// exactly: a budgeted share is never raised above its allocation. Zero
    /// selects the engine default for unbudgeted opens.
    pub fn open_with_cache(path: impl AsRef<Path>, cache_bytes: u64) -> Result<Self, StorageError> {
        let cache_bytes = if cache_bytes == 0 {
            FJALL_DEFAULT_CACHE_BYTES
        } else {
            cache_bytes
        };
        metrics::gauge!("storage.cache_capacity_bytes", "backend" => "fjall")
            .set(crate::metric_f64(cache_bytes));
        let db = Database::builder(path.as_ref())
            .cache_size(cache_bytes)
            .open()
            .map_err(StorageError::backend)?;
        let mut keyspaces = Vec::with_capacity(ColumnFamily::ALL.len());
        for cf in ColumnFamily::ALL.iter().copied() {
            keyspaces.push(
                db.keyspace(cf.name(), KeyspaceCreateOptions::default)
                    .map_err(StorageError::backend)?,
            );
        }
        Ok(Self {
            db,
            keyspaces,
            write_lock: parking_lot::Mutex::new(()),
        })
    }

    fn keyspace(&self, cf: ColumnFamily) -> Result<&Keyspace, StorageError> {
        self.keyspaces
            .get(cf.index())
            .ok_or(StorageError::UnknownColumnFamily(cf))
    }

    fn write_with_durability(
        &self,
        batch: FjallWriteBatch,
        durability: Option<PersistMode>,
    ) -> Result<(), StorageError> {
        let durability_label = match durability {
            Some(PersistMode::SyncAll) => "durable",
            Some(_) => "deferred",
            None => "default",
        };
        metrics::counter!("storage.writes_total", "backend" => "fjall", "durability" => durability_label)
            .increment(1);
        metrics::histogram!("storage.write_bytes", "backend" => "fjall")
            .record(crate::metric_f64_from_usize(batch.encoded_bytes));
        let mut fjall_batch = self.db.batch();
        if let Some(durability) = durability {
            fjall_batch = fjall_batch.durability(Some(durability));
        }
        let mut keyspaces = [None; ColumnFamily::ALL.len()];
        for op in batch.ops {
            match op {
                BatchOp::Put { cf, key, value } => {
                    fjall_batch.insert(
                        cached_keyspace(self, &mut keyspaces, cf)?,
                        key,
                        value.as_ref(),
                    );
                }
                BatchOp::Delete { cf, key } => {
                    fjall_batch.remove(cached_keyspace(self, &mut keyspaces, cf)?, key);
                }
                BatchOp::DeleteRange { cf, start, end } => {
                    let keyspace = cached_keyspace(self, &mut keyspaces, cf)?;
                    let keys = keyspace
                        .range(start..end)
                        .map(|guard| {
                            guard
                                .key()
                                .map(|key| key.to_vec())
                                .map_err(StorageError::backend)
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    for key in keys {
                        fjall_batch.remove(keyspace, key);
                    }
                }
            }
        }
        fjall_batch.commit().map_err(StorageError::backend)
    }
}

impl KvStore for FjallStore {
    type WriteBatch = FjallWriteBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.keyspace(cf)?
            .get(key)
            .map(|value| value.map(|bytes| bytes.to_vec()))
            .map_err(StorageError::backend)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<crate::trait_::KvIter<'a>, StorageError> {
        let iterator = self.keyspace(cf)?.prefix(prefix).map(|guard| {
            guard
                .into_inner()
                .map(|(key, value)| (key.to_vec(), value.to_vec()))
                .map_err(StorageError::backend)
        });
        Ok(Box::new(iterator))
    }

    fn new_batch(&self) -> Self::WriteBatch {
        FjallWriteBatch::default()
    }

    fn put(&self, cf: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let _guard = self.write_lock.lock();
        self.keyspace(cf)?
            .insert(key, value)
            .map_err(StorageError::backend)
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        let _guard = self.write_lock.lock();
        self.write_with_durability(batch, None)
    }

    fn write_durable(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        let _guard = self.write_lock.lock();
        self.write_with_durability(batch, Some(PersistMode::SyncAll))
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: FjallWriteBatch,
    ) -> Result<bool, StorageError> {
        let _guard = self.write_lock.lock();
        let mut keyspaces = [None; ColumnFamily::ALL.len()];
        for condition in conditions {
            let (cf, key) = condition.location();
            let keyspace = cached_keyspace(self, &mut keyspaces, cf)?;
            let current = keyspace.get(key).map_err(StorageError::backend)?;
            if !condition.matches(current.as_ref().map(std::convert::AsRef::as_ref)) {
                return Ok(false);
            }
        }
        self.write_with_durability(batch, Some(PersistMode::SyncAll))?;
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        metrics::counter!("storage.flushes_total", "backend" => "fjall").increment(1);
        // Fjall journals are crash-consistent before fsync; SyncAll requests full durability.
        self.db
            .persist(PersistMode::SyncAll)
            .map_err(StorageError::backend)
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        Ok(Box::new(FjallSnapshot {
            store: self,
            snapshot: self.db.snapshot(),
        }))
    }
}

/// Measurement-only settle/accounting surface for benchmark harnesses.
///
/// Compiled only under the `fjall-measurement` feature; production builds
/// never carry these accessors, and none of them change store behavior.
#[cfg(feature = "fjall-measurement")]
impl FjallStore {
    /// Blocks until the column family's active memtable is rotated and
    /// flushed into L0 tables. A no-op when the memtable is already empty.
    pub fn settle_keyspace(&self, cf: ColumnFamily) -> Result<(), StorageError> {
        self.keyspace(cf)?
            .rotate_memtable_and_wait()
            .map_err(StorageError::backend)
    }

    /// Runs a blocking major compaction over the column family.
    pub fn major_compact_keyspace(&self, cf: ColumnFamily) -> Result<(), StorageError> {
        self.keyspace(cf)?
            .major_compact()
            .map_err(StorageError::backend)
    }

    /// Returns the table+blob disk bytes the backend attributes to this
    /// column family.
    pub fn keyspace_disk_bytes(&self, cf: ColumnFamily) -> Result<u64, StorageError> {
        Ok(self.keyspace(cf)?.disk_space())
    }

    /// Returns `(table_count, blob_file_count)` for this column family.
    pub fn keyspace_table_counts(&self, cf: ColumnFamily) -> Result<(usize, usize), StorageError> {
        let keyspace = self.keyspace(cf)?;
        Ok((keyspace.table_count(), keyspace.blob_file_count()))
    }
}

fn cached_keyspace<'store>(
    store: &'store FjallStore,
    keyspaces: &mut [Option<&'store Keyspace>],
    cf: ColumnFamily,
) -> Result<&'store Keyspace, StorageError> {
    let slot = keyspaces
        .get_mut(cf.index())
        .ok_or(StorageError::UnknownColumnFamily(cf))?;
    if slot.is_none() {
        *slot = Some(store.keyspace(cf)?);
    }
    slot.ok_or(StorageError::UnknownColumnFamily(cf))
}

/// Fjall write-batch adapter.
#[derive(Default)]
pub struct FjallWriteBatch {
    ops: Vec<BatchOp>,
    /// Sum of key and value lengths across ops, for write-path metrics.
    encoded_bytes: usize,
}

impl WriteBatch for FjallWriteBatch {
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]) {
        self.put_value(cf, key, Bytes::copy_from_slice(value));
    }

    fn put_value(&mut self, cf: ColumnFamily, key: &[u8], value: Bytes) {
        self.encoded_bytes = self.encoded_bytes.saturating_add(key.len() + value.len());
        self.ops.push(BatchOp::Put {
            cf,
            key: key.to_vec(),
            value,
        });
    }

    fn delete(&mut self, cf: ColumnFamily, key: &[u8]) {
        self.encoded_bytes = self.encoded_bytes.saturating_add(key.len());
        self.ops.push(BatchOp::Delete {
            cf,
            key: key.to_vec(),
        });
    }

    fn delete_range(&mut self, cf: ColumnFamily, start: &[u8], end: &[u8]) {
        self.ops.push(BatchOp::DeleteRange {
            cf,
            start: start.to_vec(),
            end: end.to_vec(),
        });
    }
}

enum BatchOp {
    Put {
        cf: ColumnFamily,
        key: Vec<u8>,
        value: Bytes,
    },
    Delete {
        cf: ColumnFamily,
        key: Vec<u8>,
    },
    DeleteRange {
        cf: ColumnFamily,
        start: Vec<u8>,
        end: Vec<u8>,
    },
}

struct FjallSnapshot<'a> {
    store: &'a FjallStore,
    snapshot: fjall::Snapshot,
}

impl KvSnapshot for FjallSnapshot<'_> {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.snapshot
            .get(self.store.keyspace(cf)?, key)
            .map(|value| value.map(|bytes| bytes.to_vec()))
            .map_err(StorageError::backend)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<crate::trait_::KvIter<'a>, StorageError> {
        let iterator = self
            .snapshot
            .prefix(self.store.keyspace(cf)?, prefix)
            .map(|guard| {
                guard
                    .into_inner()
                    .map(|(key, value)| (key.to_vec(), value.to_vec()))
                    .map_err(StorageError::backend)
            });
        Ok(Box::new(iterator))
    }
}
