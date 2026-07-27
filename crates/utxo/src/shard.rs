use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use crossbeam_utils::CachePadded;
use hashbrown::HashTable;
use parking_lot::RwLock;
use smallvec::SmallVec;

use crate::{
    UtxoError, UtxoKey,
    record::{OneUtxoOut, OwnedUtxoOut, UtxoRecord, bitmap_vout_bit},
    set::{
        BuildPayload, ScannedUtxo, SpendPayload, UtxoAddView, UtxoChangeEvents, UtxoChangeListener,
        UtxoInserted, UtxoRemoved, UtxoScan,
    },
};

/// Per-shard hash table of owned UTXO records.
pub struct ShardTable {
    /// Hash table of heap-owned UTXO records.
    pub table: HashTable<Box<UtxoRecord>>,
}

impl ShardTable {
    fn new() -> Self {
        Self {
            table: HashTable::new(),
        }
    }

    pub(crate) fn record_count(&self) -> usize {
        self.table.len()
    }

    pub(crate) fn output_count(&self) -> usize {
        self.table.iter().map(|record| record.output_count()).sum()
    }
}

/// One live UTXO output with the metadata consensus consumers need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveOutput {
    /// The transaction output script + value.
    pub txout: TxOut,
    /// Whether the originating transaction was a coinbase.
    pub coinbase: bool,
    /// Block height at which this output was created.
    pub height: u32,
}

/// One live UTXO output's metadata without script or value materialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveOutputMeta {
    /// Whether the originating transaction was a coinbase.
    pub coinbase: bool,
    /// Block height at which this output was created.
    pub height: u32,
}

/// One cache-padded, lock-protected UTXO shard.
pub struct Shard {
    inner: CachePadded<RwLock<ShardTable>>,
}

impl Shard {
    /// Builds an empty shard.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: CachePadded::new(RwLock::new(ShardTable::new())),
        }
    }

    pub(crate) fn commit_batch(
        &self,
        adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
        removes: &[SpendPayload<'_>],
        listener: Option<&(dyn UtxoChangeListener + Send + Sync)>,
    ) -> Result<(), UtxoError> {
        let mut table = self.inner.write();
        if listener.is_some() {
            commit_batch_with_listener(&mut table, adds, removes, listener)
        } else {
            commit_batch_coalesced(&mut table, adds, removes)
        }
    }

    pub(crate) fn commit_batch_collect_events<'a>(
        &self,
        adds: &'a [(UtxoKey, Hash256, BuildPayload<'a>)],
        removes: &[SpendPayload<'_>],
        coalesce_events: bool,
    ) -> (UtxoChangeEvents<'a>, Result<(), UtxoError>) {
        let mut table = self.inner.write();
        commit_batch_collect_events(&mut table, adds, removes, coalesce_events)
    }

    pub(crate) fn commit_single_shard_batch<A: UtxoAddView>(
        &self,
        adds: &[A],
        removes: &[OutPoint],
        shard_idx: usize,
    ) -> Result<(), UtxoError> {
        let mut table = self.inner.write();
        commit_single_shard_coalesced(&mut table, adds, removes, shard_idx)
    }

    pub(crate) fn commit_single_shard_batch_with_listener<A: UtxoAddView>(
        &self,
        adds: &[A],
        removes: &[OutPoint],
        shard_idx: usize,
        listener: &(dyn UtxoChangeListener + Send + Sync),
    ) -> Result<(), UtxoError> {
        let mut table = self.inner.write();
        commit_single_shard_with_listener(&mut table, adds, removes, shard_idx, listener)
    }

    /// Returns an owned transaction output if `key:vout` is live in this shard.
    #[must_use]
    pub fn get(&self, key: &UtxoKey, txid: &Hash256, vout: u32) -> Option<TxOut> {
        let table = self.inner.read();
        let record = table.table.find(key.hash(), |record| {
            record.key() == *key && record.txid() == *txid
        })?;
        let output = record.find_output(vout)?;
        let script = record.script_slice(output)?;
        Some(txout_from_parts(output.value, script))
    }

    /// Returns the full live-output entry (txout + coinbase + height)
    /// if `key:vout` is live in this shard.
    #[must_use]
    pub fn get_entry(&self, key: &UtxoKey, txid: &Hash256, vout: u32) -> Option<LiveOutput> {
        let table = self.inner.read();
        let record = table.table.find(key.hash(), |record| {
            record.key() == *key && record.txid() == *txid
        })?;
        let output = record.find_output(vout)?;
        let script = record.script_slice(output)?;
        Some(LiveOutput {
            txout: txout_from_parts(output.value, script),
            coinbase: output.coinbase,
            height: output.height,
        })
    }

    /// Returns live-output metadata without materializing script bytes.
    #[must_use]
    pub fn get_meta(&self, key: &UtxoKey, txid: &Hash256, vout: u32) -> Option<LiveOutputMeta> {
        let table = self.inner.read();
        let record = table.table.find(key.hash(), |record| {
            record.key() == *key && record.txid() == *txid
        })?;
        let output = record.find_output(vout)?;
        Some(LiveOutputMeta {
            coinbase: output.coinbase,
            height: output.height,
        })
    }

    /// Returns true when this shard has any live output for `txid`.
    #[must_use]
    pub fn has_live_outputs_for_txid(&self, key: &UtxoKey, txid: &Hash256) -> bool {
        let table = self.inner.read();
        table
            .table
            .find(key.hash(), |record| {
                record.key() == *key && record.txid() == *txid
            })
            .is_some_and(|record| !record.is_empty())
    }

    pub(crate) fn with_table<R>(&self, f: impl FnOnce(&ShardTable) -> R) -> R {
        let table = self.inner.read();
        f(&table)
    }

    pub(crate) fn scan_script_pubkeys(
        &self,
        scripts: &[ScriptBuf],
        scan: &mut UtxoScan,
    ) -> Result<(), UtxoError> {
        let table = self.inner.read();
        for record in &table.table {
            for output in record.iter_outputs() {
                scan.txouts = scan.txouts.saturating_add(1);
                let script = record.script_slice(output).ok_or(UtxoError::CorruptArena)?;
                if scripts.iter().any(|target| target.as_bytes() == script) {
                    scan.unspents.push(ScannedUtxo {
                        outpoint: OutPoint::new(record.txid(), output.vout),
                        txout: txout_from_parts(output.value, script),
                        coinbase: output.coinbase,
                        height: output.height,
                    });
                }
            }
        }
        Ok(())
    }

    pub(crate) fn record_count(&self) -> usize {
        let table = self.inner.read();
        table.record_count()
    }

    pub(crate) fn output_count(&self) -> usize {
        let table = self.inner.read();
        table.output_count()
    }

    pub(crate) fn insert_owned_record(
        &self,
        key: UtxoKey,
        txid: Hash256,
        outputs: &[OwnedUtxoOut],
    ) -> Result<(), UtxoError> {
        // Build the complete replacement record off-table so a bad snapshot
        // script cannot erase the old record.
        let mut record = UtxoRecord::new(txid);
        for output in outputs {
            let script_len = u16::try_from(output.script_pubkey.len()).map_err(|_| {
                UtxoError::ScriptTooLarge {
                    len: output.script_pubkey.len(),
                }
            })?;
            record.prepare_script_append(output.script_pubkey.len())?;
            let (offset, _len) = record.append_script(&output.script_pubkey)?;
            record.add_output(OneUtxoOut {
                vout: output.vout,
                value: output.value,
                script_pubkey_offset: offset,
                script_pubkey_len: script_len,
                coinbase: output.coinbase,
                height: output.height,
            });
        }
        if record.is_empty() {
            return Ok(());
        }
        let mut table = self.inner.write();
        // Now replace or insert atomically.
        let entry = table
            .table
            .find_entry(key.hash(), |r| r.key() == key && r.txid() == txid);
        match entry {
            Ok(occ) => {
                **occ.into_mut() = record;
            }
            Err(absent) => {
                let table = absent.into_table();
                table.insert_unique(key.hash(), Box::new(record), |record| record.key().hash());
            }
        }
        Ok(())
    }
}

impl Default for Shard {
    fn default() -> Self {
        Self::new()
    }
}

fn commit_batch_with_listener(
    table: &mut ShardTable,
    adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
    removes: &[SpendPayload<'_>],
    listener: Option<&(dyn UtxoChangeListener + Send + Sync)>,
) -> Result<(), UtxoError> {
    let Some(listener) = listener else {
        return commit_batch_coalesced(table, adds, removes);
    };

    let mut remaining_removes = removes;
    while let Some((first, rest)) = remaining_removes.split_first() {
        let run_len = rest
            .iter()
            .take_while(|remove| remove.key == first.key && remove.txid == first.txid)
            .count()
            .saturating_add(1);
        apply_remove_run_with_listener(table, &remaining_removes[..run_len], listener)?;
        remaining_removes = &remaining_removes[run_len..];
    }

    let mut remaining_adds = adds;
    while let Some(((key, txid, _payload), rest)) = remaining_adds.split_first() {
        let run_len = rest
            .iter()
            .take_while(|(next_key, next_txid, _payload)| next_key == key && next_txid == txid)
            .count()
            .saturating_add(1);
        apply_add_run_with_listener(table, *key, *txid, &remaining_adds[..run_len], listener)?;
        remaining_adds = &remaining_adds[run_len..];
    }
    Ok(())
}

fn commit_batch_collect_events<'a>(
    table: &mut ShardTable,
    adds: &'a [(UtxoKey, Hash256, BuildPayload<'a>)],
    removes: &[SpendPayload<'_>],
    coalesce_events: bool,
) -> (UtxoChangeEvents<'a>, Result<(), UtxoError>) {
    let mut events = if coalesce_events {
        UtxoChangeEvents::with_coalesced_capacity(adds.len(), removes.len())
    } else {
        UtxoChangeEvents::default()
    };
    let mut remaining_removes = removes;
    while let Some((first, rest)) = remaining_removes.split_first() {
        let run_len = rest
            .iter()
            .take_while(|remove| remove.key == first.key && remove.txid == first.txid)
            .count()
            .saturating_add(1);
        if let Err(error) = apply_remove_run_collect_events(
            table,
            &remaining_removes[..run_len],
            &mut events,
            coalesce_events,
        ) {
            return (events, Err(error));
        }
        remaining_removes = &remaining_removes[run_len..];
    }

    reserve_add_runs(table, coalesced_add_run_count(adds));
    let mut remaining_adds = adds;
    while let Some(((key, txid, _payload), rest)) = remaining_adds.split_first() {
        let run_len = rest
            .iter()
            .take_while(|(next_key, next_txid, _payload)| next_key == key && next_txid == txid)
            .count()
            .saturating_add(1);
        if let Err(error) = apply_add_run_collect_events(
            table,
            *key,
            *txid,
            &remaining_adds[..run_len],
            &mut events,
            coalesce_events,
        ) {
            return (events, Err(error));
        }
        remaining_adds = &remaining_adds[run_len..];
    }
    (events, Ok(()))
}

fn commit_batch_coalesced(
    table: &mut ShardTable,
    adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
    removes: &[SpendPayload<'_>],
) -> Result<(), UtxoError> {
    let mut remaining_removes = removes;
    while let Some((first, rest)) = remaining_removes.split_first() {
        let run_len = rest
            .iter()
            .take_while(|remove| remove.key == first.key && remove.txid == first.txid)
            .count()
            .saturating_add(1);
        apply_remove_run(table, &remaining_removes[..run_len])?;
        remaining_removes = &remaining_removes[run_len..];
    }

    reserve_add_runs(table, coalesced_add_run_count(adds));
    let mut remaining_adds = adds;
    while let Some(((key, txid, _payload), rest)) = remaining_adds.split_first() {
        let run_len = rest
            .iter()
            .take_while(|(next_key, next_txid, _payload)| next_key == key && next_txid == txid)
            .count()
            .saturating_add(1);
        apply_add_run(table, *key, *txid, &remaining_adds[..run_len])?;
        remaining_adds = &remaining_adds[run_len..];
    }
    Ok(())
}

fn commit_single_shard_coalesced<A: UtxoAddView>(
    table: &mut ShardTable,
    adds: &[A],
    removes: &[OutPoint],
    shard_idx: usize,
) -> Result<(), UtxoError> {
    let mut remaining_removes = removes;
    while let Some((first, rest)) = remaining_removes.split_first() {
        let key = UtxoKey::from_txid(&first.txid);
        debug_assert_eq!(usize::from(key.shard()), shard_idx);
        let run_len = rest
            .iter()
            .take_while(|remove| remove.txid == first.txid)
            .count()
            .saturating_add(1);
        apply_outpoint_remove_run(table, key, first.txid, &remaining_removes[..run_len])?;
        remaining_removes = &remaining_removes[run_len..];
    }

    reserve_add_runs(table, utxo_add_run_count(adds));
    let mut remaining_adds = adds;
    while let Some((first, rest)) = remaining_adds.split_first() {
        let key = UtxoKey::from_txid(&first.outpoint().txid);
        debug_assert_eq!(usize::from(key.shard()), shard_idx);
        let run_len = rest
            .iter()
            .take_while(|add| add.outpoint().txid == first.outpoint().txid)
            .count()
            .saturating_add(1);
        apply_utxo_add_run(
            table,
            key,
            first.outpoint().txid,
            &remaining_adds[..run_len],
        )?;
        remaining_adds = &remaining_adds[run_len..];
    }
    Ok(())
}

fn commit_single_shard_with_listener<A: UtxoAddView>(
    table: &mut ShardTable,
    adds: &[A],
    removes: &[OutPoint],
    shard_idx: usize,
    listener: &(dyn UtxoChangeListener + Send + Sync),
) -> Result<(), UtxoError> {
    let mut remaining_removes = removes;
    while let Some((first, rest)) = remaining_removes.split_first() {
        let key = UtxoKey::from_txid(&first.txid);
        debug_assert_eq!(usize::from(key.shard()), shard_idx);
        let run_len = rest
            .iter()
            .take_while(|remove| remove.txid == first.txid)
            .count()
            .saturating_add(1);
        apply_outpoint_remove_run_with_listener(
            table,
            key,
            first.txid,
            &remaining_removes[..run_len],
            listener,
        )?;
        remaining_removes = &remaining_removes[run_len..];
    }

    reserve_add_runs(table, utxo_add_run_count(adds));
    let mut remaining_adds = adds;
    while let Some((first, rest)) = remaining_adds.split_first() {
        let key = UtxoKey::from_txid(&first.outpoint().txid);
        debug_assert_eq!(usize::from(key.shard()), shard_idx);
        let run_len = rest
            .iter()
            .take_while(|add| add.outpoint().txid == first.outpoint().txid)
            .count()
            .saturating_add(1);
        apply_utxo_add_run_with_listener(
            table,
            key,
            first.outpoint().txid,
            &remaining_adds[..run_len],
            listener,
        )?;
        remaining_adds = &remaining_adds[run_len..];
    }
    Ok(())
}

fn reserve_add_runs(table: &mut ShardTable, additional_runs: usize) {
    if additional_runs != 0 {
        table
            .table
            .reserve(additional_runs, |record| record.key().hash());
    }
}

fn coalesced_add_run_count(adds: &[(UtxoKey, Hash256, BuildPayload<'_>)]) -> usize {
    let mut run_count = 0usize;
    let mut remaining_adds = adds;
    while let Some(((key, txid, _payload), rest)) = remaining_adds.split_first() {
        let run_len = rest
            .iter()
            .take_while(|(next_key, next_txid, _payload)| next_key == key && next_txid == txid)
            .count()
            .saturating_add(1);
        run_count = run_count.saturating_add(1);
        remaining_adds = &remaining_adds[run_len..];
    }
    run_count
}

fn utxo_add_run_count<A: UtxoAddView>(adds: &[A]) -> usize {
    let mut run_count = 0usize;
    let mut remaining_adds = adds;
    while let Some((first, rest)) = remaining_adds.split_first() {
        let run_len = rest
            .iter()
            .take_while(|add| add.outpoint().txid == first.outpoint().txid)
            .count()
            .saturating_add(1);
        run_count = run_count.saturating_add(1);
        remaining_adds = &remaining_adds[run_len..];
    }
    run_count
}

fn apply_remove_run(table: &mut ShardTable, removes: &[SpendPayload<'_>]) -> Result<(), UtxoError> {
    let Some(first) = removes.first() else {
        return Ok(());
    };
    if delete_record_if_fully_spent(
        table,
        first.key,
        first.txid,
        removes.len(),
        |index| removes[index].vout,
        |vout| removes.iter().any(|remove| remove.vout == vout),
    ) {
        return Ok(());
    }
    let Some(record) = find_record_mut(table, first.key, first.txid) else {
        return Ok(());
    };
    for remove in removes {
        let _removed = record.remove_output(remove.vout);
    }
    if record.is_empty() {
        remove_record(table, first.key, first.txid);
    } else {
        record.compact_scripts_if_needed()?;
        record.shrink_outputs_if_needed();
    }
    Ok(())
}
fn apply_outpoint_remove_run(
    table: &mut ShardTable,
    key: UtxoKey,
    txid: Hash256,
    removes: &[OutPoint],
) -> Result<(), UtxoError> {
    if delete_record_if_fully_spent(
        table,
        key,
        txid,
        removes.len(),
        |index| removes[index].vout,
        |vout| removes.iter().any(|remove| remove.vout == vout),
    ) {
        return Ok(());
    }
    let Some(record) = find_record_mut(table, key, txid) else {
        return Ok(());
    };
    for remove in removes {
        let _removed = record.remove_output(remove.vout);
    }
    if record.is_empty() {
        remove_record(table, key, txid);
    } else {
        record.compact_scripts_if_needed()?;
        record.shrink_outputs_if_needed();
    }
    Ok(())
}
fn apply_remove_run_with_listener(
    table: &mut ShardTable,
    removes: &[SpendPayload<'_>],
    listener: &(dyn UtxoChangeListener + Send + Sync),
) -> Result<(), UtxoError> {
    let Some(first) = removes.first() else {
        return Ok(());
    };
    if let Some(removed_coins) = remove_full_record_removals_by_order::<[UtxoRemoved; 2]>(
        table,
        first.key,
        first.txid,
        removes.len(),
        |index| removes[index].vout,
        |index| *removes[index].op,
    ) {
        listener.on_remove_coins(&removed_coins);
        return Ok(());
    }
    let Some(record) = find_record_mut(table, first.key, first.txid) else {
        return Ok(());
    };
    let mut removed_coins = SmallVec::<[UtxoRemoved; 2]>::with_capacity(removes.len());
    for remove in removes {
        if let Some(removed_output) = record.remove_output(remove.vout)
            && let Some((txout, height, coinbase)) = output_details(record, &removed_output)
        {
            removed_coins.push(UtxoRemoved::new(*remove.op, txout, height, coinbase));
        }
    }
    listener.on_remove_coins(&removed_coins);
    if record.is_empty() {
        remove_record(table, first.key, first.txid);
    } else {
        record.compact_scripts_if_needed()?;
        record.shrink_outputs_if_needed();
    }
    Ok(())
}
fn apply_remove_run_collect_events(
    table: &mut ShardTable,
    removes: &[SpendPayload<'_>],
    events: &mut UtxoChangeEvents<'_>,
    coalesce_events: bool,
) -> Result<(), UtxoError> {
    let Some(first) = removes.first() else {
        return Ok(());
    };
    if let Some(removed_coins) = remove_full_record_removals_by_order::<[UtxoRemoved; 2]>(
        table,
        first.key,
        first.txid,
        removes.len(),
        |index| removes[index].vout,
        |index| *removes[index].op,
    ) {
        if coalesce_events {
            events.push_remove_batch_coalesced(removed_coins);
        } else {
            events.push_remove_batch(removed_coins);
        }
        return Ok(());
    }
    let Some(record) = find_record_mut(table, first.key, first.txid) else {
        return Ok(());
    };
    let mut removed_coins = SmallVec::<[UtxoRemoved; 2]>::with_capacity(removes.len());
    for remove in removes {
        if let Some(removed_output) = record.remove_output(remove.vout)
            && let Some((txout, height, coinbase)) = output_details(record, &removed_output)
        {
            removed_coins.push(UtxoRemoved::new(*remove.op, txout, height, coinbase));
        }
    }
    if coalesce_events {
        events.push_remove_batch_coalesced(removed_coins);
    } else {
        events.push_remove_batch(removed_coins);
    }
    if record.is_empty() {
        remove_record(table, first.key, first.txid);
    } else {
        record.compact_scripts_if_needed()?;
        record.shrink_outputs_if_needed();
    }
    Ok(())
}
fn apply_outpoint_remove_run_with_listener(
    table: &mut ShardTable,
    key: UtxoKey,
    txid: Hash256,
    removes: &[OutPoint],
    listener: &(dyn UtxoChangeListener + Send + Sync),
) -> Result<(), UtxoError> {
    if let Some(removed_coins) = remove_full_record_removals_by_order::<[UtxoRemoved; 8]>(
        table,
        key,
        txid,
        removes.len(),
        |index| removes[index].vout,
        |index| removes[index],
    ) {
        listener.on_remove_coins(&removed_coins);
        return Ok(());
    }
    let Some(record) = find_record_mut(table, key, txid) else {
        return Ok(());
    };
    let mut removed_coins = SmallVec::<[UtxoRemoved; 8]>::with_capacity(removes.len());
    for remove in removes {
        if let Some(removed_output) = record.remove_output(remove.vout)
            && let Some((txout, height, coinbase)) = output_details(record, &removed_output)
        {
            removed_coins.push(UtxoRemoved::new(*remove, txout, height, coinbase));
        }
    }
    listener.on_remove_coins(&removed_coins);
    if record.is_empty() {
        remove_record(table, key, txid);
    } else {
        record.compact_scripts_if_needed()?;
        record.shrink_outputs_if_needed();
    }
    Ok(())
}
fn remove_full_record_removals_by_order<A>(
    table: &mut ShardTable,
    key: UtxoKey,
    txid: Hash256,
    remove_count: usize,
    remove_vout: impl FnMut(usize) -> u32,
    remove_outpoint: impl FnMut(usize) -> OutPoint,
) -> Option<SmallVec<A>>
where
    A: smallvec::Array<Item = UtxoRemoved>,
{
    let entry = table
        .table
        .find_entry(key.hash(), |record| {
            record.key() == key && record.txid() == txid
        })
        .ok()?;
    let removed_coins = full_record_removals_by_order::<A>(
        entry.get(),
        remove_count,
        remove_vout,
        remove_outpoint,
    )?;
    let (_record, _vacant) = entry.remove();
    Some(removed_coins)
}

fn full_record_removals_by_order<A>(
    record: &UtxoRecord,
    remove_count: usize,
    mut remove_vout: impl FnMut(usize) -> u32,
    mut remove_outpoint: impl FnMut(usize) -> OutPoint,
) -> Option<SmallVec<A>>
where
    A: smallvec::Array<Item = UtxoRemoved>,
{
    if record.output_count() != remove_count
        || usize::try_from(record.vout_bitmap.count_ones()).ok()? != remove_count
    {
        return None;
    }

    let mut outputs = [None; 64];
    let mut record_bitmap = 0_u64;
    for output in record.iter_outputs() {
        let bit = bitmap_vout_bit(output.vout)?;
        let index = usize::try_from(output.vout).ok()?;
        if outputs[index].replace(*output).is_some() {
            return None;
        }
        record_bitmap |= bit;
    }
    if record_bitmap != record.vout_bitmap {
        return None;
    }

    let mut remove_bitmap = 0_u64;
    let mut removed_coins = SmallVec::<A>::with_capacity(remove_count);
    for index in 0..remove_count {
        let vout = remove_vout(index);
        let bit = bitmap_vout_bit(vout)?;
        if remove_bitmap & bit != 0 {
            return None;
        }
        remove_bitmap |= bit;
        let output = outputs[usize::try_from(vout).ok()?]?;
        let (txout, height, coinbase) = output_details(record, &output)?;
        removed_coins.push(UtxoRemoved::new(
            remove_outpoint(index),
            txout,
            height,
            coinbase,
        ));
    }

    (remove_bitmap == record.vout_bitmap).then_some(removed_coins)
}

fn apply_add_run(
    table: &mut ShardTable,
    key: UtxoKey,
    txid: Hash256,
    adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
) -> Result<(), UtxoError> {
    let add_unique = build_adds_extend_record_vouts(
        table,
        key,
        txid,
        adds.iter().map(|(_key, _txid, payload)| payload.vout),
    );
    let Some(record) = find_record_mut(table, key, txid) else {
        // New record: build off-table, then insert.
        let mut record = UtxoRecord::new(txid);
        prepare_add_run(&mut record, adds, add_unique)?;
        apply_add_run_outputs(&mut record, adds, add_unique)?;
        insert_record(table, record);
        return Ok(());
    };
    prepare_add_run(record, adds, add_unique)?;
    apply_add_run_outputs(record, adds, add_unique)?;
    record.compact_scripts_if_needed()?;
    Ok(())
}

fn apply_utxo_add_run<A: UtxoAddView>(
    table: &mut ShardTable,
    key: UtxoKey,
    txid: Hash256,
    adds: &[A],
) -> Result<(), UtxoError> {
    let add_unique = build_adds_extend_record_vouts(
        table,
        key,
        txid,
        adds.iter().map(|add| add.outpoint().vout),
    );
    let Some(record) = find_record_mut(table, key, txid) else {
        let mut record = UtxoRecord::new(txid);
        prepare_utxo_add_run(&mut record, adds, add_unique)?;
        apply_utxo_add_run_outputs(&mut record, adds, add_unique)?;
        insert_record(table, record);
        return Ok(());
    };
    prepare_utxo_add_run(record, adds, add_unique)?;
    apply_utxo_add_run_outputs(record, adds, add_unique)?;
    record.compact_scripts_if_needed()?;
    Ok(())
}

fn apply_utxo_add_run_with_listener<A: UtxoAddView>(
    table: &mut ShardTable,
    key: UtxoKey,
    txid: Hash256,
    adds: &[A],
    listener: &(dyn UtxoChangeListener + Send + Sync),
) -> Result<(), UtxoError> {
    let add_unique = build_adds_extend_record_vouts(
        table,
        key,
        txid,
        adds.iter().map(|add| add.outpoint().vout),
    );
    let Some(record) = find_record_mut(table, key, txid) else {
        // New record with listener.
        let mut record = UtxoRecord::new(txid);
        prepare_utxo_add_run(&mut record, adds, add_unique)?;
        if add_unique && let [add] = adds {
            let payload = add.payload();
            apply_single_unique_add(&mut record, &payload)?;
            insert_record(table, record);
            let inserted_coin = UtxoInserted::new(
                payload.outpoint,
                payload.txout,
                payload.height,
                payload.coinbase,
            );
            listener.on_insert_coins(core::slice::from_ref(&inserted_coin));
            return Ok(());
        }
        let mut inserted_coins = SmallVec::<[UtxoInserted<'_>; 8]>::with_capacity(adds.len());
        for add in adds {
            let payload = add.payload();
            if add_unique {
                apply_single_unique_add(&mut record, &payload)?;
            } else {
                let overwritten = match record.find_output(payload.vout) {
                    Some(output) => {
                        Some(output_details(&record, output).ok_or(UtxoError::CorruptArena)?)
                    }
                    None => None,
                };
                apply_single_overwrite_add(&mut record, &payload)?;
                if let Some((txout, height, coinbase)) = overwritten {
                    flush_inserted_coins(listener, &mut inserted_coins);
                    listener.on_remove_coin(payload.outpoint, &txout, height, coinbase);
                }
            }
            inserted_coins.push(UtxoInserted::new(
                payload.outpoint,
                payload.txout,
                payload.height,
                payload.coinbase,
            ));
        }
        insert_record(table, record);
        flush_inserted_coins(listener, &mut inserted_coins);
        return Ok(());
    };
    // Existing record with listener.
    prepare_utxo_add_run(record, adds, add_unique)?;
    if add_unique && let [add] = adds {
        let payload = add.payload();
        apply_single_unique_add(record, &payload)?;
        let inserted_coin = UtxoInserted::new(
            payload.outpoint,
            payload.txout,
            payload.height,
            payload.coinbase,
        );
        listener.on_insert_coins(core::slice::from_ref(&inserted_coin));
        return Ok(());
    }
    let mut inserted_coins = SmallVec::<[UtxoInserted<'_>; 8]>::with_capacity(adds.len());
    for add in adds {
        let payload = add.payload();
        if add_unique {
            apply_single_unique_add(record, &payload)?;
        } else {
            let overwritten = match record.find_output(payload.vout) {
                Some(output) => {
                    Some(output_details(record, output).ok_or(UtxoError::CorruptArena)?)
                }
                None => None,
            };
            apply_single_overwrite_add(record, &payload)?;
            if let Some((txout, height, coinbase)) = overwritten {
                flush_inserted_coins(listener, &mut inserted_coins);
                listener.on_remove_coin(payload.outpoint, &txout, height, coinbase);
            }
        }
        inserted_coins.push(UtxoInserted::new(
            payload.outpoint,
            payload.txout,
            payload.height,
            payload.coinbase,
        ));
    }
    record.compact_scripts_if_needed()?;
    flush_inserted_coins(listener, &mut inserted_coins);
    Ok(())
}

fn apply_add_run_with_listener(
    table: &mut ShardTable,
    key: UtxoKey,
    txid: Hash256,
    adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
    listener: &(dyn UtxoChangeListener + Send + Sync),
) -> Result<(), UtxoError> {
    let add_unique = build_adds_extend_record_vouts(
        table,
        key,
        txid,
        adds.iter().map(|(_key, _txid, payload)| payload.vout),
    );
    let Some(record) = find_record_mut(table, key, txid) else {
        let mut record = UtxoRecord::new(txid);
        prepare_add_run(&mut record, adds, add_unique)?;
        if add_unique && let [(_key, _txid, payload)] = adds {
            apply_single_unique_add(&mut record, payload)?;
            insert_record(table, record);
            let inserted_coin = UtxoInserted::new(
                payload.outpoint,
                payload.txout,
                payload.height,
                payload.coinbase,
            );
            listener.on_insert_coins(core::slice::from_ref(&inserted_coin));
            return Ok(());
        }
        let mut inserted_coins = SmallVec::<[UtxoInserted<'_>; 8]>::with_capacity(adds.len());
        for (_key, _txid, payload) in adds {
            if add_unique {
                apply_single_unique_add(&mut record, payload)?;
            } else {
                let overwritten = match record.find_output(payload.vout) {
                    Some(output) => {
                        Some(output_details(&record, output).ok_or(UtxoError::CorruptArena)?)
                    }
                    None => None,
                };
                apply_single_overwrite_add(&mut record, payload)?;
                if let Some((txout, height, coinbase)) = overwritten {
                    flush_inserted_coins(listener, &mut inserted_coins);
                    listener.on_remove_coin(payload.outpoint, &txout, height, coinbase);
                }
            }
            inserted_coins.push(UtxoInserted::new(
                payload.outpoint,
                payload.txout,
                payload.height,
                payload.coinbase,
            ));
        }
        insert_record(table, record);
        flush_inserted_coins(listener, &mut inserted_coins);
        return Ok(());
    };
    prepare_add_run(record, adds, add_unique)?;
    if add_unique && let [(_key, _txid, payload)] = adds {
        apply_single_unique_add(record, payload)?;
        let inserted_coin = UtxoInserted::new(
            payload.outpoint,
            payload.txout,
            payload.height,
            payload.coinbase,
        );
        listener.on_insert_coins(core::slice::from_ref(&inserted_coin));
        return Ok(());
    }
    let mut inserted_coins = SmallVec::<[UtxoInserted<'_>; 8]>::with_capacity(adds.len());
    for (_key, _txid, payload) in adds {
        if add_unique {
            apply_single_unique_add(record, payload)?;
        } else {
            let overwritten = match record.find_output(payload.vout) {
                Some(output) => {
                    Some(output_details(record, output).ok_or(UtxoError::CorruptArena)?)
                }
                None => None,
            };
            apply_single_overwrite_add(record, payload)?;
            if let Some((txout, height, coinbase)) = overwritten {
                flush_inserted_coins(listener, &mut inserted_coins);
                listener.on_remove_coin(payload.outpoint, &txout, height, coinbase);
            }
        }
        inserted_coins.push(UtxoInserted::new(
            payload.outpoint,
            payload.txout,
            payload.height,
            payload.coinbase,
        ));
    }
    record.compact_scripts_if_needed()?;
    flush_inserted_coins(listener, &mut inserted_coins);
    Ok(())
}

fn apply_add_run_collect_events<'add>(
    table: &mut ShardTable,
    key: UtxoKey,
    txid: Hash256,
    adds: &'add [(UtxoKey, Hash256, BuildPayload<'add>)],
    events: &mut UtxoChangeEvents<'add>,
    coalesce_events: bool,
) -> Result<(), UtxoError> {
    let add_unique = build_adds_extend_record_vouts(
        table,
        key,
        txid,
        adds.iter().map(|(_key, _txid, payload)| payload.vout),
    );
    let Some(record) = find_record_mut(table, key, txid) else {
        let mut record = UtxoRecord::new(txid);
        prepare_add_run(&mut record, adds, add_unique)?;
        if add_unique && coalesce_events {
            for (_key, _txid, payload) in adds {
                apply_single_unique_add(&mut record, payload)?;
                events.push_insert_coin_coalesced(UtxoInserted::new(
                    payload.outpoint,
                    payload.txout,
                    payload.height,
                    payload.coinbase,
                ));
            }
            insert_record(table, record);
            return Ok(());
        }
        let mut inserted_coins = SmallVec::<[UtxoInserted<'_>; 8]>::with_capacity(adds.len());
        for (_key, _txid, payload) in adds {
            if add_unique {
                apply_single_unique_add(&mut record, payload)?;
            } else {
                let overwritten = match record.find_output(payload.vout) {
                    Some(output) => {
                        Some(output_details(&record, output).ok_or(UtxoError::CorruptArena)?)
                    }
                    None => None,
                };
                apply_single_overwrite_add(&mut record, payload)?;
                if let Some((txout, height, coinbase)) = overwritten {
                    flush_inserted_events(events, &mut inserted_coins, coalesce_events);
                    events.push_remove_coin(UtxoRemoved::new(
                        *payload.outpoint,
                        txout,
                        height,
                        coinbase,
                    ));
                }
            }
            inserted_coins.push(UtxoInserted::new(
                payload.outpoint,
                payload.txout,
                payload.height,
                payload.coinbase,
            ));
        }
        insert_record(table, record);
        flush_inserted_events(events, &mut inserted_coins, coalesce_events);
        return Ok(());
    };
    prepare_add_run(record, adds, add_unique)?;
    if add_unique && coalesce_events {
        for (_key, _txid, payload) in adds {
            apply_single_unique_add(record, payload)?;
            events.push_insert_coin_coalesced(UtxoInserted::new(
                payload.outpoint,
                payload.txout,
                payload.height,
                payload.coinbase,
            ));
        }
        return Ok(());
    }
    let mut inserted_coins = SmallVec::<[UtxoInserted<'_>; 8]>::with_capacity(adds.len());
    for (_key, _txid, payload) in adds {
        if add_unique {
            apply_single_unique_add(record, payload)?;
        } else {
            let overwritten = match record.find_output(payload.vout) {
                Some(output) => {
                    Some(output_details(record, output).ok_or(UtxoError::CorruptArena)?)
                }
                None => None,
            };
            apply_single_overwrite_add(record, payload)?;
            if let Some((txout, height, coinbase)) = overwritten {
                flush_inserted_events(events, &mut inserted_coins, coalesce_events);
                events.push_remove_coin(UtxoRemoved::new(
                    *payload.outpoint,
                    txout,
                    height,
                    coinbase,
                ));
            }
        }
        inserted_coins.push(UtxoInserted::new(
            payload.outpoint,
            payload.txout,
            payload.height,
            payload.coinbase,
        ));
    }
    record.compact_scripts_if_needed()?;
    flush_inserted_events(events, &mut inserted_coins, coalesce_events);
    Ok(())
}

fn flush_inserted_events<'add>(
    events: &mut UtxoChangeEvents<'add>,
    inserted_coins: &mut SmallVec<[UtxoInserted<'add>; 8]>,
    coalesce_events: bool,
) {
    if !inserted_coins.is_empty() {
        if coalesce_events {
            events.push_insert_batch_coalesced(core::mem::take(inserted_coins));
        } else {
            events.push_insert_batch(core::mem::take(inserted_coins));
        }
    }
}

fn flush_inserted_coins(
    listener: &(dyn UtxoChangeListener + Send + Sync),
    inserted_coins: &mut SmallVec<[UtxoInserted<'_>; 8]>,
) {
    if !inserted_coins.is_empty() {
        listener.on_insert_coins(inserted_coins);
        inserted_coins.clear();
    }
}

/// Validates script lengths and prepares peak record-local buffer capacity for
/// a run. Sums every script in the run, including intermediate duplicate-vout
/// overwrites, which determines peak append length.
fn prepare_add_run(
    record: &mut UtxoRecord,
    adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
    _add_unique: bool,
) -> Result<(), UtxoError> {
    // Validate each script length fits u16.
    let mut peak_additional = 0usize;
    for (_key, _txid, payload) in adds {
        let script_len = payload.txout.script_pubkey.as_bytes().len();
        let _ =
            u16::try_from(script_len).map_err(|_| UtxoError::ScriptTooLarge { len: script_len })?;
        peak_additional =
            peak_additional
                .checked_add(script_len)
                .ok_or(UtxoError::ArenaOffsetOverflow {
                    len: peak_additional,
                })?;
    }
    // For overwrites, the old script for the same vout becomes dead during the
    // run; the peak is the sum of all appended scripts. For unique adds, the
    // peak is the same sum. prepare_script_append validates against u32 and
    // compacts dead bytes if needed.
    record.prepare_script_append(peak_additional)
}

fn prepare_utxo_add_run<A: UtxoAddView>(
    record: &mut UtxoRecord,
    adds: &[A],
    _add_unique: bool,
) -> Result<(), UtxoError> {
    let mut peak_additional = 0usize;
    for add in adds {
        let payload = add.payload();
        let script_len = payload.txout.script_pubkey.as_bytes().len();
        let _ =
            u16::try_from(script_len).map_err(|_| UtxoError::ScriptTooLarge { len: script_len })?;
        peak_additional =
            peak_additional
                .checked_add(script_len)
                .ok_or(UtxoError::ArenaOffsetOverflow {
                    len: peak_additional,
                })?;
    }
    record.prepare_script_append(peak_additional)
}

fn apply_add_run_outputs(
    record: &mut UtxoRecord,
    adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
    add_unique: bool,
) -> Result<(), UtxoError> {
    for (_key, _txid, payload) in adds {
        if add_unique {
            apply_single_unique_build(record, payload)?;
        } else {
            apply_single_overwrite_build(record, payload)?;
        }
    }
    Ok(())
}

fn apply_utxo_add_run_outputs<A: UtxoAddView>(
    record: &mut UtxoRecord,
    adds: &[A],
    add_unique: bool,
) -> Result<(), UtxoError> {
    for add in adds {
        let payload = add.payload();
        if add_unique {
            apply_single_unique_build(record, &payload)?;
        } else {
            apply_single_overwrite_build(record, &payload)?;
        }
    }
    Ok(())
}

fn apply_single_unique_build(
    record: &mut UtxoRecord,
    payload: &BuildPayload<'_>,
) -> Result<(), UtxoError> {
    let script = payload.txout.script_pubkey.as_bytes();
    let (offset, len) = record.append_script(script)?;
    record.add_unique_output(OneUtxoOut {
        vout: payload.vout,
        value: payload.txout.value.to_sat(),
        script_pubkey_offset: offset,
        script_pubkey_len: len,
        coinbase: payload.coinbase,
        height: payload.height,
    });
    Ok(())
}

fn apply_single_overwrite_build(
    record: &mut UtxoRecord,
    payload: &BuildPayload<'_>,
) -> Result<(), UtxoError> {
    let script = payload.txout.script_pubkey.as_bytes();
    let (offset, len) = record.append_script(script)?;
    record.add_output(OneUtxoOut {
        vout: payload.vout,
        value: payload.txout.value.to_sat(),
        script_pubkey_offset: offset,
        script_pubkey_len: len,
        coinbase: payload.coinbase,
        height: payload.height,
    });
    Ok(())
}

fn apply_single_unique_add(
    record: &mut UtxoRecord,
    payload: &BuildPayload<'_>,
) -> Result<(), UtxoError> {
    apply_single_unique_build(record, payload)
}

fn apply_single_overwrite_add(
    record: &mut UtxoRecord,
    payload: &BuildPayload<'_>,
) -> Result<(), UtxoError> {
    apply_single_overwrite_build(record, payload)
}

fn build_adds_extend_record_vouts(
    table: &ShardTable,
    key: UtxoKey,
    txid: Hash256,
    vouts: impl Iterator<Item = u32>,
) -> bool {
    let mut previous: Option<u32> = table
        .table
        .find(key.hash(), |record| {
            record.key() == key && record.txid() == txid
        })
        .and_then(|record| record.max_vout());
    for vout in vouts {
        if previous.is_some_and(|prev| vout <= prev) {
            return false;
        }
        previous = Some(vout);
    }
    true
}

fn find_record_mut(table: &mut ShardTable, key: UtxoKey, txid: Hash256) -> Option<&mut UtxoRecord> {
    table
        .table
        .find_mut(key.hash(), |record| {
            record.key() == key && record.txid() == txid
        })
        .map(Box::as_mut)
}

fn delete_record_if_fully_spent(
    table: &mut ShardTable,
    key: UtxoKey,
    txid: Hash256,
    remove_count: usize,
    mut remove_vout: impl FnMut(usize) -> u32,
    contains_vout: impl Fn(u32) -> bool,
) -> bool {
    let Ok(entry) = table.table.find_entry(key.hash(), |record| {
        record.key() == key && record.txid() == txid
    }) else {
        return false;
    };
    let record = entry.get();
    if record.output_count() != remove_count {
        return false;
    }
    match record_fully_spent_by_bitmap(record, remove_count, &mut remove_vout) {
        Some(true) => {}
        Some(false) => return false,
        None => {
            if !record
                .iter_outputs()
                .all(|output| contains_vout(output.vout))
            {
                return false;
            }
        }
    }
    let (_record, _vacant) = entry.remove();
    true
}

fn record_fully_spent_by_bitmap(
    record: &UtxoRecord,
    remove_count: usize,
    remove_vout: &mut impl FnMut(usize) -> u32,
) -> Option<bool> {
    let mut record_bitmap = 0_u64;
    for output in record.iter_outputs() {
        let bit = bitmap_vout_bit(output.vout)?;
        if record_bitmap & bit != 0 {
            return None;
        }
        record_bitmap |= bit;
    }
    if record_bitmap != record.vout_bitmap {
        return None;
    }

    let mut remove_bitmap = 0_u64;
    for index in 0..remove_count {
        let bit = bitmap_vout_bit(remove_vout(index))?;
        if remove_bitmap & bit != 0 {
            return None;
        }
        remove_bitmap |= bit;
    }
    Some(remove_bitmap == record_bitmap)
}

fn insert_record(table: &mut ShardTable, record: UtxoRecord) {
    let key = record.key();
    table
        .table
        .insert_unique(key.hash(), Box::new(record), |record| record.key().hash());
}

fn remove_record(table: &mut ShardTable, key: UtxoKey, txid: Hash256) {
    let Ok(entry) = table.table.find_entry(key.hash(), |record| {
        record.key() == key && record.txid() == txid
    }) else {
        return;
    };
    let (_record, _vacant) = entry.remove();
}

fn output_details(record: &UtxoRecord, output: &OneUtxoOut) -> Option<(TxOut, u32, bool)> {
    let script = record.script_slice(output)?;
    Some(output_details_from_parts(output, script))
}

fn output_details_from_parts(output: &OneUtxoOut, script: &[u8]) -> (TxOut, u32, bool) {
    (
        txout_from_parts(output.value, script),
        output.height,
        output.coinbase,
    )
}

fn txout_from_parts(value: u64, script: &[u8]) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: ScriptBuf::from_bytes(script.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_owned_record_is_not_inserted() -> Result<(), UtxoError> {
        let shard = Shard::new();
        shard.insert_owned_record(UtxoKey::from_prefix([0; 8]), Hash256::default(), &[])?;
        assert_eq!(shard.record_count(), 0);
        Ok(())
    }
}
