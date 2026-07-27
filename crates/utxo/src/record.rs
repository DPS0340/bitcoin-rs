use bitcoin_rs_primitives::Hash256;
use smallvec::SmallVec;

use crate::{UtxoError, UtxoKey};

/// One live output inside a transaction-level UTXO record.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct OneUtxoOut {
    /// Originating transaction output index.
    pub vout: u32,
    /// Output value in satoshis.
    pub value: u64,
    /// Byte offset into the record-local script buffer.
    pub script_pubkey_offset: u32,
    /// Script length in bytes.
    pub script_pubkey_len: u16,
    /// Whether the originating transaction was coinbase.
    pub coinbase: bool,
    /// Block height that created the output.
    pub height: u32,
}

/// Transaction-level UTXO record owning its outputs and script bytes.
///
/// `outputs` keeps the common case (≤2 live outputs) inline; it spills for
/// higher-fanout transactions. Script bytes are stored in a record-local
/// contiguous `script_bytes` buffer addressed by
/// `OneUtxoOut::{script_pubkey_offset, script_pubkey_len}`. Offsets are
/// record-local, never serialized, and rewritten by compaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoRecord {
    pub(crate) txid: Hash256,
    /// Low-vout compatibility bitmap for snapshot v2; stored outputs are authoritative.
    pub vout_bitmap: u64,
    /// Length of the legacy inline-output partition used by snapshot ordering.
    legacy_inline_len: u8,
    outputs: SmallVec<[OneUtxoOut; 2]>,
    script_bytes: SmallVec<[u8; 72]>,
}

impl UtxoRecord {
    pub(crate) fn new(txid: Hash256) -> Self {
        Self {
            txid,
            vout_bitmap: 0,
            legacy_inline_len: 0,
            outputs: SmallVec::new(),
            script_bytes: SmallVec::new(),
        }
    }
    pub(crate) fn key(&self) -> UtxoKey {
        UtxoKey::from_txid(&self.txid)
    }

    pub(crate) const fn txid(&self) -> Hash256 {
        self.txid
    }

    pub(crate) fn add_output(&mut self, output: OneUtxoOut) {
        let _removed = self.remove_output(output.vout);
        self.push_output(output);
    }

    pub(crate) fn add_unique_output(&mut self, output: OneUtxoOut) {
        debug_assert!(self.find_output(output.vout).is_none());
        self.push_output(output);
    }

    fn push_output(&mut self, output: OneUtxoOut) {
        if let Some(bit) = bitmap_vout_bit(output.vout) {
            self.vout_bitmap |= bit;
        }
        let inline_len = usize::from(self.legacy_inline_len);
        if inline_len < 8 {
            self.outputs.insert(inline_len, output);
            self.legacy_inline_len += 1;
        } else {
            self.outputs.push(output);
        }
    }

    pub(crate) fn remove_output(&mut self, vout: u32) -> Option<OneUtxoOut> {
        let index = self.outputs.iter().position(|output| output.vout == vout)?;
        let inline_len = usize::from(self.legacy_inline_len);
        let removed = if index < inline_len {
            self.outputs.swap(index, inline_len - 1);
            self.legacy_inline_len -= 1;
            Some(self.outputs.remove(inline_len - 1))
        } else {
            Some(self.outputs.swap_remove(index))
        };
        if removed.is_some()
            && let Some(bit) = bitmap_vout_bit(vout)
        {
            self.vout_bitmap &= !bit;
        }
        removed
    }

    pub(crate) fn find_output(&self, vout: u32) -> Option<&OneUtxoOut> {
        self.outputs.iter().find(|output| output.vout == vout)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }

    pub(crate) fn output_count(&self) -> usize {
        self.outputs.len()
    }

    pub(crate) fn max_vout(&self) -> Option<u32> {
        self.outputs.iter().map(|output| output.vout).max()
    }

    pub(crate) fn iter_outputs(&self) -> impl Iterator<Item = &OneUtxoOut> {
        self.outputs.iter()
    }

    /// Returns the script bytes for `output` via the record-local buffer.
    pub(crate) fn script_slice(&self, output: &OneUtxoOut) -> Option<&[u8]> {
        let start = usize::try_from(output.script_pubkey_offset).ok()?;
        let len = usize::from(output.script_pubkey_len);
        let end = start.checked_add(len)?;
        self.script_bytes.get(start..end)
    }

    /// Total length of script bytes referenced by currently-live outputs.
    /// Dead bytes (from partial spends / overwrites) are excluded.
    fn live_script_len(&self) -> usize {
        self.outputs
            .iter()
            .map(|output| usize::from(output.script_pubkey_len))
            .sum()
    }

    /// Validates that appending `additional` script bytes to the record-local
    /// buffer will not overflow `u32`. If the current buffer contains dead
    /// bytes that prevent the fit, compacts first. On success the buffer is
    /// ready for an infallible append; on failure the record is byte-identical
    /// to entry state.
    pub(crate) fn prepare_script_append(&mut self, additional: usize) -> Result<(), UtxoError> {
        let live = self.live_script_len();
        let peak = live
            .checked_add(additional)
            .ok_or(UtxoError::ArenaOffsetOverflow { len: live })?;
        let _ = u32::try_from(peak).map_err(|_| UtxoError::ArenaOffsetOverflow { len: peak })?;
        // If the current buffer cannot hold `peak` only because of dead bytes,
        // compact before reserving so the append succeeds without growing.
        let current_len = self.script_bytes.len();
        let current_peak = current_len
            .checked_add(additional)
            .ok_or(UtxoError::ArenaOffsetOverflow { len: current_len })?;
        if u32::try_from(current_peak).is_err() {
            if current_len == live {
                return Err(UtxoError::ArenaOffsetOverflow { len: current_peak });
            }
            self.compact_scripts()?;
        } else {
            let current_cap = self.script_bytes.capacity();
            if current_len > live && current_peak > current_cap && peak <= current_cap {
                self.compact_scripts_with_capacity(current_cap)?;
            }
        }
        Ok(())
    }

    /// Appends `script` to the record-local buffer and returns the offset/len
    /// pair for the new output metadata. Infallible after `prepare_script_append`.
    pub(crate) fn append_script(&mut self, script: &[u8]) -> Result<(u32, u16), UtxoError> {
        let offset =
            u32::try_from(self.script_bytes.len()).map_err(|_| UtxoError::ArenaOffsetOverflow {
                len: self.script_bytes.len(),
            })?;
        let len = u16::try_from(script.len())
            .map_err(|_| UtxoError::ScriptTooLarge { len: script.len() })?;
        self.script_bytes.extend_from_slice(script);
        Ok((offset, len))
    }

    /// Rebuilds the script buffer from live outputs in iteration order, dropping
    /// dead bytes, when `dead >= live`. Rewrites offsets atomically: the build
    /// succeeds before any metadata changes. Returns `Ok(())` if no compaction
    /// was needed or it succeeded; returns `CorruptArena` if any old range is
    /// invalid (leaving the original record untouched).
    pub(crate) fn compact_scripts_if_needed(&mut self) -> Result<(), UtxoError> {
        let live = self.live_script_len();
        let dead = self.script_bytes.len().saturating_sub(live);
        if dead == 0 || dead < live {
            return Ok(());
        }
        self.compact_scripts()
    }

    fn compact_scripts(&mut self) -> Result<(), UtxoError> {
        self.compact_scripts_with_capacity(0)
    }

    fn compact_scripts_with_capacity(&mut self, capacity: usize) -> Result<(), UtxoError> {
        // Build the new buffer from immutable old slices in output order.
        let mut new_bytes: SmallVec<[u8; 72]> = SmallVec::with_capacity(capacity);
        let mut new_outputs: SmallVec<[OneUtxoOut; 2]> =
            SmallVec::with_capacity(self.outputs.len());
        for output in &self.outputs {
            let script = self.script_slice(output).ok_or(UtxoError::CorruptArena)?;
            let offset =
                u32::try_from(new_bytes.len()).map_err(|_| UtxoError::ArenaOffsetOverflow {
                    len: new_bytes.len(),
                })?;
            let len = u16::try_from(script.len())
                .map_err(|_| UtxoError::ScriptTooLarge { len: script.len() })?;
            new_bytes.extend_from_slice(script);
            new_outputs.push(OneUtxoOut {
                vout: output.vout,
                value: output.value,
                script_pubkey_offset: offset,
                script_pubkey_len: len,
                coinbase: output.coinbase,
                height: output.height,
            });
        }
        // Swap only after the build succeeds.
        self.script_bytes = new_bytes;
        self.outputs = new_outputs;
        Ok(())
    }

    /// Shrinks a spilled output buffer when capacity far exceeds need, so a
    /// high-fanout partial spend releases peak allocation without reallocating
    /// on ordinary churn.
    pub(crate) fn shrink_outputs_if_needed(&mut self) {
        let threshold = self.outputs.len().max(2).saturating_mul(2);
        if self.outputs.capacity() > threshold {
            self.outputs.shrink_to_fit();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnedUtxoOut {
    pub(crate) vout: u32,
    pub(crate) value: u64,
    pub(crate) script_pubkey: Vec<u8>,
    pub(crate) coinbase: bool,
    pub(crate) height: u32,
}

impl OwnedUtxoOut {
    pub(crate) const fn new(
        vout: u32,
        value: u64,
        script_pubkey: Vec<u8>,
        coinbase: bool,
        height: u32,
    ) -> Self {
        Self {
            vout,
            value,
            script_pubkey,
            coinbase,
            height,
        }
    }
}

pub(crate) const fn bitmap_vout_bit(vout: u32) -> Option<u64> {
    if vout < 64 { Some(1_u64 << vout) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(vout: u32, script: &[u8], value: u64) -> Result<OneUtxoOut, UtxoError> {
        Ok(OneUtxoOut {
            vout,
            value,
            script_pubkey_offset: 0,
            script_pubkey_len: u16::try_from(script.len())
                .map_err(|_| UtxoError::ScriptTooLarge { len: script.len() })?,
            coinbase: false,
            height: 1,
        })
    }

    fn add_output(
        record: &mut UtxoRecord,
        vout: u32,
        script: &[u8],
        value: u64,
    ) -> Result<(), UtxoError> {
        record.prepare_script_append(script.len())?;
        let (offset, len) = record.append_script(script)?;
        let mut output = out(vout, script, value)?;
        output.script_pubkey_offset = offset;
        output.script_pubkey_len = len;
        record.add_unique_output(output);
        Ok(())
    }

    #[test]
    fn owned_record_layout_is_bounded() {
        assert_eq!(std::mem::size_of::<OneUtxoOut>(), 24);
        assert_eq!(
            std::mem::size_of::<SmallVec<[OneUtxoOut; 2]>>(),
            56,
            "K2 output SmallVec"
        );
        assert_eq!(
            std::mem::size_of::<SmallVec<[u8; 72]>>(),
            80,
            "K72 script SmallVec"
        );
        assert_eq!(
            std::mem::size_of::<UtxoRecord>(),
            184,
            "UtxoRecord = 48 fixed + 56 outputs + 80 scripts"
        );
    }

    #[test]
    fn partial_spend_retains_below_threshold_then_compacts_at_dead_ge_live() -> Result<(), UtxoError>
    {
        let mut record = UtxoRecord::new(Hash256::default());
        // Two outputs with 40-byte scripts each.
        let s1 = vec![0xA1_u8; 40];
        let s2 = vec![0xB2_u8; 40];
        add_output(&mut record, 0, &s1, 100)?;
        add_output(&mut record, 1, &s2, 200)?;
        assert_eq!(record.script_bytes.len(), 80);
        assert_eq!(record.output_count(), 2);

        // Remove one output — dead = 40, live = 40, dead >= live → compacts.
        let removed = record.remove_output(0);
        assert!(removed.is_some());
        record.compact_scripts_if_needed()?;
        // After compaction, buffer holds only the live output's script.
        assert_eq!(record.script_bytes.len(), 40);
        assert_eq!(record.output_count(), 1);
        // The remaining output (vout 1) must still resolve correctly.
        let live = record.find_output(1).ok_or(UtxoError::CorruptArena)?;
        assert_eq!(record.script_slice(live), Some(&s2[..]));
        assert_eq!(record.vout_bitmap, 1_u64 << 1);
        Ok(())
    }

    #[test]
    fn repeated_overwrite_never_accumulates_unbounded_script_bytes() -> Result<(), UtxoError> {
        let mut record = UtxoRecord::new(Hash256::default());
        let big = vec![0xCC_u8; 60];
        // Repeatedly overwrite the same vout.
        for i in 0..20 {
            record.prepare_script_append(big.len())?;
            let (offset, len) = record.append_script(&big)?;
            let mut output = out(0, &big, 100 + i)?;
            output.script_pubkey_offset = offset;
            output.script_pubkey_len = len;
            record.add_output(output);
            record.compact_scripts_if_needed()?;
        }
        // Logical storage must be bounded: < 2 * live.
        let live = record.live_script_len();
        assert!(record.script_bytes.len() < 2 * live || live == 0);
        // Latest bytes win.
        let output = record.find_output(0).ok_or(UtxoError::CorruptArena)?;
        assert_eq!(record.script_slice(output), Some(&big[..]));
        Ok(())
    }

    #[test]
    fn high_fanout_removal_preserves_legacy_snapshot_order() -> Result<(), UtxoError> {
        let mut record = UtxoRecord::new(Hash256::default());
        for vout in 0_u32..10 {
            add_output(&mut record, vout, &[], 1)?;
        }
        record.remove_output(0);
        assert_eq!(
            record
                .iter_outputs()
                .map(|output| output.vout)
                .collect::<Vec<_>>(),
            vec![7, 1, 2, 3, 4, 5, 6, 8, 9]
        );

        add_output(&mut record, 10, &[], 1)?;
        assert_eq!(
            record
                .iter_outputs()
                .map(|output| output.vout)
                .collect::<Vec<_>>(),
            vec![7, 1, 2, 3, 4, 5, 6, 10, 8, 9]
        );
        Ok(())
    }

    #[test]
    fn append_reuses_capacity_after_compacting_dead_scripts() -> Result<(), UtxoError> {
        let mut record = UtxoRecord::new(Hash256::default());
        add_output(&mut record, 0, &[0xAA; 40], 1)?;
        add_output(&mut record, 1, &[0xBB; 40], 1)?;
        record.prepare_script_append(20)?;
        let (offset, len) = record.append_script(&[0xCC; 20])?;
        let mut output = out(0, &[0xCC; 20], 1)?;
        output.script_pubkey_offset = offset;
        output.script_pubkey_len = len;
        record.add_output(output);

        let live = record.live_script_len();
        let capacity = record.script_bytes.capacity();
        let additional = capacity - live;
        assert!(record.script_bytes.len() > live);
        assert!(record.script_bytes.len() + additional > capacity);

        record.prepare_script_append(additional)?;
        assert_eq!(record.script_bytes.len(), live);
        assert!(record.script_bytes.capacity() >= live + additional);
        Ok(())
    }

    #[test]
    fn failed_append_preflight_leaves_record_byte_equal() -> Result<(), UtxoError> {
        let mut record = UtxoRecord::new(Hash256::default());
        add_output(&mut record, 0, &[0xAA; 10], 100)?;
        let snapshot = record.clone();
        // An overflow-sized additional value.
        let huge = usize::MAX;
        let result = record.prepare_script_append(huge);
        assert!(result.is_err());
        assert_eq!(record, snapshot);
        Ok(())
    }

    #[test]
    fn high_fanout_spend_releases_spilled_output_capacity() -> Result<(), UtxoError> {
        let mut record = UtxoRecord::new(Hash256::default());
        // Add many outputs to force a spill.
        for vout in 0_u32..64 {
            add_output(&mut record, vout, &[0xDD; 5], 1)?;
        }
        assert!(record.outputs.capacity() > 2);
        // Spend most of them.
        for vout in 1_u32..64 {
            record.remove_output(vout);
        }
        record.shrink_outputs_if_needed();
        assert!(record.outputs.capacity() <= 2 * record.outputs.len().max(2));
        Ok(())
    }
}
