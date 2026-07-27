use bitcoin_rs_primitives::Hash256;

use crate::{UtxoError, UtxoKey};

const TXID_LEN: usize = 32;
const OUTPUT_COUNT_OFFSET: usize = TXID_LEN;
const LEGACY_INLINE_LEN_OFFSET: usize = OUTPUT_COUNT_OFFSET + core::mem::size_of::<u32>();
const RECORD_HEADER_LEN: usize = LEGACY_INLINE_LEN_OFFSET + core::mem::size_of::<u8>();
const OUTPUT_METADATA_LEN: usize = 19;
const LEGACY_INLINE_CAPACITY: usize = 8;

/// One checked, zero-copy live output view inside a transaction-level record.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OneUtxoOut<'a> {
    /// Originating transaction output index.
    pub vout: u32,
    /// Output value in satoshis.
    pub value: u64,
    /// Script bytes owned by the enclosing record.
    pub script_pubkey: &'a [u8],
    /// Whether the originating transaction was coinbase.
    pub coinbase: bool,
    /// Block height that created the output.
    pub height: u32,
}

/// Transaction-level UTXO record encoded in one owned byte allocation.
///
/// The payload is `txid || output_count || legacy_inline_len || outputs`, where
/// every output is `vout || value || height || coinbase || script_len || script`
/// in little-endian canonical form. The record owns exactly its boxed payload;
/// output views borrow directly from that payload.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct UtxoRecord {
    bytes: Box<[u8]>,
}

#[derive(Copy, Clone)]
struct RecordHeader {
    txid: Hash256,
    output_count: usize,
    legacy_inline_len: usize,
}

/// Iterator over checked output views from one validated record.
pub(crate) struct UtxoOutputIter<'a> {
    bytes: &'a [u8],
    cursor: usize,
    remaining: usize,
}

impl<'a> Iterator for UtxoOutputIter<'a> {
    type Item = OneUtxoOut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let (output, next) = match decode_output(self.bytes, self.cursor) {
            Ok(decoded) => decoded,
            // `UtxoRecord` is validated at construction (`from_encoded` runs
            // `validate_encoded`, which fully decodes every output) and its
            // `bytes` field is private and immutable afterward; a decode
            // failure here means the validated record was mutated in place,
            // which is an unrecoverable internal corrupt state.
            Err(error) => panic!("validated UTXO record output must remain decodable: {error:?}"),
        };
        self.cursor = next;
        self.remaining -= 1;
        Some(output)
    }
}

impl UtxoRecord {
    /// Parses a complete encoded record. The returned record is always safe to
    /// expose through zero-copy output views.
    pub(crate) fn from_encoded(bytes: Box<[u8]>) -> Result<Self, UtxoError> {
        validate_encoded(&bytes)?;
        Ok(Self { bytes })
    }

    /// Builds a record from snapshot-owned outputs in their serialized order.
    ///
    /// This is a snapshot/untrusted boundary, so the encoded payload is
    /// re-validated through [`Self::from_encoded`] before it is trusted.
    pub(crate) fn from_owned_outputs(
        txid: Hash256,
        outputs: &[OwnedUtxoOut],
    ) -> Result<Self, UtxoError> {
        Self::from_owned_parts(txid, outputs.len().min(LEGACY_INLINE_CAPACITY), outputs)
    }

    pub(crate) fn key(&self) -> UtxoKey {
        UtxoKey::from_txid(&self.txid())
    }

    pub(crate) fn txid(&self) -> Hash256 {
        self.header().txid
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.output_count() == 0
    }

    pub(crate) fn output_count(&self) -> usize {
        self.header().output_count
    }

    /// Returns checked, zero-copy output views in the legacy snapshot order.
    ///
    /// `UtxoRecord` is validated at construction and its `bytes` field is
    /// private and immutable afterward, so the encoded payload cannot corrupt
    /// between construction and this read. The returned iterator still fails
    /// fast (panics) if an internal invariant is ever violated.
    pub(crate) fn outputs(&self) -> UtxoOutputIter<'_> {
        let header = self.header();
        UtxoOutputIter {
            bytes: &self.bytes,
            cursor: RECORD_HEADER_LEN,
            remaining: header.output_count,
        }
    }

    pub(crate) fn find_output(&self, vout: u32) -> Option<OneUtxoOut<'_>> {
        self.outputs().find(|output| output.vout == vout)
    }

    pub(crate) fn max_vout(&self) -> Option<u32> {
        self.outputs().map(|output| output.vout).max()
    }

    /// Stages an entire coalesced add run without changing this record,
    /// materializing the overwritten slots for listener/event consumers.
    ///
    /// `add_unique` is the strictly-increasing-vout fast path. Callers prove
    /// that it cannot encounter an existing vout before selecting it.
    #[cfg(test)]
    pub(crate) fn stage_add_run(
        &self,
        additions: &[OwnedUtxoOut],
        add_unique: bool,
    ) -> Result<(Self, Vec<Option<OwnedUtxoOut>>), UtxoError> {
        self.add_replacement_tracked(&owned_parts(additions), add_unique)
    }

    /// Builds the replacement record for a coalesced add run, borrowing every
    /// surviving output straight from this record's payload (no per-output
    /// script clone) and copying each addition's script exactly once. Used by
    /// the no-listener commit path, which never materializes overwritten
    /// outputs.
    pub(crate) fn add_replacement<'a>(
        &'a self,
        additions: &'a [OutputParts<'a>],
        add_unique: bool,
    ) -> Result<Self, UtxoError> {
        if add_unique {
            if let Some(record) = self.append_unique_run(additions)? {
                return Ok(record);
            }
        }
        let mut parts = self.output_parts();
        let mut legacy_inline_len = self.header().legacy_inline_len;
        apply_additions(
            &mut parts,
            &mut legacy_inline_len,
            additions,
            add_unique,
            None,
        );
        Self::from_output_parts(self.txid(), legacy_inline_len, &parts)
    }

    /// Add-run replacement that also materializes the overwritten outputs (owned,
    /// so they outlive the record swap) for listener/event consumers.
    pub(crate) fn add_replacement_tracked<'a>(
        &'a self,
        additions: &'a [OutputParts<'a>],
        add_unique: bool,
    ) -> Result<(Self, Vec<Option<OwnedUtxoOut>>), UtxoError> {
        if add_unique {
            // The unique fast path can never overwrite a live vout.
            let record = self.add_replacement(additions, true)?;
            return Ok((record, vec![None; additions.len()]));
        }
        let mut parts = self.output_parts();
        let mut legacy_inline_len = self.header().legacy_inline_len;
        let mut overwritten = Vec::with_capacity(additions.len());
        apply_additions(
            &mut parts,
            &mut legacy_inline_len,
            additions,
            false,
            Some(&mut overwritten),
        );
        let record = Self::from_output_parts(self.txid(), legacy_inline_len, &parts)?;
        Ok((record, overwritten))
    }

    /// Builds a fresh record for a coalesced add run on a transaction that has
    /// no live record. Only additions contribute bytes.
    pub(crate) fn new_add_replacement(
        txid: Hash256,
        additions: &[OutputParts<'_>],
        add_unique: bool,
    ) -> Result<Self, UtxoError> {
        if add_unique {
            // Unique adds on an empty record encode in slice order with the
            // inline partition filled to capacity; no dedup pass is needed.
            let legacy_inline_len = additions.len().min(LEGACY_INLINE_CAPACITY);
            return Self::from_output_parts(txid, legacy_inline_len, additions);
        }
        let mut parts = Vec::with_capacity(additions.len());
        let mut legacy_inline_len = 0;
        apply_additions(&mut parts, &mut legacy_inline_len, additions, false, None);
        Self::from_output_parts(txid, legacy_inline_len, &parts)
    }

    pub(crate) fn new_add_replacement_tracked(
        txid: Hash256,
        additions: &[OutputParts<'_>],
        add_unique: bool,
    ) -> Result<(Self, Vec<Option<OwnedUtxoOut>>), UtxoError> {
        if add_unique {
            let legacy_inline_len = additions.len().min(LEGACY_INLINE_CAPACITY);
            let record = Self::from_output_parts(txid, legacy_inline_len, additions)?;
            return Ok((record, vec![None; additions.len()]));
        }
        let mut parts = Vec::with_capacity(additions.len());
        let mut legacy_inline_len = 0;
        let mut overwritten = Vec::with_capacity(additions.len());
        apply_additions(
            &mut parts,
            &mut legacy_inline_len,
            additions,
            false,
            Some(&mut overwritten),
        );
        let record = Self::from_output_parts(txid, legacy_inline_len, &parts)?;
        Ok((record, overwritten))
    }

    /// Increasing-unique append-copy fast path. Returns `None` when appending
    /// would reorder the legacy partition bytes, so the caller must rebuild.
    fn append_unique_run(&self, additions: &[OutputParts<'_>]) -> Result<Option<Self>, UtxoError> {
        let header = self.header();
        let appends_at_end = header.output_count == header.legacy_inline_len
            || header.legacy_inline_len == LEGACY_INLINE_CAPACITY;
        if !appends_at_end {
            return Ok(None);
        }

        let new_count =
            header
                .output_count
                .checked_add(additions.len())
                .ok_or(UtxoError::RecordTooLarge {
                    len: header.output_count,
                })?;
        let output_count =
            u32::try_from(new_count).map_err(|_| UtxoError::RecordTooLarge { len: new_count })?;
        let legacy_inline_len =
            (header.legacy_inline_len + additions.len()).min(LEGACY_INLINE_CAPACITY);
        let legacy_inline_len_u8 =
            u8::try_from(legacy_inline_len).map_err(|_| UtxoError::CorruptRecord)?;

        let mut additions_len = 0usize;
        for addition in additions {
            additions_len = additions_len
                .checked_add(addition.encoded_len()?)
                .ok_or(UtxoError::RecordTooLarge { len: additions_len })?;
        }
        let payload_len = self
            .bytes
            .len()
            .checked_add(additions_len)
            .ok_or(UtxoError::RecordTooLarge { len: additions_len })?;
        if payload_len > usize::try_from(isize::MAX).unwrap_or(usize::MAX) {
            return Err(UtxoError::RecordTooLarge { len: payload_len });
        }

        let mut bytes = Vec::with_capacity(payload_len);
        bytes.extend_from_slice(&header.txid.to_le_bytes());
        bytes.extend_from_slice(&output_count.to_le_bytes());
        bytes.push(legacy_inline_len_u8);
        bytes.extend_from_slice(&self.bytes[RECORD_HEADER_LEN..]);
        for addition in additions {
            write_output(&mut bytes, addition)?;
        }
        debug_assert_eq!(bytes.len(), payload_len);
        // Invariant: the copied prefix came from this validated record and every
        // appended addition was size-checked above, so the payload is canonical
        // and needs no re-decode.
        Ok(Some(Self {
            bytes: bytes.into_boxed_slice(),
        }))
    }

    /// Stages an entire coalesced remove run without changing this record,
    /// materializing the removed outputs (in request order) for listener/event
    /// consumers. Only removed outputs are cloned; survivors stay borrowed.
    pub(crate) fn stage_remove_run(
        &self,
        vouts: &[u32],
    ) -> Result<(Option<Self>, Vec<Option<OwnedUtxoOut>>), UtxoError> {
        let mut parts = self.output_parts();
        let mut legacy_inline_len = self.header().legacy_inline_len;
        let mut removed = Vec::with_capacity(vouts.len());

        for &vout in vouts {
            let output = parts
                .iter()
                .position(|part| part.vout == vout)
                .map(|index| remove_part_at(&mut parts, &mut legacy_inline_len, index));
            removed.push(output.map(OutputParts::into_owned));
        }

        if removed.iter().all(Option::is_none) {
            return Ok((None, removed));
        }

        let replacement = Self::from_output_parts(self.txid(), legacy_inline_len, &parts)?;
        Ok((Some(replacement), removed))
    }

    /// Builds the replacement for a coalesced remove run without materializing
    /// any removed output. A full removal returns [`RemovedRecord::Emptied`]
    /// with no replacement allocation. Used by the no-listener commit path.
    pub(crate) fn remove_replacement(&self, vouts: &[u32]) -> Result<RemovedRecord, UtxoError> {
        if self.is_full_removal(vouts) {
            return Ok(RemovedRecord::Emptied);
        }
        let mut parts = self.output_parts();
        let mut legacy_inline_len = self.header().legacy_inline_len;
        let mut any_removed = false;
        for &vout in vouts {
            if let Some(index) = parts.iter().position(|part| part.vout == vout) {
                remove_part_at(&mut parts, &mut legacy_inline_len, index);
                any_removed = true;
            }
        }
        if !any_removed {
            return Ok(RemovedRecord::Unchanged);
        }
        if parts.is_empty() {
            return Ok(RemovedRecord::Emptied);
        }
        let replacement = Self::from_output_parts(self.txid(), legacy_inline_len, &parts)?;
        Ok(RemovedRecord::Replaced(replacement))
    }

    /// Builds the replacement for a coalesced remove run followed by a
    /// coalesced add run on this record, in one borrowed descriptor pass with a
    /// single encode. Removes model legacy-partition removal in `vouts` request
    /// order; the adds then overwrite or append in `additions` payload order.
    /// Used by the no-listener commit path when one record identity is both
    /// spent and rebuilt in the same batch; no removed or overwritten output is
    /// materialized, and each surviving output stays borrowed. A failed encode
    /// returns `Err` before any buffer is produced, so the caller's record is
    /// left byte-identical.
    pub(crate) fn edit_replacement<'a>(
        &'a self,
        vouts: &[u32],
        additions: &'a [OutputParts<'a>],
        add_unique: bool,
    ) -> Result<RemovedRecord, UtxoError> {
        if self.is_full_removal(vouts) {
            // Every live output is spent, so the additions alone form the final
            // record; survivors are never collected.
            if additions.is_empty() {
                return Ok(RemovedRecord::Emptied);
            }
            let record = Self::new_add_replacement(self.txid(), additions, add_unique)?;
            return Ok(RemovedRecord::Replaced(record));
        }
        let mut parts = self.output_parts();
        let mut legacy_inline_len = self.header().legacy_inline_len;
        for &vout in vouts {
            if let Some(index) = parts.iter().position(|part| part.vout == vout) {
                remove_part_at(&mut parts, &mut legacy_inline_len, index);
            }
        }
        apply_additions(
            &mut parts,
            &mut legacy_inline_len,
            additions,
            add_unique,
            None,
        );
        if parts.is_empty() {
            return Ok(RemovedRecord::Emptied);
        }
        let replacement = Self::from_output_parts(self.txid(), legacy_inline_len, &parts)?;
        Ok(RemovedRecord::Replaced(replacement))
    }

    /// Returns the requested outputs in request order only when the request
    /// spends this whole record exactly once per live vout. Materializes the
    /// removed outputs for listener/event consumers; survivors are never built.
    pub(crate) fn full_removals_by_vout(&self, vouts: &[u32]) -> Option<Vec<OwnedUtxoOut>> {
        if !self.is_full_removal(vouts) {
            return None;
        }
        let mut removed = Vec::with_capacity(vouts.len());
        for &vout in vouts {
            removed.push(OutputParts::from_view(&self.find_output(vout)?).into_owned());
        }
        Some(removed)
    }

    /// True when `vouts` removes every live output exactly once (no duplicate
    /// and no absent request). Borrowed header/output scan; allocates nothing.
    fn is_full_removal(&self, vouts: &[u32]) -> bool {
        if self.output_count() != vouts.len() {
            return false;
        }
        for (index, &vout) in vouts.iter().enumerate() {
            if vouts[..index].contains(&vout) || self.find_output(vout).is_none() {
                return false;
            }
        }
        true
    }

    #[cfg(test)]
    pub(crate) fn encoded_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn header(&self) -> RecordHeader {
        match decode_header(&self.bytes) {
            Ok(header) => header,
            // `UtxoRecord` is only built through `from_encoded` or
            // `from_output_parts`, both of which produce a canonical payload; a
            // header decode failure means the validated record was mutated in
            // place.
            Err(error) => panic!("UtxoRecord is validated at construction: {error:?}"),
        }
    }

    /// Borrowed descriptors for every live output, in serialized order. Scripts
    /// point straight into this record's payload; nothing is cloned.
    fn output_parts(&self) -> Vec<OutputParts<'_>> {
        self.outputs()
            .map(|output| OutputParts::from_view(&output))
            .collect()
    }

    /// Snapshot/untrusted boundary constructor: re-validates through
    /// [`Self::from_encoded`].
    fn from_owned_parts(
        txid: Hash256,
        legacy_inline_len: usize,
        outputs: &[OwnedUtxoOut],
    ) -> Result<Self, UtxoError> {
        let bytes = encode_record(txid, legacy_inline_len, &owned_parts(outputs))?;
        Self::from_encoded(bytes)
    }

    /// Internal constructor from borrowed descriptors. Every descriptor is
    /// either a validated existing output or a prevalidated addition, so the
    /// encoded payload is canonical by construction and needs no re-decode.
    fn from_output_parts(
        txid: Hash256,
        legacy_inline_len: usize,
        outputs: &[OutputParts<'_>],
    ) -> Result<Self, UtxoError> {
        let bytes = encode_record(txid, legacy_inline_len, outputs)?;
        Ok(Self { bytes })
    }
}

/// Borrowed descriptor of one output to encode into a replacement buffer.
///
/// Scripts borrow from a validated source record or a prevalidated addition, so
/// building a replacement copies each script exactly once into the new buffer
/// and never clones a surviving output.
#[derive(Copy, Clone)]
pub(crate) struct OutputParts<'a> {
    pub(crate) vout: u32,
    pub(crate) value: u64,
    pub(crate) script: &'a [u8],
    pub(crate) coinbase: bool,
    pub(crate) height: u32,
}

impl<'a> OutputParts<'a> {
    pub(crate) const fn new(
        vout: u32,
        value: u64,
        script: &'a [u8],
        coinbase: bool,
        height: u32,
    ) -> Self {
        Self {
            vout,
            value,
            script,
            coinbase,
            height,
        }
    }

    fn from_owned(output: &'a OwnedUtxoOut) -> Self {
        Self::new(
            output.vout,
            output.value,
            &output.script_pubkey,
            output.coinbase,
            output.height,
        )
    }

    fn from_view(output: &OneUtxoOut<'a>) -> Self {
        Self::new(
            output.vout,
            output.value,
            output.script_pubkey,
            output.coinbase,
            output.height,
        )
    }

    fn into_owned(self) -> OwnedUtxoOut {
        OwnedUtxoOut::new(
            self.vout,
            self.value,
            self.script.to_vec(),
            self.coinbase,
            self.height,
        )
    }

    /// Validated encoded size (19-byte metadata + script) of this output.
    fn encoded_len(&self) -> Result<usize, UtxoError> {
        let script_len = self.script.len();
        u16::try_from(script_len).map_err(|_| UtxoError::ScriptTooLarge { len: script_len })?;
        OUTPUT_METADATA_LEN
            .checked_add(script_len)
            .ok_or(UtxoError::RecordTooLarge { len: script_len })
    }
}

/// Outcome of staging a coalesced remove run without materializing removals.
pub(crate) enum RemovedRecord {
    /// No requested vout was live; the record is unchanged.
    Unchanged,
    /// Every live output was removed; the record must be deleted.
    Emptied,
    /// A partial removal produced this replacement record.
    Replaced(UtxoRecord),
}

fn owned_parts(outputs: &[OwnedUtxoOut]) -> Vec<OutputParts<'_>> {
    outputs.iter().map(OutputParts::from_owned).collect()
}

/// Applies a coalesced add run to `parts` with overwrite semantics, preserving
/// the legacy inline/overflow partition order. When `overwritten` is supplied,
/// each displaced output is cloned owned into it in addition order.
fn apply_additions<'a>(
    parts: &mut Vec<OutputParts<'a>>,
    legacy_inline_len: &mut usize,
    additions: &[OutputParts<'a>],
    add_unique: bool,
    mut overwritten: Option<&mut Vec<Option<OwnedUtxoOut>>>,
) {
    for &addition in additions {
        let old = if add_unique {
            debug_assert!(parts.iter().all(|part| part.vout != addition.vout));
            None
        } else {
            parts
                .iter()
                .position(|part| part.vout == addition.vout)
                .map(|index| remove_part_at(parts, legacy_inline_len, index))
        };
        push_part(parts, legacy_inline_len, addition);
        if let Some(sink) = overwritten.as_deref_mut() {
            sink.push(old.map(OutputParts::into_owned));
        }
    }
}

fn push_part<'a>(
    parts: &mut Vec<OutputParts<'a>>,
    legacy_inline_len: &mut usize,
    part: OutputParts<'a>,
) {
    if *legacy_inline_len < LEGACY_INLINE_CAPACITY {
        parts.insert(*legacy_inline_len, part);
        *legacy_inline_len += 1;
    } else {
        parts.push(part);
    }
}

fn remove_part_at<'a>(
    parts: &mut Vec<OutputParts<'a>>,
    legacy_inline_len: &mut usize,
    index: usize,
) -> OutputParts<'a> {
    if index < *legacy_inline_len {
        let last_inline = *legacy_inline_len - 1;
        parts.swap(index, last_inline);
        *legacy_inline_len -= 1;
        parts.remove(last_inline)
    } else {
        parts.swap_remove(index)
    }
}

/// Encodes a canonical record payload into one exact-capacity buffer. Every
/// script must be `<= u16::MAX`; existing outputs satisfy this by construction
/// and additions are prevalidated here.
fn encode_record(
    txid: Hash256,
    legacy_inline_len: usize,
    outputs: &[OutputParts<'_>],
) -> Result<Box<[u8]>, UtxoError> {
    let output_count = u32::try_from(outputs.len())
        .map_err(|_| UtxoError::RecordTooLarge { len: outputs.len() })?;
    if legacy_inline_len > LEGACY_INLINE_CAPACITY || legacy_inline_len > outputs.len() {
        return Err(UtxoError::CorruptRecord);
    }

    let mut payload_len = RECORD_HEADER_LEN;
    for output in outputs {
        payload_len = payload_len
            .checked_add(output.encoded_len()?)
            .ok_or(UtxoError::RecordTooLarge { len: payload_len })?;
    }
    if payload_len > usize::try_from(isize::MAX).unwrap_or(usize::MAX) {
        return Err(UtxoError::RecordTooLarge { len: payload_len });
    }

    let legacy_inline_len_u8 =
        u8::try_from(legacy_inline_len).map_err(|_| UtxoError::CorruptRecord)?;
    let mut bytes = Vec::with_capacity(payload_len);
    bytes.extend_from_slice(&txid.to_le_bytes());
    bytes.extend_from_slice(&output_count.to_le_bytes());
    bytes.push(legacy_inline_len_u8);
    for output in outputs {
        write_output(&mut bytes, output)?;
    }
    debug_assert_eq!(bytes.len(), payload_len);
    Ok(bytes.into_boxed_slice())
}

/// Appends one output's canonical 19-byte metadata + script, validating the
/// script length fits the `u16` length field.
fn write_output(bytes: &mut Vec<u8>, output: &OutputParts<'_>) -> Result<(), UtxoError> {
    let script_len = u16::try_from(output.script.len()).map_err(|_| UtxoError::ScriptTooLarge {
        len: output.script.len(),
    })?;
    bytes.extend_from_slice(&output.vout.to_le_bytes());
    bytes.extend_from_slice(&output.value.to_le_bytes());
    bytes.extend_from_slice(&output.height.to_le_bytes());
    bytes.push(u8::from(output.coinbase));
    bytes.extend_from_slice(&script_len.to_le_bytes());
    bytes.extend_from_slice(output.script);
    Ok(())
}

fn validate_encoded(bytes: &[u8]) -> Result<RecordHeader, UtxoError> {
    let header = decode_header(bytes)?;
    let mut cursor = RECORD_HEADER_LEN;
    for _ in 0..header.output_count {
        let (_, next) = decode_output(bytes, cursor)?;
        cursor = next;
    }
    if cursor != bytes.len() {
        return Err(UtxoError::CorruptRecord);
    }
    Ok(header)
}

fn decode_header(bytes: &[u8]) -> Result<RecordHeader, UtxoError> {
    let txid_bytes = bytes.get(..TXID_LEN).ok_or(UtxoError::CorruptRecord)?;
    let mut txid = [0_u8; TXID_LEN];
    txid.copy_from_slice(txid_bytes);
    let output_count =
        usize::try_from(read_u32(bytes, OUTPUT_COUNT_OFFSET).ok_or(UtxoError::CorruptRecord)?)
            .map_err(|_| UtxoError::RecordTooLarge { len: usize::MAX })?;
    let legacy_inline_len = usize::from(
        *bytes
            .get(LEGACY_INLINE_LEN_OFFSET)
            .ok_or(UtxoError::CorruptRecord)?,
    );
    if legacy_inline_len > LEGACY_INLINE_CAPACITY || legacy_inline_len > output_count {
        return Err(UtxoError::CorruptRecord);
    }
    Ok(RecordHeader {
        txid: Hash256::from_le_bytes(&txid),
        output_count,
        legacy_inline_len,
    })
}

fn decode_output(bytes: &[u8], offset: usize) -> Result<(OneUtxoOut<'_>, usize), UtxoError> {
    let metadata_end = offset
        .checked_add(OUTPUT_METADATA_LEN)
        .ok_or(UtxoError::CorruptRecord)?;
    let metadata = bytes
        .get(offset..metadata_end)
        .ok_or(UtxoError::CorruptRecord)?;
    let vout = read_u32(metadata, 0).ok_or(UtxoError::CorruptRecord)?;
    let value = read_u64(metadata, 4).ok_or(UtxoError::CorruptRecord)?;
    let height = read_u32(metadata, 12).ok_or(UtxoError::CorruptRecord)?;
    let coinbase = match metadata[16] {
        0 => false,
        1 => true,
        _ => return Err(UtxoError::CorruptRecord),
    };
    let script_len = usize::from(read_u16(metadata, 17).ok_or(UtxoError::CorruptRecord)?);
    let next = metadata_end
        .checked_add(script_len)
        .ok_or(UtxoError::CorruptRecord)?;
    let script_pubkey = bytes
        .get(metadata_end..next)
        .ok_or(UtxoError::CorruptRecord)?;
    Ok((
        OneUtxoOut {
            vout,
            value,
            script_pubkey,
            coinbase,
            height,
        },
        next,
    ))
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(core::mem::size_of::<u16>())?;
    let bytes = bytes.get(offset..end)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(core::mem::size_of::<u32>())?;
    let bytes = bytes.get(offset..end)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(core::mem::size_of::<u64>())?;
    let bytes = bytes.get(offset..end)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn output(vout: u32, script: &[u8], value: u64) -> OwnedUtxoOut {
        OwnedUtxoOut::new(vout, value, script.to_vec(), false, 1)
    }

    const MODEL_INLINE_CAPACITY: usize = 8;

    struct LegacyArrayVecModel {
        inline: Vec<OwnedUtxoOut>,
        overflow: Vec<OwnedUtxoOut>,
    }

    impl LegacyArrayVecModel {
        fn from_outputs(outputs: &[OwnedUtxoOut]) -> Self {
            let inline_len = outputs.len().min(MODEL_INLINE_CAPACITY);
            Self {
                inline: outputs[..inline_len].to_vec(),
                overflow: outputs[inline_len..].to_vec(),
            }
        }

        fn output_count(&self) -> usize {
            self.inline.len() + self.overflow.len()
        }

        fn outputs(&self) -> impl Iterator<Item = &OwnedUtxoOut> {
            self.inline.iter().chain(self.overflow.iter())
        }

        fn add_run(
            &mut self,
            additions: Vec<OwnedUtxoOut>,
            add_unique: bool,
        ) -> Vec<Option<OwnedUtxoOut>> {
            let mut overwritten = Vec::with_capacity(additions.len());
            for addition in additions {
                let old = if add_unique {
                    None
                } else {
                    self.remove(addition.vout)
                };
                self.push(addition);
                overwritten.push(old);
            }
            overwritten
        }

        fn remove_run(&mut self, vouts: &[u32]) -> Vec<Option<OwnedUtxoOut>> {
            vouts.iter().map(|&vout| self.remove(vout)).collect()
        }

        fn push(&mut self, output: OwnedUtxoOut) {
            if self.inline.len() < MODEL_INLINE_CAPACITY {
                self.inline.push(output);
            } else {
                self.overflow.push(output);
            }
        }

        fn remove(&mut self, vout: u32) -> Option<OwnedUtxoOut> {
            if let Some(index) = self.inline.iter().position(|output| output.vout == vout) {
                return Some(self.inline.swap_remove(index));
            }
            self.overflow
                .iter()
                .position(|output| output.vout == vout)
                .map(|index| self.overflow.swap_remove(index))
        }

        fn encode(&self, txid: Hash256) -> Result<Vec<u8>, UtxoError> {
            if self.inline.len() > MODEL_INLINE_CAPACITY {
                return Err(UtxoError::CorruptRecord);
            }

            let output_count =
                u32::try_from(self.output_count()).map_err(|_| UtxoError::RecordTooLarge {
                    len: self.output_count(),
                })?;
            let inline_len =
                u8::try_from(self.inline.len()).map_err(|_| UtxoError::CorruptRecord)?;
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&txid.to_le_bytes());
            bytes.extend_from_slice(&output_count.to_le_bytes());
            bytes.push(inline_len);
            for output in self.outputs() {
                let script_len = u16::try_from(output.script_pubkey.len()).map_err(|_| {
                    UtxoError::ScriptTooLarge {
                        len: output.script_pubkey.len(),
                    }
                })?;
                bytes.extend_from_slice(&output.vout.to_le_bytes());
                bytes.extend_from_slice(&output.value.to_le_bytes());
                bytes.extend_from_slice(&output.height.to_le_bytes());
                bytes.push(u8::from(output.coinbase));
                bytes.extend_from_slice(&script_len.to_le_bytes());
                bytes.extend_from_slice(&output.script_pubkey);
            }
            Ok(bytes)
        }
    }

    enum EditorOperation {
        Add {
            additions: Vec<OwnedUtxoOut>,
            add_unique: bool,
        },
        Remove {
            vouts: Vec<u32>,
        },
    }

    fn assert_record_matches_model(
        record: &UtxoRecord,
        txid: Hash256,
        model: &LegacyArrayVecModel,
    ) -> Result<(), UtxoError> {
        assert_eq!(record.output_count(), model.output_count());
        let expected_bytes = model.encode(txid)?;
        assert_eq!(record.encoded_bytes(), expected_bytes.as_slice());

        let actual_outputs = record
            .outputs()
            .map(|output| {
                OwnedUtxoOut::new(
                    output.vout,
                    output.value,
                    output.script_pubkey.to_vec(),
                    output.coinbase,
                    output.height,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(actual_outputs, model.outputs().cloned().collect::<Vec<_>>());
        Ok(())
    }

    #[test]
    fn codec_accepts_exact_script_length_limit() -> Result<(), UtxoError> {
        let script = vec![0xA5; usize::from(u16::MAX)];
        let record = UtxoRecord::from_owned_outputs(
            Hash256::default(),
            &[OwnedUtxoOut::new(64, 42, script.clone(), false, u32::MAX)],
        )?;
        let output = record.outputs().next().ok_or(UtxoError::CorruptRecord)?;
        assert_eq!(output.script_pubkey, script.as_slice());
        assert_eq!(record.output_count(), 1);
        Ok(())
    }

    #[test]
    fn compact_owner_is_one_fat_pointer() {
        assert_eq!(
            core::mem::size_of::<UtxoRecord>(),
            core::mem::size_of::<Box<[u8]>>()
        );
        assert_eq!(core::mem::size_of::<UtxoRecord>(), 16);
    }

    #[test]
    fn codec_keeps_canonical_metadata_and_zero_copy_script() -> Result<(), UtxoError> {
        let record = UtxoRecord::from_owned_outputs(
            Hash256::default(),
            &[OwnedUtxoOut::new(
                u32::MAX,
                42,
                vec![0x51, 0xAC],
                true,
                u32::MAX,
            )],
        )?;
        assert_eq!(
            record.encoded_bytes().len(),
            RECORD_HEADER_LEN + OUTPUT_METADATA_LEN + 2
        );
        let output = record.outputs().next().ok_or(UtxoError::CorruptRecord)?;
        assert_eq!(output.vout, u32::MAX);
        assert_eq!(output.value, 42);
        assert_eq!(output.height, u32::MAX);
        assert!(output.coinbase);
        assert_eq!(output.script_pubkey, &[0x51, 0xAC]);
        Ok(())
    }

    #[test]
    fn malformed_encoded_boundaries_are_rejected() -> Result<(), UtxoError> {
        let record =
            UtxoRecord::from_owned_outputs(Hash256::default(), &[output(0, &[0x51, 0xAC], 1)])?;
        let encoded = record.encoded_bytes();

        let truncated_metadata = encoded
            .get(..RECORD_HEADER_LEN + OUTPUT_METADATA_LEN - 1)
            .ok_or(UtxoError::CorruptRecord)?
            .to_vec();
        assert!(matches!(
            UtxoRecord::from_encoded(truncated_metadata.into_boxed_slice()),
            Err(UtxoError::CorruptRecord)
        ));

        let truncated_script_end = encoded
            .len()
            .checked_sub(1)
            .ok_or(UtxoError::CorruptRecord)?;
        let truncated_script = encoded
            .get(..truncated_script_end)
            .ok_or(UtxoError::CorruptRecord)?
            .to_vec();
        assert!(matches!(
            UtxoRecord::from_encoded(truncated_script.into_boxed_slice()),
            Err(UtxoError::CorruptRecord)
        ));

        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(matches!(
            UtxoRecord::from_encoded(trailing.into_boxed_slice()),
            Err(UtxoError::CorruptRecord)
        ));

        let mut count_mismatch = encoded.to_vec();
        let count = count_mismatch
            .get_mut(OUTPUT_COUNT_OFFSET..LEGACY_INLINE_LEN_OFFSET)
            .ok_or(UtxoError::CorruptRecord)?;
        count.copy_from_slice(&2_u32.to_le_bytes());
        assert!(matches!(
            UtxoRecord::from_encoded(count_mismatch.into_boxed_slice()),
            Err(UtxoError::CorruptRecord)
        ));

        let mut invalid_bool = encoded.to_vec();
        let bool_byte = invalid_bool
            .get_mut(RECORD_HEADER_LEN + 16)
            .ok_or(UtxoError::CorruptRecord)?;
        *bool_byte = 2;
        assert!(matches!(
            UtxoRecord::from_encoded(invalid_bool.into_boxed_slice()),
            Err(UtxoError::CorruptRecord)
        ));
        Ok(())
    }

    #[test]
    fn editor_matches_legacy_arrayvec_partition_reference_model() -> Result<(), UtxoError> {
        let txid = Hash256::from_le_bytes(&[0xA5; TXID_LEN]);
        let initial = vec![
            OwnedUtxoOut::new(0, 100, vec![], false, 0),
            OwnedUtxoOut::new(1, 101, vec![0x51], true, 1),
            OwnedUtxoOut::new(2, 102, vec![0x51, 0xAC], false, u32::MAX),
            OwnedUtxoOut::new(3, 103, vec![0x6A, 0x01, 0x03], true, 3),
            OwnedUtxoOut::new(4, 104, vec![0x00, 0x04], false, 4),
            OwnedUtxoOut::new(5, 105, vec![0x51, 0x51, 0x05], true, 5),
            OwnedUtxoOut::new(6, 106, vec![0xAC], false, 6),
        ];
        let mut model = LegacyArrayVecModel::from_outputs(&initial);
        let mut record = UtxoRecord::from_owned_outputs(txid, &initial)?;
        assert_record_matches_model(&record, txid, &model)?;

        let operations = vec![
            EditorOperation::Add {
                additions: vec![OwnedUtxoOut::new(63, 163, vec![0x63, 0x00], true, u32::MAX)],
                add_unique: true,
            },
            EditorOperation::Add {
                additions: vec![OwnedUtxoOut::new(
                    64,
                    164,
                    vec![0x64, 0x01, 0x00],
                    false,
                    64,
                )],
                add_unique: true,
            },
            EditorOperation::Add {
                additions: vec![OwnedUtxoOut::new(
                    u32::MAX,
                    1_000,
                    vec![0xFF, 0x00, 0xFE, 0x01],
                    true,
                    u32::MAX,
                )],
                add_unique: true,
            },
            EditorOperation::Remove { vouts: vec![0] },
            EditorOperation::Add {
                additions: vec![OwnedUtxoOut::new(0, 200, vec![0x00, 0x51], false, 200)],
                add_unique: true,
            },
            EditorOperation::Remove { vouts: vec![64] },
            EditorOperation::Add {
                additions: vec![OwnedUtxoOut::new(64, 264, vec![0x64], true, 264)],
                add_unique: true,
            },
            EditorOperation::Add {
                additions: vec![
                    OwnedUtxoOut::new(63, 263, vec![0x63, 0x01], false, 263),
                    OwnedUtxoOut::new(63, 363, vec![0x63, 0x02, 0x03], true, 363),
                ],
                add_unique: false,
            },
            EditorOperation::Remove {
                vouts: vec![63, 63, u32::MAX, u32::MAX],
            },
            EditorOperation::Remove {
                vouts: vec![63, u32::MAX],
            },
        ];

        for operation in operations {
            match operation {
                EditorOperation::Add {
                    additions,
                    add_unique,
                } => {
                    let expected_overwritten = model.add_run(additions.clone(), add_unique);
                    let (replacement, overwritten) =
                        record.stage_add_run(&additions, add_unique)?;
                    assert_eq!(overwritten, expected_overwritten);
                    record = replacement;
                }
                EditorOperation::Remove { vouts } => {
                    let expected_removed = model.remove_run(&vouts);
                    let (replacement, removed) = record.stage_remove_run(&vouts)?;
                    assert_eq!(removed, expected_removed);
                    if expected_removed.iter().any(Option::is_some) {
                        record = replacement.ok_or(UtxoError::CorruptRecord)?;
                    } else {
                        assert!(replacement.is_none());
                    }
                }
            }
            assert_record_matches_model(&record, txid, &model)?;
        }
        Ok(())
    }

    #[test]
    fn rejected_staged_add_leaves_source_record_unchanged() -> Result<(), UtxoError> {
        let record = UtxoRecord::from_owned_outputs(Hash256::default(), &[output(0, &[0x51], 1)])?;
        let original = record.clone();
        let too_large = OwnedUtxoOut::new(1, 2, vec![0_u8; usize::from(u16::MAX) + 1], false, 1);
        assert!(matches!(
            record.stage_add_run(&[too_large], true),
            Err(UtxoError::ScriptTooLarge { .. })
        ));
        assert_eq!(record, original);
        Ok(())
    }
}
