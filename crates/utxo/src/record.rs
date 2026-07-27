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

    /// Stages a coalesced add run for a transaction that has no live record.
    pub(crate) fn stage_new_add_run(
        txid: Hash256,
        additions: Vec<OwnedUtxoOut>,
        add_unique: bool,
    ) -> Result<(Self, Vec<Option<OwnedUtxoOut>>), UtxoError> {
        stage_add_to_parts(txid, Vec::new(), 0, additions, add_unique)
    }

    /// Stages an entire coalesced add run without changing this record.
    ///
    /// `add_unique` is the strictly-increasing-vout fast path. Callers prove
    /// that it cannot encounter an existing vout before selecting it.
    pub(crate) fn stage_add_run(
        &self,
        additions: Vec<OwnedUtxoOut>,
        add_unique: bool,
    ) -> Result<(Self, Vec<Option<OwnedUtxoOut>>), UtxoError> {
        let (outputs, legacy_inline_len) = self.owned_outputs();
        stage_add_to_parts(
            self.txid(),
            outputs,
            legacy_inline_len,
            additions,
            add_unique,
        )
    }

    /// Stages an entire coalesced remove run without changing this record.
    /// The returned slots correspond to the requested vouts in order.
    pub(crate) fn stage_remove_run(
        &self,
        vouts: &[u32],
    ) -> Result<(Option<Self>, Vec<Option<OwnedUtxoOut>>), UtxoError> {
        let (mut outputs, mut legacy_inline_len) = self.owned_outputs();
        let mut removed = Vec::with_capacity(vouts.len());

        for &vout in vouts {
            let output = outputs
                .iter()
                .position(|output| output.vout == vout)
                .map(|index| remove_output_at(&mut outputs, &mut legacy_inline_len, index));
            removed.push(output);
        }

        if removed.iter().all(Option::is_none) {
            return Ok((None, removed));
        }

        let replacement = Self::from_owned_parts(self.txid(), legacy_inline_len, &outputs)?;
        Ok((Some(replacement), removed))
    }

    /// Returns the requested outputs in request order only when the request
    /// spends this whole record exactly once per live vout.
    pub(crate) fn full_removals_by_vout(&self, vouts: &[u32]) -> Option<Vec<OwnedUtxoOut>> {
        let (outputs, _) = self.owned_outputs();
        if outputs.len() != vouts.len() {
            return None;
        }

        let mut removed = Vec::with_capacity(vouts.len());
        for &vout in vouts {
            if removed
                .iter()
                .any(|output: &OwnedUtxoOut| output.vout == vout)
            {
                return None;
            }
            let output = outputs.iter().find(|output| output.vout == vout)?;
            removed.push(output.clone());
        }
        Some(removed)
    }

    #[cfg(test)]
    pub(crate) fn encoded_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn header(&self) -> RecordHeader {
        match decode_header(&self.bytes) {
            Ok(header) => header,
            // `UtxoRecord` is only built through `from_encoded`, which runs
            // `validate_encoded` -> `decode_header`; a header decode failure
            // means the validated record was mutated in place.
            Err(error) => panic!("UtxoRecord is validated at construction: {error:?}"),
        }
    }

    fn owned_outputs(&self) -> (Vec<OwnedUtxoOut>, usize) {
        let legacy_inline_len = self.header().legacy_inline_len;
        let outputs = self
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
            .collect();
        (outputs, legacy_inline_len)
    }

    fn from_owned_parts(
        txid: Hash256,
        legacy_inline_len: usize,
        outputs: &[OwnedUtxoOut],
    ) -> Result<Self, UtxoError> {
        let output_count = u32::try_from(outputs.len())
            .map_err(|_| UtxoError::RecordTooLarge { len: outputs.len() })?;
        if legacy_inline_len > LEGACY_INLINE_CAPACITY || legacy_inline_len > outputs.len() {
            return Err(UtxoError::CorruptRecord);
        }

        let mut payload_len = RECORD_HEADER_LEN;
        for output in outputs {
            let script_len = output.script_pubkey.len();
            let _ = u16::try_from(script_len)
                .map_err(|_| UtxoError::ScriptTooLarge { len: script_len })?;
            payload_len = payload_len
                .checked_add(OUTPUT_METADATA_LEN)
                .and_then(|len| len.checked_add(script_len))
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
        debug_assert_eq!(bytes.len(), payload_len);
        Self::from_encoded(bytes.into_boxed_slice())
    }
}

fn stage_add_to_parts(
    txid: Hash256,
    mut outputs: Vec<OwnedUtxoOut>,
    mut legacy_inline_len: usize,
    additions: Vec<OwnedUtxoOut>,
    add_unique: bool,
) -> Result<(UtxoRecord, Vec<Option<OwnedUtxoOut>>), UtxoError> {
    let mut overwritten = Vec::with_capacity(additions.len());
    for addition in additions {
        if add_unique {
            debug_assert!(outputs.iter().all(|output| output.vout != addition.vout));
            push_output(&mut outputs, &mut legacy_inline_len, addition);
            overwritten.push(None);
        } else {
            let old = outputs
                .iter()
                .position(|output| output.vout == addition.vout)
                .map(|index| remove_output_at(&mut outputs, &mut legacy_inline_len, index));
            push_output(&mut outputs, &mut legacy_inline_len, addition);
            overwritten.push(old);
        }
    }
    let replacement = UtxoRecord::from_owned_parts(txid, legacy_inline_len, &outputs)?;
    Ok((replacement, overwritten))
}

fn push_output(
    outputs: &mut Vec<OwnedUtxoOut>,
    legacy_inline_len: &mut usize,
    output: OwnedUtxoOut,
) {
    if *legacy_inline_len < LEGACY_INLINE_CAPACITY {
        outputs.insert(*legacy_inline_len, output);
        *legacy_inline_len += 1;
    } else {
        outputs.push(output);
    }
}

fn remove_output_at(
    outputs: &mut Vec<OwnedUtxoOut>,
    legacy_inline_len: &mut usize,
    index: usize,
) -> OwnedUtxoOut {
    if index < *legacy_inline_len {
        let last_inline = *legacy_inline_len - 1;
        outputs.swap(index, last_inline);
        *legacy_inline_len -= 1;
        outputs.remove(last_inline)
    } else {
        outputs.swap_remove(index)
    }
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
                    let (replacement, overwritten) = record.stage_add_run(additions, add_unique)?;
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
            record.stage_add_run(vec![too_large], true),
            Err(UtxoError::ScriptTooLarge { .. })
        ));
        assert_eq!(record, original);
        Ok(())
    }
}
