//! Streaming length-prefixed Core frames for contiguous archives.
//!
//! A Core frame is a self-describing record:
//!
//! ```text
//! magic     [u8; CORE_FRAME_MAGIC_LEN]   caller-supplied magic, e.g. a network's P2P message-start bytes
//! length    u32 little-endian            payload length in bytes
//! payload   [u8; length]                 exactly `length` payload bytes
//! ```
//!
//! Record offsets point at the first byte of `magic`. The writer returns the
//! exact offset of each record it writes. The reader, given an expected magic
//! and a caller-configured maximum payload length, streams records and returns
//! `Ok(None)` exactly when a clean end-of-file boundary is reached at the start
//! of a record. Any partial magic, partial length, or partial payload is an
//! error.
//!
//! All arithmetic on offsets and lengths is checked; overflow produces
//! [`CoreFrameError::Overflow`].

use std::io::{self, Read, Write};

use thiserror::Error;

/// Byte length of the magic field in a Core frame.
pub const CORE_FRAME_MAGIC_LEN: usize = 4;
/// Total byte length of a Core frame header (magic + length).
pub const CORE_FRAME_HEADER_LEN: u64 = 8;

const LENGTH_LEN: usize = 4;
const HEADER_LEN: usize = CORE_FRAME_MAGIC_LEN + LENGTH_LEN;

/// Errors that can occur when reading or writing Core frames.
#[derive(Debug, Error)]
pub enum CoreFrameError {
    /// The magic bytes in the stream did not match the expected value.
    #[error("wrong magic: expected {expected:?}, got {got:?}")]
    WrongMagic {
        /// Magic expected by the reader.
        expected: [u8; CORE_FRAME_MAGIC_LEN],
        /// Magic read from the stream.
        got: [u8; CORE_FRAME_MAGIC_LEN],
    },
    /// The header was truncated before the full 8 bytes could be read.
    #[error("partial header: needed {needed} bytes, got {got}")]
    PartialHeader {
        /// Number of bytes required for a complete header.
        needed: usize,
        /// Number of bytes actually read.
        got: usize,
    },
    /// The payload was truncated before the declared length could be read.
    #[error("partial payload: expected {expected} bytes, got {got}")]
    PartialPayload {
        /// Declared payload length.
        expected: u32,
        /// Number of payload bytes actually read.
        got: usize,
    },
    /// The declared payload length exceeds the caller's configured maximum.
    #[error("payload too large: length {length}, maximum {max}")]
    PayloadTooLarge {
        /// Declared payload length.
        length: u32,
        /// Caller-configured maximum payload length.
        max: u32,
    },
    /// Offset or length arithmetic overflowed `u64`.
    #[error("offset/length overflow: {context}")]
    Overflow {
        /// Context describing which arithmetic operation overflowed.
        context: &'static str,
    },
    /// Underlying I/O failure.
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

/// Metadata describing one Core frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreFrameMetadata {
    /// Byte offset of the record's magic in the stream.
    pub offset: u64,
    /// Payload length in bytes, not including the 8-byte header.
    pub len: u32,
}

/// A complete Core frame returned by [`CoreFrameReader::read_next`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreFrameRecord {
    /// Position and size metadata for this record.
    pub metadata: CoreFrameMetadata,
    /// Owned payload bytes.
    pub payload: Vec<u8>,
}

/// Streaming writer for Core frames.
///
/// Each call to [`Self::write`] appends one `magic + u32 LE length + payload`
/// record and returns the exact offset of that record's magic. The payload is
/// borrowed for the write, so the caller retains ownership of the bytes.
pub struct CoreFrameWriter<W> {
    inner: W,
    magic: [u8; CORE_FRAME_MAGIC_LEN],
    offset: u64,
}

impl<W: Write> CoreFrameWriter<W> {
    /// Creates a writer starting at offset `0`.
    pub fn new(inner: W, magic: [u8; CORE_FRAME_MAGIC_LEN]) -> Self {
        Self::with_offset(inner, magic, 0)
    }

    /// Creates a writer with an explicit starting offset.
    ///
    /// `offset` is the byte position of the next record's magic in the stream.
    pub fn with_offset(inner: W, magic: [u8; CORE_FRAME_MAGIC_LEN], offset: u64) -> Self {
        Self {
            inner,
            magic,
            offset,
        }
    }

    /// Returns the byte offset of the next record to be written.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Writes one Core frame with the given payload.
    ///
    /// The payload is borrowed, not copied, before being written to the
    /// underlying stream. Returns the metadata of the record written.
    pub fn write(&mut self, payload: &[u8]) -> Result<CoreFrameMetadata, CoreFrameError> {
        let payload_len = u32::try_from(payload.len()).map_err(|_| CoreFrameError::Overflow {
            context: "payload length does not fit u32",
        })?;
        let record_len = CORE_FRAME_HEADER_LEN
            .checked_add(u64::from(payload_len))
            .ok_or(CoreFrameError::Overflow {
                context: "record length overflow",
            })?;
        let record_offset = self.offset;
        let record_end = record_offset
            .checked_add(record_len)
            .ok_or(CoreFrameError::Overflow {
                context: "record offset overflow",
            })?;

        let mut header = [0_u8; HEADER_LEN];
        header[..CORE_FRAME_MAGIC_LEN].copy_from_slice(&self.magic);
        header[CORE_FRAME_MAGIC_LEN..].copy_from_slice(&payload_len.to_le_bytes());

        self.inner.write_all(&header)?;
        self.inner.write_all(payload)?;

        self.offset = record_end;
        Ok(CoreFrameMetadata {
            offset: record_offset,
            len: payload_len,
        })
    }
}

/// Streaming reader for Core frames.
///
/// The reader expects every record to begin with the caller-supplied `magic`,
/// followed by a little-endian `u32` payload length, followed by that many
/// payload bytes. It returns `Ok(None)` when it reaches a clean end-of-file
/// boundary at the start of a record. Any partial frame is an error.
pub struct CoreFrameReader<R> {
    inner: R,
    expected_magic: [u8; CORE_FRAME_MAGIC_LEN],
    max_payload: u32,
    offset: u64,
}

impl<R: Read> CoreFrameReader<R> {
    /// Creates a reader that expects `expected_magic` and rejects payloads
    /// larger than `max_payload` bytes.
    ///
    /// The initial offset is `0`. Use [`Self::with_offset`] to start elsewhere.
    pub fn new(inner: R, expected_magic: [u8; CORE_FRAME_MAGIC_LEN], max_payload: u32) -> Self {
        Self::with_offset(inner, expected_magic, max_payload, 0)
    }

    /// Creates a reader with an explicit starting offset.
    ///
    /// `offset` is the byte position of the next record's magic in the stream.
    pub fn with_offset(
        inner: R,
        expected_magic: [u8; CORE_FRAME_MAGIC_LEN],
        max_payload: u32,
        offset: u64,
    ) -> Self {
        Self {
            inner,
            expected_magic,
            max_payload,
            offset,
        }
    }

    /// Returns the byte offset of the next record to be read.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns a shared reference to the underlying reader.
    ///
    /// This lets a wrapping [`HashingReader`] expose its current digest
    /// without consuming or bypassing the frame parser.
    #[must_use]
    pub const fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Reads the next complete Core frame.
    ///
    /// Returns `Ok(None)` when the stream ends exactly at a record boundary.
    /// Any partial magic, length, or payload is an error.
    pub fn read_next(&mut self) -> Result<Option<CoreFrameRecord>, CoreFrameError> {
        let record_offset = self.offset;

        let mut header = [0_u8; HEADER_LEN];
        let mut total = 0;
        while total < HEADER_LEN {
            match self.inner.read(&mut header[total..])? {
                0 if total == 0 => return Ok(None),
                0 => {
                    return Err(CoreFrameError::PartialHeader {
                        needed: HEADER_LEN,
                        got: total,
                    });
                }
                n => total += n,
            }
        }

        let mut magic = [0_u8; CORE_FRAME_MAGIC_LEN];
        magic.copy_from_slice(&header[..CORE_FRAME_MAGIC_LEN]);
        if magic != self.expected_magic {
            return Err(CoreFrameError::WrongMagic {
                expected: self.expected_magic,
                got: magic,
            });
        }

        let mut length_bytes = [0_u8; LENGTH_LEN];
        length_bytes.copy_from_slice(&header[CORE_FRAME_MAGIC_LEN..]);
        let length = u32::from_le_bytes(length_bytes);

        if length > self.max_payload {
            return Err(CoreFrameError::PayloadTooLarge {
                length,
                max: self.max_payload,
            });
        }

        let record_end = record_offset
            .checked_add(CORE_FRAME_HEADER_LEN)
            .and_then(|o| o.checked_add(u64::from(length)))
            .ok_or(CoreFrameError::Overflow {
                context: "record end overflow",
            })?;

        let payload_len = usize::try_from(length).map_err(|_| CoreFrameError::Overflow {
            context: "payload length does not fit usize",
        })?;
        let mut payload = vec![0_u8; payload_len];
        if payload_len > 0 {
            let mut got = 0;
            while got < payload_len {
                match self.inner.read(&mut payload[got..])? {
                    0 if got == 0 => {
                        return Err(CoreFrameError::PartialPayload {
                            expected: length,
                            got: 0,
                        });
                    }
                    0 => {
                        return Err(CoreFrameError::PartialPayload {
                            expected: length,
                            got,
                        });
                    }
                    n => got += n,
                }
            }
        }

        self.offset = record_end;
        Ok(Some(CoreFrameRecord {
            metadata: CoreFrameMetadata {
                offset: record_offset,
                len: length,
            },
            payload,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const MAGIC: [u8; 4] = *b"TEST";

    #[test]
    fn round_trips_multiple_records_and_exact_bytes() -> Result<(), CoreFrameError> {
        let mut buf = Vec::new();
        let mut writer = CoreFrameWriter::new(&mut buf, MAGIC);

        let first = writer.write(b"")?;
        let second = writer.write(b"second")?;

        assert_eq!(first, CoreFrameMetadata { offset: 0, len: 0 });
        assert_eq!(second, CoreFrameMetadata { offset: 8, len: 6 });

        let mut expected = Vec::new();
        expected.extend_from_slice(&MAGIC);
        expected.extend_from_slice(&0_u32.to_le_bytes());
        expected.extend_from_slice(&MAGIC);
        expected.extend_from_slice(&6_u32.to_le_bytes());
        expected.extend_from_slice(b"second");
        assert_eq!(buf, expected);

        let mut reader = CoreFrameReader::new(Cursor::new(&buf[..]), MAGIC, u32::MAX);

        let Some(first_record) = reader.read_next()? else {
            panic!("expected first record");
        };
        assert_eq!(
            first_record.metadata,
            CoreFrameMetadata { offset: 0, len: 0 }
        );
        assert_eq!(first_record.payload, b"");

        let Some(second_record) = reader.read_next()? else {
            panic!("expected second record");
        };
        assert_eq!(
            second_record.metadata,
            CoreFrameMetadata { offset: 8, len: 6 }
        );
        assert_eq!(second_record.payload, b"second");

        assert_eq!(reader.read_next()?, None);
        assert_eq!(reader.get_ref().position(), reader.offset());
        Ok(())
    }

    #[test]
    fn get_ref_peeks_underlying_reader_without_consuming_parser() -> Result<(), CoreFrameError> {
        let mut buf = Vec::new();
        let mut writer = CoreFrameWriter::new(&mut buf, MAGIC);
        writer.write(b"peek")?;
        let mut reader = CoreFrameReader::new(Cursor::new(&buf[..]), MAGIC, u32::MAX);
        let Some(_record) = reader.read_next()? else {
            panic!("expected one record");
        };
        // The frame reader owns the cursor, but get_ref still lets callers
        // observe the exact byte position the parser reached.
        assert_eq!(reader.get_ref().position(), reader.offset());
        assert_eq!(reader.read_next()?, None);
        Ok(())
    }

    #[test]
    fn empty_input() -> Result<(), CoreFrameError> {
        let mut reader = CoreFrameReader::new(Cursor::new(b""), MAGIC, u32::MAX);
        assert_eq!(reader.read_next()?, None);
        Ok(())
    }

    #[test]
    fn wrong_magic() -> Result<(), CoreFrameError> {
        let mut buf = Vec::new();
        CoreFrameWriter::new(&mut buf, *b"GOOD").write(b"payload")?;

        let mut reader = CoreFrameReader::new(Cursor::new(&buf[..]), *b"BADS", u32::MAX);
        match reader.read_next() {
            Err(CoreFrameError::WrongMagic { expected, got }) => {
                assert_eq!(expected, *b"BADS");
                assert_eq!(got, *b"GOOD");
            }
            other => panic!("expected WrongMagic, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn short_header() {
        let mut reader = CoreFrameReader::new(Cursor::new(&[1u8, 2, 3]), MAGIC, u32::MAX);
        match reader.read_next() {
            Err(CoreFrameError::PartialHeader { needed, got }) => {
                assert_eq!(needed, HEADER_LEN);
                assert_eq!(got, 3);
            }
            other => panic!("expected PartialHeader, got {other:?}"),
        }
    }

    #[test]
    fn short_payload() {
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC);
        data.extend_from_slice(&10_u32.to_le_bytes());
        data.extend_from_slice(b"hello");

        let mut reader = CoreFrameReader::new(Cursor::new(&data[..]), MAGIC, u32::MAX);
        match reader.read_next() {
            Err(CoreFrameError::PartialPayload { expected, got }) => {
                assert_eq!(expected, 10);
                assert_eq!(got, 5);
            }
            other => panic!("expected PartialPayload, got {other:?}"),
        }
    }

    #[test]
    fn size_limit() {
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC);
        data.extend_from_slice(&8_u32.to_le_bytes());
        data.extend_from_slice(b"12345678");

        let mut reader = CoreFrameReader::new(Cursor::new(&data[..]), MAGIC, 4);
        match reader.read_next() {
            Err(CoreFrameError::PayloadTooLarge { length, max }) => {
                assert_eq!(length, 8);
                assert_eq!(max, 4);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn reader_offset_overflow() {
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC);
        data.extend_from_slice(&4_u32.to_le_bytes());
        data.extend_from_slice(b"1234");

        let mut reader =
            CoreFrameReader::with_offset(Cursor::new(&data[..]), MAGIC, 4, u64::MAX - 7);
        match reader.read_next() {
            Err(CoreFrameError::Overflow { .. }) => {}
            other => panic!("expected Overflow, got {other:?}"),
        }
    }

    #[test]
    fn writer_offset_overflow() {
        let mut writer = CoreFrameWriter::with_offset(std::io::sink(), MAGIC, u64::MAX - 7);
        match writer.write(b"1234") {
            Err(CoreFrameError::Overflow { .. }) => {}
            other => panic!("expected Overflow, got {other:?}"),
        }
    }
}
