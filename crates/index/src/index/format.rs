//! Row-value format markers.

/// Metadata key marking which row-value format an index was written with.
pub(super) const INDEX_FORMAT_VERSION_KEY: &[u8] = b"index:format_version";

/// Current row-value format.
///
/// Version 1 added transaction byte positions to funding and txid row values;
/// version 2 added positions to spending row values; version 3 narrowed
/// positions to 6 bytes (u24 offset + u24 length); version 0 (unmarked) has
/// empty values.
pub const INDEX_FORMAT_VERSION: u32 = 3;
