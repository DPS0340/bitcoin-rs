/// BIP68 disable flag (`1 << 31`).
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
/// BIP68 type flag: set means time-based, clear means height-based (`1 << 22`).
pub(crate) const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
/// BIP68 relative-lock magnitude mask.
pub(crate) const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;
/// BIP68 time-based granularity in seconds (`2^9`).
pub(crate) const SEQUENCE_LOCKTIME_GRANULARITY_SECONDS: u32 = 512;

/// Returns whether a relative sequence lock is satisfied at `block_height` / `block_mtp`.
///
/// Unconfirmed prevouts are encoded as `prevout_height == block_height` (the
/// next block, for mempool admission) so any positive relative lock fails.
#[must_use]
pub fn sequence_lock_satisfied(
    tx_version: i32,
    sequence: u32,
    prevout_height: u32,
    prevout_mtp: u32,
    block_height: u32,
    block_mtp: u32,
) -> bool {
    if tx_version < 2 || sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
        return true;
    }
    if sequence & SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
        let relative_intervals = sequence & SEQUENCE_LOCKTIME_MASK;
        let earliest_time = prevout_mtp.saturating_add(
            relative_intervals.saturating_mul(SEQUENCE_LOCKTIME_GRANULARITY_SECONDS),
        );
        block_mtp >= earliest_time
    } else {
        let relative_blocks = sequence & SEQUENCE_LOCKTIME_MASK;
        let earliest_height = prevout_height.saturating_add(relative_blocks);
        block_height >= earliest_height
    }
}

#[cfg(test)]
mod tests {
    use super::sequence_lock_satisfied;

    #[test]
    fn next_block_height_lock_of_one_is_met_after_one_confirmation() {
        assert!(sequence_lock_satisfied(2, 1, 10, 0, 11, 0));
        assert!(!sequence_lock_satisfied(2, 1, 10, 0, 10, 0));
    }

    #[test]
    fn unconfirmed_parent_fails_positive_relative_height_lock() {
        assert!(!sequence_lock_satisfied(2, 1, 11, 0, 11, 0));
        assert!(sequence_lock_satisfied(2, 0, 11, 0, 11, 0));
    }
}
