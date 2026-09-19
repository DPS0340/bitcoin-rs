use super::*;

#[test]
fn authenticated_header_semantics_require_resync() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(2, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let tree = RwLock::new(tree);
    super::super::write_checkpoint(
        dir.path(),
        config(),
        &tree,
        &UtxoSet::new(),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    )?;
    mutate_authenticated_artifact(dir.path(), HEADERS_FILE, |bytes| {
        bytes[headers::HEADER_PREFIX_LEN + 80 + 4] ^= 1;
    })?;

    let Err(error) = load_checkpoint(dir.path(), config()) else {
        return Err("corrupt header checkpoint unexpectedly loaded".into());
    };
    assert!(error.to_string().contains("full resync"));
    Ok(())
}

/// The offsets below are the checkpoint envelope (16 bytes) followed by the
/// stable `CoinStats::to_bytes` layout defined in
/// `crates/utxo/src/stats/coin_stats.rs`: `MuHash` numerator/denominator, then
/// height, total amount, bogo size, transaction count, and UTXO count.
/// The `full resync` assertion is the checkpoint recovery contract documented
/// in `docs/policies/db-migration.md` and exercised by the loader.
#[test]
fn authenticated_coinstats_semantics_require_resync() -> Result<(), Box<dyn std::error::Error>> {
    const COINSTATS_ENVELOPE_BYTES: usize = 16;
    const MUHASH_BYTES: usize = 384 + 384;
    const HEIGHT_BYTES: usize = 4;
    const U64_BYTES: usize = 8;
    const COINSTATS_FIELD_OFFSETS: [usize; 6] = [
        COINSTATS_ENVELOPE_BYTES,
        COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES,
        COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES + HEIGHT_BYTES,
        COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES + HEIGHT_BYTES + U64_BYTES,
        COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES + HEIGHT_BYTES + 2 * U64_BYTES,
        COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES + HEIGHT_BYTES + 3 * U64_BYTES,
    ];

    for offset in COINSTATS_FIELD_OFFSETS {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        super::super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &UtxoSet::new(),
            &CoinStatsListener::new(CoinStats::new()),
            Some(&applied_tip),
        )?;
        mutate_authenticated_artifact(dir.path(), COINSTATS_FILE, |bytes| {
            bytes[offset] ^= 1;
        })?;

        let Err(error) = load_checkpoint(dir.path(), config()) else {
            return Err("corrupt CoinStats checkpoint unexpectedly loaded".into());
        };
        assert!(error.to_string().contains("full resync"));
    }
    Ok(())
}

#[test]
fn authenticated_utxo_value_mutation_requires_resync() -> Result<(), Box<dyn std::error::Error>> {
    const FIRST_VALUE_OFFSET: usize = 52 + 45 + 4;

    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    super::super::write_checkpoint(
        dir.path(),
        config(),
        &RwLock::new(tree),
        &populated_utxo()?,
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    )?;

    mutate_authenticated_artifact(dir.path(), UTXO_FILE, |bytes| {
        bytes[FIRST_VALUE_OFFSET] ^= 1;
    })?;
    let Err(error) = load_checkpoint(dir.path(), config()) else {
        return Err("corrupt UTXO checkpoint unexpectedly loaded".into());
    };
    assert!(error.to_string().contains("full resync"));
    Ok(())
}
