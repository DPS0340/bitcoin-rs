//! Boot fast path: replays validated journal records into chainstate.

use bitcoin_rs_chain::{BlockTree, NodeStatus};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Header;
use bitcoin_rs_storage::chainstate_journal::{
    Coin, JournalRecord, JournalReplayBase, JournalReplayError, Mutation, replay_committed_range,
};
use bitcoin_rs_utxo::{BorrowedBlockChanges, BorrowedUtxoAdd, UtxoSet};

/// Classification of a boot replay attempt.
pub(crate) enum ReplayOutcome {
    Replayed(Box<ReplayedState>),
    Fallback(JournalReplayError),
}

/// State reconstructed by a successful replay.
pub(crate) struct ReplayedState {
    pub tree: BlockTree,
    pub utxo: UtxoSet,
    pub coin_stats: bitcoin_rs_utxo::stats::CoinStats,
    pub applied_tip: bitcoin_rs_chain::TipSnapshot,
    pub chain_tx_count: u64,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn replay_from_journal(
    dir: &cap_std::fs::Dir,
    base_generation: u64,
    tree: BlockTree,
    utxo: UtxoSet,
    coin_stats: bitcoin_rs_utxo::stats::CoinStats,
    base_tip: bitcoin_rs_chain::TipSnapshot,
    base_chain_tx_count: u64,
) -> ReplayOutcome {
    let base_tip_hash = base_tip.hash.to_le_bytes();
    let base_tip_height = base_tip.height;
    let mut replay =
        match ReplayAccumulator::new(tree, utxo, coin_stats, base_tip, base_chain_tx_count) {
            Ok(replay) => replay,
            Err(error) => return ReplayOutcome::Fallback(error),
        };
    let head = match replay_committed_range(
        dir,
        JournalReplayBase {
            generation: base_generation,
            height: base_tip_height,
            block_hash: base_tip_hash,
            chain_tx_count: base_chain_tx_count,
        },
        |record| replay.apply(record),
    ) {
        Ok(head) => head,
        Err(error) => return ReplayOutcome::Fallback(error),
    };
    let state = replay.finish();
    if let Err(error) = validate_replayed_head(&state, head.height, head.block_hash) {
        return ReplayOutcome::Fallback(error);
    }
    if state.chain_tx_count != head.chain_tx_count {
        return ReplayOutcome::Fallback(JournalReplayError::CommittedRangeInvalid(
            "chain transaction count does not match head marker".to_owned(),
        ));
    }
    ReplayOutcome::Replayed(Box::new(state))
}

fn validate_replayed_head(
    state: &ReplayedState,
    height: u32,
    block_hash: [u8; 32],
) -> Result<(), JournalReplayError> {
    if state.applied_tip.height != height || state.applied_tip.hash.to_le_bytes() != block_hash {
        return Err(JournalReplayError::CommittedRangeInvalid(
            "replayed tip identity does not match head marker".to_owned(),
        ));
    }
    Ok(())
}

/// Applies ordered records above a restored checkpoint state.
///
/// Headers first regenerate valid `NodeId`s and chainwork. Mutations then pass
/// through the same `UtxoSet` commit surface as live apply, with a listener
/// seeded from the checkpoint `CoinStats`.
struct ReplayAccumulator {
    tree: BlockTree,
    utxo: UtxoSet,
    coin_stats: bitcoin_rs_utxo::stats::CoinStatsListener,
    applied_tip: bitcoin_rs_chain::TipSnapshot,
    prev_hash: [u8; 32],
    chain_tx_count: u64,
}

impl ReplayAccumulator {
    fn new(
        tree: BlockTree,
        mut utxo: UtxoSet,
        initial_coin_stats: bitcoin_rs_utxo::stats::CoinStats,
        base_tip: bitcoin_rs_chain::TipSnapshot,
        base_chain_tx_count: u64,
    ) -> Result<Self, JournalReplayError> {
        if base_chain_tx_count == 0 {
            return Err(JournalReplayError::CommittedRangeInvalid(
                "checkpoint chain_tx_count is unknown".to_owned(),
            ));
        }
        let base_node = tree.node(base_tip.tip_id).map_err(|error| {
            JournalReplayError::HeaderRebuildRejected(format!(
                "checkpoint tip node is unavailable: {error}"
            ))
        })?;
        if base_node.height != base_tip.height
            || base_node.hash != base_tip.hash
            || base_node.chainwork != base_tip.chainwork
        {
            return Err(JournalReplayError::HeaderRebuildRejected(
                "checkpoint tip snapshot does not match its tree node".to_owned(),
            ));
        }
        let coin_stats = bitcoin_rs_utxo::stats::CoinStatsListener::new(initial_coin_stats);
        utxo.set_listener(Box::new(coin_stats.clone()));
        let prev_hash = base_tip.hash.to_le_bytes();
        Ok(Self {
            tree,
            utxo,
            coin_stats,
            applied_tip: base_tip,
            prev_hash,
            chain_tx_count: base_chain_tx_count,
        })
    }

    fn apply(&mut self, record: &JournalRecord) -> Result<(), JournalReplayError> {
        self.chain_tx_count = self
            .chain_tx_count
            .checked_add(record.block_tx_count)
            .ok_or_else(|| {
                JournalReplayError::CommittedRangeInvalid(
                    "chain transaction count overflow".to_owned(),
                )
            })?;
        self.applied_tip =
            insert_replayed_header(&mut self.tree, record, self.prev_hash, self.chain_tx_count)?;
        apply_record_mutations(&self.utxo, record)?;
        advance_coin_stats(&self.coin_stats, record)?;
        self.prev_hash = record.block_hash;
        Ok(())
    }

    fn finish(self) -> ReplayedState {
        ReplayedState {
            tree: self.tree,
            utxo: self.utxo,
            coin_stats: self.coin_stats.snapshot(),
            applied_tip: self.applied_tip,
            chain_tx_count: self.chain_tx_count,
        }
    }
}

#[cfg(test)]
#[allow(clippy::needless_pass_by_value)]
fn replay_records(
    records: Vec<JournalRecord>,
    tree: BlockTree,
    utxo: UtxoSet,
    initial_coin_stats: bitcoin_rs_utxo::stats::CoinStats,
    base_tip: bitcoin_rs_chain::TipSnapshot,
    base_chain_tx_count: u64,
) -> Result<ReplayedState, JournalReplayError> {
    let mut replay = ReplayAccumulator::new(
        tree,
        utxo,
        initial_coin_stats,
        base_tip,
        base_chain_tx_count,
    )?;
    for record in &records {
        replay.apply(record)?;
    }
    Ok(replay.finish())
}

fn insert_replayed_header(
    tree: &mut BlockTree,
    record: &JournalRecord,
    expected_prev: [u8; 32],
    chain_tx_count: u64,
) -> Result<bitcoin_rs_chain::TipSnapshot, JournalReplayError> {
    let header = Header::consensus_decode(&record.raw_header[..]).map_err(|error| {
        JournalReplayError::HeaderRebuildRejected(format!("height {}: {error}", record.height))
    })?;
    if expected_prev != record.prev_hash
        || header.prev_blockhash.0.to_le_bytes() != record.prev_hash
        || header.compute_hash().0.to_le_bytes() != record.block_hash
    {
        return Err(JournalReplayError::CommittedRangeInvalid(format!(
            "record {} header identity does not match its chain fields",
            record.height
        )));
    }
    let parent = tree
        .lookup(Hash256::from_le_bytes(&expected_prev))
        .ok_or_else(|| {
            JournalReplayError::HeaderRebuildRejected(format!(
                "height {}: parent {} missing from checkpoint tree",
                record.height,
                hex(&record.prev_hash)
            ))
        })?;
    let node_id = tree
        .insert_node(Some(parent), header, NodeStatus::HeaderValid)
        .map_err(|error| {
            JournalReplayError::HeaderRebuildRejected(format!("height {}: {error}", record.height))
        })?;
    tree.restore_chain_tx_count(node_id, chain_tx_count)
        .map_err(|error| {
            JournalReplayError::HeaderRebuildRejected(format!("height {}: {error}", record.height))
        })?;
    let node = tree.node(node_id).map_err(|error| {
        JournalReplayError::HeaderRebuildRejected(format!("height {}: {error}", record.height))
    })?;
    if node.height != record.height || node.hash.to_le_bytes() != record.block_hash {
        return Err(JournalReplayError::HeaderRebuildRejected(format!(
            "height {}: rebuilt node identity mismatch",
            record.height
        )));
    }
    Ok(bitcoin_rs_chain::TipSnapshot {
        tip_id: node_id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
    })
}

fn apply_record_mutations(
    utxo: &UtxoSet,
    record: &JournalRecord,
) -> Result<(), JournalReplayError> {
    let mut changes =
        BorrowedBlockChanges::with_capacity(record.mutations.len(), record.mutations.len());
    for mutation in &record.mutations {
        match mutation {
            Mutation::Create { coin } => {
                if utxo.get_entry(&coin.outpoint).is_some() {
                    return Err(JournalReplayError::CommittedRangeInvalid(format!(
                        "create at height {} overwrites a live coin",
                        record.height
                    )));
                }
                changes.add(BorrowedUtxoAdd::new(
                    coin.outpoint,
                    &coin.txout,
                    coin.coinbase,
                    coin.height,
                ));
            }
            Mutation::Spend { coin } => {
                require_live_coin(utxo, coin, record.height, "spend")?;
                changes.remove(coin.outpoint);
            }
            Mutation::Overwrite { old_coin, new_coin } => {
                require_live_coin(utxo, old_coin, record.height, "overwrite")?;
                if old_coin.outpoint != new_coin.outpoint {
                    return Err(JournalReplayError::CommittedRangeInvalid(format!(
                        "overwrite at height {} changes its outpoint",
                        record.height
                    )));
                }
                changes.add(BorrowedUtxoAdd::new(
                    new_coin.outpoint,
                    &new_coin.txout,
                    new_coin.coinbase,
                    new_coin.height,
                ));
            }
        }
    }
    utxo.commit_borrowed_block(&changes, &block_hash_of(record))
        .map_err(|error| {
            JournalReplayError::CommittedRangeInvalid(format!(
                "height {}: utxo commit failed: {error}",
                record.height
            ))
        })
}

fn advance_coin_stats(
    coin_stats: &bitcoin_rs_utxo::stats::CoinStatsListener,
    record: &JournalRecord,
) -> Result<(), JournalReplayError> {
    let expected_height = i64::from(coin_stats.snapshot().height)
        .checked_add(record.coin_stats_height_delta)
        .and_then(|height| u32::try_from(height).ok())
        .ok_or_else(|| {
            JournalReplayError::CommittedRangeInvalid(format!(
                "height {}: invalid CoinStats height delta {}",
                record.height, record.coin_stats_height_delta
            ))
        })?;
    if expected_height != record.height {
        return Err(JournalReplayError::CommittedRangeInvalid(format!(
            "height {}: CoinStats delta reaches {expected_height}",
            record.height
        )));
    }
    coin_stats.finish_block(record.height, record.block_tx_count);
    Ok(())
}

fn require_live_coin(
    utxo: &UtxoSet,
    coin: &Coin,
    record_height: u32,
    mutation: &str,
) -> Result<(), JournalReplayError> {
    let Some(live) = utxo.get_entry(&coin.outpoint) else {
        return Err(JournalReplayError::CommittedRangeInvalid(format!(
            "{mutation} at height {record_height} references a missing coin"
        )));
    };
    if live.height != coin.height || live.coinbase != coin.coinbase || live.txout != coin.txout {
        return Err(JournalReplayError::CommittedRangeInvalid(format!(
            "{mutation} at height {record_height} does not match the live coin"
        )));
    }
    Ok(())
}

/// Lowercase hex for diagnostics.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// The record's block hash as a [`Hash256`] (big-endian raw, matching the
/// header chain's hash semantics).
fn block_hash_of(record: &JournalRecord) -> Hash256 {
    Hash256::from_le_bytes(&record.block_hash)
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_chain::{BlockTree, NodeStatus, TipSnapshot};
    use bitcoin_rs_primitives::{
        Amount, BlockHash, CompactTarget, Hash256, Header, OutPoint, TxOut, Txid, consensus_bytes,
    };
    use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
    use bitcoin_rs_utxo::{BorrowedBlockChanges, BorrowedUtxoAdd, UtxoSet};

    use super::{JournalRecord, Mutation, replay_records, validate_replayed_head};
    use bitcoin_rs_storage::chainstate_journal::Coin;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    type BaseState = (BlockTree, UtxoSet, CoinStats, TipSnapshot, Coin);

    fn header(prev_blockhash: BlockHash, marker: u8, time: u32) -> Header {
        let mut merkle = [0_u8; 32];
        merkle[0] = marker;
        Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::from_le_bytes(&merkle),
            time,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: u32::from(marker),
        }
    }

    fn raw_header(header: &Header) -> [u8; 80] {
        let encoded = consensus_bytes(header);
        assert_eq!(encoded.len(), 80, "consensus header length changed");
        let mut raw = [0_u8; 80];
        raw.copy_from_slice(&encoded);
        raw
    }

    fn coin(marker: u8, height: u32, value: u64) -> Coin {
        Coin {
            outpoint: OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0),
            txout: TxOut {
                value: Amount::from_sat(value),
                script_pubkey: vec![0x51].into(),
            },
            height,
            coinbase: true,
        }
    }

    fn base_state() -> TestResult<BaseState> {
        let mut tree = BlockTree::new();
        let base_header = header(BlockHash::default(), 1, 1);
        let base_id = tree.insert_node(None, base_header, NodeStatus::HeaderValid)?;
        tree.restore_chain_tx_count(base_id, 1)?;
        let base_node = tree.node(base_id)?;
        let base_tip = TipSnapshot {
            tip_id: base_id,
            height: base_node.height,
            chainwork: base_node.chainwork,
            hash: base_node.hash,
        };

        let base_coin = coin(1, 0, 50);
        let listener = CoinStatsListener::new(CoinStats::default());
        let mut utxo = UtxoSet::new();
        utxo.set_listener(Box::new(listener.clone()));
        let mut changes = BorrowedBlockChanges::with_capacity(1, 0);
        changes.add(BorrowedUtxoAdd::new(
            base_coin.outpoint,
            &base_coin.txout,
            base_coin.coinbase,
            base_coin.height,
        ));
        utxo.commit_borrowed_block(&changes, &base_tip.hash)?;
        listener.finish_block(0, 1);
        Ok((tree, utxo, listener.snapshot(), base_tip, base_coin))
    }

    #[test]
    fn replayed_frontier_must_match_the_durable_head_identity() -> TestResult {
        let (tree, utxo, coin_stats, base_tip, _) = base_state()?;
        let next_header = header(BlockHash(base_tip.hash), 2, 2);
        let next_hash = next_header.compute_hash();
        let record = JournalRecord {
            height: 1,
            block_hash: next_hash.0.to_le_bytes(),
            prev_hash: base_tip.hash.to_le_bytes(),
            block_tx_count: 2,
            coin_stats_height_delta: 1,
            raw_header: raw_header(&next_header),
            mutations: Vec::new(),
        };
        let replayed = replay_records(vec![record], tree, utxo, coin_stats, base_tip, 1)?;

        validate_replayed_head(
            &replayed,
            replayed.applied_tip.height,
            replayed.applied_tip.hash.to_le_bytes(),
        )?;
        assert!(
            validate_replayed_head(
                &replayed,
                replayed.applied_tip.height + 1,
                replayed.applied_tip.hash.to_le_bytes(),
            )
            .is_err()
        );
        let mut wrong_hash = replayed.applied_tip.hash.to_le_bytes();
        wrong_hash[0] ^= 0xff;
        assert!(
            validate_replayed_head(&replayed, replayed.applied_tip.height, wrong_hash).is_err()
        );
        Ok(())
    }

    #[test]
    fn replay_extends_checkpoint_state_and_returns_valid_tip() -> TestResult {
        let (tree, utxo, coin_stats, base_tip, base_coin) = base_state()?;
        let next_header = header(BlockHash(base_tip.hash), 2, 2);
        let next_hash = next_header.compute_hash();
        let new_coin = coin(2, 1, 25);
        let record = JournalRecord {
            height: 1,
            block_hash: next_hash.0.to_le_bytes(),
            prev_hash: base_tip.hash.to_le_bytes(),
            block_tx_count: 2,
            coin_stats_height_delta: 1,
            raw_header: raw_header(&next_header),
            mutations: vec![Mutation::Create {
                coin: new_coin.clone(),
            }],
        };

        let replayed = replay_records(vec![record], tree, utxo, coin_stats, base_tip, 1)?;

        assert!(replayed.utxo.get_entry(&base_coin.outpoint).is_some());
        assert!(replayed.utxo.get_entry(&new_coin.outpoint).is_some());
        assert_eq!(replayed.chain_tx_count, 3);
        assert_eq!(replayed.coin_stats.height, 1);
        assert_eq!(replayed.coin_stats.tx_count, 3);
        assert_eq!(replayed.applied_tip.height, 1);
        assert_eq!(replayed.applied_tip.hash, next_hash.0);
        let node = replayed.tree.node(replayed.applied_tip.tip_id)?;
        assert_eq!(node.hash, replayed.applied_tip.hash);
        assert_eq!(node.chainwork, replayed.applied_tip.chainwork);
        Ok(())
    }
}
