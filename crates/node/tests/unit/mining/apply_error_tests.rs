// CONTRACT: `docs/contracts/external-api.md#API-05` and `#API-11` own
// mining validation/submission projection; `map_apply_error` is the in-code
// mapping contract from chainstate refusal to BIP22/BIP23 validation results.
use super::{map_apply_error, test_block_validity_error};
use crate::apply::error::ApplyError;
use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::ChainWork;
use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_mining::BlockValidationResult;
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Txid;
use compact_str::CompactString;

#[test]
fn operational_failures_are_not_block_rejections() {
    fn failures() -> Vec<ApplyError> {
        use bitcoin_rs_storage::StorageError;
        vec![
            ApplyError::UtxoCommit(bitcoin_rs_utxo::UtxoError::CorruptRecord),
            ApplyError::BlockBodyPersistence(StorageError::InvalidOperation("body write failed")),
            ApplyError::UndoPersistence(StorageError::InvalidOperation("undo write failed")),
            ApplyError::DurableHeadCommit(StorageError::InvalidOperation("head write failed")),
            ApplyError::DurableHeadLineage {
                head: Hash256::default(),
                prev: Hash256::from_le_bytes(&[1; 32]),
            },
            ApplyError::Consensus(ConsensusError::Kernel("verifier unavailable".to_owned())),
            ApplyError::Consensus(ConsensusError::PrevoutMatrixSize {
                expected: 1,
                actual: 0,
            }),
        ]
    }

    for error in failures() {
        let result = map_apply_error(error);
        assert!(
            matches!(result, Err(MiningControlError::Failed(_))),
            "operational failure became a block verdict: {result:?}"
        );
    }
    for error in failures() {
        let result = test_block_validity_error(&error);
        assert!(
            matches!(result, MiningControlError::Failed(_)),
            "generateblock hid an operational error: {result:?}"
        );
    }
}

#[test]
fn duplicate_classification_waits_for_chain_transition() -> anyhow::Result<()> {
    use crate::{MiningCoordinator, Network, NodeConfig, state::NodeState};
    use bitcoin_rs_mining::MiningControl;
    use std::sync::Arc;
    use std::time::Duration;

    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let genesis = Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    let mining = Arc::new(MiningCoordinator::new(
        Network::Regtest,
        state.applied_tip(),
        state.block_tree(),
        state.mempool(),
        state.chainstate(),
        state.chain_followers(),
        Vec::new(),
        state.shutdown(),
    ));
    let handles = state.chainstate();
    let generation = handles.mempool_gateway.stable_generation();
    let lock = handles.lock_transition()?;
    let (started_tx, started_rx) = crossbeam_channel::bounded(1);
    let (result_tx, result_rx) = crossbeam_channel::bounded(1);
    let worker = std::thread::spawn(move || {
        started_tx
            .send(())
            .unwrap_or_else(|error| panic!("worker handshake: {error}"));
        result_tx
            .send(mining.submit_block(genesis))
            .unwrap_or_else(|error| panic!("submission result: {error}"));
    });
    let started = started_rx.recv_timeout(Duration::from_secs(5));
    let premature = result_rx.recv_timeout(Duration::from_millis(100));
    drop(lock);
    worker
        .join()
        .unwrap_or_else(|error| std::panic::resume_unwind(error));
    started?;
    assert!(
        matches!(premature, Err(crossbeam_channel::RecvTimeoutError::Timeout)),
        "duplicate classification escaped the transition: {premature:?}"
    );
    assert_eq!(
        result_rx.recv_timeout(Duration::from_secs(5))??,
        BlockValidationResult::Duplicate
    );
    assert_eq!(handles.mempool_gateway.stable_generation(), generation);
    Ok(())
}

fn rejected(error: ApplyError) -> CompactString {
    match map_apply_error(error) {
        Ok(BlockValidationResult::Rejected(reason)) => reason,
        other => panic!("expected rejected, got {other:?}"),
    }
}

#[test]
fn journal_backpressure_is_operational() {
    assert!(matches!(
        map_apply_error(ApplyError::JournalBackpressure("test pressure".to_owned())),
        Ok(BlockValidationResult::Inconclusive)
    ));
}

// CONTRACT: docs/contracts/external-api.md#API-30
#[test]
fn generateblock_validity_wraps_bip22_reason() {
    let error = test_block_validity_error(&ApplyError::UndoPrevoutMissing {
        txid: Txid::from(Hash256::from_le_bytes(&[0x11; 32])),
        vout: 0,
    });
    match error {
        MiningControlError::Rejected(reason) => {
            assert_eq!(
                reason.as_str(),
                "TestBlockValidity failed: bad-txns-inputs-missingorspent"
            );
        }
        other => panic!("expected rejected, got {other:?}"),
    }
}

// CONTRACT: docs/contracts/external-api.md#API-30
#[test]
fn generateblock_validity_keeps_shutdown_operational() {
    assert!(matches!(
        test_block_validity_error(&ApplyError::Shutdown),
        MiningControlError::Unavailable(_)
    ));
    assert!(matches!(
        test_block_validity_error(&ApplyError::JournalBackpressure("test pressure".to_owned())),
        MiningControlError::Unavailable(_)
    ));
}

#[test]
fn apply_errors_delegate_consensus_and_chain_reasons() {
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::MissingCoinbase)),
        "bad-cb-missing"
    );
    assert_eq!(
        rejected(ApplyError::Chain(ChainError::InvalidPow {
            hash: Hash256::default(),
            target: ChainWork::ZERO,
        })),
        "high-hash"
    );
}
