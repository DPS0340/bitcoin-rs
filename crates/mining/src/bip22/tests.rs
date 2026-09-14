// CONTRACT: `docs/contracts/external-api.md#API-05` and `#API-11` own
// mining validation/submission projection; the BIP22 reject vocabulary is
// the in-code mapping contract from consensus/chain refusal to reject
// reason strings.
use super::chain_reject_reason;
use super::consensus_reject_reason;
use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::ChainWork;
use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_primitives::Hash256;

#[test]
fn consensus_failures_use_core_bip22_reasons() {
    assert_eq!(
        consensus_reject_reason(&ConsensusError::CoinbaseAmount {
            paid: 1,
            allowed: 0,
        }),
        "bad-cb-amount"
    );
    assert_eq!(
        consensus_reject_reason(&ConsensusError::MissingCoinbase),
        "bad-cb-missing"
    );
    assert_eq!(
        consensus_reject_reason(&ConsensusError::EmptyBlock),
        "bad-cb-missing"
    );
    assert_eq!(
        consensus_reject_reason(&ConsensusError::ExtraCoinbase { tx_index: 1 }),
        "bad-cb-multiple"
    );
    assert_eq!(
        consensus_reject_reason(&ConsensusError::MerkleRoot),
        "bad-txnmrklroot"
    );
    assert_eq!(
        consensus_reject_reason(&ConsensusError::MerkleMutation),
        "bad-txns-duplicate"
    );
    assert_eq!(
        consensus_reject_reason(&ConsensusError::WitnessNonceSize),
        "bad-witness-nonce-size"
    );
    assert_eq!(
        consensus_reject_reason(&ConsensusError::UnexpectedWitness),
        "unexpected-witness"
    );
    assert_eq!(
        consensus_reject_reason(&ConsensusError::WitnessCommitment),
        "bad-witness-merkle-match"
    );
    assert_eq!(
        consensus_reject_reason(&ConsensusError::BlockWeight { weight: 5, max: 4 }),
        "bad-blk-weight"
    );
    assert_eq!(
        consensus_reject_reason(&ConsensusError::EmptyInputs),
        "bad-txns-vin-empty"
    );
    assert_eq!(
        consensus_reject_reason(&ConsensusError::MissingPrevout { input_index: 0 }),
        "bad-txns-inputs-missingorspent"
    );
    assert_eq!(
        consensus_reject_reason(&ConsensusError::InputsLessThanOutputs {
            input_value: 1,
            output_value: 2,
        }),
        "bad-txns-in-belowout"
    );
    assert_eq!(
        consensus_reject_reason(&ConsensusError::Bip {
            bip: "BIP34",
            reason: "x".to_owned(),
        }),
        "bad-cb-height"
    );
    assert_eq!(
        consensus_reject_reason(&ConsensusError::Bip {
            bip: "BIP113",
            reason: "x".to_owned(),
        }),
        "bad-txns-nonfinal"
    );
    assert_eq!(
        consensus_reject_reason(&ConsensusError::Bip {
            bip: "COINBASE_MATURITY",
            reason: "x".to_owned(),
        }),
        "bad-txns-premature-spend-of-coinbase"
    );
    assert_eq!(
        consensus_reject_reason(&ConsensusError::Script {
            input_index: 0,
            reason: "EVAL_FALSE".to_owned(),
        }),
        "block-script-verify-flag-failed (EVAL_FALSE)"
    );
}

#[test]
fn header_failures_use_core_bip22_reasons() {
    let hash = Hash256::default();
    assert_eq!(
        chain_reject_reason(&ChainError::InvalidPow {
            hash,
            target: ChainWork::ZERO,
        }),
        "high-hash"
    );
    assert_eq!(
        chain_reject_reason(&ChainError::TimestampTooEarly {
            hash,
            timestamp: 1,
            median: 2,
        }),
        "time-too-old"
    );
    assert_eq!(
        chain_reject_reason(&ChainError::TimestampTooFarAhead {
            hash,
            timestamp: 9,
            max_allowed: 1,
        }),
        "time-too-new"
    );
    assert_eq!(
        chain_reject_reason(&ChainError::MissingParent { prev_hash: hash }),
        "prev-blk-not-found"
    );
}
