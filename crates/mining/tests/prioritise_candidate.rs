//! `prioritisetransaction` invalidates the cached mining candidate.
//!
//! CONTRACT: an in-pool fee prioritisation moves the mempool's fee-delta
//! revision without moving the public membership sequence; the mining
//! generation key carries both tokens, so a prioritisation (1) changes the
//! next GBT candidate's ordering, (2) invalidates the cached candidate,
//! (3) wakes an already-waiting long poll through the connected observer, and
//! (4) leaves the public mempool mutation semantics untouched. Issue #1560
//! finding A1.

#[path = "support/fixtures.rs"]
mod common;

use std::error::Error;
use std::sync::Arc;

use parking_lot::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use bitcoin_rs_chain::header_sync::HeaderValidationMode;
use bitcoin_rs_chain::{BlockTree, BlockTreeReader, LatchReader, TipSnapshot, accept_headers};
use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_mempool::{
    Mempool, MempoolEntry, MempoolGateway, MempoolLimits, MempoolMiningSnapshot, MempoolObserver,
    MempoolReader,
};
use bitcoin_rs_mining::{
    AppliedTipSource, ChainContextSource, GenerateSelection, MempoolSequenceWake,
    MempoolSnapshotSource, MiningControlError, MiningGenerationSignal, MiningService,
};
use bitcoin_rs_primitives::{BlockHash, Hash256, Header, Network, Txid};
use common::{PAYOUT, witnessed_tx};

const GENESIS_TIME: u32 = 1_296_688_602;
/// Bound on the long-poll wake: a real dispatch returns in milliseconds; a
/// missed wake leaves the poller blocked past this deadline.
const WAKE_DEADLINE: Duration = Duration::from_secs(5);
/// Bound for the observer-dispatch proof. It is well under the coordinator's
/// one-second periodic long-poll recheck, so only a real wake can release the
/// poller inside it.
const DISPATCH_DEADLINE: Duration = Duration::from_millis(300);

/// Mines a valid regtest header: the same shape the chain fixture uses.
fn mine_header(prev_blockhash: BlockHash, height: u32) -> Header {
    let mut merkle = [0_u8; 32];
    merkle[..4].copy_from_slice(&height.to_le_bytes());
    let mut header = Header {
        version: 1,
        prev_blockhash,
        merkle_root: Hash256::from_le_bytes(&merkle),
        time: GENESIS_TIME.saturating_add(height),
        bits: bitcoin_rs_primitives::CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    while !pow_is_met(header.bits, &header.compute_hash()) {
        header.nonce = header.nonce.wrapping_add(1);
    }
    header
}

/// Differential proof-of-work oracle: `bitcoin`'s own compact-target decode
/// and comparison, not the implementation under test.
fn pow_is_met(bits: bitcoin_rs_primitives::CompactTarget, hash: &BlockHash) -> bool {
    use bitcoin::hashes::Hash as _;
    let target = bitcoin::pow::Target::from_compact(bitcoin::pow::CompactTarget::from_consensus(
        bits.to_consensus(),
    ));
    target.is_met_by(bitcoin::BlockHash::from_byte_array(*hash.as_bytes()))
}

struct FixtureTipSource {
    tip: TipSnapshot,
}

impl AppliedTipSource for FixtureTipSource {
    fn applied_tip(&self) -> Option<TipSnapshot> {
        Some(self.tip.clone())
    }
}

struct TreeChainSource {
    tree: BlockTreeReader,
    network: Network,
}

impl ChainContextSource for TreeChainSource {
    fn resolve_mining_context(
        &self,
        tip: &TipSnapshot,
        candidate_time: u32,
    ) -> Result<bitcoin_rs_mining::MiningChainContext, bitcoin_rs_chain::ChainError> {
        bitcoin_rs_mining::MiningChainContext::resolve(
            &self.tree.read(),
            self.network,
            tip.tip_id,
            candidate_time,
        )
    }

    fn tip_bits(
        &self,
        tip: &TipSnapshot,
    ) -> Result<bitcoin_rs_primitives::CompactTarget, bitcoin_rs_chain::ChainError> {
        self.tree
            .read()
            .node(tip.tip_id)
            .map(|node| node.header.bits)
    }

    fn signalling_rules(
        &self,
        _tip: &TipSnapshot,
        _height: u32,
    ) -> Vec<bitcoin_rs_mining::AvailableMiningRule> {
        Vec::new()
    }
}

/// Mempool facts read through the gateway's read passthrough, so the fixture
/// takes no pool write lock of its own.
struct LiveMempoolSource(MempoolReader);

impl MempoolSnapshotSource for LiveMempoolSource {
    fn current_sequence(&self) -> u64 {
        self.0.read().sequence_number()
    }

    fn current_fee_delta_sequence(&self) -> u64 {
        self.0.read().fee_delta_sequence_number()
    }

    fn mining_snapshot_at(
        &self,
        expected_sequence: u64,
        expected_fee_delta_sequence: u64,
    ) -> Option<MempoolMiningSnapshot> {
        let pool = self.0.read();
        if pool.sequence_number() != expected_sequence
            || pool.fee_delta_sequence_number() != expected_fee_delta_sequence
        {
            return None;
        }
        Some(pool.mining_snapshot())
    }

    fn pooled_transaction_count(&self) -> u64 {
        u64::try_from(self.0.read().len()).unwrap_or(u64::MAX)
    }

    fn selection_snapshot(
        &self,
        selection: &GenerateSelection,
        _context: &bitcoin_rs_mining::CandidateContext,
    ) -> Result<MempoolMiningSnapshot, MiningControlError> {
        match selection {
            GenerateSelection::Mempool => Ok(self.0.read().mining_snapshot()),
            GenerateSelection::Ordered(_) => Err(MiningControlError::InvalidRequest(
                "fixture does not stage ordered selections".into(),
            )),
        }
    }

    fn min_relay_fee_sat_per_kvb(&self) -> u64 {
        self.0.read().min_relay_fee_sat_per_kvb()
    }
}

/// Reads the shared gateway from several threads without holding a write lock.
fn reader(gateway: &Arc<MempoolGateway>) -> MempoolReader {
    gateway.reader()
}

/// Attaches the fixture adapter's two trait-object roles to `signal` and
/// returns the shared adapter.
///
/// `MiningGenerationSignal` stores only weak references, so the caller must
/// keep the returned `Arc` alive for the whole test. Dropping it would detach
/// every wake, and the test would still pass on the periodic long-poll
/// recheck instead of the observer dispatch.
fn attach_fixture(
    signal: &MiningGenerationSignal,
    service: &Arc<MiningService>,
) -> Arc<ServiceWake> {
    let wake = Arc::new(ServiceWake {
        service: Arc::clone(service),
        dispatched: Mutex::new(Vec::new()),
    });
    let control: Arc<dyn bitcoin_rs_mining::MiningControl> = wake.clone();
    let sequence_wake: Arc<dyn MempoolSequenceWake> = wake.clone();
    signal.attach(&control);
    signal.attach_sequence_wake(&sequence_wake);
    wake
}

/// Test-local wake + control adapter over a `MiningService`: the node's
/// `MiningCoordinator` plays this role in production, and these two methods
/// are exactly what the observer path calls. Each wake records the exact
/// tokens it received, so a test proves the observer dispatch rather than a
/// timeout.
struct ServiceWake {
    service: Arc<MiningService>,
    dispatched: Mutex<Vec<(u64, u64)>>,
}

impl bitcoin_rs_mining::MempoolSequenceWake for ServiceWake {
    fn publish_generation_from(&self, mempool_sequence: u64, fee_delta_sequence: u64) {
        self.dispatched
            .lock()
            .push((mempool_sequence, fee_delta_sequence));
        self.service
            .publish_generation_from(mempool_sequence, fee_delta_sequence);
    }
}

impl bitcoin_rs_mining::MiningControl for ServiceWake {
    fn publish_generation(&self) {
        self.service.publish_generation();
    }

    fn get_block_template(
        &self,
        _request: bitcoin_rs_mining::BlockTemplateRequest,
    ) -> Result<bitcoin_rs_mining::BlockTemplateResult, MiningControlError> {
        Err(MiningControlError::Unavailable("fixture: template".into()))
    }

    fn mining_info(&self) -> Result<bitcoin_rs_mining::MiningInfo, MiningControlError> {
        Err(MiningControlError::Unavailable("fixture: info".into()))
    }

    fn network_hash_ps(&self, _min_time: i64, _max_time: i64) -> Result<f64, MiningControlError> {
        Err(MiningControlError::Unavailable("fixture: hashrate".into()))
    }

    fn submit_block(
        &self,
        _block: bitcoin_rs_primitives::Block,
    ) -> Result<bitcoin_rs_mining::BlockValidationResult, MiningControlError> {
        Err(MiningControlError::Unavailable("fixture: submit".into()))
    }

    fn submit_header(&self, _header: Header) -> Result<(), MiningControlError> {
        Err(MiningControlError::Unavailable("fixture: header".into()))
    }

    fn generate(
        &self,
        _request: bitcoin_rs_mining::GenerateRequest,
    ) -> Result<Vec<bitcoin_rs_mining::GeneratedBlock>, MiningControlError> {
        Err(MiningControlError::Unavailable("fixture: generate".into()))
    }
}

/// A low-fee and a high-fee transaction: before prioritisation the high-fee
/// entry leads the candidate; after a prioritisation large enough to outrank
/// it, the prioritised transaction must lead the next candidate.
#[test]
#[expect(clippy::too_many_lines, reason = "one end-to-end long-poll scenario")]
fn prioritisation_invalidates_the_cached_candidate_and_wakes_the_long_poll()
-> Result<(), Box<dyn Error>> {
    // The production-style observer: a composite of the mining generation
    // signal and the coordinator wake, attached to the gateway so a
    // prioritisation dispatches through the real observer path.
    let signal = Arc::new(MiningGenerationSignal::new());
    let observer: Arc<dyn MempoolObserver> = signal.clone();
    let gateway = Arc::new(MempoolGateway::new(
        Arc::new(
            Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                ..MempoolLimits::default()
            })
            .into(),
        ),
        Some(observer),
        ValidationEngine::Native,
    ));

    // fee rate 1_000 sat/kvB vs 100 sat/kvB: the first candidate leads with tx 1.
    let high_txid;
    let low_txid;
    {
        let mut pool = gateway.pool().write();
        let high = witnessed_tx(1, 1_000, None);
        high_txid = high.txid();
        let vsize_high = u32::try_from(high.vsize())?;
        let low = witnessed_tx(2, 1_000, None);
        low_txid = low.txid();
        let vsize_low = u32::try_from(low.vsize())?;
        pool.insert_entry(MempoolEntry::new(
            Arc::new(high),
            vsize_high,
            1_000,
            1,
            100,
            0,
        ))?;
        pool.insert_entry(MempoolEntry::new(Arc::new(low), vsize_low, 100, 2, 100, 0))?;
    }

    // A real tree rooted at the compiled-in regtest genesis + one mined
    // header; `MiningChainContext::resolve` reads it exactly as production.
    let network = Network::Regtest;
    let mut tree = BlockTree::new();
    let genesis_header = network.genesis_block().header;
    let [genesis_id] = accept_headers(
        &mut tree,
        std::slice::from_ref(&genesis_header),
        network,
        genesis_header.time,
        HeaderValidationMode::LiveAdmission,
    )?[..] else {
        panic!("genesis must be accepted alone");
    };
    let genesis_hash = genesis_header.compute_hash();
    let block_header = mine_header(genesis_hash, 101);
    let [block_id] = accept_headers(
        &mut tree,
        std::slice::from_ref(&block_header),
        network,
        genesis_header.time.saturating_add(1),
        HeaderValidationMode::LiveAdmission,
    )?[..] else {
        panic!("one header must be accepted");
    };
    let _ = genesis_id;
    let block_hash = block_header.compute_hash();

    let tip = TipSnapshot {
        tip_id: block_id,
        height: 101,
        chainwork: bitcoin_rs_chain::ChainWork::ONE,
        hash: Hash256::from(block_hash),
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    };

    let tree_read = Arc::new(parking_lot::RwLock::new(tree));
    let service = Arc::new(MiningService::new(
        network,
        Arc::new(FixtureTipSource { tip }),
        Arc::new(LiveMempoolSource(reader(&gateway))),
        Arc::new(TreeChainSource {
            tree: BlockTreeReader::new(Arc::clone(&tree_read)),
            network,
        }),
        PAYOUT.to_vec(),
        LatchReader::fixture_never(),
    ));
    // Wire the observer to the coordinator exactly as the node does: the
    // signal forwards a wake the service turns into a published key.
    let wake = attach_fixture(&signal, &service);

    let first = service.get_block_template(None)?;
    let selected_first: Vec<Txid> = first
        .candidate
        .transactions
        .iter()
        .map(|tx| tx.txid)
        .collect();
    assert_eq!(
        selected_first.first(),
        Some(&high_txid),
        "the high-fee transaction must lead the first candidate"
    );
    let stale_id = first.candidate.template_id.as_str().to_owned();

    // The long poller starts BEFORE the prioritisation and enters its wait;
    // only a real wake from the prioritisation can return it.
    let poller = thread::spawn({
        let service = Arc::clone(&service);
        move || {
            let started = Instant::now();
            let waited = service
                .get_block_template(Some(stale_id.as_str()))
                .map_err(|error| error.to_string())?;
            Ok::<(String, Duration), String>((
                waited.candidate.template_id.as_str().to_owned(),
                started.elapsed(),
            ))
        }
    });
    // Give the poller time to enter its wait while the published generation
    // still matches the stale id.
    thread::sleep(Duration::from_millis(150));

    // The prioritisation must not move the public membership sequence. The
    // dispatch is synchronous, so the observer wake has already fired when
    // the call returns.
    let sequence_before = gateway.read().sequence_number();
    gateway.prioritise(low_txid, 10_000_000)?;
    assert_eq!(
        gateway.read().sequence_number(),
        sequence_before,
        "prioritisation emits no membership change, so the membership sequence stays"
    );
    assert_eq!(
        wake.dispatched.lock().len(),
        1,
        "the prioritisation must dispatch exactly one observer wake"
    );
    assert_eq!(
        wake.dispatched.lock()[0].1,
        1,
        "the wake carries the advanced fee-delta revision"
    );

    // The cached candidate must be invalidated: the next GBT reorders.
    let second = service.get_block_template(None)?;
    let selected_second: Vec<Txid> = second
        .candidate
        .transactions
        .iter()
        .map(|tx| tx.txid)
        .collect();
    assert_eq!(
        selected_second.first(),
        Some(&low_txid),
        "the prioritised transaction must lead the next candidate"
    );
    assert_ne!(
        second.candidate.template_id.as_str(),
        first.candidate.template_id.as_str(),
        "the fee-delta change must change the template identity"
    );

    // The blocked long poller must wake within a bounded time: only a real
    // dispatch from the prioritisation can release it.
    let (woken_id, elapsed) = poller
        .join()
        .unwrap_or_else(|_| panic!("long poll thread panicked"))
        .map_err(|error| -> Box<dyn Error> { error.into() })?;
    assert_ne!(
        woken_id,
        first.candidate.template_id.as_str(),
        "the long poll must wake on the prioritisation"
    );
    assert!(
        elapsed < WAKE_DEADLINE,
        "the blocked waiter must be released promptly, took {elapsed:?}"
    );
    Ok(())
}

/// An already-waiting poll must be released by the prioritisation wake itself,
/// not by the periodic long-poll recheck. The observer is disconnected, so no
/// wake can reach the service; the poller must therefore stay blocked until a
/// later unconditional `publish_generation` moves the key.
#[test]
fn a_prioritisation_wake_alone_releases_an_already_waiting_poll() -> Result<(), Box<dyn Error>> {
    let signal = Arc::new(MiningGenerationSignal::new());
    let observer: Arc<dyn MempoolObserver> = signal.clone();
    let gateway = Arc::new(MempoolGateway::new(
        Arc::new(Mempool::new(MempoolLimits::default()).into()),
        Some(observer),
        ValidationEngine::Native,
    ));
    let txid;
    {
        let mut pool = gateway.pool().write();
        let tx = witnessed_tx(9, 1_000, None);
        txid = tx.txid();
        let vsize = u32::try_from(tx.vsize())?;
        pool.insert_entry(MempoolEntry::new(Arc::new(tx), vsize, 1_000, 1, 100, 0))?;
    }
    let network = Network::Regtest;
    let mut tree = BlockTree::new();
    let genesis_header = network.genesis_block().header;
    let [genesis_id] = accept_headers(
        &mut tree,
        std::slice::from_ref(&genesis_header),
        network,
        genesis_header.time,
        HeaderValidationMode::LiveAdmission,
    )?[..] else {
        panic!("genesis must be accepted alone");
    };
    let tip = TipSnapshot {
        tip_id: genesis_id,
        height: 0,
        chainwork: bitcoin_rs_chain::ChainWork::ONE,
        hash: Hash256::from(genesis_header.compute_hash()),
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    };
    let tree_read = Arc::new(parking_lot::RwLock::new(tree));
    let service = Arc::new(MiningService::new(
        network,
        Arc::new(FixtureTipSource { tip }),
        Arc::new(LiveMempoolSource(reader(&gateway))),
        Arc::new(TreeChainSource {
            tree: BlockTreeReader::new(Arc::clone(&tree_read)),
            network,
        }),
        PAYOUT.to_vec(),
        LatchReader::fixture_never(),
    ));
    // Only the coordinator wake is attached here: the dispatch under test is
    // the observer's, and the poll must not return until the observer fires.
    let wake = attach_fixture(&signal, &service);

    service.publish_generation();
    let current = service.get_block_template(None)?;
    let stale_id = current.candidate.template_id.as_str().to_owned();

    let poller = thread::spawn({
        let service = Arc::clone(&service);
        move || service.get_block_template(Some(stale_id.as_str()))
    });
    thread::sleep(Duration::from_millis(150));
    assert!(
        !poller.is_finished(),
        "the poll must still wait while the generation is unchanged"
    );
    assert!(
        wake.dispatched.lock().is_empty(),
        "nothing has dispatched before the prioritisation"
    );

    gateway.prioritise(txid, 1)?;
    // The dispatch is synchronous: the drain runs on this thread before
    // `prioritise` returns, so the wake must already have fired.
    let dispatched = wake.dispatched.lock().clone();
    assert_eq!(
        dispatched.len(),
        1,
        "the prioritisation must dispatch exactly one wake"
    );
    assert_eq!(
        dispatched[0].1, 1,
        "the wake carries the advanced fee-delta revision"
    );

    // Release must beat the one-second periodic recheck, so only the
    // observer dispatch can explain it.
    let deadline = Instant::now() + DISPATCH_DEADLINE;
    while !poller.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        poller.is_finished(),
        "the prioritisation observer wake must release the waiting poll"
    );
    let woken = poller
        .join()
        .unwrap_or_else(|_| panic!("long poll thread panicked"))
        .map_err(|error| -> Box<dyn Error> { error.into() })?;
    assert_ne!(
        woken.candidate.template_id.as_str(),
        current.candidate.template_id.as_str(),
        "the woken poll returns the new generation"
    );
    Ok(())
}
