use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, compact_is_met_by};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, Network, OutPoint, Script,
    Sequence, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes,
};
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::{
    CommitRecords, DurableHead, DurableHeadStore, InMemoryDurableHeadStore, StorageError,
};
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use parking_lot::RwLock;

use crate::{ApplyError, Chainstate};

#[derive(Default)]
struct MemoryBodies {
    bodies: RwLock<HashMap<(u32, Hash256), Vec<u8>>>,
}

impl BlockBodyStore for MemoryBodies {
    fn persist_block_body(
        &self,
        height: u32,
        hash: Hash256,
        body: &[u8],
    ) -> Result<(), StorageError> {
        self.bodies.write().insert((height, hash), body.to_vec());
        Ok(())
    }

    fn load_block_body(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.bodies.read().get(&(height, hash)).cloned())
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

fn restored_chainstate() -> Result<(Chainstate, Block), Box<dyn std::error::Error>> {
    let network = Network::Regtest;
    let genesis = network.genesis_block();
    let handles = Chainstate::new(
        network,
        Arc::new(ArcSwapOption::empty()),
        Arc::new(ArcSwapOption::empty()),
        Arc::new(RwLock::new(BlockTree::new())),
        Arc::new(UtxoSet::new()),
        Arc::new(CoinStatsListener::new(CoinStats::default())),
        Arc::new(crate::events::ChainEventPublisher::detached(0)),
    );
    let genesis_tip = crate::connect::applied_header_tip(
        &handles,
        Hash256::from(genesis.block_hash()),
        &genesis,
        0,
    )?;
    handles
        .applied_tip
        .store(Some(Arc::new(genesis_tip.clone())));
    handles.chain_tx_count.store(1, Ordering::Release);

    let tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(vec![1, 1, 0]),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    let mut leaves = vec![*tx.txid().as_bytes()];
    let merkle = bitcoin_rs_consensus::verify_block::compute_merkle_root(&mut leaves)
        .ok_or("coinbase merkle root missing")?;
    let mut child = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash(genesis_tip.hash),
            merkle_root: Hash256::from_le_bytes(&merkle),
            time: genesis.header.time.saturating_add(1),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txs: vec![tx],
    };
    while !compact_is_met_by(child.header.bits, child.header.compute_hash().0) {
        child.header.nonce = child
            .header
            .nonce
            .checked_add(1)
            .ok_or("test nonce exhausted")?;
    }
    Ok((handles, child))
}

fn install_head(
    handles: &mut Chainstate,
    child: &Block,
    bodies: Arc<MemoryBodies>,
) -> Result<DurableHead, StorageError> {
    let hash = Hash256::from(child.block_hash());
    let head = DurableHead {
        commit_id: 7,
        height: 1,
        tip: hash,
        chain_tx_count: 2,
        body_extent: None,
        undo_extent: None,
    };
    let durable = Arc::new(InMemoryDurableHeadStore::new());
    durable.commit(None, &head, &CommitRecords::default())?;
    handles.durable_head = durable;
    handles.block_body_store = Some(bodies);
    Ok(head)
}

#[test]
fn committed_gap_replays_to_head_without_recommitting_it() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut handles, child) = restored_chainstate()?;
    let bodies = Arc::new(MemoryBodies::default());
    bodies.persist_block_body(
        1,
        Hash256::from(child.block_hash()),
        &consensus_bytes(&child),
    )?;
    let head = install_head(&mut handles, &child, bodies)?;

    super::reconcile_at_boot(&handles)?;

    let landed = handles
        .applied_tip
        .load_full()
        .ok_or("replay did not publish an applied tip")?;
    assert_eq!((landed.height, landed.hash), (head.height, head.tip));
    assert_eq!(handles.chain_tx_count.load(Ordering::Acquire), 2);
    assert_eq!(handles.durable_head.load()?, Some(head));
    assert_eq!(
        handles.durable_head.load()?.map(|head| head.commit_id),
        Some(7),
        "replay must consume the durable receipt rather than creating a new one"
    );
    Ok(())
}

#[test]
fn committed_gap_with_missing_body_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (mut handles, child) = restored_chainstate()?;
    let head = install_head(&mut handles, &child, Arc::new(MemoryBodies::default()))?;

    let error = super::reconcile_at_boot(&handles).expect_err("missing committed body must fail");
    assert!(matches!(
        error,
        ApplyError::DurableHeadGapUnrecoverable { .. }
    ));
    assert_eq!(
        handles
            .applied_tip
            .load_full()
            .map(|tip| (tip.height, tip.hash)),
        Some((0, Network::Regtest.genesis_block_hash()))
    );
    assert_eq!(handles.durable_head.load()?, Some(head));
    Ok(())
}
