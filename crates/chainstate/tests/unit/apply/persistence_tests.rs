use std::sync::Arc;
use std::sync::atomic::Ordering;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, TipSnapshot, compact_is_met_by};
use bitcoin_rs_consensus::MAX_SCRIPT_SIZE;
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, Network, OutPoint, Script,
    Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_storage::{DisconnectMarker, InMemoryUndoStore, StorageError, UndoStore};
use bitcoin_rs_utxo::connect::build_block_changes;
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet};
use hashbrown::HashMap;
use parking_lot::RwLock;

use super::{ApplyError, Chainstate, ResolvedUtxoView};

struct RejectingUndoStore {
    inner: InMemoryUndoStore,
}

impl UndoStore for RejectingUndoStore {
    fn persist_undo(
        &self,
        _height: u32,
        _hash: Hash256,
        _record: &[u8],
    ) -> Result<(), StorageError> {
        Err(StorageError::backend("injected undo-persist failure"))
    }

    fn load_undo(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_undo(height, hash)
    }

    fn arm_disconnect(&self, height: u32, hash: Hash256) -> Result<(), StorageError> {
        self.inner.arm_disconnect(height, hash)
    }

    fn complete_disconnect(&self, height: u32, hash: Hash256) -> Result<(), StorageError> {
        self.inner.complete_disconnect(height, hash)
    }

    fn disarm_disconnect(&self) -> Result<(), StorageError> {
        self.inner.disarm_disconnect()
    }

    fn load_disconnect_marker(&self) -> Result<Option<DisconnectMarker>, StorageError> {
        self.inner.load_disconnect_marker()
    }
}

fn handles(network: Network, utxo: Arc<UtxoSet>) -> Chainstate {
    Chainstate::new(
        network,
        Arc::new(ArcSwapOption::empty()),
        Arc::new(ArcSwapOption::empty()),
        Arc::new(RwLock::new(BlockTree::new())),
        utxo,
        Arc::new(CoinStatsListener::new(CoinStats::default())),
        Arc::new(crate::events::ChainEventPublisher::detached(0)),
    )
}

fn seed_genesis(handles: &Chainstate) -> Result<TipSnapshot, ApplyError> {
    let genesis = Network::Regtest.genesis_block();
    let tip = crate::connect::applied_header_tip(
        handles,
        Hash256::from(genesis.block_hash()),
        &genesis,
        0,
    )?;
    handles.applied_tip.store(Some(Arc::new(tip.clone())));
    handles.chain_tx_count.store(1, Ordering::Release);
    Ok(tip)
}

fn coinbase(height: u32) -> Tx {
    let encoded_height = u8::try_from(height).unwrap_or(u8::MAX);
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(vec![1, encoded_height, 0]),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

fn mined_child(parent: BlockHash, height: u32) -> Result<Block, Box<dyn std::error::Error>> {
    let tx = coinbase(height);
    let mut leaves = vec![*tx.txid().as_bytes()];
    let merkle = bitcoin_rs_consensus::verify_block::compute_merkle_root(&mut leaves)
        .ok_or("coinbase merkle root missing")?;
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash: parent,
            merkle_root: Hash256::from_le_bytes(&merkle),
            time: 1_296_688_602_u32.saturating_add(height),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txs: vec![tx],
    };
    while !compact_is_met_by(block.header.bits, block.header.compute_hash().0) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or("test nonce exhausted")?;
    }
    Ok(block)
}

#[test]
fn undo_persist_failure_leaves_utxo_tip_and_tree_untouched()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let utxo = Arc::new(UtxoSet::new());
    let mut handles = handles(Network::Regtest, Arc::clone(&utxo));
    seed_genesis(&handles)?;

    let first = mined_child(genesis.block_hash(), 1)?;
    handles.apply_block(&first)?;
    let applied_hash = Hash256::from(first.block_hash());
    let utxo_len = utxo.len();
    handles.undo_store = Arc::new(RejectingUndoStore {
        inner: InMemoryUndoStore::default(),
    });
    let next = mined_child(first.block_hash(), 2)?;
    let next_hash = Hash256::from(next.block_hash());

    let outcome = handles.apply_block(&next);
    assert!(matches!(outcome, Err(ApplyError::UndoPersistence(_))));
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(applied_hash),
        "a failed precommit undo write must not publish a new tip"
    );
    assert_eq!(
        utxo.len(),
        utxo_len,
        "a failed undo write must not commit UTXOs"
    );
    assert!(
        handles.block_tree.read().node_by_hash(next_hash).is_none(),
        "tree preparation must not survive a failed undo write"
    );
    Ok(())
}

#[test]
fn bip30_overwrite_undo_restores_original_coin() -> Result<(), Box<dyn std::error::Error>> {
    let utxo = UtxoSet::new();
    let block = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txs: vec![coinbase(7)],
    };
    let reused = OutPoint::new(block.txs[0].txid(), 0);
    let older = TxOut {
        value: Amount::from_sat(4_242),
        script_pubkey: Script::from_bytes(vec![0x51]),
    };
    let mut seed = BlockChanges::default();
    seed.add(UtxoAdd::new(reused, older.clone(), true, 91_722));
    utxo.commit_block(&seed, &Hash256::from_le_bytes(&[0x30; 32]))?;

    let txids = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
    let resolved = ResolvedUtxoView {
        external: HashMap::new(),
    };
    let (_changes, undo, _totals) = build_block_changes(
        &block,
        91_842,
        &txids,
        None,
        1,
        0,
        &resolved,
        Some(&utxo),
        MAX_SCRIPT_SIZE,
    )?;

    assert!(undo.removes().is_empty());
    let restored = undo
        .restores()
        .iter()
        .find(|entry| entry.outpoint == reused)
        .ok_or("undo does not restore overwritten coin")?;
    assert_eq!(restored.txout, older);
    assert_eq!(restored.height, 91_722);
    assert!(restored.coinbase);
    Ok(())
}
