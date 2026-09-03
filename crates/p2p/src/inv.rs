use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_primitives::Hash256;

use crate::wire::Message;

/// Maximum inventory vectors accepted in one message.
pub const MAX_INV_PER_MSG: usize = 50_000;

/// Inventory item advertised by a peer.
pub type InventoryVector = Inventory;

/// Classify an inbound inventory announcement into a getdata request.
///
/// Every announced item is requested. Use [`request_inventory_filtered`] to
/// suppress items the node already holds (mempool, orphan, or recent-rejects).
pub fn request_inventory(items: &[InventoryVector]) -> Option<Message> {
    request_inventory_filtered(items, &|_| false)
}

/// Classify an inbound inventory announcement into a getdata request,
/// suppressing every item for which `have` returns `true`.
///
/// `have` is the node-side "already have" predicate: it receives each
/// inventory vector and returns `true` when the node already holds the
/// referenced object, so the caller skips requesting it. Non-transaction
/// items (blocks, compact blocks, unknown) are never suppressed by the
/// tx-admission layer — the predicate is only consulted for tx-typed
/// vectors — so block relay behaviour is unchanged.
pub fn request_inventory_filtered(
    items: &[InventoryVector],
    have: &dyn Fn(&InventoryVector) -> bool,
) -> Option<Message> {
    let filtered: Vec<InventoryVector> = items.iter().copied().filter(|item| !have(item)).collect();
    if filtered.is_empty() {
        None
    } else {
        Some(Message::GetData(filtered))
    }
}

/// Returns the 32-byte hash carried by a transaction-typed inventory vector,
/// or `None` for non-transaction vectors.
///
/// For `Transaction` and `WitnessTransaction` the hash is the txid; for
/// `WTx` (BIP339) it is the wtxid. The caller interprets the hash according
/// to the peer's negotiated wtxid-relay mode.
pub fn inventory_tx_hash(item: &InventoryVector) -> Option<Hash256> {
    use bitcoin::hashes::Hash as _;
    match item {
        Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
            Some(Hash256::from_le_bytes(txid.as_byte_array()))
        }
        Inventory::WTx(wtxid) => Some(Hash256::from_le_bytes(wtxid.as_byte_array())),
        _ => None,
    }
}

/// Return true when the inventory list is within the protocol bound.
pub const fn is_within_inventory_bound(items: &[InventoryVector]) -> bool {
    items.len() <= MAX_INV_PER_MSG
}
