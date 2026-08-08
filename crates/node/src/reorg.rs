//! Switching the applied chain from one tip to another.
//!
//! [`plan_reorg`] says which blocks to disconnect and which to connect;
//! [`crate::apply::disconnect_block`] rolls one back and
//! [`crate::apply::apply_block_with_serialized`] applies one. This joins them.
//! Without it the node follows the chain forward and cannot leave a branch that
//! loses, which is the difference between a chain follower and a full node.

use alloc::vec::Vec;

use bitcoin::consensus::Decodable as _;
use bitcoin_rs_chain::{NodeId, plan_reorg};
use bitcoin_rs_primitives::Hash256;

use crate::apply::ApplyHandles;
use crate::{ApplyError, DisconnectError};

/// Why a branch switch stopped, and what the chain looks like now.
///
/// Four outcomes rather than one error type, because the caller must act
/// differently for each and the difference is exactly how much damage there is.
#[derive(Debug, thiserror::Error)]
pub enum ReorgError {
    /// Planning failed: the two tips share no ancestor, or a node is unknown.
    ///
    /// Nothing was touched.
    #[error("reorg planning failed: {0}")]
    Plan(#[source] bitcoin_rs_chain::ChainError),
    /// A block named by the plan has no stored body.
    ///
    /// Nothing was touched. A pruned node legitimately reaches this, which is
    /// why it is not fatal: it means this reorg cannot be performed, not that
    /// the chain is broken.
    #[error("no stored body for block {hash} at height {height}")]
    MissingBody {
        /// Block whose body is absent.
        hash: Hash256,
        /// Height it sits at.
        height: u32,
    },
    /// A disconnect refused before touching anything.
    ///
    /// The chain is consistent at whatever tip the walk reached. Earlier
    /// disconnects in this switch stand: each one committed fully, so the node
    /// sits on a shorter valid chain and connecting forward recovers it. No
    /// rollback is attempted, because rolling back means disconnecting, and
    /// disconnecting is what just refused.
    #[error("reorg stopped at height {stopped_at}: {source}")]
    Refused {
        /// Height the applied tip reached before stopping.
        stopped_at: u32,
        /// Why the disconnect refused.
        #[source]
        source: Box<DisconnectError>,
    },
    /// A connect failed after some of the new branch was applied.
    ///
    /// The chain is consistent at a prefix of the target branch: every block
    /// before this one committed fully. The switch is abandoned rather than
    /// rolled back — undoing the prefix means disconnecting blocks that just
    /// applied, which can fail Fatal and turn a recoverable stop into an
    /// unrecoverable one. A later switch can move the chain from here.
    #[error("reorg stopped after connecting to height {stopped_at}: {source}")]
    ConnectFailed {
        /// Height the applied tip reached before stopping.
        stopped_at: u32,
        /// Why the connect failed.
        #[source]
        source: Box<ApplyError>,
    },
    /// A disconnect died partway. The chainstate is torn.
    ///
    /// Propagated immediately and never continued past: applying the new branch
    /// on top of a half-rolled-back state would build on a chain the node
    /// cannot describe. The in-flight marker is already durable, so a restart
    /// refuses rather than serving it.
    #[error("reorg left the chainstate inconsistent: {0}")]
    Fatal(#[source] Box<DisconnectError>),
}

/// Switches the applied chain to `target`.
///
/// Disconnects back to the common ancestor, then applies the target branch
/// forward. Both walks take the plan's order: `disconnect` runs from the old
/// tip downward, `connect` from the ancestor's child upward.
///
/// # Errors
///
/// Every outcome other than reaching `target` is a [`ReorgError`] variant
/// naming how far the chain moved, because "it failed" does not tell a caller
/// whether the node is fine, degraded, or unusable.
pub fn switch_to_branch(
    handles: &ApplyHandles,
    target: NodeId,
) -> core::result::Result<(), ReorgError> {
    let plan = {
        let tree = handles.block_tree.read();
        let Some(current) = handles.applied_tip.load_full() else {
            // Nothing applied means nothing to switch away from.
            return Ok(());
        };
        let Some(current_id) = tree.lookup(current.hash) else {
            return Err(ReorgError::Plan(
                bitcoin_rs_chain::ChainError::UnknownNode { id: target },
            ));
        };
        plan_reorg(&tree, current_id, target).map_err(ReorgError::Plan)?
    };

    // Every body is loaded before anything is disconnected. A body missing
    // halfway through would otherwise strand the chain on the ancestor with the
    // old branch already gone and the new one unreachable.
    let connect = load_branch_bodies(handles, &plan.connect)?;
    let disconnect = load_branch_bodies(handles, &plan.disconnect)?;

    for (block, height) in disconnect {
        match crate::apply::disconnect_block(handles, &block) {
            Ok(_) => {}
            Err(error @ (DisconnectError::Fatal { .. } | DisconnectError::MarkerStuck { .. })) => {
                return Err(ReorgError::Fatal(Box::new(error)));
            }
            Err(error) => {
                return Err(ReorgError::Refused {
                    stopped_at: height,
                    source: Box::new(error),
                });
            }
        }
    }

    for (block, height) in connect {
        let serialized = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&block));
        if let Err(error) = crate::apply::apply_block_with_serialized(handles, &block, serialized) {
            return Err(ReorgError::ConnectFailed {
                stopped_at: height.saturating_sub(1),
                source: Box::new(error),
            });
        }
    }
    Ok(())
}

/// Loads every block named by a branch, in the order given.
fn load_branch_bodies(
    handles: &ApplyHandles,
    ids: &[NodeId],
) -> core::result::Result<Vec<(bitcoin::Block, u32)>, ReorgError> {
    let tree = handles.block_tree.read();
    let mut loaded = Vec::with_capacity(ids.len());
    for id in ids {
        let node = tree.node(*id).map_err(ReorgError::Plan)?;
        let body = handles
            .block_body_store
            .as_ref()
            .and_then(|store| store.load_block_body(node.height, node.hash).ok().flatten())
            .ok_or(ReorgError::MissingBody {
                hash: node.hash,
                height: node.height,
            })?;
        let mut cursor = std::io::Cursor::new(body.as_slice());
        let block =
            bitcoin::Block::consensus_decode(&mut cursor).map_err(|_| ReorgError::MissingBody {
                hash: node.hash,
                height: node.height,
            })?;
        loaded.push((block, node.height));
    }
    Ok(loaded)
}
