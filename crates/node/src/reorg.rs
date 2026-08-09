//! Switching the applied chain from one tip to another.
//!
//! [`plan_reorg`] says which blocks to disconnect and which to connect;
//! [`crate::apply::disconnect_block`] rolls one back and
//! [`crate::apply::apply_block_with_serialized`] applies one. This joins them.
//! Without it the node follows the chain forward and cannot leave a branch that
//! loses, which is the difference between a chain follower and a full node.

use alloc::vec::Vec;

use bitcoin::consensus::Decodable as _;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::FromHex as _;
use bitcoin_rs_chain::{NodeId, ReorgPlan, plan_reorg};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::StorageError;

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
    /// Reading a durable block body failed.
    ///
    /// Nothing was touched. This is not download lag and must remain
    /// distinguishable from an absent body.
    #[error("failed to read body for block {hash} at height {height}: {source}")]
    BodyStore {
        /// Block whose durable body could not be read.
        hash: Hash256,
        /// Height it sits at.
        height: u32,
        /// Storage backend failure.
        #[source]
        source: StorageError,
    },
    /// A durable block body was present but malformed.
    ///
    /// Nothing was touched. Corruption must not be treated as a request retry.
    #[error("failed to decode body for block {hash} at height {height}: {source}")]
    BodyDecode {
        /// Block whose durable body was malformed.
        hash: Hash256,
        /// Height it sits at.
        height: u32,
        /// Consensus decoding failure.
        #[source]
        source: bitcoin::consensus::encode::Error,
    },
    /// A loaded body's header names a block other than the planned node.
    ///
    /// Nothing was touched.
    #[error("body hash {actual} does not match planned block {expected} at height {height}")]
    BodyHashMismatch {
        /// Hash named by the reorg plan.
        expected: Hash256,
        /// Hash of the loaded body's header.
        actual: Hash256,
        /// Planned height.
        height: u32,
    },
    /// Preserved bytes are not the serialization of the supplied staged block.
    ///
    /// Nothing was touched.
    #[error("preserved bytes do not match staged block {hash} at height {height}")]
    BodyBytesMismatch {
        /// Planned block hash.
        hash: Hash256,
        /// Planned height.
        height: u32,
    },
    /// Admission closed before this switch mutated chainstate.
    #[error("reorg unavailable before mutation: {0}")]
    Unavailable(#[source] Box<ApplyError>),
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
/// tip downward, `connect` from the ancestor's child upward. `connected_body`
/// runs once per committed new-branch block after the transition guard releases.
///
/// # Errors
///
/// Every outcome other than reaching `target` is a [`ReorgError`] variant
/// naming how far the chain moved, because "it failed" does not tell a caller
/// whether the node is fine, degraded, or unusable.
pub fn switch_to_branch<F, G>(
    handles: &ApplyHandles,
    target: NodeId,
    mut staged_body: F,
    mut connected_body: G,
) -> core::result::Result<(), ReorgError>
where
    F: FnMut(Hash256) -> Option<(bitcoin::Block, bytes::Bytes)>,
    G: FnMut(Hash256),
{
    loop {
        let Some(plan) = current_reorg_plan(handles, target)? else {
            return Ok(());
        };

        // Load every body before the first disconnect. A missing body halfway
        // through must not strand the chain at the common ancestor.
        let connect = load_branch_bodies(handles, &plan.connect, &mut staged_body)?;
        let disconnect = load_branch_bodies(handles, &plan.disconnect, &mut staged_body)?;

        let transition = handles
            .begin_chain_transition()
            .map_err(|source| ReorgError::Unavailable(Box::new(source)))?;

        // Preloading is optimistic. Only an identical plan recomputed while the
        // transition lock is held may mutate chainstate.
        let Some(authoritative) = current_reorg_plan(handles, target)? else {
            return Ok(());
        };
        if plan != authoritative {
            drop(transition);
            continue;
        }

        for body in &disconnect {
            match crate::apply::disconnect_block_admitted(handles, &body.block, &transition) {
                Ok(_) => {}
                Err(
                    error @ (DisconnectError::Fatal { .. } | DisconnectError::MarkerStuck { .. }),
                ) => {
                    handles.admission.close_permanently();
                    return Err(ReorgError::Fatal(Box::new(error)));
                }
                Err(error) => {
                    return Err(ReorgError::Refused {
                        stopped_at: body.height,
                        source: Box::new(error),
                    });
                }
            }
        }

        let mut connected = 0_usize;
        let mut failure = None;
        for body in &connect {
            match crate::apply::apply_block_with_serialized_admitted(
                handles,
                &body.block,
                body.serialized.clone(),
                &transition,
            ) {
                Ok(_) => connected += 1,
                Err(source) => {
                    failure = Some(ReorgError::ConnectFailed {
                        stopped_at: body.height.saturating_sub(1),
                        source: Box::new(source),
                    });
                    break;
                }
            }
        }
        drop(transition);
        for body in &connect[..connected] {
            connected_body(body.hash);
        }
        if let Some(error) = failure {
            return Err(error);
        }
        return Ok(());
    }
}

fn current_reorg_plan(
    handles: &ApplyHandles,
    target: NodeId,
) -> core::result::Result<Option<ReorgPlan>, ReorgError> {
    let tree = handles.block_tree.read();
    let Some(current) = handles.applied_tip.load_full() else {
        return Ok(None);
    };
    let Some(current_id) = tree.lookup(current.hash) else {
        return Err(ReorgError::Plan(
            bitcoin_rs_chain::ChainError::UnknownNode { id: target },
        ));
    };
    plan_reorg(&tree, current_id, target)
        .map(Some)
        .map_err(ReorgError::Plan)
}

struct LoadedBranchBody {
    hash: Hash256,
    block: bitcoin::Block,
    serialized: bytes::Bytes,
    height: u32,
}

/// Loads every block named by a branch, in the order given.
fn load_branch_bodies<F>(
    handles: &ApplyHandles,
    ids: &[NodeId],
    staged_body: &mut F,
) -> core::result::Result<Vec<LoadedBranchBody>, ReorgError>
where
    F: FnMut(Hash256) -> Option<(bitcoin::Block, bytes::Bytes)>,
{
    let nodes = {
        let tree = handles.block_tree.read();
        ids.iter()
            .map(|id| {
                let node = tree.node(*id).map_err(ReorgError::Plan)?;
                Ok((node.hash, node.height))
            })
            .collect::<core::result::Result<Vec<_>, ReorgError>>()?
    };
    let mut loaded = Vec::with_capacity(nodes.len());
    for (hash, height) in nodes {
        if let Some((block, serialized)) = staged_body(hash) {
            loaded.push(validate_branch_body(hash, height, block, serialized)?);
            continue;
        }
        if let Some(store) = handles.block_body_store.as_ref()
            && let Some(body) =
                store
                    .load_block_body(height, hash)
                    .map_err(|source| ReorgError::BodyStore {
                        hash,
                        height,
                        source,
                    })?
        {
            loaded.push(decode_branch_body(hash, height, bytes::Bytes::from(body))?);
            continue;
        }
        if let Some(serialized) = cached_applied_body(handles, hash) {
            loaded.push(decode_branch_body(hash, height, serialized)?);
            continue;
        }
        return Err(ReorgError::MissingBody { hash, height });
    }
    Ok(loaded)
}

fn cached_applied_body(handles: &ApplyHandles, hash: Hash256) -> Option<bytes::Bytes> {
    let block_hex = handles
        .blocks
        .read()
        .iter()
        .rev()
        .find(|record| record.hash == hash && !record.block_hex.is_empty())?
        .block_hex
        .clone();
    Vec::<u8>::from_hex(&block_hex).ok().map(bytes::Bytes::from)
}

fn decode_branch_body(
    hash: Hash256,
    height: u32,
    serialized: bytes::Bytes,
) -> core::result::Result<LoadedBranchBody, ReorgError> {
    let mut cursor = std::io::Cursor::new(serialized.as_ref());
    let block =
        bitcoin::Block::consensus_decode(&mut cursor).map_err(|source| ReorgError::BodyDecode {
            hash,
            height,
            source,
        })?;
    validate_branch_body(hash, height, block, serialized)
}

fn validate_branch_body(
    expected: Hash256,
    height: u32,
    block: bitcoin::Block,
    serialized: bytes::Bytes,
) -> core::result::Result<LoadedBranchBody, ReorgError> {
    let actual = Hash256::from_le_bytes(block.block_hash().as_byte_array());
    if actual != expected {
        return Err(ReorgError::BodyHashMismatch {
            expected,
            actual,
            height,
        });
    }
    if !crate::apply::bytes_are_block(serialized.as_ref(), &block) {
        return Err(ReorgError::BodyBytesMismatch {
            hash: expected,
            height,
        });
    }
    Ok(LoadedBranchBody {
        hash: expected,
        block,
        serialized,
        height,
    })
}
