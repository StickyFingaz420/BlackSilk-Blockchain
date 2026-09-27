//! Block download and serving: the per-peer byte window, the block worker and
//! download scheduling.

use super::fatal;
use super::state::{unix_now, BlockJob, Inner, Peer, State};
use crate::dandelion::PeerId;
use crate::limits::score;
use crate::message::Message;
use blacksilk_chain::block::{Block, MAX_BLOCK_BYTES};
use blacksilk_chain::manager::{submit_block_in_steps, SubmitError, SYNC_STEP_BLOCKS};
use blacksilk_consensus::{Hash, HeaderError};
use rand_chacha::rand_core::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub(super) const BLOCK_TIMEOUT: Duration = Duration::from_secs(60);

/// Block requests in flight per peer (count cap). A block counts from its
/// request until it has been processed (connected or rejected), so the queue
/// of the block worker is bounded by the peers' windows.
const BLOCKS_IN_FLIGHT: usize = 16;

/// Bytes in flight per peer (R8-9): headers carry no body size, so each
/// request is charged `MAX_BLOCK_BYTES`; at most this many bytes' worth of
/// blocks are requested from one peer at a time (3 maximum-size blocks), so a
/// peer on a slow link is not asked for more than it can deliver before the
/// block timeout. One block is always allowed.
pub const BLOCK_WINDOW_BYTES: usize = 32 * 1024 * 1024;

pub(super) const SERVE_BLOCKS_PER_REQUEST: usize = 16;

/// Unrequested blocks queued for the block worker, node-wide. Every one is
/// penalized, and only those whose header we accepted are processed; beyond
/// this they are dropped unread (honest peers send only requested blocks).
const UNREQUESTED_QUEUE: usize = 8;

pub(super) async fn on_get_blocks(inner: &Arc<Inner>, peer: PeerId, ids: Vec<Hash>) {
    // Copied and encoded under the lock on a blocking thread; queued after.
    let (found, missing): (Vec<Vec<u8>>, Vec<Hash>) = inner
        .with_chain(move |c| {
            let mut found = Vec::new();
            let mut missing = Vec::new();
            for id in ids {
                match c.block(&id) {
                    Some(b) if found.len() < SERVE_BLOCKS_PER_REQUEST => found.push(b.encode()),
                    _ => missing.push(id),
                }
            }
            (found, missing)
        })
        .await;
    let mut st = inner.state();
    for b in found {
        inner.send(&mut st, peer, Message::Block(b));
    }
    if !missing.is_empty() {
        inner.send(&mut st, peer, Message::NotFound(missing));
    }
}

/// Frees one place in `peer`'s block request window (`BLOCKS_IN_FLIGHT`,
/// `BLOCK_WINDOW_BYTES`): the request was answered and processed, answered
/// `NotFound`, or timed out.
pub(super) fn release_block_slot(st: &mut State, peer: PeerId) {
    if let Some(p) = st.peers.get_mut(&peer) {
        p.blocks_in_flight = p.blocks_in_flight.saturating_sub(1);
        p.bytes_in_flight = p.bytes_in_flight.saturating_sub(MAX_BLOCK_BYTES);
    }
}

/// Receives a `Block` on the peer's read loop: decoded and matched against
/// our requests here, then handed to the block worker, so the read loop keeps
/// answering pings however long the block takes to connect (R8-1).
pub(super) fn on_block(inner: &Arc<Inner>, peer: PeerId, bytes: Vec<u8>) {
    let block = match Block::decode(&bytes) {
        Ok(b) => b,
        Err(e) => {
            inner.misbehave(
                peer,
                score::INVALID_BLOCK,
                &format!("block does not decode: {e:?}"),
            );
            return;
        }
    };
    let id = block.id(inner.cfg.network_id);
    let job = {
        let mut st = inner.state();
        let requested = st.block_requests.get(&id).is_some_and(|(p, _)| *p == peer);
        if requested {
            // Out of the timeout sweep; its window place is freed once the
            // block worker has processed it.
            st.block_requests.remove(&id);
        }
        let late = st.late_blocks.get(&id).is_some_and(|(p, _)| *p == peer);
        if late {
            st.late_blocks.remove(&id);
        }
        let unrequested = !requested && !late;
        if unrequested && st.unrequested_queued >= UNREQUESTED_QUEUE {
            None
        } else {
            if unrequested {
                st.unrequested_queued += 1;
            }
            st.blocks_queued.insert(id);
            Some(BlockJob {
                peer,
                block,
                requested,
                late,
            })
        }
    };
    let solicited = job.as_ref().is_some_and(|j| j.requested || j.late);
    if !solicited {
        inner.misbehave(peer, score::UNSOLICITED, "unrequested block");
    }
    if let Some(job) = job {
        if inner.block_queue.send(job).is_err() {
            log::error!("block worker stopped: block dropped");
        }
    }
}

/// Validates and connects received blocks, one at a time, in arrival order
/// (docs/p2p.md §6). Each block is connected through the bounded API
/// (`submit_block_in_steps`): at most `SYNC_STEP_BLOCKS` block validations
/// per chain-lock hold, so the gap-filling block of a long download does not
/// hold the lock while hundreds of waiting descendants connect.
pub(super) async fn block_worker(inner: Arc<Inner>, mut rx: mpsc::UnboundedReceiver<BlockJob>) {
    while let Some(job) = rx.recv().await {
        let BlockJob {
            peer,
            block,
            requested,
            late,
        } = job;
        let unrequested = !requested && !late;
        let id = block.id(inner.cfg.network_id);
        let inner2 = inner.clone();
        let result = tokio::task::spawn_blocking(move || {
            // Only a block whose header we already accepted (so it passed
            // the header gate, `worth_verifying`) is worth storing, e.g. a
            // requested block arriving after its timeout. Any other
            // unrequested body, for instance of a free low-work branch, is
            // dropped before it is hashed or written (R1-C1).
            if unrequested && inner2.chain().header(&id).is_none() {
                return None;
            }
            Some(submit_block_in_steps(
                || inner2.chain(),
                block,
                unix_now(),
                SYNC_STEP_BLOCKS,
            ))
        })
        .await;
        {
            let mut st = inner.state();
            if requested {
                release_block_slot(&mut st, peer);
            }
            if unrequested {
                st.unrequested_queued = st.unrequested_queued.saturating_sub(1);
            }
            st.blocks_queued.remove(&id);
        }
        match result {
            Ok(None) | Ok(Some(Ok(_))) | Ok(Some(Err(SubmitError::Duplicate))) => {}
            Ok(Some(Err(SubmitError::BodyMismatch))) => {
                inner.misbehave(peer, score::INVALID_BLOCK, "body does not match header")
            }
            Ok(Some(Err(SubmitError::Body(e)))) => {
                inner.misbehave(peer, score::INVALID_BLOCK, &format!("invalid block: {e:?}"))
            }
            Ok(Some(Err(SubmitError::Header(e)))) => match e {
                // `InvalidParent`: the parent's body was found invalid,
                // possibly after we requested this block (a race), so it is
                // not the sender's fault; an unrequested block was already
                // charged on arrival.
                HeaderError::Duplicate
                | HeaderError::TimestampTooFarInFuture { .. }
                | HeaderError::InvalidParent => {}
                HeaderError::UnknownParent => inner.request_headers(peer).await,
                // Confirmed with proof of work by `validate` (RT-1).
                HeaderError::UnknownUpgrade { version } => {
                    inner.note_unknown_upgrade(peer, version, false)
                }
                e => inner.misbehave(
                    peer,
                    score::INVALID_HEADER,
                    &format!("invalid block header: {e}"),
                ),
            },
            Ok(Some(Err(SubmitError::Store(e)))) => log::error!("block store: {e}"),
            // The task holds the chain lock: a panic there poisoned it.
            Err(e) if e.is_panic() => fatal(&format!("block task failed: {e}")),
            Err(_) => return, // the runtime is shutting down
        }
        schedule_downloads(&inner).await;
    }
}

/// Requests missing best-chain bodies from peers that have them (docs/p2p.md
/// §6), within each peer's window: `BLOCKS_IN_FLIGHT` blocks and
/// `BLOCK_WINDOW_BYTES` (each request charged `MAX_BLOCK_BYTES`), at least
/// one block.
pub(super) async fn schedule_downloads(inner: &Arc<Inner>) {
    let missing = inner.with_chain(|c| c.missing_bodies(256)).await;
    if missing.is_empty() {
        return;
    }
    let mut st = inner.state();
    let now = Instant::now();
    let mut batches: HashMap<PeerId, Vec<Hash>> = HashMap::new();
    for (height, id) in missing {
        if st.block_requests.contains_key(&id) || st.blocks_queued.contains(&id) {
            continue;
        }

        let candidates: Vec<PeerId> = st
            .peers
            .iter()
            .filter(|(_, p)| p.height >= height && window_has_room(p))
            .map(|(id, _)| *id)
            .collect();
        if candidates.is_empty() {
            break;
        }
        let pick = candidates[(st.rng.next_u64() % candidates.len() as u64) as usize];
        let p = st.peers.get_mut(&pick).expect("candidate");
        p.blocks_in_flight += 1;
        p.bytes_in_flight += MAX_BLOCK_BYTES;
        st.block_requests.insert(id, (pick, now));
        batches.entry(pick).or_default().push(id);
    }
    for (peer, ids) in batches {
        inner.send(&mut st, peer, Message::GetBlocks(ids));
    }
}

/// Whether another block may be requested from `p` (`schedule_downloads`).
fn window_has_room(p: &Peer) -> bool {
    p.blocks_in_flight == 0
        || (p.blocks_in_flight < BLOCKS_IN_FLIGHT
            && p.bytes_in_flight + MAX_BLOCK_BYTES <= BLOCK_WINDOW_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R8-9: the byte window, not the count, limits maximum-size blocks
    /// (3 in flight per peer; `p2p/tests/network.rs` checks it on the wire).
    #[test]
    fn the_byte_window_is_the_binding_limit() {
        let allowed = BLOCK_WINDOW_BYTES / MAX_BLOCK_BYTES;
        assert_eq!(allowed, 3);
        assert!(allowed < BLOCKS_IN_FLIGHT);
    }
}
