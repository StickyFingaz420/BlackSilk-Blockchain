//! The message dispatcher: unsolicited-reply checks, per-message routing,
//! and the per-peer slow lane (docs/p2p.md §10).

use super::addr_relay::{on_addr, on_get_addr};
use super::admission::{on_stem_tx, on_tx};
use super::blocks::{on_block, on_get_blocks, release_block_slot};
use super::headers::{in_grace, on_headers};
use super::relay::{on_get_tx, on_inv_tx, retry_tx};
use super::state::Inner;
use crate::dandelion::PeerId;
use crate::limits::score;
use crate::message::{Message, MAX_HEADERS};
use blacksilk_consensus::BlockHeader;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

// ---------------------------------------------------------------- slow lane

/// Messages queued in one peer's slow lane.
pub(super) const SLOW_LANE: usize = 64;

/// Bytes of messages queued in one peer's slow lane. A message always enters
/// an empty lane, so the lane holds at most this plus one message (one
/// maximum-size PX transaction): the bound replaces the TCP back-pressure the
/// read loop gave before it stopped waiting for the chain.
pub(super) const SLOW_LANE_BYTES: usize = 2 * 1024 * 1024;

/// Whether handling `msg` needs a chain command: it then runs on the peer's
/// slow lane ([`SlowLane`]), never on its read loop, so the read loop keeps
/// answering pings, pongs and everything else however long the chain actor
/// is busy (F34-1). Everything else reads only the network state or the
/// published chain summary, or queues work for the header and block workers.
pub(super) fn is_slow(msg: &Message) -> bool {
    matches!(
        msg,
        Message::GetHeaders { .. }
            | Message::GetBlocks(_)
            | Message::InvTx(_)
            | Message::GetTx(_)
            | Message::Tx(_)
            | Message::StemTx(_)
    )
}

/// Transaction relay, dropped without penalty when the lane is full: relay is
/// best effort, and a peer answering our `GetTx` during a long hold is honest.
fn is_relay(msg: &Message) -> bool {
    matches!(msg, Message::InvTx(_) | Message::Tx(_) | Message::StemTx(_))
}

/// One peer's slow lane: a bounded queue of its chain-touching messages and
/// the task handling them one at a time, in arrival order (per-peer order is
/// kept: `tx_requests` and `known_txs` depend on it). One peer's backlog
/// waits in its own lane; other peers' lanes and read loops are not behind
/// it (they share only the chain actor itself).
pub(super) struct SlowLane {
    queue: mpsc::Sender<(Message, usize)>,
    bytes: Arc<AtomicUsize>,
}

/// What [`SlowLane::push`] did with a message.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Pushed {
    Queued,
    /// The lane was full: dropped. `charge`: a request (not relay), charged
    /// like a message-rate excess (`score::RATE`).
    Dropped {
        charge: bool,
    },
}

impl SlowLane {
    /// Starts the lane task of `peer`. It ends when the lane is dropped (the
    /// read loop ended) or once the peer is gone, never in the middle of a
    /// message.
    pub(super) fn start(inner: &Arc<Inner>, peer: PeerId) -> Self {
        let (queue, mut rx) = mpsc::channel::<(Message, usize)>(SLOW_LANE);
        let bytes = Arc::new(AtomicUsize::new(0));
        let (inner, queued) = (inner.clone(), bytes.clone());
        tokio::spawn(async move {
            while let Some((msg, len)) = rx.recv().await {
                if !inner.state().peers.contains_key(&peer) {
                    break;
                }
                handle(&inner, peer, msg).await;
                queued.fetch_sub(len, Ordering::Relaxed);
            }
        });
        Self { queue, bytes }
    }

    /// Queues `msg` (a frame of `len` bytes), or drops it if the lane holds
    /// [`SLOW_LANE`] messages or [`SLOW_LANE_BYTES`] bytes already.
    pub(super) fn push(&self, msg: Message, len: usize) -> Pushed {
        let queued = self.bytes.load(Ordering::Relaxed);
        if queued > 0 && queued + len > SLOW_LANE_BYTES {
            return Pushed::Dropped {
                charge: !is_relay(&msg),
            };
        }
        let relay = is_relay(&msg);
        // Counted before the task can see it (the task subtracts after
        // handling it); only the read loop pushes.
        self.bytes.fetch_add(len, Ordering::Relaxed);
        match self.queue.try_send((msg, len)) {
            Ok(()) => Pushed::Queued,
            Err(_) => {
                self.bytes.fetch_sub(len, Ordering::Relaxed);
                Pushed::Dropped { charge: !relay }
            }
        }
    }
}

// ---------------------------------------------------------------- handlers

/// Whether `msg` answers a request we sent `peer` and are still waiting for:
/// a block we requested (only its header, the first `HEADER_SIZE` bytes, is
/// read), or headers while a `GetHeaders` is outstanding.
pub(super) fn requested_by_us(inner: &Inner, peer: PeerId, msg: &Message) -> bool {
    let bytes = match msg {
        Message::Block(bytes) => bytes,
        Message::Headers(h) => {
            let now = Instant::now();
            return inner.state().peers.get(&peer).is_some_and(|p| {
                p.headers_requested.is_some() || (h.len() > 1 && in_grace(p.headers_grace, now))
            });
        }
        _ => return false,
    };
    let Some(header) = bytes
        .get(..blacksilk_consensus::HEADER_SIZE)
        .and_then(BlockHeader::from_bytes)
    else {
        return false;
    };
    let id = header.id(inner.cfg.network_id);
    let st = inner.state();
    st.block_requests
        .get(&id)
        .or_else(|| st.late_blocks.get(&id))
        .is_some_and(|(p, _)| *p == peer)
}

pub(super) async fn handle(inner: &Arc<Inner>, peer: PeerId, msg: Message) {
    match msg {
        Message::Version(_) | Message::Verack => {
            inner.misbehave(peer, score::PROTOCOL, "duplicate version/verack");
        }
        Message::Ping(n) => inner.send_now(peer, Message::Pong(n)),
        Message::Pong(n) => {
            let ok = {
                let mut st = inner.state();
                match st.peers.get_mut(&peer) {
                    Some(p) if p.ping.map(|(x, _)| x) == Some(n) => {
                        p.ping = None;
                        true
                    }
                    _ => false,
                }
            };
            if !ok {
                inner.misbehave(peer, score::UNSOLICITED, "unexpected pong");
            }
        }
        Message::GetAddr => on_get_addr(inner, peer),
        Message::Addr(addrs) => on_addr(inner, peer, addrs),
        Message::GetHeaders { locator, stop } => {
            let headers = inner
                .with_chain(move |c| c.headers_after(&locator, &stop, MAX_HEADERS as usize))
                .await;
            inner.send_now(peer, Message::Headers(headers));
        }
        Message::Headers(headers) => on_headers(inner, peer, headers).await,
        Message::GetBlocks(ids) => on_get_blocks(inner, peer, ids).await,
        Message::Block(bytes) => on_block(inner, peer, bytes),
        Message::NotFound(ids) => {
            let mut st = inner.state();
            let now = Instant::now();
            for id in ids {
                if st.block_requests.get(&id).is_some_and(|(p, _)| *p == peer) {
                    st.block_requests.remove(&id);
                    release_block_slot(&mut st, peer);
                }
                if st.tx_requests.get(&id).is_some_and(|(p, _)| *p == peer) {
                    retry_tx(inner, &mut st, id, peer, now);
                }
            }
        }
        Message::InvTx(ids) => on_inv_tx(inner, peer, ids).await,
        Message::GetTx(ids) => on_get_tx(inner, peer, ids).await,
        Message::Tx(bytes) => on_tx(inner, peer, bytes).await,
        Message::StemTx(bytes) => on_stem_tx(inner, peer, bytes).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lane without its task, so nothing drains it.
    fn idle_lane() -> (SlowLane, mpsc::Receiver<(Message, usize)>) {
        let (queue, rx) = mpsc::channel(SLOW_LANE);
        let lane = SlowLane {
            queue,
            bytes: Arc::new(AtomicUsize::new(0)),
        };
        (lane, rx)
    }

    fn get_headers() -> Message {
        Message::GetHeaders {
            locator: vec![],
            stop: [0; 32],
        }
    }

    /// F34-1: exactly the chain-touching kinds use the slow lane; pings,
    /// pongs, headers and blocks stay on the read loop.
    #[test]
    fn only_chain_touching_messages_use_the_slow_lane() {
        for m in [
            get_headers(),
            Message::GetBlocks(vec![]),
            Message::InvTx(vec![]),
            Message::GetTx(vec![]),
            Message::Tx(vec![]),
            Message::StemTx(vec![]),
        ] {
            assert!(is_slow(&m), "{}", m.kind());
        }
        for m in [
            Message::Ping(1),
            Message::Pong(1),
            Message::GetAddr,
            Message::Headers(vec![]),
            Message::Block(vec![]),
            Message::NotFound(vec![]),
            Message::Verack,
        ] {
            assert!(!is_slow(&m), "{}", m.kind());
        }
    }

    /// A full lane (by count) drops relay without a charge and charges a
    /// request; nothing is queued beyond the bound, and the queue keeps the
    /// arrival order.
    #[test]
    fn a_full_lane_drops_relay_free_and_charges_requests() {
        let (lane, mut rx) = idle_lane();
        for i in 0..SLOW_LANE {
            let m = Message::InvTx(vec![[i as u8; 32]]);
            assert_eq!(lane.push(m, 40), Pushed::Queued);
        }
        let dropped = |charge| Pushed::Dropped { charge };
        assert_eq!(lane.push(Message::Tx(vec![0; 10]), 10), dropped(false));
        assert_eq!(lane.push(Message::StemTx(vec![0; 10]), 10), dropped(false));
        assert_eq!(lane.push(Message::GetTx(vec![[1; 32]]), 40), dropped(true));
        assert_eq!(lane.push(get_headers(), 40), dropped(true));
        assert_eq!(lane.bytes.load(Ordering::Relaxed), SLOW_LANE * 40);
        for i in 0..SLOW_LANE {
            let (m, _) = rx.try_recv().unwrap();
            assert_eq!(m, Message::InvTx(vec![[i as u8; 32]]));
        }
        assert!(rx.try_recv().is_err());
    }

    /// The byte bound: an empty lane takes one message of any size (the
    /// largest transaction must pass), a non-empty one nothing past the bound.
    #[test]
    fn the_lane_is_bounded_in_bytes_but_takes_one_message_of_any_size() {
        let (lane, _rx) = idle_lane();
        let big = SLOW_LANE_BYTES + 1;
        assert_eq!(lane.push(Message::Tx(vec![]), big), Pushed::Queued);
        assert_eq!(
            lane.push(get_headers(), 1),
            Pushed::Dropped { charge: true }
        );
        assert_eq!(
            lane.push(Message::InvTx(vec![]), 1),
            Pushed::Dropped { charge: false }
        );
        assert_eq!(lane.bytes.load(Ordering::Relaxed), big);
    }
}
