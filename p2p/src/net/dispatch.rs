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
use crate::message::{Message, MAX_ANY_TX_SIZE, MAX_HEADERS};
use blacksilk_consensus::BlockHeader;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

// ---------------------------------------------------------------- slow lane

/// Messages queued in one peer's slow lane, requests and relay together.
pub(super) const SLOW_LANE: usize = 64;

/// Relay messages (`InvTx`, `Tx`, `StemTx`) queued in one peer's slow lane:
/// relay never takes the last `SLOW_LANE - SLOW_LANE_RELAY` places, which
/// stay for the peer's requests.
pub(super) const SLOW_LANE_RELAY: usize = 32;

/// Room for small relay (announcements, transfers) queued ahead of a
/// maximum-size transaction in one peer's slow lane.
pub(super) const SMALL_RELAY_BYTES: usize = 2 * 1024 * 1024;

/// The largest relay frame: a `Tx` or `StemTx` of `MAX_ANY_TX_SIZE` bytes
/// (the codec's limit) plus its type byte and length varint. An `InvTx` is
/// at most `MAX_INV` ids (16 KiB).
pub(super) const MAX_RELAY_FRAME: usize = MAX_ANY_TX_SIZE + 16;

/// Bytes of relay messages (`InvTx`, `Tx`, `StemTx`) in one peer's slow
/// lane: queued, or being handled (a message is counted until its handler
/// returns). A maximum-size transaction always fits behind
/// `SMALL_RELAY_BYTES` of other relay (RTW2A-1): every measured PX transfer
/// (about 2.18 MB, its proof alone) is larger than 2 MiB, and the former
/// 2 MiB bound dropped a requested PX `Tx`, or a PX `StemTx` (a stem black
/// hole the origin then ends by fluffing its own transaction), behind a
/// single queued 40-byte `InvTx`. Two PX transfers and small relay fit
/// together. Requests are not counted here (they are bounded by their count
/// and codec limits). The bound replaces the TCP back-pressure the read
/// loop gave before it stopped waiting for the chain; the per-peer memory
/// it implies is in docs/p2p.md §10.
pub(super) const SLOW_LANE_BYTES: usize = MAX_RELAY_FRAME + SMALL_RELAY_BYTES;

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
///
/// Requests and relay share the one queue, with separate bounds (places
/// and bytes, [`SlowLane::push`]). Separate request and relay queues were
/// considered (RTW2A-5) and not made: a second task per peer would lose
/// the per-peer order across kinds that the handlers rely on, and the
/// place split already keeps relay from crowding out requests.
pub(super) struct SlowLane {
    queue: mpsc::Sender<(Message, usize)>,
    /// Relay bytes and relay messages queued (requests are not counted).
    relay_bytes: Arc<AtomicUsize>,
    relay_count: Arc<AtomicUsize>,
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
        let relay_bytes = Arc::new(AtomicUsize::new(0));
        let relay_count = Arc::new(AtomicUsize::new(0));
        let (inner, bytes, count) = (inner.clone(), relay_bytes.clone(), relay_count.clone());
        tokio::spawn(async move {
            while let Some((msg, len)) = rx.recv().await {
                if !inner.state().peers.contains_key(&peer) {
                    break;
                }
                let relay = is_relay(&msg);
                handle(&inner, peer, msg).await;
                if relay {
                    bytes.fetch_sub(len, Ordering::Relaxed);
                    count.fetch_sub(1, Ordering::Relaxed);
                }
            }
        });
        Self {
            queue,
            relay_bytes,
            relay_count,
        }
    }

    /// Queues `msg` (a frame of `len` bytes), or drops it:
    /// - relay, if [`SLOW_LANE_RELAY`] relay messages are queued already, or
    ///   if it would take the relay bytes past [`SLOW_LANE_BYTES`] (never
    ///   charged; a relay frame is at most [`MAX_RELAY_FRAME`], so an empty
    ///   lane takes any, and one of that size always fits behind
    ///   [`SMALL_RELAY_BYTES`]);
    /// - a request, only if the lane holds [`SLOW_LANE`] messages (charged:
    ///   at least `SLOW_LANE - SLOW_LANE_RELAY` of them are this peer's own
    ///   requests). Queued relay bytes never drop a request.
    pub(super) fn push(&self, msg: Message, len: usize) -> Pushed {
        let relay = is_relay(&msg);
        if relay {
            let bytes = self.relay_bytes.load(Ordering::Relaxed);
            if self.relay_count.load(Ordering::Relaxed) >= SLOW_LANE_RELAY
                || bytes + len > SLOW_LANE_BYTES
            {
                return Pushed::Dropped { charge: false };
            }
            // Counted before the task can see it (the task subtracts after
            // handling it); only the read loop pushes.
            self.relay_bytes.fetch_add(len, Ordering::Relaxed);
            self.relay_count.fetch_add(1, Ordering::Relaxed);
        }
        match self.queue.try_send((msg, len)) {
            Ok(()) => Pushed::Queued,
            Err(_) => {
                if relay {
                    self.relay_bytes.fetch_sub(len, Ordering::Relaxed);
                    self.relay_count.fetch_sub(1, Ordering::Relaxed);
                }
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
            relay_bytes: Arc::new(AtomicUsize::new(0)),
            relay_count: Arc::new(AtomicUsize::new(0)),
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

    /// Relay fills at most `SLOW_LANE_RELAY` places, dropped without a
    /// charge beyond; requests still take the rest, and only a lane full of
    /// messages charges a request. The queue keeps the arrival order.
    #[test]
    fn relay_is_bounded_apart_and_only_a_full_lane_charges_requests() {
        let (lane, mut rx) = idle_lane();
        for i in 0..SLOW_LANE_RELAY {
            let m = Message::InvTx(vec![[i as u8; 32]]);
            assert_eq!(lane.push(m, 40), Pushed::Queued);
        }
        let dropped = |charge| Pushed::Dropped { charge };
        assert_eq!(lane.push(Message::Tx(vec![0; 10]), 10), dropped(false));
        assert_eq!(lane.push(Message::StemTx(vec![0; 10]), 10), dropped(false));
        for _ in SLOW_LANE_RELAY..SLOW_LANE {
            assert_eq!(lane.push(get_headers(), 40), Pushed::Queued);
        }
        assert_eq!(lane.push(Message::GetTx(vec![[1; 32]]), 40), dropped(true));
        assert_eq!(lane.push(get_headers(), 40), dropped(true));
        assert_eq!(
            lane.relay_bytes.load(Ordering::Relaxed),
            SLOW_LANE_RELAY * 40
        );
        for i in 0..SLOW_LANE_RELAY {
            let (m, _) = rx.try_recv().unwrap();
            assert_eq!(m, Message::InvTx(vec![[i as u8; 32]]));
        }
        for _ in SLOW_LANE_RELAY..SLOW_LANE {
            assert_eq!(rx.try_recv().unwrap().0, get_headers());
        }
        assert!(rx.try_recv().is_err());
    }

    /// The relay byte bound: a lane without queued relay takes the largest
    /// relay frame, and past the bound relay is dropped; a request is still
    /// queued and never charged (the Stage 1 regression: one queued PX
    /// transaction made every later request of its peer dropped and
    /// charged).
    #[test]
    fn queued_relay_bytes_never_drop_or_charge_a_request() {
        let (lane, mut rx) = idle_lane();
        let max = Message::StemTx(vec![0; MAX_ANY_TX_SIZE]).encode().len();
        assert!(max <= MAX_RELAY_FRAME, "{max}");
        assert_eq!(lane.push(Message::StemTx(vec![]), max), Pushed::Queued);
        assert_eq!(lane.push(get_headers(), 100), Pushed::Queued);
        assert_eq!(lane.push(Message::GetBlocks(vec![]), 100), Pushed::Queued);
        let room = SLOW_LANE_BYTES - max;
        assert_eq!(
            lane.push(Message::Tx(vec![]), room + 1),
            Pushed::Dropped { charge: false }
        );
        assert_eq!(lane.push(Message::InvTx(vec![]), room), Pushed::Queued);
        assert_eq!(
            lane.push(Message::InvTx(vec![]), 1),
            Pushed::Dropped { charge: false }
        );
        assert_eq!(lane.push(get_headers(), 100), Pushed::Queued);
        assert_eq!(lane.relay_bytes.load(Ordering::Relaxed), SLOW_LANE_BYTES);
        assert_eq!(lane.relay_count.load(Ordering::Relaxed), 2);
        assert_eq!(rx.try_recv().unwrap().0, Message::StemTx(vec![]));
        assert_eq!(rx.try_recv().unwrap().0, get_headers());
    }

    /// RTW2A-1, with real PX sizes. Every measured PX transfer is larger than
    /// 2 MiB (proof alone 2,178,213 to 2,180,408 B, docs/zk.md), and the
    /// former 2 MiB bound (a lane took a message over it only when it held
    /// no relay bytes) dropped a requested PX `Tx` and a PX `StemTx` behind
    /// one queued 40-byte `InvTx`, and the second PX `Tx` of one `GetTx`
    /// answer (demonstrated on 47179f1). Now both are queued, and so is a
    /// maximum-size transaction behind `SMALL_RELAY_BYTES` of small relay.
    #[test]
    fn a_px_transaction_behind_small_queued_relay_is_queued() {
        let frame = |n| Message::StemTx(vec![0; n]).encode().len();
        let px_len = frame(2_180_408);
        assert!(px_len > 2 * 1024 * 1024);
        let (lane, _rx) = idle_lane();
        assert_eq!(lane.push(Message::InvTx(vec![[1; 32]]), 40), Pushed::Queued);
        assert_eq!(lane.push(Message::Tx(vec![]), px_len), Pushed::Queued);
        assert_eq!(lane.push(Message::StemTx(vec![]), px_len), Pushed::Queued);
        let (lane, _rx) = idle_lane();
        assert_eq!(lane.push(Message::Tx(vec![]), px_len), Pushed::Queued);
        assert_eq!(
            lane.push(Message::Tx(vec![]), px_len),
            Pushed::Queued,
            "the second PX Tx of one GetTx answer"
        );
        // The largest PX transaction behind 2 MiB of announcements and
        // transfers.
        let (lane, _rx) = idle_lane();
        let small = SMALL_RELAY_BYTES / 16;
        for i in 0..16 {
            let m = Message::InvTx(vec![[i; 32]]);
            assert_eq!(lane.push(m, small), Pushed::Queued);
        }
        let max = frame(MAX_ANY_TX_SIZE);
        assert_eq!(lane.push(Message::StemTx(vec![]), max), Pushed::Queued);
    }
}
