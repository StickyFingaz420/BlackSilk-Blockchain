//! One connection: the handshake, registration, the read loop, cleanup and
//! the writer task.

use super::addr_relay::advertise_self;
use super::blocks::SERVE_BLOCKS_PER_REQUEST;
use super::dispatch::{handle, is_slow, requested_by_us, Pushed, SlowLane, SMALL_RELAY_BYTES};
use super::maintenance::announce_tip;
use super::peers::{
    advertised_listen, evict_inbound, inbound_count, onion_inbound_count, same_ip_count,
    HandshakeSlot,
};
use super::serve_tx::{ReplyQueue, SERVE_TX_FRAMES};
use super::state::{owed_key, shuffle, unix_now, Inner, Peer, OWED_IDS, OWED_WINDOW};
use super::tx_requests::Actions;
use crate::addr::NetAddr;
use crate::addrman_gate::AddrGate;
use crate::connman::{onion_inbound_cap, ConnKind};
use crate::limits::score;
use crate::message::{
    is_known_type, Message, Version, MAX_HANDSHAKE_FRAME, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION,
};
use crate::transport::{handshake_with, FrameReader, FrameWriter, Session, TransportError};
use blacksilk_consensus::Hash;
use rand_chacha::rand_core::RngCore;
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, Notify};

/// The key exchange's own timeout (its first step), over Tor: a proxied
/// outbound connection, or an inbound one through our hidden service.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The key exchange's timeout on clearnet: one round trip of 32-byte keys.
/// An inbound connection that sends nothing leaves after this, not after the
/// whole handshake deadline (RTW3-3).
const KEY_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

/// The whole handshake, from the connection to the peer's `Verack`
/// (docs/p2p.md §4). One deadline, not one per frame: before it, a peer
/// could hold a connection slot for a step timeout per negotiation frame
/// (dossier 30 T-1). Two step timeouts leave room for Tor round trips.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(20);

const IDLE_TIMEOUT: Duration = Duration::from_secs(180);

/// Control messages queued per peer (everything except `Block` frames and
/// `GetTx` answers).
const OUTBOX: usize = 64;

/// `GetTx` answers queued per peer (at most `SERVE_TX_FRAMES` `Tx` frames
/// and their `NotFound`s).
const ANSWERS_OUTBOX: usize = 2 * SERVE_TX_FRAMES;

// `GetTx` answers take at most half of it (TM2-17).
const _: () = assert!(SERVE_TX_FRAMES <= OUTBOX / 2);

/// `Block` frames queued per peer; control messages are sent first (R8-11).
const BULK_OUTBOX: usize = 2 * SERVE_BLOCKS_PER_REQUEST;

/// Frames of unknown message types skipped between `Version` and `Verack`
/// (a later protocol version may negotiate features there).
const HANDSHAKE_UNKNOWN_FRAMES: usize = 8;

/// A frame before `Verack`: at most [`MAX_HANDSHAKE_FRAME`] bytes. The peer
/// is unregistered and unauthenticated, so a failure only closes the
/// connection; nothing is scored or banned (docs/p2p.md §4, §10).
async fn recv_handshake_frame<R: AsyncRead + Unpin>(
    inner: &Inner,
    r: &mut FrameReader<R>,
) -> Result<Vec<u8>, String> {
    r.recv_limited(MAX_HANDSHAKE_FRAME).await.map_err(|e| {
        if matches!(e, TransportError::Decrypt) {
            inner.state().transport_failures += 1;
            "a frame failed to decrypt (another network, genesis, transport version or \
             pre-shared key, tampering, or not a BlackSilk peer)"
                .to_string()
        } else {
            e.to_string()
        }
    })
}

/// Whether a message relays transactions (`InvTx`, `GetTx`, `Tx`,
/// `StemTx`): never exchanged on a block-relay-only connection.
fn is_tx_message(msg: &Message) -> bool {
    matches!(
        msg,
        Message::InvTx(_) | Message::GetTx(_) | Message::Tx(_) | Message::StemTx(_)
    )
}

/// Whether a loopback connection on the P2P listener is taken for an onion
/// peer arriving through our hidden service: only while no onion listener
/// is configured (`NetConfig::onion_listen`), and never with
/// `allow_private`.
pub(super) fn loopback_is_tor(cfg: &super::NetConfig, addr: &NetAddr) -> bool {
    cfg.onion_listen.is_none() && !cfg.allow_private && addr.ip().is_some_and(|ip| ip.is_loopback())
}

pub(super) async fn run_connection<S>(
    inner: Arc<Inner>,
    stream: S,
    addr: NetAddr,
    kind: ConnKind,
    proxied: bool,
    mut slot: Option<HandshakeSlot>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let inbound = kind.is_inbound();
    let nid = inner.cfg.network_id;
    let deadline = tokio::time::Instant::now() + HANDSHAKE_DEADLINE;
    // The session keys also bind the genesis id (R15-3), the transport
    // version and a closed network's pre-shared key (docs/p2p.md §3).
    let genesis = inner.genesis_id;
    let session = Session {
        network_id: nid,
        genesis_id: &genesis,
        psk: inner.cfg.network_psk.as_ref(),
    };
    // A pending inbound handshake the node evicted (RTW3-3) ends here, at
    // whatever step it is.
    let kill_handshake = slot.as_ref().map(|s| s.kill.clone());
    let evicted = async move {
        match kill_handshake {
            Some(kill) => kill.notified().await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(evicted);
    let via_tor = proxied || (kind == ConnKind::Inbound && loopback_is_tor(&inner.cfg, &addr));
    let key_timeout = if via_tor {
        HANDSHAKE_TIMEOUT
    } else {
        KEY_EXCHANGE_TIMEOUT
    };
    let keyed = handshake_with(stream, !inbound, session, key_timeout);
    let keyed = tokio::select! {
        r = tokio::time::timeout_at(deadline, keyed) => r,
        _ = &mut evicted => {
            log::debug!("{addr}: evicted during the key exchange");
            return;
        }
    };
    let (mut reader, mut writer) = match keyed {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => {
            log::debug!("{addr}: transport handshake failed: {e}");
            return;
        }
        Err(_) => {
            log::debug!("{addr}: transport handshake timed out");
            return;
        }
    };
    // Version exchange.
    let nonce = {
        let mut st = inner.state();
        let n = st.rng.next_u64();
        st.local_nonces.insert(n);
        n
    };
    // From the published snapshot, never a chain command: a long one must not
    // make every new connection miss the remote's handshake timeout (F34-3).
    // The connected tip of the same snapshot: the peer's first announcement
    // candidate after registration (`Peer::announced`, RT-SYNC F-B).
    let (height, tip, our_tip) = {
        let s = inner.summary.load();
        (s.header_height, s.best_header_id, s.tip_id)
    };
    // No address of ours on a block-relay-only connection: addresses are
    // never exchanged there (an anchor learns nothing to link us by).
    let our_listen = match kind {
        ConnKind::BlockRelay => None,
        _ => advertised_listen(&inner.cfg, &addr, inbound, proxied),
    };
    let ours = Version {
        protocol: PROTOCOL_VERSION,
        network: nid,
        nonce,
        height,
        tip,
        listen: our_listen.clone(),
        relay_txs: kind != ConnKind::BlockRelay,
    };
    // Before `Verack` only `Version`, then up to HANDSHAKE_UNKNOWN_FRAMES
    // frames of unknown types, then `Verack`; each at most
    // MAX_HANDSHAKE_FRAME bytes, all before the deadline. Anything else
    // closes the connection, unscored (docs/p2p.md §4).
    let exchange = async {
        writer
            .send(&Message::Version(ours).encode())
            .await
            .map_err(|e| e.to_string())?;
        let frame = recv_handshake_frame(&inner, &mut reader).await?;
        let theirs = match Message::decode(&frame).map_err(|e| format!("decode: {e:?}"))? {
            Message::Version(v) => v,
            other => return Err(format!("expected version, got {}", other.kind())),
        };
        if theirs.protocol < MIN_PROTOCOL_VERSION {
            return Err(format!("protocol {} too old", theirs.protocol));
        }
        if theirs.network != nid {
            return Err("wrong network".into());
        }
        if inner.state().local_nonces.contains(&theirs.nonce) {
            return Err("connected to self".into());
        }
        writer
            .send(&Message::Verack.encode())
            .await
            .map_err(|e| e.to_string())?;
        // A later protocol version may send messages of types we do not
        // know before its `Verack` (feature negotiation): skipped.
        let mut skipped = 0;
        loop {
            let frame = recv_handshake_frame(&inner, &mut reader).await?;
            if frame.first().is_some_and(|&t| !is_known_type(t))
                && skipped < HANDSHAKE_UNKNOWN_FRAMES
            {
                skipped += 1;
                continue;
            }
            return match Message::decode(&frame).map_err(|e| format!("decode: {e:?}"))? {
                Message::Verack => Ok(theirs),
                other => Err(format!("expected verack, got {}", other.kind())),
            };
        }
    };
    let result = tokio::select! {
        r = tokio::time::timeout_at(deadline, exchange) => {
            r.unwrap_or_else(|_| Err("handshake deadline passed".into()))
        }
        _ = &mut evicted => Err("evicted during the handshake".into()),
    };
    inner.state().local_nonces.remove(&nonce);
    let theirs = match result {
        Ok(v) => v,
        Err(e) => {
            log::debug!("{addr}: handshake failed: {e}");
            return;
        }
    };

    // Addresses are exchanged unless the connection is block-relay-only:
    // ours, or the peer's (an inbound peer that asked for no transaction
    // relay is a block-relay-only connection of its own). We ask for
    // addresses on full-relay outbound connections and address fetches.
    let addr_relay = kind.relays_addrs() && (!inbound || theirs.relay_txs);
    let asks_addresses = matches!(kind, ConnKind::FullRelay | ConnKind::AddrFetch);

    // Register.
    let (tx_out, rx_out) = mpsc::channel::<Message>(OUTBOX);
    let (tx_answers, rx_answers) = mpsc::channel::<Message>(ANSWERS_OUTBOX);
    let ping_written = Arc::new(Mutex::new(None));
    let (tx_bulk, rx_bulk) = mpsc::channel::<Message>(BULK_OUTBOX);
    let kill = Arc::new(Notify::new());
    let replies = Arc::new(ReplyQueue::default());
    let id = inner.next_id.fetch_add(1, Ordering::Relaxed);
    {
        let mut st = inner.state();
        if let Some(slot) = slot.as_mut() {
            slot.release(&mut st);
        }
        // Check the inbound limits at registration, under the same lock as
        // the insertion (the accept-time check counted this connection as
        // handshaking), and a ban that came in during the handshake. With
        // inbound full, a registered peer gives way if one is not protected
        // (`connman::select_inbound_to_evict`); else this one is refused.
        // Evicting here, not at accept, means only a peer that completed its
        // handshake can take a registered peer's place (RTW3-3).
        // Onion peers (our hidden service) share the Tor daemon's IP: no ban
        // or per-IP limit applies to them; the class is capped at a quarter of
        // `max_inbound` and makes room within itself (W3-32c, N-6).
        if inbound {
            let onion = kind == ConnKind::OnionInbound;
            let over = (!onion
                && addr.ip().is_some_and(|ip| {
                    st.bans.is_banned(&ip, unix_now())
                        || (!inner.cfg.allow_private
                            && same_ip_count(&st, ip) >= inner.cfg.max_per_ip)
                }))
                || (onion
                    && onion_inbound_count(&st) >= onion_inbound_cap(inner.cfg.max_inbound)
                    && !evict_inbound(&inner, &mut st, true))
                || (inbound_count(&st) >= inner.cfg.max_inbound
                    && !evict_inbound(&inner, &mut st, false));
            if over {
                log::debug!("{addr}: inbound limit reached at registration");
                return;
            }
        }
        // An address fetch (a seed) is not promoted: a seed operator must not
        // gain a place in every joiner's *tried* table (F32-6).
        if !inbound && kind != ConnKind::AddrFetch {
            st.addrman.good(&addr, unix_now());
            // A feeler (docs/p2p.md §9): the handshake was the test; the
            // address is now in *tried* (or its collision settled). Closed
            // without registering: no messages, no slot.
            if st.connman.feeler.as_ref() == Some(&addr) {
                log::debug!("feeler to {addr} answered");
                return;
            }
        }
        // An inbound peer's own address. Only its own (F32-8): the IP must be
        // the connection's, or it is an onion address arriving through our
        // hidden service (from loopback). Anything else would let every
        // handshake plant a third party's address, around the address rate.
        let mut addr_known = HashSet::new();
        if let Some(listen) = theirs.listen.clone().map(NetAddr::canonical) {
            let own = match listen.ip() {
                Some(ip) => !proxied && addr.ip() == Some(ip),
                None => {
                    kind == ConnKind::OnionInbound
                        || (kind == ConnKind::Inbound && loopback_is_tor(&inner.cfg, &addr))
                }
            };
            if inbound && own && (listen.is_routable() || inner.cfg.allow_private) {
                st.addrman.add(listen.clone(), &addr, unix_now());
                addr_known.insert(listen);
            }
        }
        let now = Instant::now();
        let mut addr_gate = AddrGate::new(now);
        if asks_addresses {
            addr_gate.getaddr_sent(now);
        }
        // Transaction requests are kept per network class (RT3 F6): an
        // onion peer's requests share no tracker state with clearnet ones.
        // Tor is how the connection came (RT4): a proxied one, our hidden
        // service's listener, or the legacy setup forwarding the hidden
        // service to the P2P port (a loopback inbound, `loopback_is_tor`).
        let class = u8::from(via_tor || addr.is_onion() || kind == ConnKind::OnionInbound);
        st.tx_tracker.register_peer(id, class);
        st.peers.insert(
            id,
            Peer {
                addr: addr.clone(),
                kind,
                inbound,
                proxied,
                protocol: theirs.protocol,
                out: tx_out,
                answers: tx_answers,
                ping_written: ping_written.clone(),
                bulk: tx_bulk,
                kill: kill.clone(),
                replies: replies.clone(),
                relay_txs: theirs.relay_txs && kind.relays_txs(),
                addr_relay,
                listen: theirs.listen.clone().map(NetAddr::canonical),
                height: theirs.height,
                score: 0,
                limits: inner.cfg.peer_limits.clone(),
                answered_getaddr: false,
                addr_gate,
                addr_known,
                inv_queue: Vec::new(),
                next_inv: now,
                announced_to: HashSet::new(),
                known_txs: HashSet::new(),
                recent_inv: VecDeque::new(),
                owed_key: owed_key(
                    &addr,
                    kind.is_inbound() && via_tor || kind == ConnKind::OnionInbound,
                ),
                ping: None,
                min_ping: None,
                last_ping: now,
                last_recv: now,
                blocks_in_flight: 0,
                bytes_in_flight: 0,
                headers_requested: None,
                headers_grace: VecDeque::new(),
                headers_busy: false,
                headers_pending: false,
                unknown_upgrades: 0,
                connected_at: now,
                evicted: false,
                last_new_tip: None,
                last_block: None,
                last_tx: None,
                version_tip: theirs.tip,
                known_tip: theirs.tip,
                known_work: 0,
                announced: our_tip,
            },
        );
    }
    log::info!(
        "connected {} peer {addr} (height {})",
        match kind {
            ConnKind::Inbound => "inbound",
            ConnKind::OnionInbound => "onion inbound",
            ConnKind::FullRelay => "outbound",
            ConnKind::BlockRelay => "block-relay-only outbound",
            ConnKind::AddrFetch => "address-fetch",
        },
        theirs.height
    );
    let writer_task = tokio::spawn(write_loop(
        writer,
        WriterQueues {
            control: rx_out,
            answers: rx_answers,
            bulk: rx_bulk,
        },
        replies.clone(),
        ping_written.clone(),
    ));
    if asks_addresses {
        inner.send_now(id, Message::GetAddr);
    }
    if let Some(listen) = our_listen.filter(|_| addr_relay) {
        advertise_self(&inner, id, listen);
    }
    // Ask for headers if the peer claims a greater height, or names a best
    // header we cannot place on our best header chain: an equal-height
    // rival, or a shorter branch that may be heavier (fork choice is by work,
    // not height: W4-SYNC, RT-LAB F1). One request per connection; an empty
    // or non-advancing answer lowers the peer's claimed height to ours, so a
    // fake tip is not asked about again (docs/p2p.md §6). An address fetch
    // is for addresses only.
    if kind != ConnKind::AddrFetch && (theirs.height > height || !knows_tip(&inner, &theirs.tip)) {
        inner.request_headers(id).await;
    }
    // A tip connected since the snapshot our `Version` came from (the
    // announcer ran before this peer was registered, RT-SYNC F-B).
    announce_tip(&inner);
    // A host that reconnects within `OWED_WINDOW` gets what its last
    // connection was owed (RT4): its unflushed announcements and the ones
    // it was told lately but did not ask for, still pooled, in a fresh
    // random order. Never the pool: a whole-pool re-announcement, in the
    // pool's fixed order, named the node and cost a pool of bandwidth per
    // handshake. Not for inbound peers through Tor (no stable host).
    let owed = {
        let mut st = inner.state();
        st.peers
            .get(&id)
            .and_then(|p| p.owed_key.clone())
            .map(|k| st.take_owed(&k))
            .unwrap_or_default()
    };
    if !owed.is_empty() {
        let inner2 = inner.clone();
        tokio::spawn(async move {
            let mut ids: Vec<Hash> = inner2
                .with_chain(move |c| {
                    owed.into_iter()
                        .filter(|id| c.mempool().contains(id))
                        .collect()
                })
                .await;
            shuffle(&mut ids, &mut inner2.state().rng);
            inner2.announce_to(id, ids);
        });
    }

    // Read loop. Messages whose handling needs a chain command go to the
    // peer's slow lane; the loop itself never waits for the chain (F34-1).
    let lane = SlowLane::start(&inner, id);
    loop {
        tokio::select! {
            _ = kill.notified() => break,
            frame = tokio::time::timeout(IDLE_TIMEOUT, reader.recv()) => {
                let frame = match frame {
                    Err(_) => { log::debug!("{addr}: idle timeout"); break; }
                    Ok(Err(TransportError::Io(_))) => break,
                    // Not attributable: anyone on the path can flip a bit, and
                    // a ban would let them cut honest peers apart for 24 h
                    // (docs/p2p.md §10, dossier 30 T-2). Disconnect only.
                    Ok(Err(TransportError::Decrypt)) => {
                        inner.state().transport_failures += 1;
                        log::debug!("{addr}: a frame failed to decrypt; disconnecting (not scored)");
                        break;
                    }
                    Ok(Err(e)) => { inner.misbehave(id, score::PROTOCOL, &format!("transport: {e}")); break; }
                    Ok(Ok(f)) => f,
                };
                // Rate limits. Every message counts against the message budget.
                let over = {
                    let mut st = inner.state();
                    let now = Instant::now();
                    match st.peers.get_mut(&id) {
                        Some(p) => {
                            p.last_recv = now;
                            !p.limits.messages.take(1.0, now)
                        }
                        None => break,
                    }
                };
                if over {
                    inner.misbehave(id, score::RATE, "rate limit");
                    continue;
                }
                // A message type of a later protocol version (P0-8): ignored,
                // not penalized, but charged against the byte budget like
                // any unsolicited message (and the message budget above).
                if frame.first().is_some_and(|&t| !is_known_type(t)) {
                    let over = {
                        let mut st = inner.state();
                        let now = Instant::now();
                        match st.peers.get_mut(&id) {
                            Some(p) => !p.limits.bytes.take(frame.len() as f64, now),
                            None => break,
                        }
                    };
                    if over {
                        inner.misbehave(id, score::RATE, "byte rate limit");
                    } else {
                        log::debug!("{addr}: ignored a message of unknown type {}", frame[0]);
                    }
                    continue;
                }
                let len = frame.len();
                let msg = match Message::decode(&frame) {
                    Ok(m) => m,
                    Err(e) => { inner.misbehave(id, score::PROTOCOL, &format!("malformed message: {e:?}")); break; }
                };
                // No transaction relay on a block-relay-only connection: we
                // said so (`relay_txs = false`), so the peer breaks the
                // protocol (Bitcoin Core disconnects). An address fetch
                // ignores it.
                if is_tx_message(&msg) {
                    match kind {
                        ConnKind::BlockRelay => {
                            inner.misbehave(id, score::UNSOLICITED, "transaction message on a block-relay-only connection");
                            continue;
                        }
                        ConnKind::AddrFetch => continue,
                        _ => {}
                    }
                }
                // The byte budget limits what a peer sends on its own initiative.
                // Answers to our own requests are exempt: a block we requested
                // (bounded by our request window, BLOCKS_IN_FLIGHT blocks of at
                // most MAX_BLOCK_BYTES) and the headers we asked for (one
                // outstanding request, at most MAX_HEADERS headers). Charging
                // them would drop the data we asked for during a sync.
                let requested = requested_by_us(&inner, id, &msg);
                let over = !requested && {
                    let mut st = inner.state();
                    let now = Instant::now();
                    match st.peers.get_mut(&id) {
                        Some(p) => !p.limits.bytes.take(frame.len() as f64, now),
                        None => break,
                    }
                };
                if over {
                    inner.misbehave(id, score::RATE, "byte rate limit");
                    continue;
                }
                if !is_slow(&msg) {
                    handle(&inner, id, msg).await;
                    continue;
                }
                // Relay budgets (the PX share among them) are charged when
                // the lane handles a message, after the checks that drop it
                // for free: never for a message the lane dropped (RTW2A-1,
                // RTW2A-4). The lane's own bounds limit what waits.
                let kind = msg.kind();
                let large_tx = matches!(msg, Message::Tx(_)) && len > SMALL_RELAY_BYTES;
                match lane.push(msg, len) {
                    Pushed::Queued => {}
                    Pushed::Dropped { charge: true } => {
                        inner.misbehave(id, score::RATE, "slow lane full");
                    }
                    Pushed::Dropped { charge: false } => {
                        log::debug!("{addr}: slow lane full; {kind} dropped");
                        // A large answer dropped here by this node's own
                        // lane: its request, when it times out, is asked
                        // once more, and fewer are asked of this peer at
                        // once (`tx_requests`, RT3 F1b).
                        if large_tx {
                            inner
                                .state()
                                .tx_tracker
                                .lane_dropped(id, len, Instant::now());
                        }
                    }
                }
            }
        }
    }

    // Cleanup. The lane task stops before its next message.
    drop(lane);
    writer_task.abort();
    let gone = {
        let mut st = inner.state();
        let now = Instant::now();
        let gone = st.peers.remove(&id).map(|p| {
            // What it was owed, kept for its host (RT4).
            if let Some(key) = p.owed_key.clone() {
                let mut ids: Vec<Hash> = p.inv_queue.clone();
                ids.extend(
                    p.recent_inv
                        .iter()
                        .filter(|(_, t)| now.duration_since(*t) <= OWED_WINDOW)
                        .map(|(h, _)| *h),
                );
                let mut seen = HashSet::new();
                ids.retain(|h| seen.insert(*h));
                ids.truncate(OWED_IDS);
                st.keep_owed(key, ids, now);
            }
            p.addr
        });
        replies.closed();
        st.dandelion.peer_disconnected(id);
        st.block_requests.retain(|_, (p, _)| *p != id);
        // Its transaction records go; the ids it held are asked of the next
        // announcers now, not after a timeout (`tx_requests`).
        let mut out = Actions::default();
        st.tx_tracker.peer_gone(id, now, &mut out);
        inner.apply_tx_actions(&mut st, out, now);
        gone
    };
    // Logged outside the state lock (RT2 F8).
    if let Some(addr) = gone {
        log::info!("disconnected peer {addr}");
    }
}

/// Sends a peer's queued messages: control messages (pongs, headers, relay)
/// strictly before queued `Block` frames, so a pong never waits behind a
/// batch of blocks (R8-11). A frame already being written is not interrupted.
/// A written `Tx` (only `GetTx` answers are `Tx` frames) returns its room
/// to the peer's [`ReplyQueue`].
///
/// `GetTx` answers (`Tx`, and the `NotFound` that ends them) have a queue of
/// their own, written after the control messages (RT3 F3): pings and pongs
/// queued behind `Tx` answers on a slow link waited longer than the pong
/// timeout. When a ping is written is recorded (`ping_written`): the pong
/// timeout counts from then.
async fn write_loop<W: AsyncWrite + Unpin>(
    mut writer: FrameWriter<W>,
    mut q: WriterQueues,
    replies: Arc<ReplyQueue>,
    ping_written: Arc<Mutex<Option<(u64, Instant)>>>,
) {
    loop {
        let msg = tokio::select! {
            biased;
            m = q.control.recv() => m,
            m = q.answers.recv() => m,
            m = q.bulk.recv() => m,
        };
        let Some(msg) = msg else { break };
        if writer.send(&msg.encode()).await.is_err() {
            break;
        }
        match msg {
            Message::Tx(_) => replies.written(),
            Message::Ping(n) => {
                if let Ok(mut w) = ping_written.lock() {
                    *w = Some((n, Instant::now()));
                }
            }
            _ => {}
        }
    }
}

/// A peer's outgoing queues, highest priority first.
struct WriterQueues {
    /// Everything not below, pings and pongs among them.
    control: mpsc::Receiver<Message>,
    /// `GetTx` answers.
    answers: mpsc::Receiver<Message>,
    /// `Block` frames.
    bulk: mpsc::Receiver<Message>,
}

/// Whether `tip` is on our best header chain as far as the published snapshot
/// shows without a chain command: our best header, our connected tip, or an
/// entry of our locator (genesis included). Otherwise a peer naming it may
/// be on a branch we lack (W4-SYNC).
fn knows_tip(inner: &Inner, tip: &Hash) -> bool {
    let s = inner.summary.load();
    *tip == s.best_header_id || *tip == s.tip_id || s.locator.contains(tip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::handshake;

    /// R8-11: control messages queued behind block frames are written first.
    #[tokio::test]
    async fn control_messages_overtake_queued_block_frames() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let t = Duration::from_secs(5);
        let (ours, theirs) = tokio::join!(
            handshake(a, true, 7, &[3; 32], t),
            handshake(b, false, 7, &[3; 32], t)
        );
        let ((_, writer), (mut reader, _)) = (ours.unwrap(), theirs.unwrap());
        let (control_tx, control_rx) = mpsc::channel(OUTBOX);
        let (bulk_tx, bulk_rx) = mpsc::channel(BULK_OUTBOX);
        let (answers_tx, answers_rx) = mpsc::channel(ANSWERS_OUTBOX);
        for i in 0..4u8 {
            bulk_tx.try_send(Message::Block(vec![i; 1000])).unwrap();
        }
        // RT3 F3: pings and pongs overtake queued transaction answers too.
        answers_tx.try_send(Message::Tx(vec![1; 1000])).unwrap();
        answers_tx.try_send(Message::Tx(vec![2; 1000])).unwrap();
        control_tx.try_send(Message::Pong(9)).unwrap();
        control_tx.try_send(Message::Ping(10)).unwrap();
        let written = Arc::new(Mutex::new(None));
        let task = tokio::spawn(write_loop(
            writer,
            WriterQueues {
                control: control_rx,
                answers: answers_rx,
                bulk: bulk_rx,
            },
            Arc::new(ReplyQueue::default()),
            written.clone(),
        ));
        let mut got = Vec::new();
        for _ in 0..8 {
            got.push(Message::decode(&reader.recv().await.unwrap()).unwrap());
        }
        assert_eq!(got[0], Message::Pong(9));
        assert_eq!(got[1], Message::Ping(10));
        assert_eq!(got[2], Message::Tx(vec![1; 1000]));
        assert_eq!(got[3], Message::Tx(vec![2; 1000]));
        assert!(got[4..]
            .iter()
            .enumerate()
            .all(|(i, m)| *m == Message::Block(vec![i as u8; 1000])));
        assert_eq!(written.lock().unwrap().map(|(n, _)| n), Some(10));
        drop((control_tx, bulk_tx, answers_tx));
        task.await.unwrap();
    }
}
