//! One connection: the handshake, registration, the read loop, cleanup and
//! the writer task.

use super::addr_relay::advertise_self;
use super::blocks::SERVE_BLOCKS_PER_REQUEST;
use super::dispatch::{handle, is_slow, requested_by_us, Pushed, SlowLane};
use super::maintenance::announce_tip;
use super::peers::{
    advertised_listen, evict_inbound, inbound_count, onion_inbound_count, same_ip_count,
    HandshakeSlot,
};
use super::relay::retry_tx;
use super::state::{unix_now, Inner, Peer};
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
use std::sync::Arc;
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

/// Control messages queued per peer (everything except `Block`).
const OUTBOX: usize = 64;

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
    let (tx_bulk, rx_bulk) = mpsc::channel::<Message>(BULK_OUTBOX);
    let kill = Arc::new(Notify::new());
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
        st.peers.insert(
            id,
            Peer {
                addr: addr.clone(),
                kind,
                inbound,
                proxied,
                protocol: theirs.protocol,
                out: tx_out,
                bulk: tx_bulk,
                kill: kill.clone(),
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
    let writer_task = tokio::spawn(write_loop(writer, rx_out, rx_bulk));
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
                match lane.push(msg, len) {
                    Pushed::Queued => {}
                    Pushed::Dropped { charge: true } => {
                        inner.misbehave(id, score::RATE, "slow lane full");
                    }
                    Pushed::Dropped { charge: false } => {
                        log::debug!("{addr}: slow lane full; {kind} dropped");
                    }
                }
            }
        }
    }

    // Cleanup. The lane task stops before its next message.
    drop(lane);
    writer_task.abort();
    let mut st = inner.state();
    if let Some(p) = st.peers.remove(&id) {
        log::info!("disconnected peer {}", p.addr);
    }
    st.dandelion.peer_disconnected(id);
    st.block_requests.retain(|_, (p, _)| *p != id);
    // Transaction requests this peer owned move to the next announcer now,
    // not after TX_TIMEOUT; announcer queues it leaves empty are dropped.
    let owned: Vec<Hash> = st
        .tx_requests
        .iter()
        .filter(|(_, (p, _))| *p == id)
        .map(|(h, _)| *h)
        .collect();
    let now = Instant::now();
    for h in owned {
        retry_tx(&inner, &mut st, h, id, now);
    }
    st.tx_announcers.retain(|_, q| {
        q.retain(|p| *p != id);
        !q.is_empty()
    });
}

/// Sends a peer's queued messages: control messages (pongs, headers, relay)
/// strictly before queued `Block` frames, so a pong never waits behind a
/// batch of blocks (R8-11). A frame already being written is not interrupted.
async fn write_loop<W: AsyncWrite + Unpin>(
    mut writer: FrameWriter<W>,
    mut control: mpsc::Receiver<Message>,
    mut bulk: mpsc::Receiver<Message>,
) {
    loop {
        let msg = tokio::select! {
            biased;
            m = control.recv() => m,
            m = bulk.recv() => m,
        };
        let Some(msg) = msg else { break };
        if writer.send(&msg.encode()).await.is_err() {
            break;
        }
    }
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

    /// The outbox sizes as specified (docs/p2p.md §10: 64 control messages,
    /// 32 `Block` frames, two full answers to `GetBlocks`), written as
    /// numbers so that a change of them is noticed (mutation run E).
    #[test]
    fn the_outboxes_hold_64_control_messages_and_32_block_frames() {
        assert_eq!((OUTBOX, BULK_OUTBOX), (64, 32));
        assert_eq!(BULK_OUTBOX, 2 * SERVE_BLOCKS_PER_REQUEST);
    }

    /// The connection timeouts as specified (docs/p2p.md §4: the key exchange
    /// within 5 s on clearnet and 10 s over Tor, the handshake within 20 s;
    /// "Liveness": closed after 180 s without a message), written as numbers.
    /// The tests of their behavior bound the observed close from below
    /// exactly; from above only with a margin for load, which a second more
    /// would pass (mutation run E's hand mutants).
    #[test]
    fn the_connection_timeouts_are_the_specified_ones() {
        assert_eq!(KEY_EXCHANGE_TIMEOUT, Duration::from_secs(5));
        assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(10));
        assert_eq!(HANDSHAKE_DEADLINE, Duration::from_secs(20));
        assert_eq!(IDLE_TIMEOUT, Duration::from_secs(180));
    }

    /// A block-relay-only connection never relays transactions, whatever the
    /// peer's `Version` asks (`relay_txs`): the node dials its one table
    /// address block-relay-only and the peer claims `relay_txs = true`
    /// (mutation run E: `theirs.relay_txs && kind.relays_txs()` had no test
    /// with a peer asking for relay on such a connection).
    #[tokio::test]
    async fn a_block_relay_only_peer_relays_no_transactions_whatever_it_asks() {
        use crate::message::{Version, PROTOCOL_VERSION};
        struct ZeroPow;
        impl blacksilk_consensus::PowFunction for ZeroPow {
            fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
                [0; 32]
            }
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = NetAddr::Ip(listener.local_addr().unwrap());
        let dir = std::env::temp_dir().join(format!("bs-p2p-conn-brelay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut table = crate::addrman::AddrMan::with_key([5; 32]);
        table.set_private_groups(true);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(table.add(peer.clone(), &NetAddr::parse("127.0.0.9:1").unwrap(), now));
        table.save(&dir.join("peers.json")).unwrap();
        let p = blacksilk_consensus::ChainParams::regtest();
        let m = blacksilk_chain::manager::ChainManager::open(
            p.clone(),
            blacksilk_tx::params::TxRules::for_chain(&p),
            Arc::new(ZeroPow),
            Box::<blacksilk_chain::store::MemoryStore>::default(),
            [6; 32],
        )
        .unwrap();
        let mut cfg = crate::NetConfig::new(p.network_id);
        cfg.allow_private = true;
        cfg.max_outbound = 0;
        cfg.block_relay_only = 1;
        cfg.tick = Duration::from_millis(50);
        cfg.data_dir = Some(dir.clone());
        let genesis = p.genesis_id();
        let net = crate::Network::start(cfg, Arc::new(std::sync::Mutex::new(m)))
            .await
            .unwrap();
        let (s, _) = tokio::time::timeout(Duration::from_secs(20), listener.accept())
            .await
            .expect("dialed")
            .unwrap();
        let (mut r, mut w) = handshake(s, false, p.network_id, &genesis, Duration::from_secs(5))
            .await
            .unwrap();
        let Message::Version(theirs) = Message::decode(&r.recv().await.unwrap()).unwrap() else {
            panic!("expected version");
        };
        assert!(!theirs.relay_txs, "the node asks for no relay");
        let v = Version {
            protocol: PROTOCOL_VERSION,
            network: p.network_id,
            nonce: 0x1357,
            height: 0,
            tip: genesis,
            listen: None,
            relay_txs: true,
        };
        w.send(&Message::Version(v).encode()).await.unwrap();
        assert!(matches!(
            Message::decode(&r.recv().await.unwrap()).unwrap(),
            Message::Verack
        ));
        w.send(&Message::Verack.encode()).await.unwrap();
        w.send(&Message::Ping(2).encode()).await.unwrap();
        loop {
            if matches!(
                Message::decode(&r.recv().await.unwrap()).unwrap(),
                Message::Pong(2)
            ) {
                break;
            }
        }
        {
            let st = net.inner.state();
            let p = st.peers.values().next().expect("registered");
            assert_eq!(p.kind, ConnKind::BlockRelay);
            assert!(!p.relay_txs, "no transaction relay there");
        }
        drop((r, w, net));
        let _ = std::fs::remove_dir_all(&dir);
    }

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
        for i in 0..4u8 {
            bulk_tx.try_send(Message::Block(vec![i; 1000])).unwrap();
        }
        control_tx.try_send(Message::Pong(9)).unwrap();
        control_tx.try_send(Message::Ping(10)).unwrap();
        let task = tokio::spawn(write_loop(writer, control_rx, bulk_rx));
        let mut got = Vec::new();
        for _ in 0..6 {
            got.push(Message::decode(&reader.recv().await.unwrap()).unwrap());
        }
        assert_eq!(got[0], Message::Pong(9));
        assert_eq!(got[1], Message::Ping(10));
        assert!(got[2..]
            .iter()
            .enumerate()
            .all(|(i, m)| *m == Message::Block(vec![i as u8; 1000])));
        drop((control_tx, bulk_tx));
        task.await.unwrap();
    }
}
