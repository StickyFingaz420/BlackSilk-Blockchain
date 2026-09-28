//! One connection: the handshake, registration, the read loop, cleanup and
//! the writer task.

use super::addr_relay::advertise_self;
use super::blocks::SERVE_BLOCKS_PER_REQUEST;
use super::dispatch::{handle, is_slow, requested_by_us, Pushed, SlowLane};
use super::peers::{advertised_listen, inbound_count, same_ip_count, HandshakeSlot};
use super::relay::retry_tx;
use super::state::{unix_now, Inner, Peer, State};
use crate::addr::NetAddr;
use crate::addrman_gate::AddrGate;
use crate::limits::score;
use crate::message::{is_known_type, Message, Version, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION};
use crate::transport::{handshake, FrameReader, FrameWriter, TransportError};
use blacksilk_consensus::Hash;
use rand_chacha::rand_core::RngCore;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, Notify};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const IDLE_TIMEOUT: Duration = Duration::from_secs(180);

/// Control messages queued per peer (everything except `Block`).
const OUTBOX: usize = 64;

/// `Block` frames queued per peer; control messages are sent first (R8-11).
const BULK_OUTBOX: usize = 2 * SERVE_BLOCKS_PER_REQUEST;

/// Frames of unknown message types skipped between `Version` and `Verack`
/// (a later protocol version may negotiate features there).
const HANDSHAKE_UNKNOWN_FRAMES: usize = 8;

async fn recv_msg<R: AsyncRead + Unpin>(
    r: &mut FrameReader<R>,
    timeout: Duration,
) -> Result<Message, String> {
    let frame = tokio::time::timeout(timeout, r.recv())
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;
    Message::decode(&frame).map_err(|e| format!("decode: {e:?}"))
}

pub(super) async fn run_connection<S>(
    inner: Arc<Inner>,
    stream: S,
    addr: NetAddr,
    inbound: bool,
    proxied: bool,
    mut slot: Option<HandshakeSlot>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let nid = inner.cfg.network_id;
    // The session keys also bind the genesis id (R15-3).
    let genesis = inner.genesis_id;
    let (mut reader, mut writer) =
        match handshake(stream, !inbound, nid, &genesis, HANDSHAKE_TIMEOUT).await {
            Ok(x) => x,
            Err(e) => {
                log::debug!("{addr}: transport handshake failed: {e}");
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
    let (height, tip) = {
        let s = inner.summary.load();
        (s.header_height, s.best_header_id)
    };
    let our_listen = advertised_listen(&inner.cfg, &addr, inbound, proxied);
    let ours = Version {
        protocol: PROTOCOL_VERSION,
        network: nid,
        nonce,
        height,
        tip,
        listen: our_listen.clone(),
        relay_txs: true,
    };
    let result = async {
        writer
            .send(&Message::Version(ours).encode())
            .await
            .map_err(|e| e.to_string())?;
        let theirs = match recv_msg(&mut reader, HANDSHAKE_TIMEOUT).await? {
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
            let frame = tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.recv())
                .await
                .map_err(|_| "timeout".to_string())?
                .map_err(|e| e.to_string())?;
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
    }
    .await;
    inner.state().local_nonces.remove(&nonce);
    let theirs = match result {
        Ok(v) => v,
        Err(e) => {
            log::debug!("{addr}: handshake failed: {e}");
            return;
        }
    };

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
        // Re-check the inbound limits at registration, under the same lock
        // as the insertion (the accept-time check counted this connection
        // as handshaking), and a ban that came in during the handshake.
        if inbound {
            let over = addr.ip().is_some_and(|ip| {
                st.bans.is_banned(&ip, unix_now())
                    || (!inner.cfg.allow_private && same_ip_count(&st, ip) >= inner.cfg.max_per_ip)
            }) || inbound_count(&st) >= inner.cfg.max_inbound;
            if over {
                log::debug!("{addr}: inbound limit reached at registration");
                return;
            }
        }
        if !inbound {
            st.addrman.mark_good(&addr, unix_now());
        }
        // An inbound peer's own address. Only its own (F32-8): the IP must be
        // the connection's, or it is an onion address arriving through our
        // hidden service (from loopback). Anything else would let every
        // handshake plant a third party's address, around the address rate.
        let mut addr_known = HashSet::new();
        if let Some(listen) = theirs.listen.clone().map(NetAddr::canonical) {
            let own = match listen.ip() {
                Some(ip) => addr.ip() == Some(ip),
                None => addr.ip().is_some_and(|ip| ip.is_loopback()),
            };
            if inbound && own && (listen.is_routable() || inner.cfg.allow_private) {
                let src = addr.clone();
                let State { addrman, rng, .. } = &mut *st;
                addrman.add(listen.clone(), &src, rng);
                addr_known.insert(listen);
            }
        }
        let now = Instant::now();
        let mut addr_gate = AddrGate::new(now);
        if !inbound {
            addr_gate.getaddr_sent(now);
        }
        st.peers.insert(
            id,
            Peer {
                addr: addr.clone(),
                inbound,
                proxied,
                protocol: theirs.protocol,
                out: tx_out,
                bulk: tx_bulk,
                kill: kill.clone(),
                relay_txs: theirs.relay_txs,
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
                last_ping: now,
                last_recv: now,
                blocks_in_flight: 0,
                bytes_in_flight: 0,
                headers_requested: None,
                headers_grace: None,
                headers_busy: false,
                headers_pending: false,
                unknown_upgrades: 0,
            },
        );
    }
    log::info!(
        "connected {} peer {addr} (height {})",
        if inbound { "inbound" } else { "outbound" },
        theirs.height
    );
    let writer_task = tokio::spawn(write_loop(writer, rx_out, rx_bulk));
    if !inbound {
        inner.send_now(id, Message::GetAddr);
    }
    if let Some(listen) = our_listen {
        advertise_self(&inner, id, listen);
    }
    if theirs.height > height {
        inner.request_headers(id).await;
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

#[cfg(test)]
mod tests {
    use super::*;

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
