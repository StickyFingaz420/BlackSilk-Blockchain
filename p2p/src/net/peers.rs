//! Peer management: misbehavior scoring and bans, inbound accept limits and
//! eviction, outbound connections and the outbound maintenance (anchors,
//! block-relay-only connections, feelers, seed address fetches, stale-tip
//! rotation; docs/p2p.md §9, `crate::connman`).

use super::config::NetConfig;
use super::conn::{loopback_is_tor, run_connection};
use super::state::{unix_now, HeaderBatch, Inner, PendingHandshake, State, ONION_HANDSHAKE_GROUP};
use crate::addr::{peer_key, NetAddr};
use crate::addrman::BanList;
use crate::connman::{
    self, next_feeler, select_inbound_to_evict, select_outbound_to_evict, ConnKind,
    EvictionCandidate, OutboundCandidate, StaleTip, SEED_FALLBACK_OUTBOUND,
};
use crate::dandelion::PeerId;
use crate::limits::{BAN_SECS, BAN_THRESHOLD};
use crate::socks5;
use blacksilk_consensus::ChainParams;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A seed is asked for addresses at most this often.
const SEED_RETRY: Duration = Duration::from_secs(30);

/// A dial attempt is remembered this long (longer than every backoff).
const LAST_ATTEMPT_KEEP: Duration = Duration::from_secs(600);

impl Inner {
    /// Adds a misbehavior score; at the threshold the peer is disconnected and,
    /// where meaningful, its IP banned (docs/p2p.md §10).
    pub(super) fn misbehave(&self, peer: PeerId, points: u32, reason: &str) {
        let mut st = self.state();
        self.penalize(&mut st, peer, points, reason);
    }

    /// `misbehave` on a locked state. Returns false if the peer is gone.
    fn penalize(&self, st: &mut State, peer: PeerId, points: u32, reason: &str) -> bool {
        let Some(p) = st.peers.get_mut(&peer) else {
            return false;
        };
        p.score = p.score.saturating_add(points);
        log::debug!(
            "peer {} misbehaved (+{points}, {}): {reason}",
            p.addr,
            p.score
        );
        if p.score < BAN_THRESHOLD {
            return true;
        }
        log::info!("disconnecting peer {} for misbehavior: {reason}", p.addr);
        p.kill.notify_one();
        let (addr, proxied) = (p.addr.clone(), p.proxied);
        st.misbehaving_disconnects += 1;
        self.ban_addr(st, &addr, proxied);
        true
    }

    /// Bans the IP of `addr` (unless it is proxied, or loopback in
    /// `allow_private` mode) and disconnects every live peer from that IP: a
    /// ban must not leave the offender's other connections open. An IPv6
    /// ban covers the address's /64 ([`peer_key`]).
    fn ban_addr(&self, st: &mut State, addr: &NetAddr, proxied: bool) {
        let Some(ip) = addr.ip() else { return };
        let local = ip.is_loopback() && self.cfg.allow_private;
        if proxied || local {
            return;
        }
        st.bans.ban(ip, unix_now() + BAN_SECS);
        st.bans_dirty = true;
        let key = peer_key(ip);
        for p in st.peers.values() {
            if !p.proxied && p.addr.ip().map(peer_key) == Some(key) {
                p.kill.notify_one();
            }
        }
    }

    /// `misbehave` for work that finished after its sender may have
    /// disconnected: a violation worth a ban on its own still bans the address.
    /// One lock for the check and the penalty, so a sender leaving in between
    /// cannot escape the ban.
    pub(super) fn misbehave_departed(&self, batch: &HeaderBatch, points: u32, reason: &str) {
        let mut st = self.state();
        if self.penalize(&mut st, batch.peer, points, reason) || points < BAN_THRESHOLD {
            return;
        }
        log::info!(
            "banning departed peer {} for misbehavior: {reason}",
            batch.addr
        );
        st.misbehaving_disconnects += 1;
        self.ban_addr(&mut st, &batch.addr, batch.proxied);
    }
}

// ---------------------------------------------------------------- connections

/// Concurrent inbound handshakes (accepted, not yet registered), at most: in
/// total a quarter of `max_inbound` (at least one), and per group (IPv4 /16,
/// IPv6 /32) a quarter of that (at least one). RTW3-3: before, handshakes
/// counted against `max_inbound` and made room by evicting registered peers,
/// so connections that never sent a byte pushed honest peers out.
pub(super) fn handshake_caps(max_inbound: usize) -> (usize, usize) {
    let total = (max_inbound / 4).max(1);
    (total, (total / 4).max(1))
}

/// Closes the oldest pending inbound handshake (of `group` only, if given),
/// releasing its place at once. Returns whether there was one.
fn evict_handshake(st: &mut State, group: Option<&[u8]>) -> bool {
    let oldest = st
        .handshakes
        .iter()
        .filter(|(_, h)| group.is_none_or(|g| h.group == g))
        .min_by_key(|(id, h)| (h.started, **id))
        .map(|(id, _)| *id);
    let Some(id) = oldest else { return false };
    let h = release_handshake(st, id).expect("present");
    log::debug!("inbound handshakes full: closing the oldest");
    h.kill.notify_one();
    true
}

/// Removes pending handshake `id` from the state and the per-IP counts.
fn release_handshake(st: &mut State, id: u64) -> Option<PendingHandshake> {
    let h = st.handshakes.remove(&id)?;
    if let Some(ip) = h.ip {
        if let Some(n) = st.handshaking_ip.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                st.handshaking_ip.remove(&ip);
            }
        }
    }
    Some(h)
}

/// Accepts inbound connections on `listener`: the P2P listener, or with
/// `onion` the onion listener (`NetConfig::onion_listen`), whose connections
/// all come from the Tor daemon: no ban or per-IP limit is checked for them,
/// and their handshakes are bounded as one group (`ONION_HANDSHAKE_GROUP`).
pub(super) async fn accept_loop(inner: Arc<Inner>, listener: TcpListener, onion: bool) {
    loop {
        let (stream, remote) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                log::warn!("accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        // Canonical (an IPv4 peer on a dual-stack listener arrives as
        // ::ffff:a.b.c.d): bans and per-IP limits key on one form per host.
        let addr = NetAddr::Ip(remote).canonical();
        let Some(ip) = addr.ip() else { continue };
        // Per-IP limits key on the IPv4 address or the IPv6 /64 (W6).
        let key = peer_key(ip);
        let slot = {
            let mut st = inner.state();
            // Connections still in their handshake count against the per-IP
            // limit like registered ones: otherwise concurrent handshakes
            // bypass it.
            let same_ip =
                same_ip_count(&st, ip) + st.handshaking_ip.get(&key).copied().unwrap_or(0);
            if inner.cfg.max_inbound == 0
                || (!onion
                    && (st.bans.is_banned(&ip, unix_now())
                        || (!inner.cfg.allow_private && same_ip >= inner.cfg.max_per_ip)))
            {
                continue; // drop the socket
            }
            // Handshakes are bounded on their own and never evict a
            // registered peer (RTW3-3): a full group, then a full total,
            // gives way oldest first. Room among the registered peers is
            // made at registration (`conn::run_connection`), for a peer
            // that completed its handshake.
            let group = if onion {
                ONION_HANDSHAKE_GROUP.to_vec()
            } else {
                st.addrman.bucket_group(&addr)
            };
            let (total, per_group) = handshake_caps(inner.cfg.max_inbound);
            let in_group = st.handshakes.values().filter(|h| h.group == group).count();
            if in_group >= per_group {
                evict_handshake(&mut st, Some(&group));
            }
            if st.handshakes.len() >= total {
                evict_handshake(&mut st, None);
            }
            let id = st.next_handshake;
            st.next_handshake += 1;
            let kill = Arc::new(Notify::new());
            st.handshakes.insert(
                id,
                PendingHandshake {
                    started: Instant::now(),
                    ip: (!onion).then_some(key),
                    group,
                    kill: kill.clone(),
                },
            );
            if !onion {
                *st.handshaking_ip.entry(key).or_default() += 1;
            }
            HandshakeSlot {
                inner: inner.clone(),
                id,
                kill,
                released: false,
                local: stream.local_addr().ok(),
            }
        };
        let _ = stream.set_nodelay(true);
        let kind = if onion {
            ConnKind::OnionInbound
        } else {
            ConnKind::Inbound
        };
        tokio::spawn(run_connection(
            inner.clone(),
            stream,
            addr,
            kind,
            onion,
            Some(slot),
        ));
    }
}

/// Registered inbound peers, except those being evicted.
pub(super) fn inbound_count(st: &State) -> usize {
    st.peers
        .values()
        .filter(|p| p.inbound && !p.evicted)
        .count()
}

/// Registered onion inbound peers (`ConnKind::OnionInbound`), except those
/// being evicted.
pub(super) fn onion_inbound_count(st: &State) -> usize {
    st.peers
        .values()
        .filter(|p| p.kind == ConnKind::OnionInbound && !p.evicted)
        .count()
}

/// Registered non-proxied peers from `ip`'s IPv4 address or IPv6 /64.
pub(super) fn same_ip_count(st: &State, ip: IpAddr) -> usize {
    let key = peer_key(ip);
    st.peers
        .values()
        .filter(|p| !p.proxied && p.addr.ip().map(peer_key) == Some(key))
        .count()
}

/// Disconnects one registered inbound peer to make room for a newly
/// registering one, if `connman::select_inbound_to_evict` finds one that is
/// not protected; among onion inbound peers only if `onion_only` (their
/// class is full). Returns whether it did. Onion peers (through our hidden
/// service) are the disadvantaged class. Groups are keyed with the address
/// table's secret key, so peers cannot tell which groups are protected.
pub(super) fn evict_inbound(inner: &Inner, st: &mut State, onion_only: bool) -> bool {
    let candidates: Vec<EvictionCandidate> = st
        .peers
        .iter()
        .filter(|(_, p)| {
            p.inbound && !p.evicted && (!onion_only || p.kind == ConnKind::OnionInbound)
        })
        .map(|(id, p)| EvictionCandidate {
            id: *id,
            keyed_group: st.addrman.keyed_group(&st.addrman.bucket_group(&p.addr)),
            connected: p.connected_at,
            disadvantaged: p.kind == ConnKind::OnionInbound || loopback_is_tor(&inner.cfg, &p.addr),
            min_ping: p.min_ping,
            last_tx: p.last_tx,
            last_block: p.last_block,
            relay_txs: p.relay_txs,
        })
        .collect();
    let Some(victim) = select_inbound_to_evict(&candidates) else {
        return false;
    };
    let p = st.peers.get_mut(&victim).expect("candidate");
    log::debug!("inbound full: evicting peer {}", p.addr);
    p.evicted = true;
    p.kill.notify_one();
    true
}

/// An inbound connection's place among the pending handshakes, from accept
/// until it is registered or fails. Released under the state lock at
/// registration; otherwise on drop (never dropped while the state lock is
/// held). `kill` is notified when the handshake is evicted (RTW3-3).
pub(super) struct HandshakeSlot {
    pub(super) inner: Arc<Inner>,
    id: u64,
    pub(super) kill: Arc<Notify>,
    released: bool,
    /// The local endpoint the connection was accepted on (its trickle key).
    pub(super) local: Option<SocketAddr>,
}

impl HandshakeSlot {
    pub(super) fn release(&mut self, st: &mut State) {
        if !std::mem::replace(&mut self.released, true) {
            release_handshake(st, self.id);
        }
    }
}

impl Drop for HandshakeSlot {
    fn drop(&mut self) {
        if !self.released {
            let inner = self.inner.clone();
            let mut st = inner.state();
            self.release(&mut st);
        }
    }
}

/// Dials `addr` for a connection of `kind`. The address stays in
/// `connecting` from the dial until the connection ends, registered or not:
/// it is never dialed twice at once. A registered outbound peer is therefore
/// in both `connecting` and the peer map; [`pending_dials`] counts it once
/// (RTW3-2). An address fetch (a seed) is not an attempt on a table entry.
pub(super) async fn connect_outbound(inner: Arc<Inner>, addr: NetAddr, kind: ConnKind) {
    let addr = addr.canonical();
    {
        let mut st = inner.state();
        if st.connecting.contains_key(&addr) {
            return;
        }
        st.connecting.insert(addr.clone(), kind);
        if kind != ConnKind::AddrFetch {
            st.last_attempt.insert(addr.clone(), Instant::now());
            // Counted when made: a success resets it (`AddrMan::good`).
            st.addrman.attempt(&addr, unix_now());
        }
    }
    let proxied = inner.cfg.proxy.is_some();
    let result = tokio::time::timeout(CONNECT_TIMEOUT, async {
        match inner.cfg.proxy {
            Some(proxy) => socks5::connect(proxy, &addr).await,
            None => match &addr {
                NetAddr::Ip(a) => TcpStream::connect(a).await,
                NetAddr::Onion { .. } => Err(std::io::Error::other("onion address needs a proxy")),
            },
        }
    })
    .await;
    match result {
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            run_connection(inner.clone(), stream, addr.clone(), kind, proxied, None).await;
        }
        _ => log::debug!("connect {addr} failed"),
    }
    let mut st = inner.state();
    st.connecting.remove(&addr);
    if st.connman.feeler.as_ref() == Some(&addr) {
        st.connman.feeler = None;
    }
}

/// Our address to advertise on a connection (`Version.listen`): an onion
/// address only over Tor (a proxied outbound connection, or an inbound one
/// through our hidden service: on the onion listener, or from loopback on
/// the P2P listener when there is none and private addresses are not
/// allowed, `loopback_is_tor`), a clearnet address only over clearnet.
/// Advertising one over the other would link the node's two identities
/// (I3-2).
pub(super) fn advertised_listen(
    cfg: &NetConfig,
    addr: &NetAddr,
    inbound: bool,
    proxied: bool,
) -> Option<NetAddr> {
    let public = cfg.public_address.as_ref()?;
    let via_tor = proxied || (inbound && loopback_is_tor(cfg, addr));
    (public.is_onion() == via_tor).then(|| public.clone())
}

/// Dials of `kind` in progress that are not yet registered outbound peers,
/// feelers excluded: `connecting` also holds every registered outbound
/// peer's address until its connection ends (`connect_outbound`), and
/// counting those twice left a node refilling lost outbound slots only below
/// half its target (RTW3-2).
fn pending_dials(
    connecting: &HashMap<NetAddr, ConnKind>,
    registered: &HashSet<NetAddr>,
    feeler: Option<&NetAddr>,
    kind: ConnKind,
) -> usize {
    connecting
        .iter()
        .filter(|(a, k)| **k == kind && !registered.contains(*a) && Some(*a) != feeler)
        .count()
}

/// Why an address is not dialed now: connected or being dialed, our own,
/// banned, unroutable, of a group already taken (outside `allow_private`),
/// an onion without a proxy, or tried in the last minute.
struct Dialable<'a> {
    cfg: &'a NetConfig,
    local_addr: Option<std::net::SocketAddr>,
    connected: &'a HashSet<NetAddr>,
    connecting: &'a HashMap<NetAddr, ConnKind>,
    bans: &'a BanList,
    last_attempt: &'a HashMap<NetAddr, Instant>,
    now: Instant,
    unix: u64,
}

impl Dialable<'_> {
    fn skip(&self, a: &NetAddr, to_connect: &[Dial], groups: &HashSet<Vec<u8>>) -> bool {
        self.skip_test(a, to_connect)
            || (!self.cfg.allow_private && groups.contains(&a.group()))
            || self
                .last_attempt
                .get(a)
                .is_some_and(|t| self.now.duration_since(*t) < Duration::from_secs(60))
    }

    /// For a feeler testing a *tried* collision's occupant (RTW3-9): the
    /// group and backoff filters do not apply. The occupant's group may be
    /// one of our outbound peers' (a regular dial would skip it forever),
    /// and a recent failed attempt is exactly what the test must repeat
    /// before the occupant can be replaced. Everything else does.
    fn skip_test(&self, a: &NetAddr, to_connect: &[Dial]) -> bool {
        let cfg = self.cfg;
        self.connected.contains(a)
            || self.connecting.contains_key(a)
            || to_connect.iter().any(|(x, _)| x == a)
            || Some(a) == cfg.public_address.as_ref()
            || a.ip().is_some_and(|ip| self.bans.is_banned(&ip, self.unix))
            || (!cfg.allow_private && !a.is_routable())
            || (a.is_onion() && cfg.proxy.is_none())
            || self.local_addr.is_some_and(|l| a == &NetAddr::Ip(l))
    }
}

/// A dial this maintenance round decided: the address and the kind of
/// connection.
type Dial = (NetAddr, ConnKind);

/// Keeps the outbound connections (docs/p2p.md §9), every 2 s:
/// - manual peers are reconnected (full-relay);
/// - anchors saved at the last shutdown are dialed first, once, as
///   block-relay-only connections;
/// - free full-relay slots, then free block-relay-only slots
///   (`NetConfig::block_relay_only`), are filled from the address table,
///   one per group across both;
/// - seeds are asked for addresses (one-shot address fetches, not peers)
///   when the table is empty, when fewer than two full-relay outbound peers
///   were up for `seed_fallback_after`, or while the tip is stale;
/// - while the tip is stale, one extra full-relay connection every
///   `stale_check_interval`, and when there are more full-relay peers than
///   the target, the one that brought the least is disconnected (not
///   banned): the oldest last validated new tip, never the claimed height
///   (RTW3-4);
/// - when the full-relay slots are full, a feeler about every
///   `feeler_interval` (Poisson): a short connection that tests a *tried*
///   collision or a *new* address and moves it to *tried* if it answers.
///
/// A registered outbound peer is counted once (RTW3-2, [`pending_dials`]).
pub(super) fn maintain_outbound(inner: &Arc<Inner>) {
    let now = Instant::now();
    let unix = unix_now();
    let cfg = &inner.cfg;
    let tip = inner.summary.load();
    let mut to_connect: Vec<Dial> = Vec::new();
    let mut feeler = None;
    {
        let mut st = inner.state();
        // Attempt times matter for at most a minute (the backoffs below):
        // older ones are dropped, so dialing junk addresses does not grow the
        // map without bound (F32-10).
        st.last_attempt
            .retain(|_, t| now.duration_since(*t) < LAST_ATTEMPT_KEEP);
        st.connman
            .seed_fetches
            .retain(|_, t| now.duration_since(*t) < LAST_ATTEMPT_KEEP);
        st.addrman.resolve_collisions(unix);
        if st.connman.anchors.is_none() {
            st.connman.anchors = Some(match &cfg.data_dir {
                Some(dir) if !cfg.connect_only && cfg.block_relay_only > 0 => {
                    connman::take_anchors(dir)
                }
                _ => Vec::new(),
            });
        }
        let stale = match st.connman.stale.as_mut() {
            Some(s) => s.observe(tip.tip_id, now),
            None => {
                let threshold = cfg.stale_tip_after.unwrap_or_else(|| {
                    connman::stale_threshold(
                        ChainParams::for_network(tip.network).target_block_time,
                    )
                });
                st.connman.stale = Some(StaleTip::new(
                    tip.tip_id,
                    now,
                    threshold,
                    cfg.stale_check_interval,
                ));
                false
            }
        };
        let extra = stale
            && !cfg.connect_only
            && st.connman.stale.as_ref().is_some_and(|s| s.extra_due(now));
        let connected: HashSet<NetAddr> = st.peers.values().map(|p| p.addr.clone()).collect();
        // Manual peers: always reconnect (after a short backoff).
        for a in &cfg.connect {
            if !connected.contains(a)
                && !st.connecting.contains_key(a)
                && st
                    .last_attempt
                    .get(a)
                    .is_none_or(|t| now.duration_since(*t) > Duration::from_secs(10))
            {
                to_connect.push((a.clone(), ConnKind::FullRelay));
            }
        }
        // Outbound peers still up keep their table entries fresh (and a
        // *tried* one is never replaced by test-before-evict).
        let State { peers, addrman, .. } = &mut *st;
        for p in peers
            .values()
            .filter(|p| !p.inbound && p.kind != ConnKind::AddrFetch)
        {
            addrman.connected(&p.addr, unix);
        }
        let registered: HashSet<NetAddr> = st
            .peers
            .values()
            .filter(|p| !p.inbound)
            .map(|p| p.addr.clone())
            .collect();
        let count = |k: ConnKind| st.peers.values().filter(|p| p.kind == k).count();
        let (full, block_relay) = (count(ConnKind::FullRelay), count(ConnKind::BlockRelay));
        let pending = |k| pending_dials(&st.connecting, &registered, st.connman.feeler.as_ref(), k);
        let (pending_full, pending_block_relay) =
            (pending(ConnKind::FullRelay), pending(ConnKind::BlockRelay));
        let target = cfg.max_outbound + usize::from(extra);
        let (free, mut free_block_relay) = if cfg.connect_only {
            (0, 0)
        } else {
            (
                target.saturating_sub(full + pending_full + to_connect.len()),
                cfg.block_relay_only
                    .saturating_sub(block_relay + pending_block_relay),
            )
        };
        // One outbound connection per network group (docs/p2p.md §9): the
        // groups of live and pending outbound connections (address fetches
        // aside: they are short), and of the manual peers and anchors picked
        // below (F32-12), are taken.
        let mut groups: HashSet<Vec<u8>> = st
            .peers
            .values()
            .filter(|p| !p.inbound && p.kind != ConnKind::AddrFetch)
            .map(|p| p.addr.group())
            .chain(
                st.connecting
                    .iter()
                    .filter(|(_, k)| **k != ConnKind::AddrFetch)
                    .map(|(a, _)| a.group()),
            )
            .chain(to_connect.iter().map(|(a, _)| a.group()))
            .collect();
        let anchors = st
            .connman
            .anchors
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default();
        // Seeds are asked when fewer than two full-relay outbound peers have
        // been up for a while.
        let low = full < SEED_FALLBACK_OUTBOUND;
        let low_since = match (low, st.connman.low_outbound_since) {
            (false, _) => None,
            (true, since) => Some(since.unwrap_or(now)),
        };
        st.connman.low_outbound_since = low_since;
        let State {
            addrman,
            rng,
            bans,
            connecting,
            last_attempt,
            connman: conn,
            ..
        } = &mut *st;
        let dialable = Dialable {
            cfg,
            local_addr: inner.local_addr,
            connected: &connected,
            connecting,
            bans,
            last_attempt,
            now,
            unix,
        };
        // Anchors first (W4): the block-relay-only peers this node had when
        // it last shut down, so a restart does not redraw every slot from a
        // table an attacker may have filled.
        for a in anchors {
            if free_block_relay > 0 && !dialable.skip(&a, &to_connect, &groups) {
                log::info!("dialing anchor {a}");
                groups.insert(a.group());
                to_connect.push((a, ConnKind::BlockRelay));
                free_block_relay -= 1;
            }
        }
        // Full-relay slots, then block-relay-only slots, from the table.
        let mut picked_full = 0;
        for (slots, kind) in [
            (free, ConnKind::FullRelay),
            (free_block_relay, ConnKind::BlockRelay),
        ] {
            for _ in 0..slots {
                match addrman.select(rng, unix, false, |a| dialable.skip(a, &to_connect, &groups)) {
                    Some(a) => {
                        // One outbound connection per group, also among the
                        // picks of this round (R8-4).
                        groups.insert(a.group());
                        to_connect.push((a, kind));
                        picked_full += usize::from(kind == ConnKind::FullRelay);
                    }
                    None => break,
                }
            }
        }
        // The extra connection counts as made only once something was
        // dialed for it; otherwise the next round tries again.
        if extra && picked_full > 0 {
            log::info!("tip unchanged for too long: trying an extra outbound peer");
            if let Some(s) = conn.stale.as_mut() {
                s.extra_started(now);
            }
        }
        // Seeds: one-shot address fetches (W7, F32-6): `GetAddr`, then the
        // connection closes. A seed never holds an outbound slot, an anchor
        // or a *tried* entry of the joiner. Each seed at most every
        // SEED_RETRY.
        let want_seeds = !cfg.connect_only
            && (addrman.is_empty()
                || low_since.is_some_and(|t| now.duration_since(t) >= cfg.seed_fallback_after)
                || stale);
        if want_seeds {
            for s in &cfg.seeds {
                let recent = conn
                    .seed_fetches
                    .get(s)
                    .is_some_and(|t| now.duration_since(*t) < SEED_RETRY);
                if !connected.contains(s) && !connecting.contains_key(s) && !recent {
                    conn.seed_fetches.insert(s.clone(), now);
                    to_connect.push((s.clone(), ConnKind::AddrFetch));
                }
            }
        }
        // Feelers (W5), only when every full-relay slot is taken: the regular
        // dials test addresses otherwise.
        if !cfg.connect_only && full >= cfg.max_outbound && conn.feeler.is_none() {
            let mean = cfg.feeler_interval;
            let due = *conn
                .next_feeler
                .get_or_insert_with(|| next_feeler(now, mean, rng));
            if now >= due {
                conn.next_feeler = Some(next_feeler(now, mean, rng));
                let skip = |a: &NetAddr| dialable.skip(a, &to_connect, &groups);
                // A collision test ignores the group and backoff filters
                // (RTW3-9, `Dialable::skip_test`).
                let pick = addrman
                    .select_tried_collision(rng)
                    .filter(|a| !dialable.skip_test(a, &to_connect))
                    .or_else(|| addrman.select(rng, unix, true, skip));
                if let Some(a) = pick {
                    log::debug!("feeler to {a}");
                    conn.feeler = Some(a.clone());
                    feeler = Some(a);
                }
            }
        }
        // More full-relay peers than the target (the extra stale-tip peer
        // connected, or manual peers came up): of all discovered full-relay
        // peers, the one whose last validated new tip is oldest goes; if it
        // is too young to have shown one, or has blocks in flight, the
        // rotation waits for it (RTW3-4).
        if full > cfg.max_outbound {
            let candidates: Vec<OutboundCandidate> = st
                .peers
                .iter()
                .filter(|(_, p)| p.kind == ConnKind::FullRelay && !cfg.connect.contains(&p.addr))
                .map(|(id, p)| OutboundCandidate {
                    id: *id,
                    last_new_tip: p.last_new_tip,
                    connected: p.connected_at,
                    blocks_in_flight: p.blocks_in_flight > 0,
                })
                .collect();
            if let Some(v) = select_outbound_to_evict(&candidates, now, cfg.min_connect_time) {
                let p = st.peers.get_mut(&v).expect("candidate");
                log::info!(
                    "rotating out outbound peer {} (last new tip: {})",
                    p.addr,
                    p.last_new_tip.map_or("never".into(), |t| format!(
                        "{} s ago",
                        now.saturating_duration_since(t).as_secs()
                    ))
                );
                p.kill.notify_one();
            }
        }
    }
    for (a, kind) in to_connect {
        tokio::spawn(connect_outbound(inner.clone(), a, kind));
    }
    if let Some(a) = feeler {
        tokio::spawn(connect_outbound(inner.clone(), a, ConnKind::FullRelay));
    }
}

/// Writes the anchors at shutdown (W4): up to `MAX_ANCHORS` of this node's
/// block-relay-only peers (never manual peers or seeds: a seed operator must
/// not hold every joiner's anchors), longest connected first. The next start
/// dials them, as block-relay-only connections, before anything else.
pub(super) fn save_anchors(inner: &Inner) {
    let Some(dir) = &inner.cfg.data_dir else {
        return;
    };
    let mut outbound: Vec<(Instant, NetAddr)> = {
        let st = inner.state();
        st.peers
            .values()
            .filter(|p| {
                p.kind == ConnKind::BlockRelay
                    && !inner.cfg.connect.contains(&p.addr)
                    && !inner.cfg.seeds.contains(&p.addr)
            })
            .map(|p| (p.connected_at, p.addr.clone()))
            .collect()
    };
    outbound.sort();
    let anchors: Vec<NetAddr> = outbound
        .into_iter()
        .map(|(_, a)| a)
        .take(connman::MAX_ANCHORS)
        .collect();
    if let Err(e) = connman::save_anchors(dir, &anchors) {
        log::warn!("saving {}: {e}", connman::ANCHORS_FILE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> NetAddr {
        NetAddr::parse(s).unwrap()
    }

    /// RTW3-2: a registered outbound peer's address is in `connecting` for
    /// its whole session; it is counted once. The feeler is not a dial for a
    /// slot.
    #[test]
    fn pending_dials_count_registered_peers_once() {
        let (p1, p2, dial, feeler) = (
            a("8.8.8.8:1"),
            a("9.9.9.9:1"),
            a("7.7.7.7:1"),
            a("6.6.6.6:1"),
        );
        let full = ConnKind::FullRelay;
        let mut connecting: HashMap<NetAddr, ConnKind> = [&p1, &p2, &dial, &feeler]
            .into_iter()
            .map(|a| (a.clone(), full))
            .collect();
        let registered: HashSet<NetAddr> = [p1, p2].into_iter().collect();
        assert_eq!(
            pending_dials(&connecting, &registered, Some(&feeler), full),
            1
        );
        assert_eq!(pending_dials(&connecting, &registered, None, full), 2);
        assert_eq!(pending_dials(&connecting, &HashSet::new(), None, full), 4);
        // Counted per kind: a block-relay-only dial is not a full-relay one.
        connecting.insert(a("5.5.5.5:1"), ConnKind::BlockRelay);
        assert_eq!(pending_dials(&connecting, &registered, None, full), 2);
        let br = ConnKind::BlockRelay;
        assert_eq!(pending_dials(&connecting, &registered, None, br), 1);
    }

    /// RTW3-9: a feeler testing a *tried* collision's occupant ignores the
    /// group and backoff filters; the regular filters still apply to it
    /// otherwise (connected, banned, unroutable, onion without a proxy).
    #[test]
    fn collision_tests_skip_the_group_and_backoff_filters() {
        let cfg = NetConfig::new(1);
        let occupant = a("8.8.8.8:1");
        let group: HashSet<Vec<u8>> = [a("8.8.9.9:2").group()].into_iter().collect();
        let now = Instant::now() + Duration::from_secs(1000);
        let last_attempt: HashMap<NetAddr, Instant> =
            [(occupant.clone(), now - Duration::from_secs(5))]
                .into_iter()
                .collect();
        let bans = BanList::default();
        let empty = HashMap::new();
        let connected: HashSet<NetAddr> = [a("5.5.5.5:1")].into_iter().collect();
        let d = Dialable {
            cfg: &cfg,
            local_addr: None,
            connected: &connected,
            connecting: &empty,
            bans: &bans,
            last_attempt: &last_attempt,
            now,
            unix: 1_000,
        };
        assert!(d.skip(&occupant, &[], &group), "a regular dial skips it");
        assert!(d.skip(&occupant, &[], &HashSet::new()), "backoff");
        assert!(!d.skip_test(&occupant, &[]), "a collision test does not");
        assert!(d.skip_test(&a("5.5.5.5:1"), &[]), "connected");
        assert!(d.skip_test(&a("10.0.0.1:1"), &[]), "unroutable");
        assert!(
            d.skip_test(&occupant, &[(occupant.clone(), ConnKind::FullRelay)]),
            "being dialed"
        );
        let mut banned = BanList::default();
        banned.ban(occupant.ip().unwrap(), 2_000);
        let d = Dialable { bans: &banned, ..d };
        assert!(d.skip_test(&occupant, &[]), "banned");
    }

    #[test]
    fn handshake_caps_are_a_quarter_and_a_sixteenth() {
        assert_eq!(handshake_caps(64), (16, 4));
        assert_eq!(handshake_caps(12), (3, 1));
        assert_eq!(handshake_caps(3), (1, 1));
        assert_eq!(handshake_caps(0), (1, 1));
    }
}
