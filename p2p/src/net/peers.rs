//! Peer management: misbehavior scoring and bans, inbound accept limits and
//! eviction, outbound connections and the outbound maintenance (anchors,
//! feelers, stale-tip rotation; docs/p2p.md §9, `crate::connman`).

use super::config::NetConfig;
use super::conn::run_connection;
use super::state::{unix_now, HeaderBatch, Inner, State};
use crate::addr::{peer_key, NetAddr};
use crate::addrman::BanList;
use crate::connman::{
    self, next_feeler, select_inbound_to_evict, select_outbound_to_evict, EvictionCandidate,
    OutboundCandidate, StaleTip,
};
use crate::dandelion::PeerId;
use crate::limits::{BAN_SECS, BAN_THRESHOLD};
use crate::socks5;
use blacksilk_consensus::ChainParams;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A seed is dialed at most this often.
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
pub(super) async fn accept_loop(inner: Arc<Inner>, listener: TcpListener) {
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
            // Connections still in their handshake count like registered
            // ones: otherwise concurrent handshakes bypass both limits.
            let inbound = inbound_count(&st) + st.handshaking;
            let same_ip =
                same_ip_count(&st, ip) + st.handshaking_ip.get(&key).copied().unwrap_or(0);
            if st.bans.is_banned(&ip, unix_now())
                || (!inner.cfg.allow_private && same_ip >= inner.cfg.max_per_ip)
            {
                continue; // drop the socket
            }
            // Inbound full: a registered peer gives way if one is not
            // protected (`connman::select_inbound_to_evict`); else the new
            // connection is dropped.
            if inbound >= inner.cfg.max_inbound && !evict_inbound(&inner, &mut st) {
                continue;
            }
            st.handshaking += 1;
            *st.handshaking_ip.entry(key).or_default() += 1;
            HandshakeSlot {
                inner: inner.clone(),
                ip: key,
                released: false,
            }
        };
        let _ = stream.set_nodelay(true);
        tokio::spawn(run_connection(
            inner.clone(),
            stream,
            addr,
            true,
            false,
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

/// Registered non-proxied peers from `ip`'s IPv4 address or IPv6 /64.
pub(super) fn same_ip_count(st: &State, ip: IpAddr) -> usize {
    let key = peer_key(ip);
    st.peers
        .values()
        .filter(|p| !p.proxied && p.addr.ip().map(peer_key) == Some(key))
        .count()
}

/// Disconnects one registered inbound peer to make room for a new one, if
/// `connman::select_inbound_to_evict` finds one that is not protected.
/// Returns whether it did. Onion peers (through our hidden service, from
/// loopback) are the disadvantaged class. Groups are keyed with the address
/// table's secret key, so peers cannot tell which groups are protected.
fn evict_inbound(inner: &Inner, st: &mut State) -> bool {
    let candidates: Vec<EvictionCandidate> = st
        .peers
        .iter()
        .filter(|(_, p)| p.inbound && !p.evicted)
        .map(|(id, p)| EvictionCandidate {
            id: *id,
            keyed_group: st.addrman.keyed_group(&st.addrman.bucket_group(&p.addr)),
            connected: p.connected_at,
            disadvantaged: !inner.cfg.allow_private
                && p.addr.ip().is_some_and(|ip| ip.is_loopback()),
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

/// An inbound connection's place in the `handshaking` counts, from accept until
/// it is registered or fails. Released under the state lock at registration;
/// otherwise on drop (never dropped while the state lock is held).
pub(super) struct HandshakeSlot {
    pub(super) inner: Arc<Inner>,
    pub(super) ip: IpAddr,
    released: bool,
}

impl HandshakeSlot {
    pub(super) fn release(&mut self, st: &mut State) {
        if std::mem::replace(&mut self.released, true) {
            return;
        }
        st.handshaking = st.handshaking.saturating_sub(1);
        if let Some(n) = st.handshaking_ip.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                st.handshaking_ip.remove(&self.ip);
            }
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

pub(super) async fn connect_outbound(inner: Arc<Inner>, addr: NetAddr) {
    let addr = addr.canonical();
    {
        let mut st = inner.state();
        if !st.connecting.insert(addr.clone()) {
            return;
        }
        st.last_attempt.insert(addr.clone(), Instant::now());
        // Counted when made: a success resets it (`AddrMan::good`).
        st.addrman.attempt(&addr, unix_now());
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
            run_connection(inner.clone(), stream, addr.clone(), false, proxied, None).await;
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
/// through our hidden service, which arrives from loopback), a clearnet
/// address only over clearnet. Advertising one over the other would link the
/// node's two identities (I3-2).
pub(super) fn advertised_listen(
    cfg: &NetConfig,
    addr: &NetAddr,
    inbound: bool,
    proxied: bool,
) -> Option<NetAddr> {
    let public = cfg.public_address.as_ref()?;
    let via_tor = proxied || (inbound && addr.ip().is_some_and(|ip| ip.is_loopback()));
    (public.is_onion() == via_tor).then(|| public.clone())
}

/// Why an address is not dialed now: connected or being dialed, our own,
/// banned, unroutable, of a group already taken (outside `allow_private`),
/// an onion without a proxy, or tried in the last minute.
struct Dialable<'a> {
    inner: &'a Inner,
    connected: &'a HashSet<NetAddr>,
    connecting: &'a HashSet<NetAddr>,
    bans: &'a BanList,
    last_attempt: &'a HashMap<NetAddr, Instant>,
    now: Instant,
    unix: u64,
}

impl Dialable<'_> {
    fn skip(&self, a: &NetAddr, to_connect: &[NetAddr], groups: &HashSet<Vec<u8>>) -> bool {
        let cfg = &self.inner.cfg;
        self.connected.contains(a)
            || self.connecting.contains(a)
            || to_connect.contains(a)
            || Some(a) == cfg.public_address.as_ref()
            || a.ip().is_some_and(|ip| self.bans.is_banned(&ip, self.unix))
            || (!cfg.allow_private && (!a.is_routable() || groups.contains(&a.group())))
            || (a.is_onion() && cfg.proxy.is_none())
            || self
                .last_attempt
                .get(a)
                .is_some_and(|t| self.now.duration_since(*t) < Duration::from_secs(60))
            || self.inner.local_addr.is_some_and(|l| a == &NetAddr::Ip(l))
    }
}

/// Keeps the outbound connections (docs/p2p.md §9), every 2 s:
/// - manual peers are reconnected;
/// - anchors saved at the last shutdown are dialed first, once;
/// - seeds, when the table is empty, no outbound peer is up, or the tip is
///   stale;
/// - free slots are filled from the address table, one per group;
/// - while the tip is stale, one extra outbound connection every
///   `STALE_CHECK_INTERVAL`, and when there are more outbound peers than the
///   target, the one with the lowest chain is disconnected (not banned);
/// - when the outbound slots are full, a feeler about every 2 minutes
///   (Poisson): a short connection that tests a *tried* collision or a *new*
///   address and moves it to *tried* if it answers.
pub(super) fn maintain_outbound(inner: &Arc<Inner>) {
    let now = Instant::now();
    let unix = unix_now();
    let cfg = &inner.cfg;
    let tip = inner.summary.load();
    let mut to_connect = Vec::new();
    let mut feeler = None;
    {
        let mut st = inner.state();
        // Attempt times matter for at most a minute (the backoffs below):
        // older ones are dropped, so dialing junk addresses does not grow the
        // map without bound (F32-10).
        st.last_attempt
            .retain(|_, t| now.duration_since(*t) < LAST_ATTEMPT_KEEP);
        st.addrman.resolve_collisions(unix);
        if st.connman.anchors.is_none() {
            st.connman.anchors = Some(match &cfg.data_dir {
                Some(dir) if !cfg.connect_only => connman::take_anchors(dir),
                _ => Vec::new(),
            });
        }
        let stale = match st.connman.stale.as_mut() {
            Some(s) => s.observe(tip.tip_id, now),
            None => {
                let target = ChainParams::for_network(tip.network).target_block_time;
                st.connman.stale = Some(StaleTip::new(tip.tip_id, now, target));
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
                && !st.connecting.contains(a)
                && st
                    .last_attempt
                    .get(a)
                    .is_none_or(|t| now.duration_since(*t) > Duration::from_secs(10))
            {
                to_connect.push(a.clone());
            }
        }
        // Outbound peers still up keep their table entries fresh (and a
        // *tried* one is never replaced by test-before-evict).
        let State { peers, addrman, .. } = &mut *st;
        for p in peers.values().filter(|p| !p.inbound) {
            addrman.connected(&p.addr, unix);
        }
        let feeler_addr = st.connman.feeler.clone();
        let registered_outbound = st.peers.values().filter(|p| !p.inbound).count();
        let pending = st
            .connecting
            .iter()
            .filter(|a| Some(*a) != feeler_addr.as_ref())
            .count();
        let target = cfg.max_outbound + usize::from(extra);
        let mut free = if cfg.connect_only {
            0
        } else {
            target.saturating_sub(registered_outbound + pending + to_connect.len())
        };
        // One outbound connection per network group (docs/p2p.md §9): the
        // groups of live and pending outbound connections, and of the manual
        // peers, anchors and seeds picked below (F32-12), are taken.
        let mut groups: HashSet<Vec<u8>> = st
            .peers
            .values()
            .filter(|p| !p.inbound)
            .map(|p| p.addr.group())
            .chain(st.connecting.iter().map(|a| a.group()))
            .chain(to_connect.iter().map(|a| a.group()))
            .collect();
        let anchors = st
            .connman
            .anchors
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default();
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
            inner,
            connected: &connected,
            connecting,
            bans,
            last_attempt,
            now,
            unix,
        };
        // Anchors first (W4): the outbound peers this node had when it last
        // shut down, so a restart does not redraw every slot from a table an
        // attacker may have filled.
        for a in anchors {
            if free > 0 && !dialable.skip(&a, &to_connect, &groups) {
                log::info!("dialing anchor {a}");
                groups.insert(a.group());
                to_connect.push(a);
                free -= 1;
            }
        }
        // Seeds: when we know no address, when no outbound connection is up
        // (every known address may be stale or hostile), and when the tip is
        // stale; each at most every SEED_RETRY.
        if free > 0 && (addrman.is_empty() || registered_outbound == 0 || stale) {
            for s in &cfg.seeds {
                if free == 0 {
                    break;
                }
                let recent = last_attempt
                    .get(s)
                    .is_some_and(|t| now.duration_since(*t) < SEED_RETRY);
                if !connected.contains(s) && !connecting.contains(s) && !recent {
                    groups.insert(s.group());
                    to_connect.push(s.clone());
                    free -= 1;
                }
            }
        }
        for _ in 0..free {
            match addrman.select(rng, unix, false, |a| dialable.skip(a, &to_connect, &groups)) {
                Some(a) => {
                    // One outbound connection per group, also among the
                    // picks of this round (R8-4).
                    groups.insert(a.group());
                    to_connect.push(a);
                }
                None => break,
            }
        }
        if extra {
            log::info!("tip unchanged for too long: trying an extra outbound peer");
            if let Some(s) = conn.stale.as_mut() {
                s.extra_started(now);
            }
        }
        // Feelers (W5), only when every outbound slot is taken: the regular
        // dials test addresses otherwise.
        if !cfg.connect_only && registered_outbound >= cfg.max_outbound && conn.feeler.is_none() {
            let due = *conn
                .next_feeler
                .get_or_insert_with(|| next_feeler(now, rng));
            if now >= due {
                conn.next_feeler = Some(next_feeler(now, rng));
                let skip = |a: &NetAddr| dialable.skip(a, &to_connect, &groups);
                let pick = addrman
                    .select_tried_collision(rng)
                    .filter(|a| !skip(a))
                    .or_else(|| addrman.select(rng, unix, true, skip));
                if let Some(a) = pick {
                    log::debug!("feeler to {a}");
                    conn.feeler = Some(a.clone());
                    feeler = Some(a);
                }
            }
        }
        // More outbound peers than the target (the extra stale-tip peer
        // connected, or manual peers came up): the discovered peer with the
        // lowest chain goes, once connected long enough to show its chain.
        if registered_outbound > cfg.max_outbound {
            let candidates: Vec<OutboundCandidate> = st
                .peers
                .iter()
                .filter(|(_, p)| !p.inbound && !cfg.connect.contains(&p.addr))
                .map(|(id, p)| OutboundCandidate {
                    id: *id,
                    height: p.height,
                    connected: p.connected_at,
                })
                .collect();
            if let Some(v) = select_outbound_to_evict(&candidates, now) {
                let p = st.peers.get_mut(&v).expect("candidate");
                log::info!(
                    "rotating out outbound peer {} (height {})",
                    p.addr,
                    p.height
                );
                p.kill.notify_one();
            }
        }
    }
    for a in to_connect.into_iter().chain(feeler) {
        tokio::spawn(connect_outbound(inner.clone(), a));
    }
}

/// Writes the anchors at shutdown (W4): up to `MAX_ANCHORS` outbound peers
/// this node dialed from its table (not manual peers, not seeds: a seed
/// operator must not hold every joiner's anchors), longest connected first.
/// The next start dials them before anything else.
pub(super) fn save_anchors(inner: &Inner) {
    let Some(dir) = &inner.cfg.data_dir else {
        return;
    };
    let mut outbound: Vec<(Instant, NetAddr)> = {
        let st = inner.state();
        st.peers
            .values()
            .filter(|p| {
                !p.inbound
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
