//! Peer management: misbehavior scoring and bans, inbound accept limits and
//! eviction, outbound connections and the outbound maintenance (anchors,
//! feelers, stale-tip rotation; docs/p2p.md §9, `crate::connman`).

use super::config::NetConfig;
use super::conn::run_connection;
use super::state::{unix_now, HeaderBatch, Inner, PendingHandshake, State};
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
use tokio::sync::Notify;

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
    if let Some(n) = st.handshaking_ip.get_mut(&h.ip) {
        *n -= 1;
        if *n == 0 {
            st.handshaking_ip.remove(&h.ip);
        }
    }
    Some(h)
}

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
            // Connections still in their handshake count against the per-IP
            // limit like registered ones: otherwise concurrent handshakes
            // bypass it.
            let same_ip =
                same_ip_count(&st, ip) + st.handshaking_ip.get(&key).copied().unwrap_or(0);
            if inner.cfg.max_inbound == 0
                || st.bans.is_banned(&ip, unix_now())
                || (!inner.cfg.allow_private && same_ip >= inner.cfg.max_per_ip)
            {
                continue; // drop the socket
            }
            // Handshakes are bounded on their own and never evict a
            // registered peer (RTW3-3): a full group, then a full total,
            // gives way oldest first. Room among the registered peers is
            // made at registration (`conn::run_connection`), for a peer
            // that completed its handshake.
            let group = st.addrman.bucket_group(&addr);
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
                    ip: key,
                    group,
                    kill: kill.clone(),
                },
            );
            *st.handshaking_ip.entry(key).or_default() += 1;
            HandshakeSlot {
                inner: inner.clone(),
                id,
                kill,
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

/// Disconnects one registered inbound peer to make room for a newly
/// registering one, if `connman::select_inbound_to_evict` finds one that is
/// not protected. Returns whether it did. Onion peers (through our hidden
/// service, from loopback) are the disadvantaged class. Groups are keyed with
/// the address table's secret key, so peers cannot tell which groups are
/// protected.
pub(super) fn evict_inbound(inner: &Inner, st: &mut State) -> bool {
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

/// An inbound connection's place among the pending handshakes, from accept
/// until it is registered or fails. Released under the state lock at
/// registration; otherwise on drop (never dropped while the state lock is
/// held). `kill` is notified when the handshake is evicted (RTW3-3).
pub(super) struct HandshakeSlot {
    pub(super) inner: Arc<Inner>,
    id: u64,
    pub(super) kill: Arc<Notify>,
    released: bool,
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

/// Dials `addr`. The address stays in `connecting` from the dial until the
/// connection ends, registered or not: it is never dialed twice at once.
/// A registered outbound peer is therefore in both `connecting` and the peer
/// map; [`pending_dials`] counts it once (RTW3-2).
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

/// Dials in progress that are not yet registered outbound peers, feelers
/// excluded: `connecting` also holds every registered outbound peer's
/// address until its connection ends (`connect_outbound`), and counting those
/// twice left a node refilling lost outbound slots only below half its
/// target (RTW3-2).
fn pending_dials(
    connecting: &HashSet<NetAddr>,
    registered: &HashSet<NetAddr>,
    feeler: Option<&NetAddr>,
) -> usize {
    connecting
        .iter()
        .filter(|a| !registered.contains(*a) && Some(*a) != feeler)
        .count()
}

/// Why an address is not dialed now: connected or being dialed, our own,
/// banned, unroutable, of a group already taken (outside `allow_private`),
/// an onion without a proxy, or tried in the last minute.
struct Dialable<'a> {
    cfg: &'a NetConfig,
    local_addr: Option<std::net::SocketAddr>,
    connected: &'a HashSet<NetAddr>,
    connecting: &'a HashSet<NetAddr>,
    bans: &'a BanList,
    last_attempt: &'a HashMap<NetAddr, Instant>,
    now: Instant,
    unix: u64,
}

impl Dialable<'_> {
    fn skip(&self, a: &NetAddr, to_connect: &[NetAddr], groups: &HashSet<Vec<u8>>) -> bool {
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
    fn skip_test(&self, a: &NetAddr, to_connect: &[NetAddr]) -> bool {
        let cfg = self.cfg;
        self.connected.contains(a)
            || self.connecting.contains(a)
            || to_connect.contains(a)
            || Some(a) == cfg.public_address.as_ref()
            || a.ip().is_some_and(|ip| self.bans.is_banned(&ip, self.unix))
            || (!cfg.allow_private && !a.is_routable())
            || (a.is_onion() && cfg.proxy.is_none())
            || self.local_addr.is_some_and(|l| a == &NetAddr::Ip(l))
    }
}

/// Keeps the outbound connections (docs/p2p.md §9), every 2 s:
/// - manual peers are reconnected;
/// - anchors saved at the last shutdown are dialed first, once;
/// - seeds, when the table is empty, no outbound peer is up, or the tip is
///   stale;
/// - free slots are filled from the address table, one per group;
/// - while the tip is stale, one extra outbound connection every
///   `stale_check_interval`, and when there are more outbound peers than the
///   target, the one that brought the least is disconnected (not banned):
///   the oldest last validated new tip, never the claimed height (RTW3-4);
/// - when the outbound slots are full, a feeler about every
///   `feeler_interval` (Poisson): a short connection that tests a *tried*
///   collision or a *new* address and moves it to *tried* if it answers.
///
/// A registered outbound peer is counted once (RTW3-2, [`pending_dials`]).
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
        let outbound_addrs: HashSet<NetAddr> = st
            .peers
            .values()
            .filter(|p| !p.inbound)
            .map(|p| p.addr.clone())
            .collect();
        let registered_outbound = st.peers.values().filter(|p| !p.inbound).count();
        let pending = pending_dials(&st.connecting, &outbound_addrs, st.connman.feeler.as_ref());
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
            cfg,
            local_addr: inner.local_addr,
            connected: &connected,
            connecting,
            bans,
            last_attempt,
            now,
            unix,
        };
        let policy_start = to_connect.len();
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
        // The extra connection counts as made only once something was
        // dialed for it; otherwise the next round tries again.
        if extra && to_connect.len() > policy_start {
            log::info!("tip unchanged for too long: trying an extra outbound peer");
            if let Some(s) = conn.stale.as_mut() {
                s.extra_started(now);
            }
        }
        // Feelers (W5), only when every outbound slot is taken: the regular
        // dials test addresses otherwise.
        if !cfg.connect_only && registered_outbound >= cfg.max_outbound && conn.feeler.is_none() {
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
        // More outbound peers than the target (the extra stale-tip peer
        // connected, or manual peers came up): of all discovered outbound
        // peers, the one whose last validated new tip is oldest goes; if it
        // is too young to have shown one, or has blocks in flight, the
        // rotation waits for it (RTW3-4).
        if registered_outbound > cfg.max_outbound {
            let candidates: Vec<OutboundCandidate> = st
                .peers
                .iter()
                .filter(|(_, p)| !p.inbound && !cfg.connect.contains(&p.addr))
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
        let connecting: HashSet<NetAddr> =
            [&p1, &p2, &dial, &feeler].into_iter().cloned().collect();
        let registered: HashSet<NetAddr> = [p1, p2].into_iter().collect();
        assert_eq!(pending_dials(&connecting, &registered, Some(&feeler)), 1);
        assert_eq!(pending_dials(&connecting, &registered, None), 2);
        assert_eq!(pending_dials(&connecting, &HashSet::new(), None), 4);
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
        let empty = HashSet::new();
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
            d.skip_test(&occupant, std::slice::from_ref(&occupant)),
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
