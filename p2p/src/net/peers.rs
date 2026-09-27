//! Peer management: misbehavior scoring and bans, inbound accept limits,
//! outbound connections and the outbound maintenance.

use super::config::NetConfig;
use super::conn::run_connection;
use super::state::{unix_now, HeaderBatch, Inner, State};
use crate::addr::NetAddr;
use crate::dandelion::PeerId;
use crate::limits::{BAN_SECS, BAN_THRESHOLD};
use crate::socks5;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A seed is dialed at most this often.
const SEED_RETRY: Duration = Duration::from_secs(30);

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
    /// ban must not leave the offender's other connections open.
    fn ban_addr(&self, st: &mut State, addr: &NetAddr, proxied: bool) {
        let Some(ip) = addr.ip() else { return };
        let local = ip.is_loopback() && self.cfg.allow_private;
        if proxied || local {
            return;
        }
        st.bans.ban(ip, unix_now() + BAN_SECS);
        st.bans_dirty = true;
        for p in st.peers.values() {
            if !p.proxied && p.addr.ip() == Some(ip) {
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
        let addr = NetAddr::Ip(remote);
        let ip = remote.ip();
        let slot = {
            let mut st = inner.state();
            // Connections still in their handshake count like registered
            // ones: otherwise concurrent handshakes bypass both limits.
            let inbound = inbound_count(&st) + st.handshaking;
            let same_ip = same_ip_count(&st, ip) + st.handshaking_ip.get(&ip).copied().unwrap_or(0);
            if st.bans.is_banned(&ip, unix_now())
                || inbound >= inner.cfg.max_inbound
                || (!inner.cfg.allow_private && same_ip >= inner.cfg.max_per_ip)
            {
                continue; // drop the socket
            }
            st.handshaking += 1;
            *st.handshaking_ip.entry(ip).or_default() += 1;
            HandshakeSlot {
                inner: inner.clone(),
                ip,
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

pub(super) fn inbound_count(st: &State) -> usize {
    st.peers.values().filter(|p| p.inbound).count()
}

/// Registered non-proxied peers from `ip`.
pub(super) fn same_ip_count(st: &State, ip: IpAddr) -> usize {
    st.peers
        .values()
        .filter(|p| !p.proxied && p.addr.ip() == Some(ip))
        .count()
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
    {
        let mut st = inner.state();
        if !st.connecting.insert(addr.clone()) {
            return;
        }
        st.last_attempt.insert(addr.clone(), Instant::now());
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
        _ => {
            log::debug!("connect {addr} failed");
            inner.state().addrman.mark_failed(&addr);
        }
    }
    inner.state().connecting.remove(&addr);
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

pub(super) fn maintain_outbound(inner: &Arc<Inner>) {
    let now = Instant::now();
    let mut to_connect = Vec::new();
    {
        let mut st = inner.state();
        let connected: HashSet<NetAddr> = st.peers.values().map(|p| p.addr.clone()).collect();
        // Manual peers: always reconnect (after a short backoff).
        for a in &inner.cfg.connect {
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
        let outbound = st.peers.values().filter(|p| !p.inbound).count() + st.connecting.len();
        let mut free = if inner.cfg.connect_only {
            0
        } else {
            inner
                .cfg
                .max_outbound
                .saturating_sub(outbound + to_connect.len())
        };
        // Seeds: when we know no address, and also when no outbound
        // connection is up (every known address may be stale or hostile),
        // each at most every SEED_RETRY.
        let registered_outbound = st.peers.values().filter(|p| !p.inbound).count();
        if free > 0 && (st.addrman.is_empty() || registered_outbound == 0) {
            for s in &inner.cfg.seeds {
                if free == 0 {
                    break;
                }
                let recent = st
                    .last_attempt
                    .get(s)
                    .is_some_and(|t| now.duration_since(*t) < SEED_RETRY);
                if !connected.contains(s) && !st.connecting.contains(s) && !recent {
                    to_connect.push(s.clone());
                    free -= 1;
                }
            }
        }
        let mut groups: HashSet<Vec<u8>> = st
            .peers
            .values()
            .filter(|p| !p.inbound)
            .map(|p| p.addr.group())
            .chain(st.connecting.iter().map(|a| a.group()))
            .collect();
        let unix = unix_now();
        let cfg = &inner.cfg;
        for _ in 0..free {
            let State {
                addrman,
                rng,
                bans,
                connecting,
                last_attempt,
                ..
            } = &mut *st;
            let pick = addrman.select(rng, |a| {
                connected.contains(a)
                    || connecting.contains(a)
                    || to_connect.contains(a)
                    || Some(a) == cfg.public_address.as_ref()
                    || a.ip().is_some_and(|ip| bans.is_banned(&ip, unix))
                    || (!cfg.allow_private && (!a.is_routable() || groups.contains(&a.group())))
                    || (a.is_onion() && cfg.proxy.is_none())
                    || last_attempt
                        .get(a)
                        .is_some_and(|t| now.duration_since(*t) < Duration::from_secs(60))
                    || inner.local_addr.is_some_and(|l| a == &NetAddr::Ip(l))
            });
            match pick {
                Some(a) => {
                    // One outbound connection per group, also among the
                    // picks of this round (R8-4).
                    groups.insert(a.group());
                    to_connect.push(a);
                }
                None => break,
            }
        }
    }
    for a in to_connect {
        tokio::spawn(connect_outbound(inner.clone(), a));
    }
}
