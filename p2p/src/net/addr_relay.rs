//! Address relay: `GetAddr` and `Addr` handling, and our own address
//! advertisement (docs/p2p.md §9).

use super::state::{unix_now, Inner, State, ADDR_KNOWN_MAX};
use crate::addr::{AddrEntry, NetAddr};
use crate::addrman_gate::{is_fresh, Verdict};
use crate::connman::ConnKind;
use crate::dandelion::PeerId;
use crate::limits::score;
use crate::message::Message;
use rand_chacha::rand_core::RngCore;
use std::sync::Arc;
use std::time::Instant;

/// Entry times we send for our own address are rounded down to this many
/// seconds (they reveal the node's clock no finer than that).
const SELF_TIME_ROUNDING: u64 = 300;

/// Relay targets of one fresh address.
const RELAY_TARGETS: usize = 2;

pub(super) fn on_get_addr(inner: &Arc<Inner>, peer: PeerId) {
    let mut st = inner.state();
    let Some(p) = st.peers.get_mut(&peer) else {
        return;
    };
    // Only inbound peers are answered (F32-4): answering a peer we dialed
    // lets it recognize addresses it planted earlier, and so link this node
    // across sessions, IPs and Tor circuits (Biryukov and Pustogarov, "Bitcoin
    // over Tor isn't a good idea", 2015). Nor a block-relay-only connection
    // (no addresses there). Ignored, not penalized.
    if !p.inbound || !p.addr_relay {
        return;
    }
    if p.answered_getaddr {
        drop(st);
        inner.misbehave(peer, score::UNSOLICITED, "repeated getaddr");
        return;
    }
    p.answered_getaddr = true;
    let now = unix_now();
    let allow_private = inner.cfg.allow_private;
    let State {
        addrman, rng, bans, ..
    } = &mut *st;
    // At most 23 % of the table, none terrible (`AddrMan::get_addr`). Every
    // entry carries time 0 ("unknown"): the table's per-address times stay
    // local, so nothing about the table or the clock is revealed.
    let sample: Vec<AddrEntry> = addrman
        .get_addr(1000, rng, now)
        .into_iter()
        .filter(|a| a.is_routable() || allow_private)
        .filter(|a| a.ip().is_none_or(|ip| !bans.is_banned(&ip, now)))
        .map(|a| AddrEntry::new(0, a))
        .collect();
    log::debug!(
        "peer {peer}: getaddr answered with {} addresses",
        sample.len()
    );
    inner.send(&mut st, peer, Message::Addr(sample));
}

pub(super) fn on_addr(inner: &Arc<Inner>, peer: PeerId, entries: Vec<AddrEntry>) {
    let now = unix_now();
    let mut st = inner.state();
    let Some(p) = st.peers.get_mut(&peer) else {
        return;
    };
    // No addresses on a block-relay-only connection: ignored, not penalized
    // (a self-advertisement may cross our `Version`).
    if !p.addr_relay {
        return;
    }
    log::debug!("peer {peer}: addr with {} entries", entries.len());
    // A seed's address fetch ends with its answer: any `Addr` except a
    // single entry (the seed's own address, sent on every connection).
    // Bitcoin Core closes on more than one entry; an empty answer ends it
    // here too.
    if p.kind == ConnKind::AddrFetch && entries.len() != 1 {
        p.kill.notify_one();
    }
    let (admit, relay) = match p.addr_gate.check(entries.len(), Instant::now()) {
        Verdict::Answer => (entries.len(), false),
        Verdict::Limited { admit } => (admit, true),
        Verdict::Unsolicited => {
            drop(st);
            inner.misbehave(peer, score::UNSOLICITED, "unsolicited address batch");
            return;
        }
    };
    if admit < entries.len() {
        log::debug!(
            "peer {}: {} addresses over the rate limit dropped",
            p.addr,
            entries.len() - admit
        );
    }
    let source = p.addr.clone();
    let allow_private = inner.cfg.allow_private;
    let mut fresh = Vec::new();
    {
        let State { addrman, peers, .. } = &mut *st;
        let known = &mut peers.get_mut(&peer).expect("checked").addr_known;
        // Entries of networks this version does not know are skipped.
        for e in entries.iter().take(admit) {
            let Some(a) = e.known() else { continue };
            let a = a.clone().canonical();
            if !(a.is_routable() || allow_private) {
                continue;
            }
            remember(known, a.clone());
            // Our own address is relayed like any other but not stored: it
            // is never dialed, and in a `GetAddr` answer (at most 23 % of
            // the table: 1 entry of up to 4) it would crowd out an address
            // the asker can use. A joiner that knew one node of a 4-node
            // labnet learned nothing it could dial in 7 of 32 runs (INV-PEERS).
            let own = inner.cfg.public_address.as_ref() == Some(&a);
            // Relay depends on the entry, never on whether the table knew the
            // address: that would tell a spy what the table holds (F32-5).
            if relay && is_fresh(e.time, now) {
                fresh.push(AddrEntry::new(e.time, a.clone()));
            }
            if !own {
                addrman.add(a, &source, now);
            }
        }
    }
    relay_fresh(inner, &mut st, Some(peer), fresh);
}

/// Sends each fresh entry to up to [`RELAY_TARGETS`] random peers other than
/// `from`, except to peers known to have it already.
fn relay_fresh(inner: &Inner, st: &mut State, from: Option<PeerId>, fresh: Vec<AddrEntry>) {
    if fresh.is_empty() {
        return;
    }
    // Not to block-relay-only connections, nor to a seed being asked.
    let others: Vec<PeerId> = st
        .peers
        .iter()
        .filter(|(id, p)| Some(**id) != from && p.addr_relay && p.kind != ConnKind::AddrFetch)
        .map(|(id, _)| *id)
        .collect();
    let mut out: Vec<(PeerId, Vec<AddrEntry>)> = Vec::new();
    for e in fresh {
        let a = e.known().expect("known").clone();
        let mut pool = others.clone();
        for _ in 0..RELAY_TARGETS.min(pool.len()) {
            let i = (st.rng.next_u64() % pool.len() as u64) as usize;
            let target = pool.swap_remove(i);
            let Some(p) = st.peers.get_mut(&target) else {
                continue;
            };
            if p.addr_known.contains(&a) {
                continue;
            }
            remember(&mut p.addr_known, a.clone());
            match out.iter_mut().find(|(t, _)| *t == target) {
                Some((_, v)) => v.push(e.clone()),
                None => out.push((target, vec![e.clone()])),
            }
        }
    }
    for (target, entries) in out {
        inner.send(st, target, Message::Addr(entries));
    }
}

fn remember(known: &mut std::collections::HashSet<NetAddr>, a: NetAddr) {
    if known.len() >= ADDR_KNOWN_MAX {
        known.clear();
    }
    known.insert(a);
}

/// Advertises our own address (`listen`, the one `Version.listen` carried on
/// this connection) to a newly registered peer as a one-entry `Addr` with a
/// fresh time, so the peer can relay it (docs/p2p.md §9).
pub(super) fn advertise_self(inner: &Inner, peer: PeerId, listen: NetAddr) {
    let now = unix_now();
    let time = (now - now % SELF_TIME_ROUNDING).min(u64::from(u32::MAX)) as u32;
    let mut st = inner.state();
    if let Some(p) = st.peers.get_mut(&peer) {
        remember(&mut p.addr_known, listen.clone());
    }
    inner.send(
        &mut st,
        peer,
        Message::Addr(vec![AddrEntry::new(time, listen)]),
    );
}
