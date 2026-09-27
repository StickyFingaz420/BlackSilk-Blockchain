//! Address relay: `GetAddr` and `Addr` handling.

use super::state::{unix_now, Inner, State};
use crate::addr::NetAddr;
use crate::dandelion::PeerId;
use crate::limits::score;
use crate::message::Message;
use rand_chacha::rand_core::RngCore;
use std::sync::Arc;

pub(super) fn on_get_addr(inner: &Arc<Inner>, peer: PeerId) {
    let mut st = inner.state();
    let Some(p) = st.peers.get_mut(&peer) else {
        return;
    };
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
    let sample: Vec<NetAddr> = addrman
        .sample(1000, rng)
        .into_iter()
        .filter(|a| a.is_routable() || allow_private)
        .filter(|a| a.ip().is_none_or(|ip| !bans.is_banned(&ip, now)))
        .collect();
    inner.send(&mut st, peer, Message::Addr(sample));
}

pub(super) fn on_addr(inner: &Arc<Inner>, peer: PeerId, addrs: Vec<NetAddr>) {
    let mut st = inner.state();
    let Some(p) = st.peers.get_mut(&peer) else {
        return;
    };
    if addrs.len() > 10 {
        // One large batch (the answer to our GetAddr) per connection.
        if p.received_addr_batch {
            drop(st);
            inner.misbehave(peer, score::UNSOLICITED, "unsolicited address batch");
            return;
        }
        p.received_addr_batch = true;
    }
    let source = p.addr.clone();
    let allow_private = inner.cfg.allow_private;
    let mut fresh = Vec::new();
    {
        let State { addrman, rng, .. } = &mut *st;
        for a in addrs {
            if (a.is_routable() || allow_private) && addrman.add(a.clone(), &source, rng) {
                fresh.push(a);
            }
        }
    }
    // Relay small announcements of new addresses to two random peers.
    if !fresh.is_empty() && fresh.len() <= 10 {
        let mut others: Vec<PeerId> = st.peers.keys().copied().filter(|&p| p != peer).collect();
        for _ in 0..2.min(others.len()) {
            let i = (st.rng.next_u64() % others.len() as u64) as usize;
            let target = others.swap_remove(i);
            inner.send(&mut st, target, Message::Addr(fresh.clone()));
        }
    }
}
