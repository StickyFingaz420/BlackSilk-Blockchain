//! The message dispatcher: unsolicited-reply checks and per-message routing.

use super::addr_relay::{on_addr, on_get_addr};
use super::admission::{on_stem_tx, on_tx};
use super::blocks::{on_block, on_get_blocks, release_block_slot};
use super::headers::{in_grace, on_headers};
use super::relay::{on_get_tx, on_inv_tx, retry_tx};
use super::state::Inner;
use crate::dandelion::PeerId;
use crate::limits::score;
use crate::message::{Message, MAX_HEADERS};
use blacksilk_consensus::BlockHeader;
use std::sync::Arc;
use std::time::Instant;

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
