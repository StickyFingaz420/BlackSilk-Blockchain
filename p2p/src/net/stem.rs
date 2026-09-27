//! Dandelion++ glue: stem keys, stem-or-fluff routing, held local
//! transactions and fluffing.

use super::state::{short, Inner, State, StemEntry};
use crate::dandelion::{PeerId, Route, Source};
use crate::message::Message;
use blacksilk_chain::mempool::MempoolError;
use blacksilk_consensus::Hash;
use blacksilk_tx::types::Transaction;
use std::sync::Arc;
use std::time::Instant;

/// Stem-pool conflict keys: key images, and PX nullifiers.
pub(super) fn stem_keys(tx: &Transaction) -> Vec<[u8; 32]> {
    let mut keys: Vec<[u8; 32]> = tx.key_images().iter().map(|k| *k.bytes()).collect();
    if let Transaction::Px(t) = tx {
        keys.extend(t.nullifiers.iter().map(blacksilk_tx::px::digest_bytes));
    }
    keys
}

pub(super) fn unstem_key_images(st: &mut State, tx: &Transaction) {
    for k in stem_keys(tx) {
        st.stem_key_images.remove(&k);
    }
}

/// Stem-phase handling of a validated transaction (docs/p2p.md §8).
pub(super) async fn stem_or_fluff(inner: &Arc<Inner>, tx: Transaction, id: Hash, source: Source) {
    let route = {
        let mut st = inner.state();
        // Conflicts with another stem transaction: first seen wins.
        let keys = stem_keys(&tx);
        if keys.iter().any(|k| st.stem_key_images.contains_key(k)) {
            return;
        }
        for k in keys {
            st.stem_key_images.insert(k, id);
        }
        let State { dandelion, rng, .. } = &mut *st;
        let route = dandelion.route(source, rng);
        let embargo = Instant::now() + dandelion.embargo(rng);
        // A local transaction is never diffused by its origin on purpose
        // (`Dandelion::route`), so `Fluff` here means there is no stem peer
        // yet (e.g. just after startup). Broadcasting it now would show every
        // connected (inbound) spy where it comes from: hold it until a stem
        // route exists, with the embargo as the fallback.
        let hold = source == Source::Local && route == Route::Fluff;
        st.stempool.insert(
            id,
            StemEntry {
                tx: tx.clone(),
                embargo,
                awaiting_stem: hold,
            },
        );
        if hold {
            log::debug!("local tx {} held until a stem peer exists", short(&id));
            return;
        }
        route
    };
    match route {
        Route::Fluff => fluff(inner, id, None).await,
        Route::Stem(p) => {
            log::debug!("stem tx {} -> peer {p}", short(&id));
            inner.send_now(p, Message::StemTx(tx.encode()));
        }
    }
}

/// Sends local transactions held for lack of a stem peer (`stem_or_fluff`)
/// into the stem, once the epoch has one.
pub(super) fn send_held_local_txs(inner: &Inner, st: &mut State) {
    if st.dandelion.stems().is_empty() {
        return;
    }
    let held: Vec<Hash> = st
        .stempool
        .iter()
        .filter(|(_, e)| e.awaiting_stem)
        .map(|(id, _)| *id)
        .collect();
    for id in held {
        let State { dandelion, rng, .. } = &mut *st;
        let Route::Stem(p) = dandelion.route(Source::Local, rng) else {
            return;
        };
        let Some(e) = st.stempool.get_mut(&id) else {
            continue;
        };
        e.awaiting_stem = false;
        let msg = Message::StemTx(e.tx.encode());
        log::debug!("held local tx {} -> stem peer {p}", short(&id));
        inner.send(st, p, msg);
    }
}

/// Moves a stem transaction into the mempool and announces it.
pub(super) async fn fluff(inner: &Arc<Inner>, id: Hash, except: Option<PeerId>) {
    let entry = {
        let mut st = inner.state();
        let e = st.stempool.remove(&id);
        if let Some(e) = &e {
            unstem_key_images(&mut st, &e.tx);
        }
        e
    };
    let Some(entry) = entry else { return };
    let result = inner.with_chain(move |c| c.submit_tx(entry.tx)).await;
    match result {
        Ok(_) | Err(MempoolError::AlreadyKnown) => {
            log::debug!("fluff tx {}", short(&id));
            inner.announce_tx(id, except);
        }
        Err(e) => log::debug!("fluffing {} failed: {e:?}", short(&id)),
    }
}
