//! Dandelion++ glue: stem keys, stem-or-fluff routing, held local
//! transactions and fluffing; local origination through the originated set
//! (docs/p2p.md §8.1).
//!
//! **Logging (privacy).** Lines about a *local* transaction (one this node
//! originates) never carry its id, at any level: a shared or leaked debug
//! log would otherwise name this node as the origin of that transaction,
//! which Dandelion++ exists to hide. Every transaction id that reaches a log
//! line in this crate goes through `Inner::tx_log_id`, which names a
//! transaction of the originated set "a local tx" (stem, embargo fluff,
//! admission of a copy a peer sends back); the origination lines here name
//! none. Relayed transactions keep their short id at debug. Limit: an entry
//! leaves the originated set when its window ends (by then the transaction
//! is mined or expired network-wide) or, past `ORIGINATED_CAP` entries,
//! oldest first (warned).

use super::lock_or_exit;
use super::state::{Inner, State, StemEntry};
use crate::dandelion::{PeerId, Route, Source};
use crate::message::Message;
use crate::originated::{write_atomic, Verdict};
use blacksilk_chain::actor::Lane;
use blacksilk_chain::mempool::MempoolError;
use blacksilk_consensus::Hash;
use blacksilk_tx::types::Transaction;
use std::path::Path;
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
/// Returns whether it entered the stempool (`false`: it conflicts with a
/// stem transaction, and nothing was sent).
pub(super) async fn stem_or_fluff(
    inner: &Arc<Inner>,
    tx: Transaction,
    id: Hash,
    source: Source,
) -> bool {
    let route = {
        let mut st = inner.state();
        // Conflicts with another stem transaction: first seen wins.
        let keys = stem_keys(&tx);
        if keys.iter().any(|k| st.stem_key_images.contains_key(k)) {
            return false;
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
            None
        } else {
            Some(route)
        }
    };
    // Logged outside the state lock (RT2 F8).
    let Some(route) = route else {
        log::debug!("a local tx is held until a stem peer exists");
        return true;
    };
    match route {
        Route::Fluff => fluff(inner, id, None).await,
        Route::Stem(p) => {
            if source == Source::Local {
                log::debug!("local tx -> stem peer {p}");
            } else {
                log::debug!("stem tx {} -> peer {p}", inner.tx_log_id(&id));
            }
            inner.send_now(p, Message::StemTx(tx.encode()));
        }
    }
    true
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
        log::debug!("held local tx -> stem peer {p}");
        inner.send(st, p, msg);
    }
}

/// Moves a stem transaction into the mempool and announces it.
pub(super) async fn fluff(inner: &Arc<Inner>, id: Hash, except: Option<PeerId>) {
    let Some(entry) = take_stem(&mut inner.state(), &id) else {
        return;
    };
    fluff_entry(inner, id, entry, except).await;
}

/// Removes `id` from the stempool (with its stem keys), for a fluff.
pub(super) fn take_stem(st: &mut State, id: &Hash) -> Option<StemEntry> {
    let e = st.stempool.remove(id)?;
    unstem_key_images(st, &e.tx);
    Some(e)
}

/// [`fluff`] of an entry already taken from the stempool ([`take_stem`]).
pub(super) async fn fluff_entry(
    inner: &Arc<Inner>,
    id: Hash,
    entry: StemEntry,
    except: Option<PeerId>,
) {
    // The Tx lane, waiting for room: a fluff is this node's own decision,
    // not relay volume, and the transaction left the stempool already.
    let result = inner
        .chain_on(Lane::Tx, move |c| c.submit_tx(entry.tx))
        .await;
    match result {
        Ok(_) | Err(MempoolError::AlreadyKnown) => {
            log::debug!("fluff tx {}", inner.tx_log_id(&id));
            // Pooled: nothing more to ask anyone (`tx_requests`).
            Inner::forget_tx(&mut inner.state(), &id, None);
            inner.announce_tx(id, except);
        }
        Err(e) => log::debug!("fluffing {} failed: {e:?}", inner.tx_log_id(&id)),
    }
}

/// The originated set's file in the data directory (docs/p2p.md §8.1).
pub(super) const ORIGINATED_FILE: &str = "originated.json";

impl Inner {
    /// Writes the originated set to the data directory if it changed. Blocks
    /// on file I/O: call it on a blocking thread ([`Inner::save_originated`])
    /// or at shutdown. A failed write is logged and retried at the next
    /// change or save.
    pub(super) fn write_originated(&self, dir: &Path) {
        let _io = lock_or_exit(&self.originated_io, "originated set file");
        let bytes = {
            let mut st = self.state();
            if !st.originated.is_dirty() {
                return;
            }
            st.originated.encode()
        };
        if let Err(e) = write_atomic(&dir.join(ORIGINATED_FILE), &bytes) {
            log::error!(
                "saving {ORIGINATED_FILE}: {e}; after a restart this node could originate \
                 again a transaction it originated before"
            );
            self.state().originated.mark_dirty();
        }
    }

    /// [`Inner::write_originated`] on a blocking thread.
    pub(super) async fn save_originated(self: &Arc<Self>) {
        let Some(dir) = self.cfg.data_dir.clone() else {
            return;
        };
        let inner = self.clone();
        let _ = tokio::task::spawn_blocking(move || inner.write_originated(&dir)).await;
    }
}

/// Submits a transaction originated here (docs/p2p.md §8, §8.1): the only
/// origination path, so the only one applying the recently-expired guard
/// and the originated set. A peer's transactions are relayed regardless
/// (RTW1B-1).
pub(super) async fn submit_local(inner: &Arc<Inner>, tx: Transaction) -> Result<Hash, String> {
    // Hashing a PX transaction reads megabytes: off the async workers (and
    // off the chain actor, which it does not need). The next height is the
    // published snapshot's, as a command run just after its publication
    // would read it.
    let tx2 = tx.clone();
    let id = match tokio::task::spawn_blocking(move || tx2.hash()).await {
        Ok(id) => id,
        Err(e) => return Err(format!("hashing the transaction: {e}")),
    };
    let next = inner.summary.load().height + 1;
    let verdict = {
        let st = inner.state();
        if st.stempool.contains_key(&id) {
            // Already in our stem (this submission or an earlier one):
            // nothing more to send.
            return Ok(id);
        }
        st.originated.verdict(&id, next)
    };
    match verdict {
        Verdict::Held => {
            // Other nodes most likely still pool it. Checked as any
            // submission is (the answer is the pool's: `AlreadyKnown` if
            // pooled here), but neither stemmed, announced nor pooled: the
            // node then holds it exactly as a restarted relay does, not at
            // all, and fetches it on the next announcement like any
            // transaction (RT-TM2P2P: a pooled copy answered an `InvTx`
            // probe unlike a relay's, docs/p2p.md §8.1).
            let r = inner
                .chain_on(Lane::Tx, move |c| c.check_local_tx(&tx))
                .await;
            if r.is_ok() {
                log::debug!(
                    "a local tx was originated here before: accepted, not originated again"
                );
            }
            return r.map(|_| id).map_err(|e| format!("{e:?}"));
        }
        Verdict::Expired => {
            log::debug!(
                "a local tx was originated here and expired network-wide recently: refused"
            );
            return Err(format!("{:?}", MempoolError::Expired));
        }
        Verdict::Fresh => {}
    }
    let tx2 = tx.clone();
    let next = inner
        .chain_on(Lane::Tx, move |c| {
            c.check_local_tx(&tx2).map(|_| c.height() + 1)
        })
        .await
        .map_err(|e| format!("{e:?}"))?;
    // Recorded, and written, before the transaction leaves the node: a crash
    // right after sending must not forget it.
    inner.state().originated.record(id, next);
    inner.save_originated().await;
    if !stem_or_fluff(inner, tx, id, Source::Local).await {
        // A conflicting stem transaction won: this one was not sent.
        inner.state().originated.forget(&id);
        inner.save_originated().await;
    }
    Ok(id)
}
