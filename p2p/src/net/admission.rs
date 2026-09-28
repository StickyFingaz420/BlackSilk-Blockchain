//! Transaction admission: decoding, contextual reject caching, mempool
//! admission and invalid-transaction scoring, fluff and stem receipt.

use super::state::{short, Inner, State};
use super::stem::{stem_keys, stem_or_fluff, unstem_key_images};
use crate::dandelion::{PeerId, Source};
use crate::limits::score;
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::mempool::MempoolError;
use blacksilk_consensus::Hash;
use blacksilk_tx::types::Transaction;
use std::sync::Arc;
use std::time::Instant;

const RECENT_REJECTS: usize = 10_000;

impl Inner {
    fn reject_cache(st: &mut State, id: Hash) {
        if st.recent_rejects_set.insert(id) {
            st.recent_rejects.push_back(id);
            if st.recent_rejects.len() > RECENT_REJECTS {
                if let Some(old) = st.recent_rejects.pop_front() {
                    st.recent_rejects_set.remove(&old);
                }
            }
        }
    }
}

fn decode_tx(bytes: &[u8]) -> Option<Transaction> {
    match Transaction::decode(bytes) {
        Ok(Transaction::Coinbase(_)) | Err(_) => None,
        Ok(t) => Some(t),
    }
}

fn is_px(tx: &Transaction) -> bool {
    matches!(tx, Transaction::Px(_) | Transaction::PxDeploy(_))
}

/// The ring indices of each v1 input (for `provably_invalid_signature`).
fn input_rings(tx: &Transaction) -> Vec<Vec<u64>> {
    let inputs: &[blacksilk_tx::types::Input] = match tx {
        Transaction::Coinbase(_) => &[],
        Transaction::Transfer(t) => &t.inputs,
        Transaction::Px(t) => &t.inputs,
        Transaction::PxDeploy(t) => &t.inputs,
    };
    inputs.iter().map(|i| i.ring.to_vec()).collect()
}

/// Whether `id` failed a contextual rule at our current tip `tip`.
pub(super) fn ctx_rejected(st: &State, id: &Hash, tip: &Hash) -> bool {
    st.ctx_rejects_tip == *tip && st.ctx_rejects.contains(id)
}

/// Remembers that `id` failed a contextual rule at tip `tip`: the same bytes
/// are not verified again until the tip changes (the cache is emptied then).
fn ctx_reject(st: &mut State, id: Hash, tip: Hash) {
    if st.ctx_rejects_tip != tip || st.ctx_rejects.len() >= RECENT_REJECTS {
        st.ctx_rejects.clear();
        st.ctx_rejects_tip = tip;
    }
    st.ctx_rejects.insert(id);
}

/// Everything a relayed transaction goes through before its expensive checks
/// (ring signatures, range proofs, PX proof), in order of cost (docs/p2p.md
/// §10):
/// 1. a transaction already proven invalid is dropped (and a peer stemming it
///    again is penalized);
/// 2. the peer's signature budget is charged one token per v1 input (one
///    CLSAG verification each), and a PX or deploy transaction its PX share;
/// 3. a transaction already in the mempool, one that conflicts with a pooled
///    transaction (same key image, nullifier or contract id; the
///    pool keeps the first seen, so it would be refused after verification),
///    or one that failed a contextual rule at the current tip, is dropped
///    unverified;
/// 4. cheap checks: structure and balance (stateless), and a PX proof's
///    decoding (stateless), then the contextual rules an extension can change
///    (key images, PX anchor, nullifiers, registry, pool, contract id), then
///    a PX proof's shape against its registered functions;
/// 5. only then the node-wide PX token: transactions that fail the cheap
///    checks (e.g. a random PX anchor, or a garbage proof, penalized as
///    `PxProof`) never consume it, so they cannot starve honest PX relay.
///
/// `stem`: an unsolicited `StemTx` (rate excesses are penalized) rather than a
/// `Tx` we requested (never penalized for its rate: we asked for it; over a
/// limit it is dropped unverified). Returns whether to verify.
async fn admit_tx(
    inner: &Arc<Inner>,
    peer: PeerId,
    tx: &Transaction,
    id: Hash,
    stem: bool,
) -> bool {
    let now = Instant::now();
    let px = is_px(tx);
    let over = {
        let mut st = inner.state();
        if st.recent_rejects_set.contains(&id) {
            drop(st);
            if stem {
                inner.misbehave(peer, score::INVALID_TX, "known invalid transaction");
            }
            return false;
        }
        let cost = tx.key_images().len().max(1) as f64;
        let Some(p) = st.peers.get_mut(&peer) else {
            return false;
        };
        if !p.limits.inputs.take(cost, now) {
            Some("input rate")
        } else if px && !p.limits.px.take(1.0, now) {
            Some("PX stem rate")
        } else {
            None
        }
    };
    if let Some(reason) = over {
        log::debug!("transaction {} dropped: {reason}", short(&id));
        if stem {
            inner.misbehave(peer, score::RATE, reason);
        }
        return false;
    }
    let tx = Arc::new(tx.clone());
    let tx2 = tx.clone();
    let (tip, pooled, conflict) = inner
        .with_chain(move |c| {
            let pool = c.mempool();
            (c.tip_id(), pool.contains(&id), pool.conflicts(&tx2))
        })
        .await;
    // Already pooled (a replay): nothing to verify, no budget spent (SX2).
    // A conflict with a pooled transaction would be refused after
    // verification (first seen wins): dropped now, before the node-wide PX
    // token. Not penalized: the conflicting transaction may be an honest
    // double spend that lost a race.
    if pooled || ctx_rejected(&inner.state(), &id, &tip) {
        return false;
    }
    if conflict {
        log::debug!(
            "transaction {} conflicts with a pooled one; dropped",
            short(&id)
        );
        return false;
    }
    let cheap = inner
        .with_chain(move |c| {
            // The cheap stateless rules first, as in full validation: a
            // transaction that breaks one is penalized whatever its context.
            // A PX proof is decoded with them (a few milliseconds, far below
            // the verification it gates) and shape-checked once its
            // functions are known to be registered, so a malformed proof
            // never reaches the node-wide PX token, a ring or a CLSAG
            // (RTW1-2).
            use blacksilk_tx::{px, validate};
            let rules = c.next_rules();
            let mut proof = None;
            let stateless = match &*tx {
                Transaction::Coinbase(_) => Err(blacksilk_tx::TxError::CoinbaseNotAllowed),
                Transaction::Transfer(t) => {
                    validate::check_structure(t, &rules).and_then(|_| validate::check_balance(t))
                }
                Transaction::Px(t) => px::check_px_structure(t)
                    .and_then(|_| px::check_px_balance(t))
                    .and_then(|_| validate::decode_px_proof(t))
                    .map(|p| proof = Some(p)),
                Transaction::PxDeploy(t) => px::check_deploy_structure(t, &rules)
                    .and_then(|_| validate::check_balance(&t.as_transfer())),
            };
            let r = stateless
                .and_then(|_| validate::revalidate_after_extension(&tx, c.state(), c.height() + 1))
                .and_then(|_| match (&*tx, &proof) {
                    (Transaction::Px(t), Some(p)) => {
                        validate::check_px_proof_shape(t, c.state(), &rules, p)
                    }
                    _ => Ok(()),
                });
            // Near an activation a proof made for the neighbouring rule set
            // fails honestly: contextual then (`is_stateless_at`).
            r.map_err(|e| (e, e.is_stateless_at(c.params(), c.height() + 1)))
        })
        .await;
    if let Err((e, stateless)) = cheap {
        if stateless {
            Inner::reject_cache(&mut inner.state(), id);
            inner.misbehave(
                peer,
                score::INVALID_TX,
                &format!("invalid transaction: {e:?}"),
            );
        } else {
            log::debug!("transaction {} not valid here: {e:?}", short(&id));
            ctx_reject(&mut inner.state(), id, tip);
        }
        return false;
    }
    if px {
        let mut st = inner.state();
        if !st.px_global.take(1.0, now) {
            // Says nothing about this peer (others drain the bucket): never
            // penalized.
            st.px_global_drops += 1;
            log::debug!(
                "PX transaction {} dropped: node-wide relay limit",
                short(&id)
            );
            return false;
        }
    }
    true
}

/// Ring members this deep below our tip resolve to the same outputs on every
/// branch we could plausibly reorganize to, so a signature that fails over
/// them fails for every honest node too (docs/p2p.md §10). Far beyond the
/// reorganization depth that only warns (`DEEP_REORG_WARN_DEPTH` = 10): a
/// reorganization this deep would penalize honest relays, so the margin is
/// wide (the coinbase maturity). Spam over younger rings still pays the
/// per-peer input budget.
const SIGNATURE_BURIAL: u64 = 60;

/// Whether an `InvalidSignature` for an input with ring `ring` proves the
/// sender relayed an invalid transaction: every ring member is at least
/// `SIGNATURE_BURIAL` blocks below our tip.
fn provably_invalid_signature(c: &ChainManager, ring: Option<&Vec<u64>>) -> bool {
    use blacksilk_tx::validate::ChainView;
    let Some(ring) = ring else { return false };
    let tip = c.height();
    !ring.is_empty()
        && ring.iter().all(|&i| {
            c.state()
                .output(i)
                .is_some_and(|r| r.height + SIGNATURE_BURIAL <= tip)
        })
}

/// Whether the verification failure `e` of a transaction whose inputs have
/// rings `rings` proves that its relayer broke the rules: a stateless
/// failure, or a signature that fails over deeply buried ring members. Runs
/// under the chain lock, with the verification (same tip).
fn proven_invalid(c: &ChainManager, rings: &[Vec<u64>], e: &MempoolError) -> bool {
    match e {
        MempoolError::Invalid(e) => {
            // Near an activation, proofs and signatures made for the
            // neighbouring rule set fail honestly
            // (`validate::ACTIVATION_GRACE_BLOCKS`).
            let next = c.height() + 1;
            let near = blacksilk_tx::validate::near_activation(c.params(), next);
            e.is_stateless_at(c.params(), next)
                || match e {
                    blacksilk_tx::TxError::InvalidSignature { input } if !near => {
                        provably_invalid_signature(c, rings.get(*input))
                    }
                    _ => false,
                }
        }
        _ => false,
    }
}

/// A relayed transaction failed full verification at tip `tip`. Proven
/// failures (`proven_invalid`) are penalized and remembered for good. Other
/// (contextual) failures can be honest races: not penalized, and not
/// verified again at this tip.
fn on_invalid_tx(
    inner: &Arc<Inner>,
    peer: PeerId,
    id: Hash,
    tip: Hash,
    e: blacksilk_tx::TxError,
    proven: bool,
) {
    if proven {
        Inner::reject_cache(&mut inner.state(), id);
        inner.misbehave(
            peer,
            score::INVALID_TX,
            &format!("invalid transaction: {e:?}"),
        );
    } else {
        log::debug!("transaction {} not valid here: {e:?}", short(&id));
        ctx_reject(&mut inner.state(), id, tip);
    }
}

pub(super) async fn on_tx(inner: &Arc<Inner>, peer: PeerId, bytes: Vec<u8>) {
    let Some(tx) = decode_tx(&bytes) else {
        inner.misbehave(peer, score::INVALID_TX, "transaction does not decode");
        return;
    };
    let id = tx.hash();
    let requested = {
        let mut st = inner.state();
        let r = st.tx_requests.get(&id).is_some_and(|(p, _)| *p == peer);
        if r {
            st.tx_requests.remove(&id);
            st.tx_announcers.remove(&id);
        }
        r
    };
    if !requested {
        inner.misbehave(peer, score::UNSOLICITED, "unrequested transaction");
        return;
    }
    if !admit_tx(inner, peer, &tx, id, false).await {
        return;
    }
    let rings = input_rings(&tx);
    let result = inner
        .with_chain(move |c| {
            let tip = c.tip_id();
            let r = c.submit_tx(tx);
            let proven = r.as_ref().is_err_and(|e| proven_invalid(c, &rings, e));
            (tip, r, proven)
        })
        .await;
    inner.state().tx_verifications += 1;
    match result {
        (_, Ok(_), _) => {
            {
                let mut st = inner.state();
                if let Some(e) = st.stempool.remove(&id) {
                    unstem_key_images(&mut st, &e.tx);
                }
            }
            inner.announce_tx(id, Some(peer));
        }
        (tip, Err(MempoolError::Invalid(e)), proven) => {
            on_invalid_tx(inner, peer, id, tip, e, proven)
        }
        (_, Err(_), _) => {}
    }
}

pub(super) async fn on_stem_tx(inner: &Arc<Inner>, peer: PeerId, bytes: Vec<u8>) {
    {
        let mut st = inner.state();
        let now = Instant::now();
        let within = match st.peers.get_mut(&peer) {
            Some(p) => p.limits.txs.take(1.0, now),
            None => return,
        };
        if !within {
            drop(st);
            inner.misbehave(peer, score::RATE, "stem rate");
            return;
        }
    }
    let Some(tx) = decode_tx(&bytes) else {
        inner.misbehave(peer, score::INVALID_TX, "stem transaction does not decode");
        return;
    };
    let id = tx.hash();
    {
        // Already stemmed, or a conflict with a stem transaction (first seen
        // wins): dropped before any verification, so valid double-spend
        // variants cost nothing (R8-7).
        let st = inner.state();
        if st.stempool.contains_key(&id)
            || stem_keys(&tx)
                .iter()
                .any(|k| st.stem_key_images.contains_key(k))
        {
            return;
        }
    }
    if !admit_tx(inner, peer, &tx, id, true).await {
        return;
    }
    let rings = input_rings(&tx);
    let tx2 = tx.clone();
    let checked = inner
        .with_chain(move |c| {
            let r = c.check_tx(&tx2);
            let proven = r.as_ref().is_err_and(|e| proven_invalid(c, &rings, e));
            (c.tip_id(), r, proven)
        })
        .await;
    inner.state().tx_verifications += 1;
    match checked {
        (_, Ok(_), _) => stem_or_fluff(inner, tx, id, Source::Peer(peer)).await,
        (tip, Err(MempoolError::Invalid(e)), proven) => {
            on_invalid_tx(inner, peer, id, tip, e, proven)
        }
        (_, Err(_), _) => {}
    }
}
