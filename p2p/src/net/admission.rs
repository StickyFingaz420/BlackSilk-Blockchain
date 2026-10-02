//! Transaction admission: decoding, contextual reject caching, mempool
//! admission and invalid-transaction scoring, fluff and stem receipt.

use super::chain_access;
use super::dispatch::SMALL_RELAY_BYTES;
use super::state::{short, Inner, State};
use super::stem::{stem_keys, stem_or_fluff, unstem_key_images};
use super::tx_requests::{answer_dropped, forget, request_wanted};
use crate::dandelion::{PeerId, Source};
use crate::limits::score;
use blacksilk_chain::actor::{Lane, SendError};
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::mempool::MempoolError;
use blacksilk_consensus::Hash;
use blacksilk_tx::px::PxTx;
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

/// Decodes a relayed transaction once, into the `Arc` every later step
/// shares (RTW2A-5: no copy of a multi-megabyte PX transaction per chain
/// command). The frame's bytes are freed by the caller right after.
fn decode_tx(bytes: &[u8]) -> Option<Arc<Transaction>> {
    match Transaction::decode(bytes) {
        Ok(Transaction::Coinbase(_)) | Err(_) => None,
        Ok(t) => Some(Arc::new(t)),
    }
}

/// The transaction behind `tx`, without a copy once every chain command
/// that shared it has run (their closures are dropped before they reply).
fn unshare(tx: Arc<Transaction>) -> Transaction {
    Arc::try_unwrap(tx).unwrap_or_else(|shared| (*shared).clone())
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
/// 2. the peer's relay budgets are charged, all or nothing
///    (`PeerLimits::charge_relay`): a `txs` token for a `StemTx`, the PX
///    share for a PX or deploy transaction, and one signature token per v1
///    input (one CLSAG verification each). Over a budget the transaction is
///    dropped unverified and NOT penalized, a `StemTx` included (RTW2A-4):
///    an honest node forwarding many peers' stems exceeds a rate without
///    misbehaving, and a penalty would get it banned. It is not fluffed
///    either (a forced fluff helps locate the origin); its origin's embargo
///    ends the stem. Floods are still bounded, and scored, on the read loop
///    (message and byte rates) and by the slow lane's bounds. Charged only
///    here, after the free drops (dedupe in `on_stem_tx`, step 1), and only
///    for a message the lane took (RTW2A-1);
/// 3. a transaction already in the mempool, one that conflicts with a pooled
///    transaction (same key image, nullifier or contract id; the
///    pool keeps the first seen, so it would be refused after verification),
///    or one that failed a contextual rule at the current tip, is dropped
///    unverified;
/// 4. cheap checks: a PX transaction whose window ends within
///    `PX_EXPIRING_SOON_BLOCKS` of the next block is refused first, as a
///    contextual failure (never scored; RTW1C-4, `px_expires_soon`), before
///    its proof is decoded; then structure and balance (stateless), and a PX proof's
///    decoding (stateless, bounded; for a PX transaction these three run off
///    the chain actor, on a blocking thread, and only their result enters the
///    chain command: `px_pre_checks`, RT-FUZZ-1), then the contextual rules
///    an extension can change
///    (key images, PX anchor, nullifiers, registry, pool, contract id), then
///    a PX proof's shape against its registered functions;
/// 5. only then the node-wide PX token: transactions that fail the cheap
///    checks (e.g. a random PX anchor, or a garbage proof, penalized as
///    `PxProof`) never consume it, so they cannot starve honest PX relay.
///
/// `stem`: an unsolicited `StemTx` rather than a `Tx` we requested. Returns
/// whether to verify ([`Admit`]).
/// What [`admit_tx`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admit {
    /// Verify it now.
    Verify,
    /// Dropped for good: known, conflicting, invalid, or not valid here.
    Done,
    /// Dropped for this node's own budgets (the peer's relay share, the
    /// node-wide PX share): an answer to our request is asked again later
    /// (`tx_requests::answer_dropped`).
    Busy,
}

async fn admit_tx(
    inner: &Arc<Inner>,
    peer: PeerId,
    tx: &Arc<Transaction>,
    id: Hash,
    stem: bool,
) -> Admit {
    let now = Instant::now();
    let px = matches!(**tx, Transaction::Px(_) | Transaction::PxDeploy(_));
    let over = {
        let mut st = inner.state();
        if st.recent_rejects_set.contains(&id) {
            drop(st);
            if stem {
                inner.misbehave(peer, score::INVALID_TX, "known invalid transaction");
            }
            return Admit::Done;
        }
        let Some(p) = st.peers.get_mut(&peer) else {
            return Admit::Done;
        };
        p.limits
            .charge_relay(stem, px, tx.key_images().len(), now)
            .err()
    };
    if let Some(reason) = over {
        log::debug!(
            "peer {peer}: transaction {} over its {reason}; dropped (not penalized)",
            short(&id)
        );
        return Admit::Busy;
    }
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
        return Admit::Done;
    }
    if conflict {
        log::debug!(
            "transaction {} conflicts with a pooled one; dropped",
            short(&id)
        );
        return Admit::Done;
    }
    // A PX transaction's stateless checks, its proof decoding among them,
    // run here, off the chain actor (RT-FUZZ-1); the command below keeps
    // only the checks that read chain state.
    let pre = match px_pre_checks(inner, tx).await {
        Some(pre) => pre,
        None => return Admit::Done,
    };
    let tx3 = tx.clone();
    // The tip these checks ran at keys the contextual-reject cache
    // (RTW2A-7): the tip may have moved since the first command.
    // The command carries the proof's degree bits, never the proof: it was
    // freed on the blocking thread (RT-PXDOS F1).
    let (tip, cheap) = inner
        .with_chain(move |c| {
            let mut pre = pre;
            (c.tip_id(), cheap_checks(c, &tx3, &mut pre))
        })
        .await;
    if matches!(cheap, Ok(false)) {
        // Refused like any contextual failure: not scored, not verified
        // again at this tip.
        log::debug!("PX transaction {} expires soon; not relayed", short(&id));
        ctx_reject(&mut inner.state(), id, tip);
        return Admit::Done;
    }
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
        return Admit::Done;
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
            return Admit::Busy;
        }
        st.px_global_taken += 1;
    }
    Admit::Verify
}

/// The stateless checks of a PX transaction, in full validation's order:
/// structure, balance, then the strict proof decoding. They read only the
/// transaction, so their result does not depend on when or where they run.
/// Of the decoded proof only its degree bits are kept, the one part the
/// shape check reads; the rest is freed where this runs (RT-PXDOS F1).
fn px_stateless(t: &PxTx) -> PxPre {
    use blacksilk_tx::{px, validate};
    px::check_px_structure(t)
        .and_then(|_| px::check_px_balance(t))
        .and_then(|_| validate::decode_px_proof(t))
        .map(|proof| proof.degree_bits)
}

/// [`px_stateless`]'s result: the decoded proof's degree bits (all of the
/// proof that enters the chain command), or the rule that failed.
type PxPre = Result<Vec<usize>, blacksilk_tx::TxError>;

/// Concurrent off-actor PX proof decodings, node-wide (process-wide: nodes
/// sharing a process, as in tests, share it). Each holds up to about
/// 6 times its bytes of heap, about 16 MB at `MAX_PROOF_BYTES`, for tens of
/// milliseconds (`decode_px_proof`); peers wait their
/// turn, as they waited for the chain actor before (RT-FUZZ-1).
static PX_DECODES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

/// Runs [`px_stateless`] for a PX transaction on a blocking thread, off the
/// chain actor and the async workers: `Some(Some(result))`. `Some(None)`
/// for any other transaction, or a PX transaction that expires soon at the
/// published height (its proof is not decoded, RTW1C-4; `cheap_checks`
/// refuses it, or decodes it itself if the height went back). `None` if
/// the node is shutting down or the checks panicked (logged at warn).
async fn px_pre_checks(inner: &Arc<Inner>, tx: &Arc<Transaction>) -> Option<Option<PxPre>> {
    let Transaction::Px(t) = &**tx else {
        return Some(None);
    };
    let next = inner.summary.load().height + 1;
    if blacksilk_tx::validate::px_expires_soon(t, next) {
        return Some(None);
    }
    let _slot = PX_DECODES.acquire().await.ok()?;
    let tx2 = tx.clone();
    let pre = tokio::task::spawn_blocking(move || match &*tx2 {
        Transaction::Px(t) => Some(px_stateless(t)),
        _ => None,
    })
    .await;
    match pre {
        Ok(pre) => Some(pre),
        // The decoder contains Plonky3's panics itself (`catch_unwind`), so
        // a panic here is a bug in the stateless checks. The transaction is
        // dropped unscored (as a busy node drops one), but not silently.
        Err(e) if e.is_panic() => {
            log::warn!("the stateless PX checks panicked (a bug); transaction dropped: {e}");
            None
        }
        // Cancelled: the runtime is shutting down.
        Err(_) => None,
    }
}

/// The cheap checks of `admit_tx` (step 4), in one chain command: `Ok(false)`
/// if a PX transaction expires soon, `Err((e, stateless))` if a rule fails.
/// `pre` is a PX transaction's [`px_stateless`] result, computed off the
/// actor; if it is `None`, they run here and their result is left in it.
fn cheap_checks(
    c: &ChainManager,
    tx: &Transaction,
    pre: &mut Option<PxPre>,
) -> Result<bool, (blacksilk_tx::TxError, bool)> {
    // The cheap stateless rules first, as in full validation: a
    // transaction that breaks one is penalized whatever its context.
    // A PX proof is decoded with them (bounded: about 11 to 13 ms and
    // 4 times its size in heap for a transfer proof, `decode_px_proof`,
    // far below the verification it gates; normally already done off
    // the actor, `px_pre_checks`) and shape-checked once its functions
    // are known to be registered, so a malformed proof never reaches
    // the node-wide PX token, a ring or a CLSAG (RTW1-2).
    use blacksilk_tx::{px, validate};
    // Expiring soon (RTW1C-4): policy, contextual, before anything
    // is decoded or verified and before the node-wide PX token.
    if let Transaction::Px(t) = tx {
        if validate::px_expires_soon(t, c.height() + 1) {
            return Ok(false);
        }
    }
    let rules = c.next_rules();
    let stateless = match tx {
        Transaction::Coinbase(_) => Err(blacksilk_tx::TxError::CoinbaseNotAllowed),
        Transaction::Transfer(t) => {
            validate::check_structure(t, &rules).and_then(|_| validate::check_balance(t))
        }
        Transaction::Px(t) => match pre.get_or_insert_with(|| px_stateless(t)) {
            Ok(_) => Ok(()),
            Err(e) => Err(*e),
        },
        Transaction::PxDeploy(t) => px::check_deploy_structure(t, &rules)
            .and_then(|_| validate::check_balance(&t.as_transfer())),
    };
    let r = stateless
        .and_then(|_| validate::revalidate_after_extension(tx, c.state(), c.height() + 1))
        .and_then(|_| match (tx, pre.as_ref()) {
            (Transaction::Px(t), Some(Ok(bits))) => {
                validate::check_px_proof_shape_bits(t, c.state(), &rules, bits)
            }
            _ => Ok(()),
        });
    // Near an activation a proof made for the neighbouring rule set
    // fails honestly: contextual then (`is_stateless_at`).
    r.map(|()| true)
        .map_err(|e| (e, e.is_stateless_at(c.params(), c.height() + 1)))
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
/// in the verification's chain command (same tip).
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

/// Runs the verification of a relayed transaction on the chain actor's Tx
/// lane, below blocks, headers and queries. A full lane drops it (`None`):
/// relay is best effort, so the sender is not penalized and the drop is
/// only counted (`NetStats::tx_lane_drops`, F34-5).
async fn verify_on_tx_lane<T: Send + 'static>(
    inner: &Arc<Inner>,
    id: Hash,
    f: impl FnOnce(&mut ChainManager) -> T + Send + 'static,
) -> Option<T> {
    match chain_access::try_call(&inner.chain, Lane::Tx, f).await {
        Ok(t) => Some(t),
        Err(SendError::Full(_)) => {
            inner.state().tx_lane_drops += 1;
            log::debug!(
                "transaction {} dropped: the chain's transaction lane is full",
                short(&id)
            );
            None
        }
        // The node is shutting down.
        Err(SendError::Stopped) => std::future::pending().await,
    }
}

/// `peer` delivered a new transaction that passed verification: inbound
/// eviction protects the recent relayers (docs/p2p.md §9).
fn note_new_tx(st: &mut State, peer: PeerId) {
    if let Some(p) = st.peers.get_mut(&peer) {
        p.last_tx = Some(Instant::now());
    }
}

pub(super) async fn on_tx(inner: &Arc<Inner>, peer: PeerId, bytes: Vec<u8>) {
    let Some(tx) = decode_tx(&bytes) else {
        inner.misbehave(peer, score::INVALID_TX, "transaction does not decode");
        return;
    };
    let large = bytes.len() > SMALL_RELAY_BYTES;
    drop(bytes);
    let id = tx.hash();
    let (requested, ours) = {
        let mut st = inner.state();
        let r = st.tx_requests.get(&id).is_some_and(|(p, _)| *p == peer);
        if let Some(p) = st.peers.get_mut(&peer).filter(|_| r) {
            // One request at a time to a peer whose answers are large
            // (`tx_requests`).
            p.tx_large = large;
        }
        // An answer to our request that timed out and moved on (P2P-FIX2):
        // accepted, unpenalized. The request to the next announcer stays,
        // so its answer is not unrequested either (a pooled copy is then
        // dropped for free).
        (r || st.late_txs.remove(&(id, peer)).is_some(), r)
    };
    if !requested {
        inner.misbehave(peer, score::UNSOLICITED, "unrequested transaction");
        return;
    }
    // The request ends only once the answer is taken: an answer dropped for
    // this node's own budgets is asked again (RT-TM2P2P item 1).
    let verdict = admit_tx(inner, peer, &tx, id, false).await;
    if ours {
        let mut st = inner.state();
        let now = Instant::now();
        if verdict == Admit::Busy {
            answer_dropped(&mut st, id, peer, now);
        } else {
            forget(&mut st, &id);
            // Its request ended: what else it announced may be asked now.
            request_wanted(inner, &mut st, peer, now);
        }
    }
    if verdict != Admit::Verify {
        return;
    }
    let rings = input_rings(&tx);
    // One Tx-lane command: the tip, the verification and the penalty
    // classification see the same state (one former lock hold).
    let Some(result) = verify_on_tx_lane(inner, id, move |c| {
        let tip = c.tip_id();
        let r = c.submit_tx(unshare(tx));
        let proven = r.as_ref().is_err_and(|e| proven_invalid(c, &rings, e));
        (tip, r, proven)
    })
    .await
    else {
        // The Tx lane was full: our own budget, asked again later.
        if ours {
            answer_dropped(&mut inner.state(), id, peer, Instant::now());
        }
        return;
    };
    inner.state().tx_verifications += 1;
    match result {
        (_, Ok(_), _) => {
            {
                let mut st = inner.state();
                if let Some(e) = st.stempool.remove(&id) {
                    unstem_key_images(&mut st, &e.tx);
                }
                note_new_tx(&mut st, peer);
            }
            inner.announce_tx(id, Some(peer));
        }
        (tip, Err(MempoolError::Invalid(e)), proven) => {
            on_invalid_tx(inner, peer, id, tip, e, proven)
        }
        (_, Err(_), _) => {}
    }
}

/// A relayed `StemTx`. The free drops come first: a transaction that does
/// not decode is penalized; one already stemmed, or conflicting with a stem
/// transaction, is dropped silently. Only then are the peer's budgets
/// charged (`admit_tx`; over one, dropped without penalty, RTW2A-4).
pub(super) async fn on_stem_tx(inner: &Arc<Inner>, peer: PeerId, bytes: Vec<u8>) {
    let Some(tx) = decode_tx(&bytes) else {
        inner.misbehave(peer, score::INVALID_TX, "stem transaction does not decode");
        return;
    };
    drop(bytes);
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
    if admit_tx(inner, peer, &tx, id, true).await != Admit::Verify {
        return;
    }
    let rings = input_rings(&tx);
    let tx2 = tx.clone();
    let Some(checked) = verify_on_tx_lane(inner, id, move |c| {
        let r = c.check_tx(&tx2);
        let proven = r.as_ref().is_err_and(|e| proven_invalid(c, &rings, e));
        (c.tip_id(), r, proven)
    })
    .await
    else {
        return;
    };
    inner.state().tx_verifications += 1;
    match checked {
        // A peer's transaction is relayed whether or not this node
        // originated it (the originated set, docs/p2p.md §8.1, and the
        // recently-expired guard apply to local origination only: RTW1B-1).
        (_, Ok(_), _) => {
            note_new_tx(&mut inner.state(), peer);
            stem_or_fluff(inner, unshare(tx), id, Source::Peer(peer)).await;
        }
        (tip, Err(MempoolError::Invalid(e)), proven) => {
            on_invalid_tx(inner, peer, id, tip, e, proven)
        }
        // `ReorgPending` among them: a returned transaction holds its keys
        // until a reorganization's drain ends (contextual, never scored).
        (_, Err(_), _) => {}
    }
}

/// [`super::fuzzing::admission`] (feature `test-hooks` only): the steps of
/// `admit_tx` that read the chain, then those of `on_tx`'s verification, in
/// their order and with their functions, synchronously on `c`.
#[cfg(feature = "test-hooks")]
pub(super) fn for_tests(c: &ChainManager, bytes: &[u8], verify: bool) -> super::fuzzing::Admission {
    let mut out = super::fuzzing::Admission {
        decoded: false,
        id: None,
        pre: None,
        cheap: None,
        verified: None,
    };
    let Some(tx) = decode_tx(bytes) else {
        return out;
    };
    out.decoded = true;
    let id = tx.hash();
    out.id = Some(id);
    // Step 3 of `admit_tx`: dropped unverified, never scored.
    let pool = c.mempool();
    if pool.contains(&id) || pool.conflicts(&tx) {
        return out;
    }
    // `px_pre_checks`, here on the caller's thread.
    let mut pre = match &*tx {
        Transaction::Px(t) if !blacksilk_tx::validate::px_expires_soon(t, c.height() + 1) => {
            Some(px_stateless(t))
        }
        _ => None,
    };
    let cheap = cheap_checks(c, &tx, &mut pre);
    out.pre = pre;
    out.cheap = Some(cheap);
    if !matches!(cheap, Ok(true)) || !verify {
        return out;
    }
    let rings = input_rings(&tx);
    let r = c.check_tx(&tx);
    let proven = r.as_ref().is_err_and(|e| proven_invalid(c, &rings, e));
    out.verified = Some((r, proven));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RT-PXDOS F1: of a PX transaction's off-actor checks, only the verdict
    /// and the proof's degree bits enter the chain command (and wait in its
    /// queue), never the decoded proof: the types say so.
    #[test]
    fn the_chain_command_carries_no_decoded_proof() {
        type Pre = Result<Vec<usize>, blacksilk_tx::TxError>;
        type Verdict = Result<bool, (blacksilk_tx::TxError, bool)>;
        let stateless: fn(&PxTx) -> Pre = px_stateless;
        let cheap: fn(&ChainManager, &Transaction, &mut Option<Pre>) -> Verdict = cheap_checks;
        let _ = (stateless, cheap);
        // A vector header and a tag: no proof inline.
        assert!(std::mem::size_of::<Option<PxPre>>() <= 32);
    }

    /// A network over a fresh regtest chain, listening nowhere (the caches'
    /// tests need only its state).
    async fn idle_network() -> crate::Network {
        struct ZeroPow;
        impl blacksilk_consensus::PowFunction for ZeroPow {
            fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
                [0; 32]
            }
        }
        let p = blacksilk_consensus::ChainParams::regtest();
        let m = ChainManager::open(
            p.clone(),
            blacksilk_tx::params::TxRules::for_chain(&p),
            Arc::new(ZeroPow),
            Box::<blacksilk_chain::store::MemoryStore>::default(),
            [1; 32],
        )
        .unwrap();
        let cfg = crate::NetConfig::new(p.network_id);
        crate::Network::start(cfg, Arc::new(std::sync::Mutex::new(m)))
            .await
            .unwrap()
    }

    /// Both reject caches hold 10,000 ids (`RECENT_REJECTS`, docs/p2p.md), written out so
    /// that a change of the constant is noticed (RT-MUTD).
    const CAPACITY: u32 = 10_000;

    fn id(i: u32) -> Hash {
        let mut h = [0; 32];
        h[..4].copy_from_slice(&i.to_le_bytes());
        h
    }

    /// The proven-invalid cache keeps exactly the last `RECENT_REJECTS` ids:
    /// the oldest goes when one more arrives, the second oldest stays
    /// (mutation run D: the boundary `>` against `>=` and `==` was untested).
    /// An id already cached is not added twice.
    #[tokio::test]
    async fn the_proven_invalid_cache_keeps_exactly_its_capacity() {
        let net = idle_network().await;
        let mut st = net.inner.state();
        let n = CAPACITY;
        for i in 0..n {
            Inner::reject_cache(&mut st, id(i));
        }
        Inner::reject_cache(&mut st, id(5));
        assert_eq!(st.recent_rejects.len(), 10_000, "no duplicate");
        assert!(st.recent_rejects_set.contains(&id(0)));
        Inner::reject_cache(&mut st, id(n));
        assert_eq!(st.recent_rejects.len(), 10_000);
        assert_eq!(st.recent_rejects_set.len(), 10_000);
        assert!(!st.recent_rejects_set.contains(&id(0)), "the oldest went");
        assert!(
            st.recent_rejects_set.contains(&id(1)),
            "the second oldest stays"
        );
        assert!(st.recent_rejects_set.contains(&id(n)));
    }

    /// The node's node-wide PX relay bucket (net.rs) has a burst of exactly
    /// 10 tokens and a rate of exactly 2 per second, on a controlled clock
    /// (RT-MUTD: the network test can bound them only by wall time).
    #[tokio::test]
    async fn the_node_wide_px_bucket_has_burst_10_and_rate_2() {
        let net = idle_network().await;
        let mut st = net.inner.state();
        let t0 = Instant::now() + std::time::Duration::from_secs(3600);
        let at = |ms: u64| t0 + std::time::Duration::from_millis(ms);
        let taken = (0..11).filter(|_| st.px_global.take(1.0, t0)).count();
        assert_eq!(taken, 10, "the burst");
        assert!(!st.px_global.take(1.0, at(250)), "0.5 tokens after 250 ms");
        // 2.0 tokens after 1 s: two, not a third.
        assert!(st.px_global.take(1.0, at(1000)));
        assert!(st.px_global.take(1.0, at(1000)));
        assert!(!st.px_global.take(1.0, at(1000)));
        // A long idle period refills to the burst, no further.
        let taken = (0..11)
            .filter(|_| st.px_global.take(1.0, at(60_000)))
            .count();
        assert_eq!(taken, 10);
    }

    /// The contextual-reject cache holds every id rejected at one tip, up to
    /// `RECENT_REJECTS`; the next one at that tip starts it afresh, as does a
    /// new tip (mutation run D: `>=` against `>` and `<` was untested).
    #[tokio::test]
    async fn the_contextual_reject_cache_is_per_tip_and_bounded() {
        let net = idle_network().await;
        let mut st = net.inner.state();
        let tip = [7; 32];
        let n = CAPACITY;
        for i in 0..n {
            ctx_reject(&mut st, id(i), tip);
        }
        assert_eq!(st.ctx_rejects.len(), 10_000);
        assert!(ctx_rejected(&st, &id(0), &tip) && ctx_rejected(&st, &id(n - 1), &tip));
        assert!(!ctx_rejected(&st, &id(0), &[8; 32]), "another tip");
        ctx_reject(&mut st, id(n), tip);
        assert_eq!(st.ctx_rejects.len(), 1, "full: started afresh");
        assert!(ctx_rejected(&st, &id(n), &tip) && !ctx_rejected(&st, &id(0), &tip));
        ctx_reject(&mut st, id(1), [8; 32]);
        assert_eq!(st.ctx_rejects.len(), 1, "a new tip: started afresh");
        assert!(ctx_rejected(&st, &id(1), &[8; 32]) && !ctx_rejected(&st, &id(n), &tip));
    }
}
