//! Header-first sync: header requests, the header queue and worker, the
//! anti-DoS work threshold, header verification and header error scoring.

use super::blocks::schedule_downloads;
use super::fatal;
use super::state::{
    unix_now, upgrade_reporter_key, HeaderBatch, Inner, State, UNKNOWN_UPGRADE_DISCONNECT,
};
use crate::addr::NetAddr;
use crate::dandelion::PeerId;
use crate::limits::score;
use crate::message::{Message, MAX_HEADERS};
use blacksilk_consensus::{seed_height, BlockHeader, Hash, HeaderChain, HeaderError};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub(super) const HEADERS_TIMEOUT: Duration = Duration::from_secs(60);

/// The origin a queued header batch is charged to: the sender's IP (port
/// dropped), or the whole address for onion peers.
fn queue_key(addr: &NetAddr) -> NetAddr {
    match addr {
        NetAddr::Ip(a) => NetAddr::Ip(SocketAddr::new(a.ip(), 0)),
        other => other.clone(),
    }
}

impl Inner {
    /// Whether a header batch from `addr` may be queued now: at most
    /// `max_per_ip` batches per origin (not enforced for loopback-style
    /// `allow_private` setups, like the connection limit) and
    /// `2 × (max_inbound + max_outbound)` in total.
    pub(super) fn header_queue_room(&self, st: &State, addr: &NetAddr) -> bool {
        let total = 2 * (self.cfg.max_inbound + self.cfg.max_outbound).max(1);
        if st.header_queue_len >= total {
            return false;
        }
        self.cfg.allow_private
            || st
                .header_queue_origin
                .get(&queue_key(addr))
                .is_none_or(|&n| n < self.cfg.max_per_ip.max(1))
    }

    /// `peer` sent a header whose version no epoch of this node's schedule
    /// uses, with valid proof of work (`HeaderError::UnknownUpgrade`, confirmed
    /// by `validate`; RT-1). Not scored, since the peer may run a newer release
    /// that is right. After [`UNKNOWN_UPGRADE_DISCONNECT`] such headers the peer
    /// is disconnected without a ban. The operator is warned once, and only
    /// past a peer-count or work threshold (`state::UNKNOWN_UPGRADE_WARN_PEERS`,
    /// `UpgradeWork::heavy`), counting only reports from outbound peers whose
    /// header passes the anti-DoS work threshold (RTW1-1, `UpgradeReports`).
    pub(super) fn note_unknown_upgrade(&self, peer: PeerId, version: u32, work: UpgradeWork) {
        let (verdict, addr) = {
            let mut st = self.state();
            let Some(p) = st.peers.get_mut(&peer) else {
                return;
            };
            p.unknown_upgrades = p.unknown_upgrades.saturating_add(1);
            let (count, addr) = (p.unknown_upgrades, p.addr.clone());
            let qualifying = (!p.inbound && work.threshold)
                .then(|| upgrade_reporter_key(&addr, self.cfg.allow_private));
            let verdict = st.upgrades.report(qualifying, count, work.heavy);
            if verdict.disconnect {
                if let Some(p) = st.peers.get(&peer) {
                    p.kill.notify_one();
                }
            }
            (verdict, addr)
        };
        log::info!(
            "peer {addr} sent a header of unknown version {version} with valid proof of work"
        );
        if verdict.disconnect {
            log::info!(
                "disconnecting peer {addr} (not banned): {UNKNOWN_UPGRADE_DISCONNECT} headers \
                 of an unknown consensus version"
            );
        }
        if verdict.warn {
            log::warn!(
                "peers are on a newer consensus version (header version {version} with valid \
                 proof of work{}); this node may need an upgrade",
                if work.heavy {
                    ", on a branch with at least our best chain's work"
                } else {
                    ", from several outbound peers"
                }
            );
        }
    }

    /// Asks `peer` for headers after our best header chain.
    pub(super) async fn request_headers(self: &Arc<Self>, peer: PeerId) {
        self.request_headers_after(peer, None).await;
    }

    /// Asks `peer` for headers. With `from`, the locator starts at that header
    /// (the last one of the batch the peer just sent), then continues with our
    /// best chain: the peer continues where it stopped even when its branch is
    /// not (yet) our best chain, as for a fork deeper than one batch.
    ///
    /// At most one `GetHeaders` is outstanding per peer: if another task (the
    /// maintenance loop, the header worker) already asked, this does nothing
    /// (the second reply would arrive unsolicited). The request is marked
    /// outstanding, under the same lock as that check, before the locator is
    /// read on a blocking thread.
    async fn request_headers_after(self: &Arc<Self>, peer: PeerId, from: Option<Hash>) {
        {
            let mut st = self.state();
            match st.peers.get_mut(&peer) {
                Some(p) if p.headers_requested.is_none() => {
                    p.headers_requested = Some(Instant::now());
                    p.headers_grace = None;
                    p.headers_pending = false;
                }
                _ => return,
            }
        }
        let mut locator = self.with_chain(|c| c.locator()).await;
        if let Some(id) = from {
            locator.retain(|h| *h != id);
            locator.insert(0, id);
            if locator.len() > crate::message::MAX_LOCATOR as usize {
                // Keep the last entry (genesis): drop the one before it.
                locator.remove(locator.len() - 2);
            }
        }
        let mut st = self.state();
        if let Some(p) = st.peers.get_mut(&peer) {
            p.headers_requested = Some(Instant::now());
            p.headers_grace = None;
            p.headers_pending = false;
        }
        self.send(
            &mut st,
            peer,
            Message::GetHeaders {
                locator,
                stop: [0; 32],
            },
        );
    }
}

pub(super) fn in_grace(grace: Option<Instant>, now: Instant) -> bool {
    grace.is_some_and(|t| now.duration_since(t) <= HEADERS_TIMEOUT)
}

/// Receives a `Headers` message on the peer's read loop. Only cheap checks run
/// here; the batch is verified by the header worker, so the read loop keeps
/// answering pings however long the proof of work takes (docs/p2p.md §6).
pub(super) async fn on_headers(inner: &Arc<Inner>, peer: PeerId, headers: Vec<BlockHeader>) {
    let nid = inner.cfg.network_id;
    // Only needed for an empty reply; read before the state lock (the two
    // locks are never held together).
    let ours = if headers.is_empty() {
        Some(inner.with_chain(|c| c.header_height()).await)
    } else {
        None
    };
    let penalty = {
        let mut st = inner.state();
        let room = st
            .peers
            .get(&peer)
            .is_some_and(|p| inner.header_queue_room(&st, &p.addr));
        let Some(p) = st.peers.get_mut(&peer) else {
            return;
        };
        let now = Instant::now();
        let solicited = if let Some(t) = p.headers_requested.take() {
            // One header may be a tip announcement that crossed our request:
            // the real (multi-header) reply may still come, once.
            p.headers_grace = (headers.len() == 1).then_some(t);
            true
        } else if headers.len() > 1 && in_grace(p.headers_grace, now) {
            p.headers_grace = None;
            true
        } else {
            false
        };
        if let Some(ours) = ours {
            // An empty answer: the peer has nothing after our locator. Stop
            // asking it every tick until it announces something new.
            if solicited {
                p.height = p.height.min(ours);
            }
            return;
        }
        if !solicited && headers.len() > 1 {
            // Unrequested headers are tip announcements: one header. A longer
            // batch would make us verify work we never asked for.
            Some((score::UNSOLICITED, "unrequested header batch"))
        } else if headers
            .windows(2)
            .any(|w| w[1].prev_id != w[0].id(nid) || w[1].height != w[0].height + 1)
        {
            Some((score::UNCONNECTED_HEADERS, "headers are not a chain"))
        } else if p.headers_busy || !room {
            // Still verifying this peer's previous batch, or the queue is
            // full (for this origin or in total): ask again afterwards.
            p.headers_pending = true;
            None
        } else {
            p.headers_busy = true;
            let batch = HeaderBatch {
                peer,
                addr: p.addr.clone(),
                proxied: p.proxied,
                solicited,
                headers,
            };
            let key = queue_key(&batch.addr);
            if inner.header_queue.send(batch).is_err() {
                p.headers_busy = false;
                log::error!("header worker stopped: header batch dropped");
            } else {
                st.header_queue_len += 1;
                *st.header_queue_origin.entry(key).or_default() += 1;
            }
            None
        }
    };
    if let Some((points, reason)) = penalty {
        inner.misbehave(peer, points, reason);
    }
}

/// Outcome of verifying one header batch.
enum HeaderOutcome {
    /// Every header is stored (new or already known). `last` is the height of
    /// the last one, `last_id` its id; `advanced`: the batch added headers, or
    /// ends on a stored branch that is not our best chain (a fork being
    /// fetched), so asking the peer for more is useful.
    Accepted {
        last: u64,
        last_id: Hash,
        advanced: bool,
    },
    /// The batch's cumulative work would not exceed our best header chain's
    /// (and it cannot be the start of a heavier branch, `low_work`): dropped
    /// without proof of work, without penalty and without re-requesting.
    LowWork,
    /// The first header does not connect to anything we know.
    Unconnected,
    /// A header failed; the ones before it are stored, unless the failure is
    /// one the sender is penalized for (then nothing is hashed or stored).
    Failed(HeaderError),
    /// The sender left or was banned before its batch was verified; only the
    /// cheap pre-check ran (a pre-check violation is still a `Failed`).
    Abandoned,
}

/// Header errors the sender is penalized for (see `on_header_error`).
fn penalized(e: &HeaderError) -> bool {
    !matches!(
        e,
        HeaderError::Duplicate
            | HeaderError::TimestampTooFarInFuture { .. }
            | HeaderError::InvalidParent
            | HeaderError::UnknownParent
            | HeaderError::UnknownUpgrade { .. }
    )
}

/// The work of the branch an unknown-version header (proof of work confirmed,
/// parent stored) extends, counted with the difficulty this node requires of
/// it, never the difficulty it claims (RTW1-1).
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct UpgradeWork {
    /// It reaches `anti_dos_threshold`: the report may count toward the
    /// operator warning (if its sender is an outbound peer).
    pub(super) threshold: bool,
    /// It reaches our best chain's work: a qualifying report warns at once.
    pub(super) heavy: bool,
}

impl UpgradeWork {
    fn of(hc: &HeaderChain, header: &BlockHeader) -> Self {
        let (Some(parent_work), Some(t)) =
            (hc.work(&header.prev_id), hc.template_on(header.prev_id))
        else {
            return Self::default();
        };
        let work = parent_work + t.difficulty as u128;
        Self {
            threshold: work >= anti_dos_threshold(hc),
            heavy: work >= hc.best_work(),
        }
    }
}

/// Whether `seed` is the RandomX key of the next block on our best chain, or
/// the key after it once the block holding it exists: the two keys
/// `RandomXPow` keeps built. An unknown-version header under any other key is
/// never hashed, so it cannot make the node build (and evict) a cache
/// (RTW1-1 (c)).
fn seed_is_live(hc: &HeaderChain, seed: &Hash) -> bool {
    let p = hc.params();
    let next = hc.height() + 1;
    [next, next + p.seed_epoch]
        .into_iter()
        .any(|h| hc.main_id_at(seed_height(h, p.seed_epoch, p.seed_lag)) == Some(*seed))
}

/// The RandomX key of `headers[i]`, on its own branch: `headers` is a linked
/// batch whose first header's parent is stored, one height below it (as
/// `ChainManager::pow_jobs` computes it).
fn batch_seed(hc: &HeaderChain, headers: &[BlockHeader], i: usize) -> Hash {
    let p = hc.params();
    let (first, h) = (&headers[0], &headers[i]);
    let sh = seed_height(h.height, p.seed_epoch, p.seed_lag);
    if sh >= first.height {
        headers[(sh - first.height) as usize].id(p.network_id)
    } else {
        hc.seed_id_for(first.prev_id, h.height)
    }
}

/// Verifies header batches one at a time (docs/p2p.md §6):
/// 1. every rule except proof of work, for the whole batch, before any RandomX
///    hash (`ChainManager::precheck_headers`); a violation the sender is
///    penalized for rejects the batch without any hash;
/// 2. headers already stored are skipped, and a batch whose work cannot beat
///    our best header chain is dropped (`low_work`);
/// 3. proof of work in chunks of `pow_threads` headers, each chunk accepted
///    before the next is hashed, so a batch that fails costs at most one
///    chunk of hashes beyond its last valid header.
///
/// One worker for all peers: batches from several peers covering the same
/// headers are hashed once (the second finds them stored). The queue is
/// bounded per origin and in total (`Inner::header_queue_room`); batches of
/// senders that left or were banned are only pre-checked.
pub(super) async fn header_worker(inner: Arc<Inner>, mut rx: mpsc::UnboundedReceiver<HeaderBatch>) {
    while let Some(mut batch) = rx.recv().await {
        let peer = batch.peer;
        let headers = std::mem::take(&mut batch.headers);
        let full = headers.len() as u64 == MAX_HEADERS;
        let count = headers.len();
        let last_height = headers.last().map_or(0, |h| h.height);
        let inner2 = inner.clone();
        let addr = batch.addr.clone();
        // Our header height after the batch is read on the same blocking
        // thread, so the peer's claimed height is corrected below under the
        // same state lock that ends `headers_busy`: the maintenance loop
        // never sees the peer idle with its stale (higher) height, which
        // would ask it again (R8-15 request loops).
        let result = tokio::task::spawn_blocking(move || {
            let outcome = verify_headers(&inner2, peer, &addr, &headers);
            let ours = inner2.chain().header_height();
            (outcome, ours)
        })
        .await;
        let (outcome, ours) = match result {
            Ok((outcome, ours)) => (Ok(outcome), ours),
            Err(e) => (Err(e), 0),
        };
        let pending = {
            let mut st = inner.state();
            st.header_queue_len = st.header_queue_len.saturating_sub(1);
            let key = queue_key(&batch.addr);
            if let Some(n) = st.header_queue_origin.get_mut(&key) {
                *n -= 1;
                if *n == 0 {
                    st.header_queue_origin.remove(&key);
                }
            }
            match st.peers.get_mut(&peer) {
                Some(p) => {
                    p.headers_busy = false;
                    match &outcome {
                        Ok(HeaderOutcome::Accepted { last, advanced, .. }) => {
                            p.height = p.height.max(*last);
                            if !advanced && batch.solicited {
                                // A solicited reply that taught us nothing:
                                // do not ask this peer again every tick.
                                p.height = p.height.min(ours.max(*last));
                            }
                        }
                        Ok(HeaderOutcome::LowWork) if batch.solicited => {
                            p.height = p.height.min(ours);
                        }
                        // After relaying headers of a block whose body is
                        // invalid, the peer is not asked again until it
                        // announces a new tip (`on_header_error`).
                        Ok(HeaderOutcome::Failed(HeaderError::InvalidParent)) => {
                            p.height = p.height.min(ours);
                        }
                        // Nothing past an unknown-version header is usable,
                        // hashed or not (RTW1-1): not asked again every tick.
                        Ok(HeaderOutcome::Failed(HeaderError::UnknownUpgrade { .. })) => {
                            p.height = p.height.min(ours);
                        }
                        _ => {}
                    }
                    std::mem::take(&mut p.headers_pending)
                }
                None => false,
            }
        };
        match outcome {
            Ok(HeaderOutcome::Accepted {
                last_id, advanced, ..
            }) => {
                log::debug!(
                    "peer {peer}: {count} headers up to height {last_height} accepted (new: {advanced})"
                );
                if full && advanced {
                    inner.request_headers_after(peer, Some(last_id)).await;
                } else if pending {
                    inner.request_headers(peer).await;
                }
            }
            Ok(HeaderOutcome::LowWork) => {
                log::debug!(
                    "peer {peer}: {count} headers up to height {last_height} do not beat our best chain; dropped"
                );
                // Not re-requested because of this batch. Headers the peer
                // sent meanwhile (e.g. the child that makes an equal-work
                // rival heavier) are asked for again.
                if pending {
                    inner.request_headers(peer).await;
                }
            }
            Ok(HeaderOutcome::Unconnected) => {
                // A gap or a deeper fork: fetch from our locator.
                if count > 1 {
                    inner.misbehave_departed(
                        &batch,
                        score::UNCONNECTED_HEADERS,
                        "headers do not connect",
                    );
                }
                inner.request_headers(peer).await;
            }
            Ok(HeaderOutcome::Failed(e)) => {
                on_header_error(&inner, &batch, e, last_height, pending).await
            }
            Ok(HeaderOutcome::Abandoned) => {}
            // `verify_headers` takes the chain lock: a panic there poisoned it.
            Err(e) if e.is_panic() => fatal(&format!("header task failed: {e}")),
            Err(_) => return, // the runtime is shutting down
        }
        schedule_downloads(&inner).await;
    }
}

/// Whether the sender of a queued batch is still connected and not banned.
fn sender_live(inner: &Inner, peer: PeerId, addr: &NetAddr) -> bool {
    let st = inner.state();
    st.peers.contains_key(&peer)
        && addr
            .ip()
            .is_none_or(|ip| !st.bans.is_banned(&ip, unix_now()))
}

/// Blocks of main-chain work below our best that a competing branch may lack
/// and still be verified and stored (R1-C1; Bitcoin Core's anti-DoS work
/// threshold uses 144 blocks as well).
const ANTI_DOS_BLOCKS: u64 = 144;

/// Claimed cumulative work a branch must reach to be hashed and stored:
/// `best_work - work(last ANTI_DOS_BLOCKS main blocks)`, i.e. the work of our
/// best chain at `tip - ANTI_DOS_BLOCKS`. There is no hard-coded minimum
/// chain work (docs/p2p.md §12).
fn anti_dos_threshold(hc: &HeaderChain) -> u128 {
    let base = hc.height().saturating_sub(ANTI_DOS_BLOCKS);
    hc.main_id_at(base).and_then(|id| hc.work(&id)).unwrap_or(0)
}

/// Whether headers `fresh` (linked, not stored, every rule but PoW checked,
/// the first one's parent stored) are worth their proof of work: RandomX
/// hashes are spent only on headers that can make a chain competitive with
/// our best one (docs/p2p.md §6). The difficulties are the required ones (the
/// pre-check passed, and the caller replaced the unchecked difficulty of an
/// unknown-version header by the required one, RTW1-1), so the sums below are
/// the work this node would count for the headers.
///
/// - The batch's claimed tip work reaches `anti_dos_threshold` (our best
///   work minus that of our last 144 blocks): verify. This covers every
///   extension of our best chain and near-tip competing branches.
/// - Otherwise, if the message was not a full batch (`MAX_HEADERS`), the
///   peer's branch ends here, far below our work: dropped.
/// - A full batch may be the start of a longer, heavier branch (a fork deeper
///   than one batch). It is verified only if its work per height is at least
///   half of our best chain's over the same heights (our tip's difficulty for
///   heights above our tip). Cheap branches (difficulty driven down with
///   spread-out timestamps) fail this; an honest competing branch, mined at
///   comparable difficulty, passes.
fn worth_verifying(hc: &HeaderChain, fresh: &[BlockHeader], full: bool) -> bool {
    let Some(first) = fresh.first() else {
        return true;
    };
    let Some(parent_work) = hc.work(&first.prev_id) else {
        return true; // not reached: the parent is stored
    };
    let batch: u128 = fresh.iter().map(|h| h.difficulty as u128).sum();
    if parent_work + batch >= anti_dos_threshold(hc) {
        return true;
    }
    if !full {
        return false;
    }
    let last = first.height + fresh.len() as u64 - 1;
    let tip = hc.height();
    let tip_difficulty = hc.tip().difficulty as u128;
    let ours = if first.height > tip {
        tip_difficulty * fresh.len() as u128
    } else {
        let top = last.min(tip);
        let work_at = |h: u64| hc.main_id_at(h).and_then(|id| hc.work(&id)).unwrap_or(0);
        work_at(top).saturating_sub(work_at(first.height - 1))
            + tip_difficulty * (last - top) as u128
    };
    batch.saturating_mul(2) >= ours
}

/// Pre-check, then chunked proof of work and acceptance. Runs on a blocking
/// thread; the chain lock is held only for the cheap steps, never while
/// hashing.
fn verify_headers(
    inner: &Inner,
    peer: PeerId,
    addr: &NetAddr,
    headers: &[BlockHeader],
) -> HeaderOutcome {
    let now = unix_now();
    let full = headers.len() as u64 == MAX_HEADERS;
    let live = sender_live(inner, peer, addr);
    if !live
        && addr
            .ip()
            .is_some_and(|ip| inner.state().bans.is_banned(&ip, now))
    {
        return HeaderOutcome::Abandoned;
    }
    let nid = inner.cfg.network_id;
    let (checked, fresh_range, worth, hash_unknown) = {
        let c = inner.chain();
        if c.header(&headers[0].prev_id).is_none() {
            return HeaderOutcome::Unconnected;
        }
        let checked = c.precheck_headers(headers, now);
        let good_end = match &checked {
            Ok(()) => headers.len(),
            Err((i, _)) => *i,
        };
        // A header of an unknown version is unconfirmed after the pre-check
        // (no proof of work yet): it is hashed with the batch, if the batch is
        // worth it, and only then classified (RT-1). Its claimed difficulty
        // was never checked, so it is charged the difficulty this node
        // requires at its position (RTW1-1 (a)); under a RandomX key that is
        // not live it is never hashed (RTW1-1 (c)).
        let hc = c.headers();
        let required = match &checked {
            Err((i, HeaderError::UnknownUpgrade { .. }))
                if seed_is_live(hc, &batch_seed(hc, headers, *i)) =>
            {
                hc.required_difficulty_after(headers[0].prev_id, &headers[..*i])
            }
            _ => None,
        };
        // Headers we already have (a prefix: a stored header cannot follow
        // an unstored one) cost nothing more.
        let start = headers[..good_end]
            .iter()
            .position(|h| c.header(&h.id(nid)).is_none())
            .unwrap_or(good_end);
        let worth = match required {
            Some(difficulty) => {
                let mut charged = headers[start..=good_end].to_vec();
                if let Some(unknown) = charged.last_mut() {
                    unknown.difficulty = difficulty;
                }
                worth_verifying(hc, &charged, full)
            }
            None => worth_verifying(hc, &headers[start..good_end], full),
        };
        (checked, start..good_end, worth, required.is_some())
    };
    let precheck_error = match checked {
        // A violation the sender is banned for: no hash for its batch.
        Err((_, e)) if penalized(&e) => return HeaderOutcome::Failed(e),
        Err((_, e)) => Some(e),
        Ok(()) => None,
    };
    if !live {
        return HeaderOutcome::Abandoned;
    }
    if !worth {
        return HeaderOutcome::LowWork;
    }
    let unknown_at = fresh_range.end;
    let fresh = &headers[fresh_range];
    let chunk = inner.cfg.pow_threads.max(1);
    let mut new = 0;
    for (k, part) in fresh.chunks(chunk).enumerate() {
        if k > 0 && !sender_live(inner, peer, addr) {
            return HeaderOutcome::Abandoned;
        }
        let jobs = inner.chain().pow_jobs(part);
        let Some((pow, jobs)) = jobs else {
            return HeaderOutcome::Unconnected;
        };
        pow.compute_parallel(&jobs, chunk);
        match inner.chain().accept_headers(part, now) {
            Ok(n) => new += n,
            Err((_, e)) => return HeaderOutcome::Failed(e),
        }
    }
    if let (Some(HeaderError::UnknownUpgrade { .. }), true) = (&precheck_error, hash_unknown) {
        // The unknown-version header's parent is now stored: hash it off the
        // chain lock, then let `validate` classify it (RT-1). Junk proof of work
        // is `InsufficientWork` (penalized); real work is `UnknownUpgrade`.
        let one = &headers[unknown_at..=unknown_at];
        let Some((pow, jobs)) = inner.chain().pow_jobs(one) else {
            return HeaderOutcome::Unconnected;
        };
        pow.compute_parallel(&jobs, 1);
        let mut c = inner.chain();
        match c.accept_headers(one, now) {
            Err((_, e)) => {
                if let HeaderError::UnknownUpgrade { version } = e {
                    let work = UpgradeWork::of(c.headers(), &one[0]);
                    drop(c);
                    inner.note_unknown_upgrade(peer, version, work);
                }
                return HeaderOutcome::Failed(e);
            }
            // Not reached: a header of an unknown version is never valid.
            Ok(n) => new += n,
        }
    } else if let Some(e) = precheck_error {
        return HeaderOutcome::Failed(e);
    }
    let last = headers.last().expect("a batch is not empty");
    let last_id = last.id(nid);
    let on_main = inner.chain().headers().is_on_main(&last_id);
    HeaderOutcome::Accepted {
        last: last.height,
        last_id,
        advanced: new > 0 || !on_main,
    }
}

/// Penalties for a failed header batch. Only failures a peer can check itself
/// from the headers are penalized:
/// - `InvalidParent` means the header descends from a block whose *body* we
///   found invalid. A peer relaying headers cannot know that without the body
///   (it may not have downloaded it yet, or its sender withholds it), so it is
///   not penalized; we stop asking it for headers until it announces again.
/// - `Duplicate` and `TimestampTooFarInFuture` are not permanent.
/// - `UnknownUpgrade`: the header's version is above every version this
///   node's schedule knows, and its proof of work is real (RT-1: with junk
///   proof of work it is `InsufficientWork`), so the peer probably runs a newer
///   release and may be right. It is not penalized; `verify_headers` counts it
///   (disconnect without a ban after `UNKNOWN_UPGRADE_DISCONNECT`) and warns
///   the operator only past the peer or work threshold (docs/consensus.md §11,
///   docs/p2p.md §6).
/// - Every other failure is a header that breaks the rules: the peer relayed
///   it without checking, and is penalized.
///
/// Headers that arrived from the peer meanwhile (`pending`) are asked for
/// again whenever the peer is not penalized.
async fn on_header_error(
    inner: &Arc<Inner>,
    batch: &HeaderBatch,
    e: HeaderError,
    last_height: u64,
    pending: bool,
) {
    let peer = batch.peer;
    match e {
        HeaderError::Duplicate | HeaderError::TimestampTooFarInFuture { .. } => {
            if pending {
                inner.request_headers(peer).await;
            }
        }
        HeaderError::UnknownParent => inner.request_headers(peer).await,
        // Counted (and the operator warned past the thresholds) by
        // `verify_headers`, once its proof of work was confirmed (RT-1).
        HeaderError::UnknownUpgrade { .. } => {}
        HeaderError::InvalidParent => {
            log::info!(
                "peer {peer} relays headers (up to height {last_height}) descending from a block with an invalid body"
            );
            // Its claimed height was lowered to ours by the header worker.
            if pending {
                inner.request_headers(peer).await;
            }
        }

        e => inner.misbehave_departed(
            batch,
            score::INVALID_HEADER,
            &format!("invalid header: {e}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_queue_origins_ignore_the_port() {
        let a = NetAddr::parse("1.2.3.4:5").unwrap();
        let b = NetAddr::parse("1.2.3.4:6").unwrap();
        assert_eq!(queue_key(&a), queue_key(&b));
        assert_ne!(
            queue_key(&a),
            queue_key(&NetAddr::parse("1.2.3.5:5").unwrap())
        );
    }

    /// A header from a newer release (a version no epoch of the schedule
    /// uses) is not scored; a bad version the schedule does know is.
    #[test]
    fn unknown_upgrades_are_not_penalized() {
        assert!(!penalized(&HeaderError::UnknownUpgrade { version: 9 }));
        assert!(penalized(&HeaderError::BadVersion {
            expected: 1,
            got: 0
        }));
        assert!(!penalized(&HeaderError::Duplicate));
        assert!(penalized(&HeaderError::InsufficientWork));
    }
}
