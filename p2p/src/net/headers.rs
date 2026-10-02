//! Header-first sync: header requests, the header queue and worker, header
//! verification and header error scoring. The anti-DoS work gate, the live
//! RandomX keys and the PoW chunk cap are `blacksilk_chain::sync_policy`'s,
//! shared with the RPC `/block` gate.

use super::blocks::schedule_downloads;
use super::fatal;
use super::state::{
    unix_now, upgrade_reporter_key, HeaderBatch, Inner, State, UNKNOWN_UPGRADE_DISCONNECT,
};
use crate::addr::NetAddr;
use crate::clock::{Accepted, ClockLevel};
use crate::dandelion::PeerId;
use crate::limits::score;
use crate::message::{Message, MAX_HEADERS};
use blacksilk_chain::actor::Lane;
use blacksilk_chain::manager::{CachedPow, ChainManager, PowJob};
use blacksilk_chain::sync_policy::{anti_dos_threshold, pow_chunk, seed_is_live, worth_verifying};
use blacksilk_consensus::{seed_height, BlockHeader, Hash, HeaderChain, HeaderError};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::ops::Range;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub(super) const HEADERS_TIMEOUT: Duration = Duration::from_secs(60);
/// The most `GetHeaders` replies a peer may still owe once nothing is
/// outstanding (`Peer::headers_grace`). One is added per request we sent,
/// so this bounds only memory.
pub(super) const MAX_HEADER_GRACE: usize = 8;

/// The origin a queued header batch is charged to: the sender's IP (port
/// dropped), or the whole address for onion peers and for peers whose IP is
/// not their own (`proxied`: those reaching our hidden service all share the
/// Tor daemon's IP).
fn queue_key(addr: &NetAddr, proxied: bool) -> NetAddr {
    match addr {
        NetAddr::Ip(a) if !proxied => NetAddr::Ip(SocketAddr::new(a.ip(), 0)),
        other => other.clone(),
    }
}

impl Inner {
    /// Whether a header batch from `addr` may be queued now: at most
    /// `max_per_ip` batches per origin (not enforced for loopback-style
    /// `allow_private` setups, like the connection limit) and
    /// `2 × (max_inbound + max_outbound)` in total.
    pub(super) fn header_queue_room(&self, st: &State, addr: &NetAddr, proxied: bool) -> bool {
        let total = 2 * (self.cfg.max_inbound + self.cfg.max_outbound).max(1);
        if st.header_queue_len >= total {
            return false;
        }
        self.cfg.allow_private
            || st
                .header_queue_origin
                .get(&queue_key(addr, proxied))
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
    /// outstanding, under the same lock as that check. The locator is the
    /// published chain snapshot's (never a chain command): the actor
    /// republishes it after every command that changes the best header chain.
    async fn request_headers_after(self: &Arc<Self>, peer: PeerId, from: Option<Hash>) {
        {
            let mut st = self.state();
            match st.peers.get_mut(&peer) {
                Some(p) if p.headers_requested.is_none() => {
                    p.headers_requested = Some(Instant::now());
                    p.headers_pending = false;
                }
                _ => return,
            }
        }
        let mut locator = self.summary.load().locator.clone();
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

/// Drops the expired entries of `grace` (older than `HEADERS_TIMEOUT`);
/// then whether a reply is still owed.
pub(super) fn in_grace(grace: &mut VecDeque<Instant>, now: Instant) -> bool {
    while grace
        .front()
        .is_some_and(|t| now.duration_since(*t) > HEADERS_TIMEOUT)
    {
        grace.pop_front();
    }
    !grace.is_empty()
}

/// Takes one owed reply (the oldest) from `grace`, if any is still owed.
pub(super) fn take_grace(grace: &mut VecDeque<Instant>, now: Instant) -> bool {
    in_grace(grace, now) && grace.pop_front().is_some()
}

/// Remembers that the reply to a request sent at `t` may still come.
pub(super) fn add_grace(grace: &mut VecDeque<Instant>, t: Instant) {
    if grace.len() >= MAX_HEADER_GRACE {
        grace.pop_front();
    }
    grace.push_back(t);
}

/// Receives a `Headers` message on the peer's read loop. Only cheap checks run
/// here; the batch is verified by the header worker, so the read loop keeps
/// answering pings however long the proof of work takes (docs/p2p.md §6).
pub(super) async fn on_headers(inner: &Arc<Inner>, peer: PeerId, headers: Vec<BlockHeader>) {
    let nid = inner.cfg.network_id;
    // Only needed for an empty reply: the published snapshot's (the read loop
    // never waits for the chain).
    let ours = headers
        .is_empty()
        .then(|| inner.summary.load().header_height);
    let penalty = {
        let mut st = inner.state();
        let room = st
            .peers
            .get(&peer)
            .is_some_and(|p| inner.header_queue_room(&st, &p.addr, p.proxied));
        let Some(p) = st.peers.get_mut(&peer) else {
            return;
        };
        let now = Instant::now();
        // Every `GetHeaders` gets exactly one `Headers` reply; a tip
        // announcement is one header, unrequested. A reply of other than one
        // header answers the outstanding request or, failing that, an owed
        // one (`headers_grace`): a slow peer, or a node slow to read, may
        // have two replies in flight. Before P2P-FIX2 a new request cancelled
        // the owed one, and its reply cost an honest peer 10 points.
        let solicited = if let Some(t) = p.headers_requested.take() {
            // One header may be a tip announcement that crossed our request:
            // the real reply may still come, once.
            if headers.len() == 1 {
                add_grace(&mut p.headers_grace, t);
            }
            true
        } else {
            headers.len() != 1 && take_grace(&mut p.headers_grace, now)
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
            let key = queue_key(&batch.addr, batch.proxied);
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
        /// The batch stored new headers and ends on our best header chain:
        /// the sender delivered a validated new tip (RTW3-4, outbound
        /// rotation).
        new_tip: bool,
        /// The cumulative work of the last header (`Peer::known_work`).
        work: u128,
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
/// 3. proof of work in chunks of `pow_threads` headers, at most `seed_lag`
///    (`sync_policy::pow_chunk`), each chunk accepted before the next is
///    hashed, so a batch that fails costs at most one chunk of hashes beyond
///    its last valid header, and no header is hashed under a key taken from
///    an unverified header of its own chunk (F07-4).
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
        // Our header height after the batch is read before the peer's
        // claimed height is corrected below under the same state lock that
        // ends `headers_busy`, so the maintenance loop never sees the peer
        // idle with its stale (higher) height, which would ask it again
        // (R8-15 request loops). The snapshot is published before the
        // actor answers the batch's last command, so it includes the batch.
        let result = tokio::task::spawn_blocking(move || {
            let outcome = verify_headers(&inner2, peer, &addr, &headers);
            let ours = inner2.summary.load().header_height;
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
            let key = queue_key(&batch.addr, batch.proxied);
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
                        Ok(HeaderOutcome::Accepted {
                            last,
                            last_id,
                            advanced,
                            new_tip,
                            work,
                        }) => {
                            // The sender has this header (announcements,
                            // `Peer::wants_tip`).
                            p.has_header(*last_id, *work);
                            if *new_tip {
                                p.last_new_tip = Some(Instant::now());
                            }
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
            // A panic outside the actor (the PoW jobs): stop as for one in it.
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

/// The PoW work of one chunk (`ChainManager::pow_jobs`); `None` if the
/// chunk does not extend a known header.
type Jobs = Option<(Arc<CachedPow>, Vec<PowJob>)>;

/// What the first command of a batch found (`precheck`).
struct Prechecked {
    checked: Result<(), (usize, HeaderError)>,
    /// The headers not stored yet, up to the first failing one.
    fresh: Range<usize>,
    worth: bool,
    /// The failing header is of an unknown version and will be hashed.
    hash_unknown: bool,
    /// Headers per PoW chunk (`sync_policy::pow_chunk`).
    chunk: usize,
    /// The PoW jobs of the first fresh chunk.
    jobs: Jobs,
    /// The future time limit (for the clock monitor).
    ftl: u64,
}

/// The first command of a batch (one former lock hold, plus the first
/// chunk's PoW jobs, formerly the next hold): every rule except proof of
/// work, the stored prefix, the work gate. `None` if the batch does not
/// connect to a known header.
fn precheck(
    c: &ChainManager,
    headers: &[BlockHeader],
    now: u64,
    full: bool,
    pow_threads: usize,
) -> Option<Prechecked> {
    let nid = c.params().network_id;
    c.header(&headers[0].prev_id)?;
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
    let chunk = pow_chunk(pow_threads, c.params());
    let first = start..good_end.min(start + chunk);
    let jobs = if first.is_empty() || !worth {
        None
    } else {
        c.pow_jobs(&headers[first])
    };
    Some(Prechecked {
        checked,
        fresh: start..good_end,
        worth,
        hash_unknown: required.is_some(),
        chunk,
        jobs,
        ftl: c.params().future_time_limit,
    })
}

/// Pre-check, then chunked proof of work and acceptance. Runs on a blocking
/// thread; the chain actor runs only the cheap steps (Headers lane), never
/// the hashing. A batch of `k` fresh chunks costs `k + 1` commands: the
/// pre-check with the first chunk's jobs, then each chunk's acceptance with
/// the next chunk's jobs (adjacent former lock holds merged: a schedule the
/// lock allowed). Each command waits for at most one drain step
/// (docs/p2p.md §10, test L7).
fn verify_headers(
    inner: &Inner,
    peer: PeerId,
    addr: &NetAddr,
    headers: &[BlockHeader],
) -> HeaderOutcome {
    let now = unix_now();
    // Our best header height when the batch is taken up (the clock
    // monitor's live-arrival test).
    let ours_before = inner.summary.load().header_height;
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
    let batch: Arc<[BlockHeader]> = headers.into();
    let b = batch.clone();
    let pow_threads = inner.cfg.pow_threads;
    let Some(pre) = inner.chain_blocking(Lane::Headers, move |c| {
        precheck(c, &b, now, full, pow_threads)
    }) else {
        return HeaderOutcome::Abandoned; // the node is stopping
    };
    let Some(Prechecked {
        checked,
        fresh,
        worth,
        hash_unknown,
        chunk,
        mut jobs,
        ftl,
    }) = pre
    else {
        return HeaderOutcome::Unconnected;
    };
    if let Err((i, HeaderError::TimestampTooFarInFuture { .. })) = &checked {
        // Unverified: remembered, a sample only if accepted later
        // (`crate::clock`).
        inner.clock().note_future_refusal(headers[*i].id(nid), now);
    }
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
    let unknown_at = fresh.end;
    let last = headers.last().expect("a batch is not empty");
    let last_id = last.id(nid);
    let parts: Vec<Range<usize>> = fresh
        .clone()
        .step_by(chunk)
        .map(|i| i..(i + chunk).min(fresh.end))
        .collect();
    let mut new = 0;
    // Whether the last header is on our best header chain, and its work.
    let mut on_main = None;
    for (k, part) in parts.iter().enumerate() {
        if k > 0 && !sender_live(inner, peer, addr) {
            return HeaderOutcome::Abandoned;
        }
        let Some((pow, j)) = jobs.take() else {
            return HeaderOutcome::Unconnected;
        };
        pow.compute_parallel(&j, chunk);
        let (b, part, next) = (batch.clone(), part.clone(), parts.get(k + 1).cloned());
        let Some((accepted, next_jobs, main)) = inner.chain_blocking(Lane::Headers, move |c| {
            let accepted = c.accept_headers(&b[part], now);
            let next_jobs = match (&accepted, next) {
                (Ok(_), Some(n)) => c.pow_jobs(&b[n]),
                _ => None,
            };
            (accepted, next_jobs, end_of(c, &last_id))
        }) else {
            return HeaderOutcome::Abandoned;
        };
        match accepted {
            Ok(n) => new += n,
            Err((_, e)) => return HeaderOutcome::Failed(e),
        }
        note_clock(inner, peer, &batch[parts[k].clone()], false, now, ftl);
        jobs = next_jobs;
        on_main = Some(main);
    }
    if let (Some(HeaderError::UnknownUpgrade { .. }), true) = (&precheck_error, hash_unknown) {
        // The unknown-version header's parent is now stored: hash it off the
        // actor, then let `validate` classify it (RT-1). Junk proof of work
        // is `InsufficientWork` (penalized); real work is `UnknownUpgrade`.
        let one = unknown_at..unknown_at + 1;
        let (b, o) = (batch.clone(), one.clone());
        let Some(jobs) = inner.chain_blocking(Lane::Headers, move |c| c.pow_jobs(&b[o])) else {
            return HeaderOutcome::Abandoned;
        };
        let Some((pow, jobs)) = jobs else {
            return HeaderOutcome::Unconnected;
        };
        pow.compute_parallel(&jobs, 1);
        let b = batch.clone();
        let Some((accepted, work)) = inner.chain_blocking(Lane::Headers, move |c| {
            let accepted = c.accept_headers(&b[one.clone()], now);
            let work = match &accepted {
                Err((_, HeaderError::UnknownUpgrade { .. })) => {
                    Some(UpgradeWork::of(c.headers(), &b[one.start]))
                }
                _ => None,
            };
            (accepted, work)
        }) else {
            return HeaderOutcome::Abandoned;
        };
        match accepted {
            Err((_, e)) => {
                if let (HeaderError::UnknownUpgrade { version }, Some(work)) = (&e, work) {
                    inner.note_unknown_upgrade(peer, *version, work);
                }
                return HeaderOutcome::Failed(e);
            }
            // Not reached: a header of an unknown version is never valid.
            Ok(n) => {
                new += n;
                on_main = None;
            }
        }
    } else if let Some(e) = precheck_error {
        return HeaderOutcome::Failed(e);
    }
    let (on_main, work) = match on_main {
        Some(m) => m,
        None => {
            let Some(m) = inner.chain_blocking(Lane::Headers, move |c| end_of(c, &last_id)) else {
                return HeaderOutcome::Abandoned;
            };
            m
        }
    };
    // A live arrival: the batch extended the best header chain outside bulk
    // sync. Its last header is a sample of the clock monitor.
    if new > 0 && on_main && !full && last.height > ours_before {
        note_clock(inner, peer, std::slice::from_ref(last), true, now, ftl);
    }
    HeaderOutcome::Accepted {
        last: last.height,
        last_id,
        advanced: new > 0 || !on_main,
        new_tip: new > 0 && on_main,
        work,
    }
}

/// Whether the stored header `id` is on our best header chain, and its
/// cumulative work (0 if it is not stored).
fn end_of(c: &ChainManager, id: &Hash) -> (bool, u128) {
    let hc = c.headers();
    (hc.is_on_main(id), hc.work(id).unwrap_or(0))
}

/// Feeds the clock monitor (`crate::clock`) with headers just accepted, their
/// proof of work verified, that arrived from `peer` at local time `arrival`:
/// each is a sample if it was refused by the future time limit before, and
/// the last one also if `live_last`. Logs what the monitor reports.
fn note_clock(
    inner: &Inner,
    peer: PeerId,
    accepted: &[BlockHeader],
    live_last: bool,
    arrival: u64,
    ftl: u64,
) {
    let nid = inner.cfg.network_id;
    let mono = Instant::now();
    let mut reports = Vec::new();
    {
        let mut clock = inner.clock();
        for (i, h) in accepted.iter().enumerate() {
            let live = live_last && i + 1 == accepted.len();
            if !live && !clock.has_refusals() {
                continue;
            }
            let a = Accepted {
                id: h.id(nid),
                timestamp: h.timestamp,
                peer,
                arrival,
                live,
            };
            reports.extend(clock.note_accepted(a, ftl, mono));
        }
    }
    for r in reports {
        match r.level {
            ClockLevel::Error => log::error!("{}", r.message),
            ClockLevel::Warn => log::warn!("{}", r.message),
            ClockLevel::Normal => log::info!("{}", r.message),
        }
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
        assert_eq!(queue_key(&a, false), queue_key(&b, false));
        assert_ne!(
            queue_key(&a, false),
            queue_key(&NetAddr::parse("1.2.3.5:5").unwrap(), false)
        );
        // Onion peers through our hidden service: one origin per connection.
        let (o1, o2) = (
            NetAddr::parse("127.0.0.1:50001").unwrap(),
            NetAddr::parse("127.0.0.1:50002").unwrap(),
        );
        assert_ne!(queue_key(&o1, true), queue_key(&o2, true));
    }

    /// A network over a fresh regtest chain with `cfg`, listening nowhere
    /// (the queue-room tests need only its state).
    async fn idle_network(edit: impl FnOnce(&mut crate::NetConfig)) -> crate::Network {
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
        let mut cfg = crate::NetConfig::new(p.network_id);
        cfg.listen = None;
        edit(&mut cfg);
        crate::Network::start(cfg, Arc::new(std::sync::Mutex::new(m)))
            .await
            .unwrap()
    }

    /// The header queue takes at most `max_per_ip` batches per origin (not
    /// with `allow_private`) and `2 × (max_inbound + max_outbound)` in total
    /// (mutation run E: the total had no test). Defaults: 64 inbound, 8
    /// outbound, 2 per IP: 144 in total.
    #[tokio::test]
    async fn the_header_queue_has_room_per_origin_and_in_total() {
        let a = NetAddr::parse("1.2.3.4:5").unwrap();
        let a2 = NetAddr::parse("1.2.3.4:6").unwrap();
        let b = NetAddr::parse("5.6.7.8:5").unwrap();
        let net = idle_network(|_| {}).await;
        let inner = &net.inner;
        {
            let mut st = inner.state();
            st.header_queue_len = 143;
            assert!(inner.header_queue_room(&st, &a, false), "143 of 144");
            st.header_queue_len = 144;
            assert!(!inner.header_queue_room(&st, &a, false), "144 of 144");
            st.header_queue_len = 1;
            st.header_queue_origin.insert(queue_key(&a, false), 1);
            assert!(inner.header_queue_room(&st, &a, false), "1 of 2 for the IP");
            st.header_queue_origin.insert(queue_key(&a, false), 2);
            assert!(
                !inner.header_queue_room(&st, &a, false),
                "2 of 2 for the IP"
            );
            assert!(!inner.header_queue_room(&st, &a2, false), "the same IP");
            assert!(inner.header_queue_room(&st, &b, false), "another IP");
            assert!(inner.header_queue_room(&st, &a2, true), "a proxied origin");
        }
        // `allow_private`: no limit per origin, the total still holds.
        let net = idle_network(|c| c.allow_private = true).await;
        {
            let inner = &net.inner;
            let mut st = inner.state();
            st.header_queue_origin.insert(queue_key(&a, false), 50);
            st.header_queue_len = 143;
            assert!(inner.header_queue_room(&st, &a, false));
            st.header_queue_len = 144;
            assert!(!inner.header_queue_room(&st, &a, false));
        }
        // Zero limits count as one: one batch per origin, two in total.
        let net = idle_network(|c| {
            c.max_inbound = 0;
            c.max_outbound = 0;
            c.max_per_ip = 0;
        })
        .await;
        let inner = &net.inner;
        let mut st = inner.state();
        assert!(inner.header_queue_room(&st, &a, false));
        st.header_queue_origin.insert(queue_key(&a, false), 1);
        st.header_queue_len = 1;
        assert!(
            !inner.header_queue_room(&st, &a, false),
            "1 of 1 for the IP"
        );
        assert!(inner.header_queue_room(&st, &b, false), "1 of 2 in total");
        st.header_queue_len = 2;
        assert!(!inner.header_queue_room(&st, &b, false), "2 of 2 in total");
    }

    /// At most one `GetHeaders` is outstanding per peer (mutation run E: the
    /// guard in `request_headers_after` had no test; under it another task
    /// asking while a request is outstanding sends nothing). A raw peer
    /// claiming more height gets the handshake's request; two more requests
    /// while it is unanswered send nothing: the node's next control frame,
    /// its answer to a ping sent after them, follows the one `GetHeaders`.
    #[tokio::test]
    async fn a_second_header_request_waits_for_the_outstanding_one() {
        use crate::message::{Message, Version, PROTOCOL_VERSION};
        let net = idle_network(|c| {
            c.listen = Some("127.0.0.1:0".parse().unwrap());
            c.allow_private = true;
            c.tick = std::time::Duration::from_secs(600);
        })
        .await;
        let inner = net.inner.clone();
        let stream = tokio::net::TcpStream::connect(net.local_addr().unwrap())
            .await
            .unwrap();
        let (mut r, mut w) = crate::transport::handshake(
            stream,
            true,
            inner.cfg.network_id,
            &inner.genesis_id,
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();
        let v = Version {
            protocol: PROTOCOL_VERSION,
            network: inner.cfg.network_id,
            nonce: 0xdead_beef,
            height: 5,
            tip: [0; 32],
            listen: None,
            relay_txs: true,
        };
        w.send(&Message::Version(v).encode()).await.unwrap();
        let recv = |m: Vec<u8>| Message::decode(&m).unwrap();
        assert!(matches!(recv(r.recv().await.unwrap()), Message::Version(_)));
        w.send(&Message::Verack.encode()).await.unwrap();
        assert!(matches!(recv(r.recv().await.unwrap()), Message::Verack));
        // The handshake's request, then the peer's id.
        let mut get_headers = 0;
        loop {
            if let Message::GetHeaders { .. } = recv(r.recv().await.unwrap()) {
                get_headers += 1;
                break;
            }
        }
        let peer = *inner.state().peers.keys().next().expect("registered");
        inner.request_headers(peer).await;
        inner.request_headers_after(peer, Some([3; 32])).await;
        w.send(&Message::Ping(77).encode()).await.unwrap();
        loop {
            match recv(r.recv().await.unwrap()) {
                Message::Pong(77) => break,
                Message::GetHeaders { .. } => get_headers += 1,
                _ => {}
            }
        }
        assert_eq!(get_headers, 1, "one request outstanding at a time");
    }

    /// The owed replies (`headers_grace`, P2P-FIX2): a reply is owed for
    /// `HEADERS_TIMEOUT` after its request, and no longer; each owed reply
    /// is taken once, the oldest first; at most `MAX_HEADER_GRACE` are kept
    /// (mutation run E: the grace functions had no unit test).
    #[test]
    fn owed_header_replies_expire_and_are_taken_once() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut g = VecDeque::new();
        assert!(!in_grace(&mut g, t0));
        assert!(!take_grace(&mut g, t0), "nothing owed");
        add_grace(&mut g, t0);
        add_grace(&mut g, at(10));
        assert!(in_grace(&mut g, at(60)), "60 s: still owed");
        assert_eq!(g.len(), 2);
        assert!(in_grace(&mut g, at(61)), "the second is still owed");
        assert_eq!(g, [at(10)], "the first expired");
        assert!(take_grace(&mut g, at(61)));
        assert!(!take_grace(&mut g, at(61)), "taken once");
        add_grace(&mut g, t0);
        assert!(!take_grace(&mut g, at(61)), "an expired one is not taken");
        assert!(g.is_empty());
        for k in 0..MAX_HEADER_GRACE as u64 + 3 {
            add_grace(&mut g, at(k));
        }
        assert_eq!(g.len(), MAX_HEADER_GRACE);
        assert_eq!(MAX_HEADER_GRACE, 8);
        assert_eq!(g.front(), Some(&at(3)), "the oldest go first");
    }

    /// A request after a batch starts its locator at the batch's last
    /// header, once, then our best chain down to the genesis (mutation run
    /// E: the locator's edit had no test). A fresh node's own locator is the
    /// genesis alone.
    #[tokio::test]
    async fn a_request_after_a_batch_starts_its_locator_at_the_batch() {
        use crate::message::{Message, Version, PROTOCOL_VERSION};
        let net = idle_network(|c| {
            c.listen = Some("127.0.0.1:0".parse().unwrap());
            c.allow_private = true;
            c.tick = Duration::from_secs(600);
        })
        .await;
        let inner = net.inner.clone();
        let stream = tokio::net::TcpStream::connect(net.local_addr().unwrap())
            .await
            .unwrap();
        let (mut r, mut w) = crate::transport::handshake(
            stream,
            true,
            inner.cfg.network_id,
            &inner.genesis_id,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        // At height 0 with the genesis as its tip: the node asks nothing.
        let v = Version {
            protocol: PROTOCOL_VERSION,
            network: inner.cfg.network_id,
            nonce: 0xdead_beef,
            height: 0,
            tip: inner.genesis_id,
            listen: None,
            relay_txs: true,
        };
        w.send(&Message::Version(v).encode()).await.unwrap();
        let recv = |m: Vec<u8>| Message::decode(&m).unwrap();
        assert!(matches!(recv(r.recv().await.unwrap()), Message::Version(_)));
        w.send(&Message::Verack.encode()).await.unwrap();
        assert!(matches!(recv(r.recv().await.unwrap()), Message::Verack));
        let peer = loop {
            if let Some(id) = inner.state().peers.keys().next().copied() {
                break id;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let genesis = inner.genesis_id;
        for from in [[4; 32], genesis] {
            inner.request_headers_after(peer, Some(from)).await;
            let locator = loop {
                if let Message::GetHeaders { locator, .. } = recv(r.recv().await.unwrap()) {
                    break locator;
                }
            };
            if from == genesis {
                assert_eq!(locator, [genesis], "the genesis once");
            } else {
                assert_eq!(locator, [from, genesis]);
            }
            // Answered (empty): the next request may go.
            w.send(&Message::Headers(vec![]).encode()).await.unwrap();
            while inner
                .state()
                .peers
                .get(&peer)
                .is_some_and(|p| p.headers_requested.is_some())
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    /// Once the worker has taken up a queued batch, its origin's count
    /// drops back, and an origin with nothing queued leaves the map
    /// (mutation run E: with `allow_private`, as in the network tests, the
    /// per-origin count is never read, so nothing noticed a count that never
    /// fell). One solicited header, then a second.
    #[tokio::test]
    async fn the_header_queue_counts_return_to_zero_after_the_worker() {
        use crate::message::{Message, Version, PROTOCOL_VERSION};
        let net = idle_network(|c| {
            c.listen = Some("127.0.0.1:0".parse().unwrap());
            c.allow_private = true;
            c.tick = Duration::from_millis(50);
        })
        .await;
        let inner = net.inner.clone();
        let stream = tokio::net::TcpStream::connect(net.local_addr().unwrap())
            .await
            .unwrap();
        let (mut r, mut w) = crate::transport::handshake(
            stream,
            true,
            inner.cfg.network_id,
            &inner.genesis_id,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let v = Version {
            protocol: PROTOCOL_VERSION,
            network: inner.cfg.network_id,
            nonce: 0xdead_beef,
            height: 5,
            tip: [0; 32],
            listen: None,
            relay_txs: true,
        };
        w.send(&Message::Version(v).encode()).await.unwrap();
        let recv = |m: Vec<u8>| Message::decode(&m).unwrap();
        assert!(matches!(recv(r.recv().await.unwrap()), Message::Version(_)));
        w.send(&Message::Verack.encode()).await.unwrap();
        assert!(matches!(recv(r.recv().await.unwrap()), Message::Verack));
        // Two headers on the genesis, one per request.
        struct ZeroPow;
        impl blacksilk_consensus::PowFunction for ZeroPow {
            fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
                [0; 32]
            }
        }
        let mut g = HeaderChain::new(
            blacksilk_consensus::ChainParams::regtest(),
            Arc::new(ZeroPow),
        );
        for k in 0..2u64 {
            let t = g.template();
            let parent = *g.header(&t.prev_id).unwrap();
            let h = BlockHeader {
                version: t.version,
                height: t.height,
                prev_id: t.prev_id,
                timestamp: t.min_timestamp.max(parent.timestamp + 10),
                difficulty: t.difficulty,
                tx_root: [0; 32],
                nonce: k,
            };
            g.accept(h, u64::MAX / 2).unwrap();
            loop {
                if let Message::GetHeaders { .. } = recv(r.recv().await.unwrap()) {
                    break;
                }
            }
            w.send(&Message::Headers(vec![h]).encode()).await.unwrap();
            w.send(&Message::Ping(k).encode()).await.unwrap();
            loop {
                if matches!(recv(r.recv().await.unwrap()), Message::Pong(x) if x == k) {
                    break;
                }
            }
            // Taken up by the worker: the header is stored.
            let mut waited = 0;
            while inner.summary.load().header_height < k + 1 || inner.state().header_queue_len > 0 {
                assert!(waited < 500, "the batch is never taken up");
                waited += 1;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let st = inner.state();
            assert_eq!(st.header_queue_len, 0);
            assert!(
                st.header_queue_origin.is_empty(),
                "{:?}",
                st.header_queue_origin
            );
        }
    }

    /// A queued batch whose sender has left and is banned is abandoned
    /// before any chain command (not even the pre-check runs: its result
    /// could only charge a sender already banned); a departed sender that
    /// is not banned still has its batch pre-checked, and a rule-breaking
    /// one is `Failed` (mutation run E: the network tests use loopback
    /// peers, which are never IP-banned, so the first branch had no test).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_banned_departed_senders_batch_is_abandoned_unchecked() {
        let net = idle_network(|_| {}).await;
        let inner = net.inner.clone();
        // A header that breaks a rule (difficulty), on the genesis.
        struct ZeroPow;
        impl blacksilk_consensus::PowFunction for ZeroPow {
            fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
                [0; 32]
            }
        }
        let g = HeaderChain::new(
            blacksilk_consensus::ChainParams::regtest(),
            Arc::new(ZeroPow),
        );
        let t = g.template();
        let bad = BlockHeader {
            version: t.version,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t
                .min_timestamp
                .max(g.header(&t.prev_id).unwrap().timestamp + 10),
            difficulty: t.difficulty + 5,
            tx_root: [0; 32],
            nonce: 0,
        };
        let addr = NetAddr::parse("1.2.3.4:5").unwrap();
        let verify = |inner: Arc<Inner>| {
            let addr = addr.clone();
            tokio::task::spawn_blocking(move || verify_headers(&inner, 999, &addr, &[bad]))
        };
        // Departed (no peer 999), not banned: pre-checked, refused.
        match verify(inner.clone()).await.unwrap() {
            HeaderOutcome::Failed(HeaderError::BadDifficulty { .. }) => {}
            HeaderOutcome::Failed(e) => panic!("another failure: {e:?}"),
            _ => panic!("not failed"),
        }
        // Departed and banned: abandoned before the pre-check.
        inner
            .state()
            .bans
            .ban("1.2.3.4".parse().unwrap(), unix_now() + 3600);
        assert!(matches!(
            verify(inner.clone()).await.unwrap(),
            HeaderOutcome::Abandoned
        ));
    }

    /// `note_clock` feeds the clock monitor the headers just accepted: a
    /// header the future time limit refused before is a sample (and is no
    /// longer remembered as refused), in any position of any batch; of the
    /// others, only the last header of a live arrival is (mutation run E:
    /// the refusal path had no test, and the network tests cannot wait out
    /// regtest's 360 s limit).
    #[tokio::test]
    async fn note_clock_samples_refused_headers_and_live_arrivals() {
        let net = idle_network(|_| {}).await;
        let inner = net.inner.clone();
        let nid = inner.cfg.network_id;
        let header = |n: u64| BlockHeader {
            version: 1,
            height: n,
            prev_id: [0; 32],
            timestamp: 1_000 + n,
            difficulty: 1,
            tx_root: [0; 32],
            nonce: n,
        };
        // A refused header, accepted inside a batch that is not live.
        inner.clock().note_future_refusal(header(1).id(nid), 900);
        assert!(inner.clock().has_refusals());
        note_clock(&inner, 1, &[header(1), header(2)], false, 1_000, 360);
        assert!(!inner.clock().has_refusals(), "taken as a sample");
        // Live arrivals: only the last header of each batch.
        for (k, peer) in [1, 2, 3, 1].into_iter().enumerate() {
            let n = 10 + 2 * k as u64;
            note_clock(&inner, peer, &[header(n), header(n + 1)], true, 1_000, 360);
        }
        let e = inner.clock().estimate().expect("5 samples from 3 peers");
        assert_eq!((e.samples, e.peers), (5, 3));
        // Not live and nothing refused: no sample.
        note_clock(&inner, 2, &[header(30), header(31)], false, 1_000, 360);
        assert_eq!(inner.clock().estimate().unwrap().samples, 5);
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
