//! Header-chain checks on the blocks a wallet scans (dossier 39 W5, F39-10;
//! W3-39b).
//!
//! Without them a wallet trusts its node for proof of work: a node could
//! serve a forged block, for example one that hides an old spend from a
//! restored wallet, which would then spend the output again with a new ring
//! (the two rings intersect at the real input). The checks are those of
//! `blacksilk_consensus::HeaderChain`, on the headers the wallet receives:
//! - each header extends the previous one (height and `prev_id`) with the
//!   version its height's rule set requires;
//! - its difficulty is the LWMA rule's (`next_difficulty`) over its own
//!   ancestors, recomputed by the wallet;
//! - its timestamp is after the median time past and within the future
//!   time limit of the local clock;
//! - its RandomX hash (light mode) meets its difficulty: for every one of
//!   the node's last `DENSE_POW_TAIL` (720) headers and the first scanned
//!   one (the caller forces them, RTW3-5), and for a random sample of the
//!   others, drawn from the OS RNG as the headers arrive ([`HEADER_SAMPLES`]
//!   expected), so the node cannot know which ones are checked. A forged
//!   header forces the node to forge every header after it, so a forgery is
//!   a suffix of its chain: one within the last 720 headers is always
//!   caught, and a deeper one, covering a fraction `f` of the sampled
//!   headers, with probability about `1 − (1 − f)^HEADER_SAMPLES` besides.
//!   (Uniform sampling alone let a 4-header forged suffix pass most
//!   restores: RTW3-5.)
//!
//! **Anchored at the genesis.** Every check starts at the genesis
//! ([`HeaderCheck::from_genesis`]): the wallet reads the headers below the
//! blocks it scans from the node's header feed (`/headers`, 100 bytes each),
//! so the difficulty of every header, at any restore height, follows from
//! the genesis by the LWMA rule, and the sampled work is drawn from the whole
//! chain. A later check continues from the wallet's own last headers when
//! an earlier one checked them from the genesis ([`HeaderCheck::resume`]).
//! A node can therefore not serve a consistent chain at a lower difficulty
//! of its choice. It can still serve a chain it mined itself from the
//! genesis under the rule (timestamps spaced at the target keep the
//! difficulty at the genesis level): the check proves work under the rule,
//! not that the chain is the network's heaviest, which only other nodes can
//! show.
//!
//! On by default for restores (the first sync of a restored wallet),
//! opt-in for routine syncs (decisions, "Agent 39").
//!
//! **Parallel proof of work (W3-39c).** The dense tail alone is about 720
//! light-mode RandomX hashes, about 13 minutes on one thread. The cheap
//! checks run in order as headers arrive; the proof-of-work checks they
//! call for are queued ([`HeaderCheck::check_deferred`]) and computed
//! together ([`HeaderCheck::flush`]) on up to [`HeaderCheck::threads`]
//! scoped threads. The threads share the proof-of-work function, so the
//! one light cache per RandomX key that `RandomXPow` keeps is built once
//! and read by all of them (each hash runs its own light-mode VM over it).
//! The verdict is the one of checking header by header: the first header
//! that fails, in chain order, cheap check or proof of work, with its
//! message (`parallel_and_sequential_verdicts_agree` in the wallet's sync
//! tests).

use blacksilk_consensus::difficulty::next_difficulty;
use blacksilk_consensus::pow::{check_hash, seed_height};
use blacksilk_consensus::timestamp::median;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Headers whose proof of work is checked per sync, in expectation, below
/// the densely checked tail (module docs).
pub const HEADER_SAMPLES: u64 = 16;

/// Deferred proof-of-work checks are computed once this many are queued
/// ([`HeaderCheck::check_deferred`]): enough to keep every thread busy,
/// few enough that a forged header is caught soon.
pub const POW_BATCH: usize = 256;

/// A proof-of-work check the cheap checks called for, not computed yet.
struct PowJob {
    header: BlockHeader,
    seed: Hash,
}

/// Checks a run of headers from the genesis (module docs).
pub struct HeaderCheck<'a> {
    params: &'a ChainParams,
    pow: &'a dyn PowFunction,
    /// The last headers checked or given, oldest first, with their ids and
    /// cumulative difficulty (from the first one given).
    recent: VecDeque<(BlockHeader, Hash, u128)>,
    /// Ids of the blocks at RandomX key heights.
    seeds: HashMap<u64, Hash>,
    /// A header's work is checked when a draw is below this.
    threshold: u64,
    rng: ChaCha20Rng,
    now: u64,
    /// Proof-of-work checks queued, in chain order ([`Self::flush`]).
    pending: Vec<PowJob>,
    /// Threads [`Self::flush`] uses.
    threads: usize,
    /// The first refusal, with the height it was at: a check is spent after
    /// it (every later call returns it again).
    refused: Option<(u64, String)>,
    /// Headers whose proof of work was computed.
    pub pow_checked: u64,
}

impl<'a> HeaderCheck<'a> {
    /// A check from the genesis. `expected` is about how many headers will
    /// be checked (for the sampling rate), `samples` how many of them should
    /// have their work checked, and `now` the local time.
    pub fn from_genesis(
        params: &'a ChainParams,
        pow: &'a dyn PowFunction,
        expected: u64,
        samples: u64,
        now: u64,
    ) -> Result<Self, String> {
        Self::build(
            params,
            pow,
            std::slice::from_ref(&params.genesis),
            &[],
            expected,
            samples,
            now,
        )
    }

    /// A check continuing one that checked `start` from the genesis (the
    /// wallet's own last headers, [`HeaderCheck::last`]): consecutive
    /// headers, oldest first, either from the genesis or at least
    /// `max(difficulty_ancestors, median_time_window)` of them, with the ids
    /// of the RandomX key blocks below them (`seeds`, from the same check).
    /// The caller vouches that they were checked; nothing here can tell.
    pub fn resume(
        params: &'a ChainParams,
        pow: &'a dyn PowFunction,
        start: &[BlockHeader],
        seeds: &[(u64, Hash)],
        expected: u64,
        samples: u64,
        now: u64,
    ) -> Result<Self, String> {
        Self::build(params, pow, start, seeds, expected, samples, now)
    }

    fn build(
        params: &'a ChainParams,
        pow: &'a dyn PowFunction,
        start: &[BlockHeader],
        seeds_below: &[(u64, Hash)],
        expected: u64,
        samples: u64,
        now: u64,
    ) -> Result<Self, String> {
        let first = start.first().ok_or("no headers to start from")?;
        let nid = params.network_id;
        if first.height == 0 && *first != params.genesis {
            return Err("the node's genesis header is not this wallet's".into());
        }
        if first.height != 0 && start.len() < Self::context_len(params) {
            return Err("too few headers to recompute the difficulty".into());
        }
        let mut recent = VecDeque::new();
        let mut seeds: HashMap<u64, Hash> = seeds_below.iter().copied().collect();
        let mut cumulative = 0u128;
        for (i, h) in start.iter().enumerate() {
            let id = h.id(nid);
            if i > 0 {
                let (p, pid, _) = recent.back().expect("pushed");
                let p: &BlockHeader = p;
                if h.height != p.height + 1 || h.prev_id != *pid {
                    return Err(format!(
                        "header {} does not extend header {}",
                        h.height, p.height
                    ));
                }
            }
            cumulative += h.difficulty as u128;
            if h.height.is_multiple_of(params.seed_epoch) {
                seeds.insert(h.height, id);
            }
            recent.push_back((*h, id, cumulative));
        }
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| format!("OS RNG: {e}"))?;
        let threshold = if samples >= expected.max(1) {
            u64::MAX
        } else {
            ((u64::MAX as u128 * samples as u128) / expected.max(1) as u128) as u64
        };
        let mut check = HeaderCheck {
            params,
            pow,
            recent,
            seeds,
            threshold,
            rng: ChaCha20Rng::from_seed(seed),
            now,
            pending: Vec::new(),
            threads: std::thread::available_parallelism().map_or(1, |n| n.get()),
            refused: None,
            pow_checked: 0,
        };
        check.trim();
        Ok(check)
    }

    /// Threads the proof-of-work checks use (default: the machine's
    /// available parallelism; 1 computes them on the calling thread).
    pub fn threads(&self) -> usize {
        self.threads
    }

    /// The height of the header the check refused (for a header that does
    /// not extend the last one, the height expected next), if it refused
    /// one.
    pub fn refused_height(&self) -> Option<u64> {
        self.refused.as_ref().map(|r| r.0)
    }

    /// Sets [`Self::threads`] (at least 1).
    pub fn set_threads(&mut self, threads: usize) {
        self.threads = threads.max(1);
    }

    /// Headers a check keeps as the context of the next one.
    pub fn context_len(params: &ChainParams) -> usize {
        params.difficulty_ancestors().max(params.median_time_window)
    }

    /// Whether the id of the key block at `height` is known.
    pub fn has_seed(&self, height: u64) -> bool {
        self.seeds.contains_key(&height)
    }

    /// The ids of the RandomX key blocks checked or given, by height.
    pub fn seeds(&self) -> impl Iterator<Item = (u64, Hash)> + '_ {
        self.seeds.iter().map(|(h, id)| (*h, *id))
    }

    /// The last header checked (or given) and its id.
    pub fn last(&self) -> (BlockHeader, Hash) {
        let (h, id, _) = self.recent.back().expect("never empty");
        (*h, *id)
    }

    /// The headers the check holds, oldest first, without the genesis: the
    /// context a later check resumes from ([`Self::resume`]).
    pub fn context(&self) -> impl Iterator<Item = BlockHeader> + '_ {
        self.recent.iter().map(|e| e.0).filter(|h| h.height > 0)
    }

    fn trim(&mut self) {
        let keep = Self::context_len(self.params);
        while self.recent.len() > keep {
            self.recent.pop_front();
        }
    }

    /// Checks the next header; `force_pow` checks its work whatever the
    /// draw. On success the header joins the context. Proof-of-work checks
    /// queued before it are computed first ([`Self::flush`]).
    pub fn check(&mut self, header: &BlockHeader, force_pow: bool) -> Result<(), String> {
        self.check_deferred(header, force_pow)?;
        self.flush()
    }

    /// [`Self::check`] with the header's proof-of-work check, if it has
    /// one, queued: computed with others by [`Self::flush`], which the
    /// caller runs before it relies on the headers (at most [`POW_BATCH`]
    /// wait; more are computed here). The header joins the context at once,
    /// so the headers after it can be checked. A refusal is the first one in
    /// chain order: when a cheap check fails, the queued checks are computed
    /// first, and one of them that fails is the refusal instead.
    pub fn check_deferred(&mut self, header: &BlockHeader, force_pow: bool) -> Result<(), String> {
        if let Some((_, e)) = &self.refused {
            return Err(e.clone());
        }
        let queued = self.precheck(header, force_pow);
        if queued.is_err() || self.pending.len() >= POW_BATCH {
            self.flush()?;
        }
        if let Err(e) = &queued {
            let at = self.last().0.height + 1;
            self.refused = Some((at, e.clone()));
        }
        queued
    }

    /// Computes the queued proof-of-work checks, on [`Self::threads`]
    /// threads. Refuses with the first header, in chain order, whose hash
    /// does not meet its difficulty.
    pub fn flush(&mut self) -> Result<(), String> {
        if let Some((_, e)) = &self.refused {
            return Err(e.clone());
        }
        let jobs = std::mem::take(&mut self.pending);
        let computed = AtomicU64::new(0);
        let failed = first_failure(self.pow, &jobs, self.threads, &computed);
        self.pow_checked += computed.into_inner();
        match failed {
            None => Ok(()),
            Some(i) => {
                let e = format!(
                    "header {}'s proof of work does not meet its difficulty",
                    jobs[i].header.height
                );
                self.refused = Some((jobs[i].header.height, e.clone()));
                Err(e)
            }
        }
    }

    /// Every check of [`Self::check`] but the proof of work, which is
    /// queued.
    fn precheck(&mut self, header: &BlockHeader, force_pow: bool) -> Result<(), String> {
        let p = &self.params;
        let (parent, parent_id, parent_cum) = *self.recent.back().expect("never empty");
        let height = parent.height + 1;
        if header.height != height || header.prev_id != parent_id {
            return Err(format!(
                "header {} does not extend header {}",
                header.height, parent.height
            ));
        }
        let version = p.epoch_at(height).header_version;
        if header.version != version {
            return Err(format!(
                "header {height} has version {} where the rules require {version} (a consensus \
                 upgrade this wallet does not know, or a forged header)",
                header.version
            ));
        }
        let ancestors = p.difficulty_ancestors();
        let from = self.recent.len().saturating_sub(ancestors);
        let ts: Vec<u64> = self
            .recent
            .iter()
            .skip(from)
            .map(|e| e.0.timestamp)
            .collect();
        let cd: Vec<u128> = self.recent.iter().skip(from).map(|e| e.2).collect();
        let required = next_difficulty(
            &ts,
            &cd,
            p.target_block_time,
            p.difficulty_window,
            p.initial_difficulty,
        );
        if header.difficulty != required {
            return Err(format!(
                "header {height} claims difficulty {} where the LWMA rule gives {required}",
                header.difficulty
            ));
        }
        let mtp_from = self.recent.len().saturating_sub(p.median_time_window);
        let mtp_ts: Vec<u64> = self
            .recent
            .iter()
            .skip(mtp_from)
            .map(|e| e.0.timestamp)
            .collect();
        let mtp = median(&mtp_ts);
        if header.timestamp <= mtp {
            return Err(format!(
                "header {height}'s timestamp is not after the median time past"
            ));
        }
        if header.timestamp > self.now.saturating_add(p.future_time_limit) {
            return Err(format!("header {height}'s timestamp is in the future"));
        }
        let sampled = force_pow || self.rng.next_u64() <= self.threshold;
        // Every hash meets difficulty 1 (`check_hash`): nothing to compute.
        if sampled && header.difficulty > 1 {
            let key = seed_height(height, p.seed_epoch, p.seed_lag);
            let seed = *self.seeds.get(&key).ok_or_else(|| {
                format!("the RandomX key block {key} of header {height} is unknown")
            })?;
            self.pending.push(PowJob {
                header: *header,
                seed,
            });
        }
        let id = header.id(p.network_id);
        if height.is_multiple_of(p.seed_epoch) {
            self.seeds.insert(height, id);
        }
        self.recent
            .push_back((*header, id, parent_cum + header.difficulty as u128));
        self.trim();
        Ok(())
    }
}

/// The index of the first job, in order, whose hash does not meet its
/// difficulty. The jobs are computed on up to `threads` scoped threads (the
/// caller's included), which take them in order from a shared counter.
/// Every job before the first failure is computed, so the result is the one
/// of computing them one by one; jobs after a known failure are skipped.
/// `computed` counts the hashes computed.
fn first_failure(
    pow: &dyn PowFunction,
    jobs: &[PowJob],
    threads: usize,
    computed: &AtomicU64,
) -> Option<usize> {
    let next = AtomicUsize::new(0);
    let failed = AtomicUsize::new(usize::MAX);
    let work = || loop {
        let i = next.fetch_add(1, Ordering::Relaxed);
        // Indices are taken in increasing order: once one is past a known
        // failure, every later one is too.
        if i >= jobs.len() || i > failed.load(Ordering::Relaxed) {
            return;
        }
        let job = &jobs[i];
        computed.fetch_add(1, Ordering::Relaxed);
        let hash = pow.pow_hash(&job.seed, &job.header.to_bytes());
        if !check_hash(&hash, job.header.difficulty) {
            failed.fetch_min(i, Ordering::Relaxed);
        }
    };
    let helpers = threads.min(jobs.len()).saturating_sub(1);
    if helpers == 0 {
        work();
    } else {
        std::thread::scope(|s| {
            for _ in 0..helpers {
                // A thread that cannot be started leaves its share to the
                // others.
                let _ = std::thread::Builder::new()
                    .name("header-pow".into())
                    .spawn_scoped(s, work);
            }
            work();
        });
    }
    let failed = failed.into_inner();
    (failed != usize::MAX).then_some(failed)
}
