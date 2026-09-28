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

use blacksilk_consensus::difficulty::next_difficulty;
use blacksilk_consensus::pow::{check_hash, seed_height};
use blacksilk_consensus::timestamp::median;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::{HashMap, VecDeque};

/// Headers whose proof of work is checked per sync, in expectation, below
/// the densely checked tail (module docs).
pub const HEADER_SAMPLES: u64 = 16;

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
            pow_checked: 0,
        };
        check.trim();
        Ok(check)
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
    /// draw. On success the header joins the context.
    pub fn check(&mut self, header: &BlockHeader, force_pow: bool) -> Result<(), String> {
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
            self.pow_checked += 1;
            let hash = self.pow.pow_hash(&seed, &header.to_bytes());
            if !check_hash(&hash, header.difficulty) {
                return Err(format!(
                    "header {height}'s proof of work does not meet its difficulty"
                ));
            }
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
