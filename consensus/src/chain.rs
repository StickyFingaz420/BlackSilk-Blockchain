//! Header tree, validation in branch context, best-chain selection and reorgs
//! (spec §6 and §8).
//!
//! Validation of a header depends only on its own ancestors, never on which
//! branch is currently best, so every node reaches the same verdict regardless of
//! the order in which it receives headers.

use crate::difficulty::next_difficulty;
use crate::hash::Hash;
use crate::header::{BlockHeader, HEADER_VERSION};
use crate::params::ChainParams;
use crate::pow::{check_hash, seed_height, PowFunction};
use crate::timestamp::{after_median_time_past, median, within_future_limit};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// Already known (valid or invalid).
    Duplicate,
    /// Parent not known yet; the network layer should fetch ancestors.
    UnknownParent,
    /// Parent (or one of its ancestors) was marked invalid.
    InvalidParent,
    BadVersion(u32),
    BadHeight { expected: u64, got: u64 },
    /// Not after the median-time-past.
    TimestampTooOld { median_time_past: u64, got: u64 },
    /// Beyond the future time limit of the local clock. Not permanent.
    TimestampTooFarInFuture { limit: u64, got: u64 },
    BadDifficulty { expected: u64, got: u64 },
    /// The RandomX hash does not satisfy the header's difficulty.
    InsufficientWork,
}

impl HeaderError {
    /// Whether the header can never become valid. Peers sending such headers
    /// should be penalized; non-permanent failures may succeed later.
    pub fn is_permanent(&self) -> bool {
        !matches!(
            self,
            HeaderError::Duplicate
                | HeaderError::UnknownParent
                | HeaderError::TimestampTooFarInFuture { .. }
        )
    }
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for HeaderError {}

/// A change of the best chain. Apply `disconnected` in order (tip first), then
/// `connected` in order (lowest first).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reorg {
    /// Height of the last block common to the old and new best chains.
    pub fork_height: u64,
    pub disconnected: Vec<Hash>,
    pub connected: Vec<Hash>,
}

impl Reorg {
    /// A plain extension of the tip (nothing disconnected).
    pub fn is_extension(&self) -> bool {
        self.disconnected.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub id: Hash,
    /// `Some` when the best chain changed because of this header.
    pub reorg: Option<Reorg>,
}

/// Everything a miner needs to build the next block on the best chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockTemplate {
    pub height: u64,
    pub prev_id: Hash,
    pub difficulty: u64,
    /// RandomX key for this height.
    pub seed_id: Hash,
    /// Smallest timestamp the block may carry.
    pub min_timestamp: u64,
}

#[derive(Clone, Debug)]
struct Entry {
    header: BlockHeader,
    cumulative: u128,
    valid: bool,
    /// Arrival order, for first-seen tie breaking.
    seq: u64,
}

pub struct HeaderChain {
    params: ChainParams,
    pow: Arc<dyn PowFunction>,
    entries: HashMap<Hash, Entry>,
    children: HashMap<Hash, Vec<Hash>>,
    /// Best chain: `main[h]` is the id at height `h`.
    main: Vec<Hash>,
    next_seq: u64,
}

impl HeaderChain {
    pub fn new(params: ChainParams, pow: Arc<dyn PowFunction>) -> Self {
        let genesis = params.genesis;
        let id = genesis.id(params.network_id);
        let mut entries = HashMap::new();
        entries.insert(
            id,
            Entry { header: genesis, cumulative: genesis.difficulty as u128, valid: true, seq: 0 },
        );
        Self { params, pow, entries, children: HashMap::new(), main: vec![id], next_seq: 1 }
    }

    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    pub fn tip_id(&self) -> Hash {
        *self.main.last().expect("main chain always contains genesis")
    }

    pub fn tip(&self) -> &BlockHeader {
        &self.entries[&self.tip_id()].header
    }

    pub fn height(&self) -> u64 {
        self.main.len() as u64 - 1
    }

    /// Cumulative work of the best chain.
    pub fn best_work(&self) -> u128 {
        self.entries[&self.tip_id()].cumulative
    }

    pub fn header(&self, id: &Hash) -> Option<&BlockHeader> {
        self.entries.get(id).map(|e| &e.header)
    }

    pub fn is_valid(&self, id: &Hash) -> Option<bool> {
        self.entries.get(id).map(|e| e.valid)
    }

    pub fn main_id_at(&self, height: u64) -> Option<Hash> {
        self.main.get(height as usize).copied()
    }

    pub fn is_on_main(&self, id: &Hash) -> bool {
        self.entries
            .get(id)
            .is_some_and(|e| self.main_id_at(e.header.height) == Some(*id))
    }

    /// Id of the ancestor of `id` (inclusive) at `height` on `id`'s branch.
    fn ancestor_id(&self, id: Hash, height: u64) -> Hash {
        let mut cur = id;
        loop {
            let e = &self.entries[&cur];
            debug_assert!(e.header.height >= height);
            if e.header.height == height {
                return cur;
            }
            if self.main_id_at(e.header.height) == Some(cur) {
                return self.main[height as usize];
            }
            cur = e.header.prev_id;
        }
    }

    /// Up to `count` most recent blocks ending at `id` (inclusive), oldest first.
    fn recent(&self, id: Hash, count: usize) -> Vec<&Entry> {
        let mut out = Vec::with_capacity(count);
        let mut cur = id;
        while out.len() < count {
            let e = &self.entries[&cur];
            out.push(e);
            if e.header.height == 0 {
                break;
            }
            cur = e.header.prev_id;
        }
        out.reverse();
        out
    }

    /// Difficulty required for a child of `parent_id` (spec §4).
    fn required_difficulty(&self, parent_id: Hash) -> u64 {
        let recent = self.recent(parent_id, self.params.difficulty_window + 1);
        let ts: Vec<u64> = recent.iter().map(|e| e.header.timestamp).collect();
        let cd: Vec<u128> = recent.iter().map(|e| e.cumulative).collect();
        next_difficulty(
            &ts,
            &cd,
            self.params.target_block_time,
            self.params.difficulty_window,
            self.params.initial_difficulty,
        )
    }

    fn median_time_past(&self, parent_id: Hash) -> u64 {
        let ts: Vec<u64> = self
            .recent(parent_id, self.params.median_time_window)
            .iter()
            .map(|e| e.header.timestamp)
            .collect();
        median(&ts)
    }

    /// RandomX key for a block at `height` whose parent is `parent_id`.
    pub fn seed_id_for(&self, parent_id: Hash, height: u64) -> Hash {
        let h = seed_height(height, self.params.seed_epoch, self.params.seed_lag);
        self.ancestor_id(parent_id, h)
    }

    /// Template for the next block on the best chain.
    pub fn template(&self) -> BlockTemplate {
        let prev_id = self.tip_id();
        let height = self.height() + 1;
        BlockTemplate {
            height,
            prev_id,
            difficulty: self.required_difficulty(prev_id),
            seed_id: self.seed_id_for(prev_id, height),
            min_timestamp: self.median_time_past(prev_id) + 1,
        }
    }

    /// Validates `header` against its own branch (spec §6). `now` is the local
    /// time in seconds since the Unix epoch.
    pub fn validate(&self, header: &BlockHeader, now: u64) -> Result<Hash, HeaderError> {
        let id = header.id(self.params.network_id);
        if self.entries.contains_key(&id) {
            return Err(HeaderError::Duplicate);
        }
        let parent = self.entries.get(&header.prev_id).ok_or(HeaderError::UnknownParent)?;
        if !parent.valid {
            return Err(HeaderError::InvalidParent);
        }
        if header.version != HEADER_VERSION {
            return Err(HeaderError::BadVersion(header.version));
        }
        let expected_height = parent.header.height + 1;
        if header.height != expected_height {
            return Err(HeaderError::BadHeight { expected: expected_height, got: header.height });
        }

        let mtp = self.median_time_past(header.prev_id);
        if !after_median_time_past(header.timestamp, &[mtp]) {
            return Err(HeaderError::TimestampTooOld { median_time_past: mtp, got: header.timestamp });
        }
        if !within_future_limit(header.timestamp, now, self.params.future_time_limit) {
            return Err(HeaderError::TimestampTooFarInFuture {
                limit: now.saturating_add(self.params.future_time_limit),
                got: header.timestamp,
            });
        }

        let expected = self.required_difficulty(header.prev_id);
        if header.difficulty != expected {
            return Err(HeaderError::BadDifficulty { expected, got: header.difficulty });
        }

        // Expensive check last.
        let seed = self.seed_id_for(header.prev_id, header.height);
        let pow_hash = self.pow.pow_hash(&seed, &header.to_bytes());
        if !check_hash(&pow_hash, header.difficulty) {
            return Err(HeaderError::InsufficientWork);
        }
        Ok(id)
    }

    /// Validates and stores `header`, switching the best chain if it now has the
    /// most work.
    pub fn accept(&mut self, header: BlockHeader, now: u64) -> Result<Accepted, HeaderError> {
        let id = self.validate(&header, now)?;
        let parent_cumulative = self.entries[&header.prev_id].cumulative;
        let seq = self.next_seq;
        self.next_seq += 1;
        self.entries.insert(
            id,
            Entry {
                header,
                cumulative: parent_cumulative + header.difficulty as u128,
                valid: true,
                seq,
            },
        );
        self.children.entry(header.prev_id).or_default().push(id);

        let reorg = if self.entries[&id].cumulative > self.best_work() {
            Some(self.switch_to(id))
        } else {
            None
        };
        Ok(Accepted { id, reorg })
    }

    /// Makes `new_tip` the best chain and describes the change.
    fn switch_to(&mut self, new_tip: Hash) -> Reorg {
        let mut connected = Vec::new();
        let mut cur = new_tip;
        while !self.is_on_main(&cur) {
            connected.push(cur);
            cur = self.entries[&cur].header.prev_id;
        }
        connected.reverse();
        let fork_height = self.entries[&cur].header.height;

        let disconnected: Vec<Hash> =
            self.main.drain(fork_height as usize + 1..).rev().collect();
        self.main.extend_from_slice(&connected);
        Reorg { fork_height, disconnected, connected }
    }

    /// Marks `id` and all its descendants invalid (e.g. a block body failed
    /// validation) and re-selects the best chain. Returns the resulting reorg, if
    /// the best chain changed. Genesis cannot be invalidated.
    pub fn mark_invalid(&mut self, id: &Hash) -> Option<Reorg> {
        let e = self.entries.get(id)?;
        if e.header.height == 0 {
            return None;
        }
        let mut stack = vec![*id];
        while let Some(cur) = stack.pop() {
            if let Some(e) = self.entries.get_mut(&cur) {
                e.valid = false;
            }
            if let Some(kids) = self.children.get(&cur) {
                stack.extend_from_slice(kids);
            }
        }
        if !self.is_on_main(id) {
            return None;
        }
        // Best valid tip: most work, then earliest arrival.
        let best = self
            .entries
            .iter()
            .filter(|(_, e)| e.valid)
            .max_by(|(_, a), (_, b)| a.cumulative.cmp(&b.cumulative).then(b.seq.cmp(&a.seq)))
            .map(|(k, _)| *k)
            .expect("genesis is always valid");
        Some(self.switch_to(best))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::H;
    use crate::merkle::tx_root;

    /// Fast stand-in for RandomX so chain logic can be tested over thousands of
    /// blocks. Test-only; production code always uses `RandomXPow`.
    struct TestPow;
    impl PowFunction for TestPow {
        fn pow_hash(&self, seed: &Hash, blob: &[u8]) -> Hash {
            H::new().chain(seed).chain(blob).finish()
        }
    }

    const START: u64 = 1_700_000_000;

    fn chain() -> HeaderChain {
        HeaderChain::new(ChainParams::regtest(), Arc::new(TestPow))
    }

    /// Mines a valid child of `parent` on its branch, `dt` seconds after it.
    fn mine_on(c: &HeaderChain, parent: Hash, dt: u64, tag: u8) -> BlockHeader {
        let p = *c.header(&parent).unwrap();
        let mut h = BlockHeader {
            version: 1,
            height: p.height + 1,
            prev_id: parent,
            timestamp: p.timestamp + dt,
            difficulty: c.required_difficulty(parent),
            tx_root: tx_root(&[[tag; 32]]),
            nonce: 0,
        };
        let seed = c.seed_id_for(parent, h.height);
        while !check_hash(&TestPow.pow_hash(&seed, &h.to_bytes()), h.difficulty) {
            h.nonce += 1;
        }
        h
    }

    fn extend(c: &mut HeaderChain, parent: Hash, n: usize, dt: u64, tag: u8) -> Vec<Hash> {
        let mut ids = Vec::new();
        let mut p = parent;
        for _ in 0..n {
            let h = mine_on(c, p, dt, tag);
            p = c.accept(h, u64::MAX / 2).unwrap().id;
            ids.push(p);
        }
        ids
    }

    #[test]
    fn linear_chain_and_template() {
        let mut c = chain();
        let g = c.tip_id();
        let ids = extend(&mut c, g, 100, 120, 1);
        assert_eq!(c.height(), 100);
        assert_eq!(c.tip_id(), *ids.last().unwrap());
        let t = c.template();
        assert_eq!(t.height, 101);
        assert_eq!(t.prev_id, c.tip_id());
        assert_eq!(t.seed_id, c.params().genesis_id(), "seed is genesis before height 2113");
        let accepted = mine_on(&c, c.tip_id(), 120, 1);
        assert_eq!(accepted.difficulty, t.difficulty);
    }

    #[test]
    fn rejects_each_invalid_field() {
        let mut c = chain();
        let g = c.tip_id();
        extend(&mut c, g, 20, 120, 1);
        let tip = c.tip_id();
        let good = mine_on(&c, tip, 120, 1);
        let now = good.timestamp;

        let mut h = good;
        h.version = 2;
        assert_eq!(c.validate(&h, now), Err(HeaderError::BadVersion(2)));

        let mut h = good;
        h.height += 1;
        assert!(matches!(c.validate(&h, now), Err(HeaderError::BadHeight { .. })));

        let mut h = good;
        h.prev_id = [0xAB; 32];
        assert_eq!(c.validate(&h, now), Err(HeaderError::UnknownParent));

        let mut h = good;
        h.timestamp = c.median_time_past(tip);
        assert!(matches!(c.validate(&h, now), Err(HeaderError::TimestampTooOld { .. })));

        let h = good;
        let e = c.validate(&h, h.timestamp - 361).unwrap_err();
        assert!(matches!(e, HeaderError::TimestampTooFarInFuture { .. }));
        assert!(!e.is_permanent());

        let mut h = good;
        h.difficulty += 1;
        assert!(matches!(c.validate(&h, now), Err(HeaderError::BadDifficulty { .. })));

        // Find a nonce that fails the PoW check at the required difficulty.
        let mut h = good;
        let seed = c.seed_id_for(tip, h.height);
        loop {
            h.nonce += 1;
            if !check_hash(&TestPow.pow_hash(&seed, &h.to_bytes()), h.difficulty) {
                break;
            }
        }
        assert_eq!(c.validate(&h, now), Err(HeaderError::InsufficientWork));

        let id = c.accept(good, now).unwrap().id;
        assert_eq!(c.accept(good, now), Err(HeaderError::Duplicate));
        assert_eq!(c.tip_id(), id);
    }

    #[test]
    fn heavier_fork_reorgs_and_lighter_fork_does_not() {
        let mut c = chain();
        let g = c.tip_id();
        let common = extend(&mut c, g, 30, 120, 1);
        let fork_point = *common.last().unwrap();
        let old = extend(&mut c, fork_point, 5, 120, 1);
        let old_work = c.best_work();

        // A competing branch that is not heavier (same blocks, same pace) does not switch.
        let side = extend(&mut c, fork_point, 5, 120, 2);
        assert_eq!(c.tip_id(), *old.last().unwrap());
        assert_eq!(c.best_work(), old_work);

        // Extending the side branch makes it heavier: one reorg with exact lists.
        let side_next = mine_on(&c, *side.last().unwrap(), 120, 2);
        let acc = c.accept(side_next, u64::MAX / 2).unwrap();
        let reorg = acc.reorg.expect("heavier branch becomes best");
        assert_eq!(reorg.fork_height, 30);
        let mut expected_disc = old.clone();
        expected_disc.reverse();
        assert_eq!(reorg.disconnected, expected_disc);
        let mut expected_conn = side.clone();
        expected_conn.push(acc.id);
        assert_eq!(reorg.connected, expected_conn);
        assert_eq!(c.tip_id(), acc.id);
        for id in &old {
            assert!(!c.is_on_main(id));
        }
    }

    #[test]
    fn verdicts_do_not_depend_on_arrival_order() {
        // Build two branches in one chain, then feed all headers to a fresh chain
        // in a different order: same best tip, same work.
        let mut a = chain();
        let g = a.tip_id();
        let base = extend(&mut a, g, 10, 120, 1);
        // y is strictly heavier than x, so first-seen tie breaking never applies.
        let x = extend(&mut a, *base.last().unwrap(), 5, 60, 1);
        let y = extend(&mut a, *base.last().unwrap(), 20, 150, 2);
        let all: Vec<BlockHeader> = base
            .iter()
            .chain(y.iter())
            .chain(x.iter())
            .map(|id| *a.header(id).unwrap())
            .collect();

        let mut b = chain();
        for h in &all {
            b.accept(*h, u64::MAX / 2).unwrap();
        }
        assert_eq!(a.tip_id(), b.tip_id());
        assert_eq!(a.best_work(), b.best_work());
    }

    #[test]
    fn invalidating_a_block_falls_back_to_best_remaining_branch() {
        let mut c = chain();
        let g = c.tip_id();
        let base = extend(&mut c, g, 10, 120, 1);
        let fork = *base.last().unwrap();
        let heavy = extend(&mut c, fork, 6, 120, 1);
        let light = extend(&mut c, fork, 3, 120, 2);
        assert_eq!(c.tip_id(), *heavy.last().unwrap());

        // Body validation fails for heavy[2]: it and its descendants are excluded.
        let reorg = c.mark_invalid(&heavy[2]).expect("best chain changes");
        assert_eq!(reorg.fork_height, 10);
        assert_eq!(c.tip_id(), *light.last().unwrap());
        assert!(reorg.disconnected.contains(&heavy[5]));
        for id in &heavy[2..] {
            assert_eq!(c.is_valid(id), Some(false));
        }
        // Children of invalid blocks are rejected.
        let child = mine_on(&c, heavy[5], 120, 1);
        assert_eq!(c.accept(child, u64::MAX / 2), Err(HeaderError::InvalidParent));
    }

    #[test]
    fn difficulty_tracks_hashrate_over_a_long_chain() {
        let mut c = chain();
        let g = c.tip_id();
        extend(&mut c, g, 150, 30, 1); // blocks 4x too fast
        let fast = c.template().difficulty;
        assert!(fast > 1, "difficulty rose from 1 to {fast}");
        let tip = c.tip_id();
        extend(&mut c, tip, 150, 480, 1); // then 4x too slow
        assert!(c.template().difficulty < fast);
    }

    #[test]
    fn seed_is_taken_from_the_headers_own_branch() {
        let mut c = chain();
        let g = c.tip_id();
        // Past the first key epoch: seed height for 2113..=4160 is 2048.
        let main = extend(&mut c, g, 2115, 120, 1);
        assert_eq!(c.template().seed_id, main[2047], "block at height 2048");

        // A branch forking below height 2048 uses its own block 2048 as the key.
        let fork_parent = main[2000 - 1]; // height 2000
        let side = extend(&mut c, fork_parent, 114, 120, 2); // side heights 2001..=2114
        let side_2048 = side[2048 - 2001];
        let side_tip = *side.last().unwrap();
        assert_eq!(c.seed_id_for(side_tip, 2115), side_2048);
        assert_ne!(side_2048, main[2047]);
    }
}
