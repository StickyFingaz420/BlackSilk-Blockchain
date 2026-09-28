//! An independent, deliberately simple executable model of the connection
//! rules of docs/blocks.md §6 and the pool rules of §7 (dossier 02 W-1).
//!
//! It knows nothing of `ChainManager`'s data structures. Blocks are indices
//! into a fixed tree ([`Spec`]); index 0 ([`ROOT`]) is the connected block the
//! tree grows from (genesis, or the tip of a pre-built trunk). Validity is
//! ground truth, decided by the model itself from the tree: a block is valid
//! if its coinbase claims the right amount and no key image repeats within it
//! or appears in one of its ancestors (rule C2). Every operation recomputes
//! what it needs by brute force; nothing is incremental, so the model is easy
//! to check against the text of the specification, and slow.
//!
//! What the model encodes, clause by clause (docs/blocks.md):
//! - §6 "connection target": the most-work block that is body-complete and
//!   not known to be invalid; between equal-work candidates the connected
//!   tip stays, otherwise the one completed first wins ([`Model::target`]).
//! - §6 completion: a block completes when its body is kept and its parent is
//!   complete; blocks waiting for a parent complete in body arrival order, and
//!   the state is synced after every single completion ([`Model::drain`]).
//! - §6 reorganization: disconnect to the fork point, connect the target's
//!   branch block by block; a failing body marks the block and every
//!   descendant invalid, and the loop repeats ([`Model::sync`]).
//! - §7 pool: first seen wins on key images; a connected block removes its
//!   transactions and every pooled transaction sharing a key image with it;
//!   transactions of disconnected blocks return if still valid; the pool is
//!   revalidated against the new tip ([`Model::finish`], [`Model::submit_tx`]).
//! - §7 expiry and the recently-expired guard, for the pool alone
//!   ([`PoolModel`]).
#![allow(dead_code)]

use std::collections::{BTreeSet, HashMap, HashSet};

/// The block the tree grows from; always connected.
pub const ROOT: usize = 0;

/// A fixed block tree. Index 0 is [`ROOT`]; every other block's parent has a
/// smaller index.
#[derive(Clone, Debug, Default)]
pub struct Spec {
    pub parent: Vec<usize>,
    /// Header difficulty (the block's own work).
    pub difficulty: Vec<u128>,
    /// Whether the coinbase claims exactly reward plus fees.
    pub claim_ok: Vec<bool>,
    /// Transactions included after the coinbase (indices into the tx set).
    pub txs: Vec<Vec<usize>>,
    /// The key image (an abstract id) each transaction of the set spends.
    pub key_of: Vec<usize>,
}

impl Spec {
    pub fn len(&self) -> usize {
        self.parent.len()
    }

    /// `b`'s ancestors from just above [`ROOT`] down to `b` itself.
    pub fn path(&self, b: usize) -> Vec<usize> {
        let mut p = Vec::new();
        let mut cur = b;
        while cur != ROOT {
            p.push(cur);
            cur = self.parent[cur];
        }
        p.reverse();
        p
    }

    /// Whether `a` is `b` or one of its ancestors.
    pub fn is_ancestor_or_self(&self, a: usize, b: usize) -> bool {
        let mut cur = b;
        loop {
            if cur == a {
                return true;
            }
            if cur == ROOT {
                return false;
            }
            cur = self.parent[cur];
        }
    }

    pub fn keys(&self, b: usize) -> Vec<usize> {
        self.txs[b].iter().map(|&t| self.key_of[t]).collect()
    }
}

/// The outcome of submitting a body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Kept, and on the connected chain afterwards.
    Connected,
    /// Kept, not on the connected chain.
    Stored,
    Duplicate,
    UnknownParent,
    /// The block or an ancestor is known to be invalid.
    InvalidParent,
    /// The block's own body failed when it was connected.
    BodyInvalid,
}

/// The outcome of submitting a transaction to the pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxVerdict {
    Added,
    AlreadyKnown,
    Conflict,
    /// Refused by validation (here: its key image is spent on the chain).
    Invalid,
    /// Refused by the recently-expired guard (local origination only).
    Expired,
}

pub struct Model {
    pub spec: Spec,
    /// Cumulative work above [`ROOT`].
    pub work: Vec<u128>,
    /// Ground-truth body validity (given its ancestors).
    pub valid: Vec<bool>,
    pub header: Vec<bool>,
    /// Body arrival index of every kept body.
    pub body: Vec<Option<u64>>,
    next_body: u64,
    /// Completion index of every complete block.
    pub complete: Vec<Option<u64>>,
    next_complete: u64,
    /// Known to be invalid: a failed body or a descendant of one.
    pub invalid: Vec<bool>,
    /// The body failed itself (the block is the reported culprit).
    pub failed: Vec<bool>,
    /// The connected chain from [`ROOT`].
    pub connected: Vec<usize>,
    pub deepest_reorg: usize,
    /// Pooled transactions, in admission order.
    pub pool: Vec<usize>,
}

impl Model {
    pub fn new(spec: Spec) -> Self {
        let n = spec.len();
        let mut work = vec![0u128; n];
        let mut valid = vec![true; n];
        for b in 1..n {
            let p = spec.parent[b];
            assert!(p < b, "parents come first");
            work[b] = work[p] + spec.difficulty[b];
            let mut spent: HashSet<usize> = HashSet::new();
            for a in spec.path(p) {
                spent.extend(spec.keys(a));
            }
            let mut own = HashSet::new();
            let keys_ok = spec
                .keys(b)
                .iter()
                .all(|k| !spent.contains(k) && own.insert(*k));
            valid[b] = spec.claim_ok[b] && keys_ok;
        }
        let mut header = vec![false; n];
        header[ROOT] = true;
        let mut complete = vec![None; n];
        complete[ROOT] = Some(0);
        Self {
            spec,
            work,
            valid,
            header,
            body: vec![None; n],
            next_body: 0,
            complete,
            next_complete: 1,
            invalid: vec![false; n],
            failed: vec![false; n],
            connected: vec![ROOT],
            deepest_reorg: 0,
            pool: Vec::new(),
        }
    }

    pub fn tip(&self) -> usize {
        *self.connected.last().expect("root")
    }

    fn descendants_or_self(&self, b: usize) -> Vec<usize> {
        (0..self.spec.len())
            .filter(|&d| self.spec.is_ancestor_or_self(b, d))
            .collect()
    }

    /// Headers of `b`'s path, in order, as a header batch. Known headers are
    /// skipped; a known-invalid one, or a new one whose parent is invalid,
    /// stops the batch with its index. Returns the number of new headers.
    pub fn headers(&mut self, b: usize) -> Result<usize, usize> {
        let mut new = 0;
        for (i, x) in self.spec.path(b).into_iter().enumerate() {
            if self.header[x] {
                if self.invalid[x] {
                    return Err(i);
                }
                continue;
            }
            // The parent is known: the batch is a chain from a known block.
            if self.invalid[self.spec.parent[x]] {
                return Err(i);
            }
            self.header[x] = true;
            new += 1;
        }
        Ok(new)
    }

    /// Submits `b`'s body.
    pub fn body(&mut self, b: usize) -> Verdict {
        let p = self.spec.parent[b];
        if self.header[b] {
            if self.body[b].is_some() {
                return Verdict::Duplicate;
            }
            if self.invalid[b] {
                return Verdict::InvalidParent;
            }
        } else {
            if !self.header[p] {
                return Verdict::UnknownParent;
            }
            if self.invalid[p] {
                return Verdict::InvalidParent;
            }
            self.header[b] = true;
        }
        self.body[b] = Some(self.next_body);
        self.next_body += 1;
        self.drain();
        if self.failed[b] {
            Verdict::BodyInvalid
        } else if self.connected.contains(&b) {
            Verdict::Connected
        } else {
            Verdict::Stored
        }
    }

    /// Completes every block that can complete, lowest body arrival first,
    /// syncing after each; then updates the pool once.
    fn drain(&mut self) {
        let mut returned = Vec::new();
        loop {
            let next = (1..self.spec.len())
                .filter(|&x| {
                    self.body[x].is_some()
                        && self.complete[x].is_none()
                        && !self.invalid[x]
                        && self.complete[self.spec.parent[x]].is_some()
                })
                .min_by_key(|&x| self.body[x]);
            let Some(x) = next else {
                break;
            };
            self.complete[x] = Some(self.next_complete);
            self.next_complete += 1;
            self.sync(&mut returned);
        }
        self.finish(returned);
    }

    /// The connection target (docs/blocks.md §6).
    pub fn target(&self) -> usize {
        let candidates: Vec<usize> = (0..self.spec.len())
            .filter(|&x| self.complete[x].is_some() && !self.invalid[x])
            .collect();
        let max = candidates
            .iter()
            .map(|&x| self.work[x])
            .max()
            .expect("root");
        let tip = self.tip();
        if self.work[tip] == max {
            return tip;
        }
        candidates
            .into_iter()
            .filter(|&x| self.work[x] == max)
            .min_by_key(|&x| self.complete[x])
            .expect("a candidate")
    }

    fn sync(&mut self, returned: &mut Vec<usize>) {
        loop {
            let target = self.target();
            if target == self.tip() {
                return;
            }
            assert!(self.work[target] > self.work[self.tip()]);
            let mut path = Vec::new();
            let mut cur = target;
            while !self.connected.contains(&cur) {
                path.push(cur);
                cur = self.spec.parent[cur];
            }
            path.reverse();
            let fork = self.connected.iter().position(|&x| x == cur).unwrap();
            self.deepest_reorg = self.deepest_reorg.max(self.connected.len() - 1 - fork);
            while self.connected.len() - 1 > fork {
                let x = self.connected.pop().unwrap();
                returned.extend(self.spec.txs[x].iter().copied());
            }
            for x in path {
                if self.valid[x] {
                    self.connected.push(x);
                    let keys = self.spec.keys(x);
                    self.pool.retain(|&t| !keys.contains(&self.spec.key_of[t]));
                } else {
                    self.fail(x);
                    break;
                }
            }
        }
    }

    fn fail(&mut self, b: usize) {
        self.failed[b] = true;
        for d in self.descendants_or_self(b) {
            self.invalid[d] = true;
            self.body[d] = None;
            self.complete[d] = None;
        }
    }

    fn spent_on_chain(&self, key: usize) -> bool {
        self.connected
            .iter()
            .any(|&x| self.spec.keys(x).contains(&key))
    }

    fn pooled_key(&self, key: usize) -> bool {
        self.pool.iter().any(|&t| self.spec.key_of[t] == key)
    }

    /// After a change of the connected chain: transactions of disconnected
    /// blocks return if still valid, then the pool drops what the new tip
    /// invalidates.
    fn finish(&mut self, returned: Vec<usize>) {
        for t in returned {
            let _ = self.submit_tx(t);
        }
        let keep: Vec<usize> = self
            .pool
            .iter()
            .copied()
            .filter(|&t| !self.spent_on_chain(self.spec.key_of[t]))
            .collect();
        self.pool = keep;
    }

    /// A transaction for the next block (first seen wins).
    pub fn submit_tx(&mut self, t: usize) -> TxVerdict {
        if self.pool.contains(&t) {
            return TxVerdict::AlreadyKnown;
        }
        let key = self.spec.key_of[t];
        if self.pooled_key(key) {
            return TxVerdict::Conflict;
        }
        if self.spent_on_chain(key) {
            return TxVerdict::Invalid;
        }
        self.pool.push(t);
        TxVerdict::Added
    }

    /// Blocks whose body the node should download: known valid headers
    /// without a body on the way to a known valid header with more work
    /// than the connected tip (§6 "Downloads").
    pub fn missing_bodies(&self) -> BTreeSet<usize> {
        let tip_work = self.work[self.tip()];
        let usable = |x: usize| self.header[x] && !self.invalid[x];
        (1..self.spec.len())
            .filter(|&b| usable(b) && self.body[b].is_none())
            .filter(|&b| {
                (1..self.spec.len()).any(|d| {
                    usable(d) && self.work[d] > tip_work && self.spec.is_ancestor_or_self(b, d)
                })
            })
            .collect()
    }

    /// The declarative form of the rule (INV-1): the most work among blocks
    /// whose whole branch has kept, valid bodies.
    pub fn best_valid_complete_work(&self) -> u128 {
        (0..self.spec.len())
            .filter(|&b| {
                self.spec
                    .path(b)
                    .iter()
                    .all(|&x| self.body[x].is_some() && self.valid[x])
            })
            .map(|b| self.work[b])
            .max()
            .expect("root")
    }
}

/// Pool alone (docs/blocks.md §7): admission, conflicts, removal by a
/// connected block, expiry and the recently-expired guard, at explicit
/// heights. Transactions are abstract ids with one key image each;
/// `spent` is the set of key images spent on the (fixed) chain.
pub struct PoolModel {
    pub key_of: Vec<usize>,
    pub spent: HashSet<usize>,
    /// tx -> admission height.
    pub pool: HashMap<usize, u64>,
    /// tx -> height it expired at.
    pub expired: HashMap<usize, u64>,
    pub expiry: u64,
    pub guard: u64,
}

impl PoolModel {
    pub fn new(key_of: Vec<usize>, spent: HashSet<usize>, expiry: u64, guard: u64) -> Self {
        Self {
            key_of,
            spent,
            pool: HashMap::new(),
            expired: HashMap::new(),
            expiry,
            guard,
        }
    }

    pub fn recently_expired(&self, t: usize, height: u64) -> bool {
        self.expired
            .get(&t)
            .is_some_and(|&at| height < at + self.guard)
    }

    /// Admission for inclusion at `height`; `local` applies the guard.
    pub fn add(&mut self, t: usize, height: u64, local: bool) -> TxVerdict {
        if self.pool.contains_key(&t) {
            return TxVerdict::AlreadyKnown;
        }
        if local && self.recently_expired(t, height) {
            return TxVerdict::Expired;
        }
        let key = self.key_of[t];
        if self.pool.keys().any(|&u| self.key_of[u] == key) {
            return TxVerdict::Conflict;
        }
        if self.spent.contains(&key) {
            return TxVerdict::Invalid;
        }
        self.pool.insert(t, height);
        TxVerdict::Added
    }

    /// A transaction returned by a disconnected block: admitted like a
    /// peer's; its guard entry is cleared only if it is pooled.
    pub fn readmit(&mut self, t: usize, height: u64) -> TxVerdict {
        let v = self.add(t, height, false);
        if v == TxVerdict::Added {
            self.expired.remove(&t);
        }
        v
    }

    /// The next block's height is `height`: guard entries older than the
    /// guard are forgotten, and transactions admitted `expiry` or more
    /// blocks before leave the pool and enter the guard. Returns how many.
    pub fn expire(&mut self, height: u64) -> usize {
        let guard = self.guard;
        self.expired.retain(|_, at| height < *at + guard);
        let old: Vec<usize> = self
            .pool
            .iter()
            .filter(|(_, &at)| height >= at + self.expiry)
            .map(|(&t, _)| t)
            .collect();
        for &t in &old {
            self.pool.remove(&t);
            self.expired.insert(t, height);
        }
        old.len()
    }

    /// A connected block with transactions `txs`: they leave the pool, and
    /// so does every pooled transaction sharing a key image with them.
    pub fn remove_block(&mut self, txs: &[usize]) {
        let keys: HashSet<usize> = txs.iter().map(|&t| self.key_of[t]).collect();
        self.pool
            .retain(|&t, _| !txs.contains(&t) && !keys.contains(&self.key_of[t]));
    }

    /// Whether `t` shares a key image with a pooled transaction other than
    /// itself.
    pub fn conflicts(&self, t: usize) -> bool {
        self.pool
            .keys()
            .any(|&u| u != t && self.key_of[u] == self.key_of[t])
    }
}
