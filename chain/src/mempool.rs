//! Transaction pool (docs/blocks.md §7, docs/px.md §11.5). Policy, not consensus.
//!
//! Holds every kind of non-coinbase transaction. Two classes with separate
//! size caps and fee rates:
//! - **v1** (transfers): fee per weight, bounded by [`MEMPOOL_MAX_BYTES`];
//! - **PX** (PX transactions and deploys): fee per byte, bounded by
//!   [`MEMPOOL_MAX_PX_BYTES`], selected against the block's PX byte budget.
//!
//! Conflicts are first-seen-wins on key images, PX nullifiers and deploy
//! contract ids.
//!
//! **PX proofs are verified once, on admission.** After a block, pooled PX
//! transactions are revalidated against the new state (anchor, nullifiers,
//! registry, pool, rings) without re-verifying the proof, which depends only
//! on the transaction and its registered programs; a change to those fails
//! the state checks. Re-verifying every pooled proof at every block would be a
//! denial-of-service lever.

use blacksilk_consensus::Hash;
use blacksilk_tx::params::{TxRules, MAX_PX_BLOCK_BYTES};
use blacksilk_tx::px::digest_bytes;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::{validate_mempool_tx, validate_px_without_proof, ChainView, TxError};
use std::collections::HashMap;

/// Maximum total encoded size of pooled v1 transactions.
pub const MEMPOOL_MAX_BYTES: usize = 50_000_000;
/// Maximum total encoded size of pooled PX and deploy transactions.
pub const MEMPOOL_MAX_PX_BYTES: usize = 64 * 1024 * 1024;
/// Weight reserved for the coinbase in block templates.
pub const COINBASE_RESERVE: u64 = 3_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MempoolError {
    AlreadyKnown,
    /// A key image, PX nullifier or contract id is already used by another
    /// pooled transaction (first seen wins).
    Conflict,
    Coinbase,
    Invalid(TxError),
    /// The pool is full and the fee rate does not beat the cheapest entry of
    /// the same class.
    FeeTooLowForFullPool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    V1,
    Px,
}

struct Entry {
    tx: Transaction,
    class: Class,
    size: usize,
    /// v1 weight, or PX bytes: the unit of the class's fee rate.
    cost: u64,
    seq: u64,
    /// Conflict keys: key images, nullifiers, contract ids.
    keys: Vec<[u8; 32]>,
}

impl Entry {
    /// Fee per cost unit, compared without division.
    fn rate_cmp(&self, other: &Entry) -> std::cmp::Ordering {
        (self.tx.fee() as u128 * other.cost as u128)
            .cmp(&(other.tx.fee() as u128 * self.cost as u128))
    }
}

fn class_of(tx: &Transaction) -> Class {
    match tx {
        Transaction::Px(_) | Transaction::PxDeploy(_) => Class::Px,
        _ => Class::V1,
    }
}

/// The conflict keys of a transaction.
fn conflict_keys(tx: &Transaction) -> Vec<[u8; 32]> {
    let mut keys: Vec<[u8; 32]> = tx.key_images().iter().map(|k| *k.bytes()).collect();
    match tx {
        Transaction::Px(t) => keys.extend(t.nullifiers.iter().map(digest_bytes)),
        Transaction::PxDeploy(t) => keys.push(digest_bytes(&t.contract_id())),
        _ => {}
    }
    keys
}

#[derive(Default)]
pub struct Mempool {
    entries: HashMap<Hash, Entry>,
    keys: HashMap<[u8; 32], Hash>,
    bytes: [usize; 2],
    next_seq: u64,
}

impl Mempool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total encoded size of pooled transactions (both classes).
    pub fn bytes(&self) -> usize {
        self.bytes[0] + self.bytes[1]
    }

    pub fn contains(&self, id: &Hash) -> bool {
        self.entries.contains_key(id)
    }

    fn cap(class: Class) -> usize {
        match class {
            Class::V1 => MEMPOOL_MAX_BYTES,
            Class::Px => MEMPOOL_MAX_PX_BYTES,
        }
    }

    fn slot(class: Class) -> usize {
        match class {
            Class::V1 => 0,
            Class::Px => 1,
        }
    }

    fn precheck(&self, tx: &Transaction) -> Result<(Hash, Vec<[u8; 32]>), MempoolError> {
        if tx.is_coinbase() {
            return Err(MempoolError::Coinbase);
        }
        let id = tx.hash();
        if self.entries.contains_key(&id) {
            return Err(MempoolError::AlreadyKnown);
        }
        let keys = conflict_keys(tx);
        if keys.iter().any(|k| self.keys.contains_key(k)) {
            return Err(MempoolError::Conflict);
        }
        Ok((id, keys))
    }

    /// Validates `tx` for inclusion at `height` without adding it. Returns its id.
    pub fn check(
        &self,
        tx: &Transaction,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
    ) -> Result<Hash, MempoolError> {
        let (id, _) = self.precheck(tx)?;
        validate_mempool_tx(tx, chain, height, rules).map_err(MempoolError::Invalid)?;
        Ok(id)
    }

    /// A pooled transaction by id.
    pub fn get(&self, id: &Hash) -> Option<&Transaction> {
        self.entries.get(id).map(|e| &e.tx)
    }

    /// Validates `tx` for inclusion at `height` and adds it.
    pub fn add(
        &mut self,
        tx: Transaction,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
    ) -> Result<Hash, MempoolError> {
        let (id, keys) = self.precheck(&tx)?;
        validate_mempool_tx(&tx, chain, height, rules).map_err(MempoolError::Invalid)?;
        self.insert(id, tx, keys)
    }

    fn insert(
        &mut self,
        id: Hash,
        tx: Transaction,
        keys: Vec<[u8; 32]>,
    ) -> Result<Hash, MempoolError> {
        let class = class_of(&tx);
        let size = tx.encode().len();
        let cost = match class {
            Class::V1 => tx.weight(),
            Class::Px => tx.px_bytes(),
        };
        let entry = Entry {
            tx,
            class,
            size,
            cost,
            seq: self.next_seq,
            keys,
        };
        // Make room if needed by evicting strictly cheaper entries of the class.
        let s = Self::slot(class);
        while self.bytes[s] + size > Self::cap(class) {
            let cheapest = self
                .entries
                .iter()
                .filter(|(_, e)| e.class == class)
                .min_by(|a, b| a.1.rate_cmp(b.1).then(b.1.seq.cmp(&a.1.seq)))
                .map(|(id, e)| (*id, e.rate_cmp(&entry)));
            match cheapest {
                Some((victim, std::cmp::Ordering::Less)) => {
                    self.remove(&victim);
                }
                _ => return Err(MempoolError::FeeTooLowForFullPool),
            }
        }
        for k in &entry.keys {
            self.keys.insert(*k, id);
        }
        self.bytes[s] += size;
        self.next_seq += 1;
        self.entries.insert(id, entry);
        Ok(id)
    }

    pub fn remove(&mut self, id: &Hash) -> Option<Transaction> {
        let e = self.entries.remove(id)?;
        for k in &e.keys {
            self.keys.remove(k);
        }
        self.bytes[Self::slot(e.class)] -= e.size;
        Some(e.tx)
    }

    /// Removes the transactions of a newly connected block, and any pooled
    /// transaction that conflicts with it.
    pub fn remove_block(&mut self, txs: &[Transaction]) {
        for tx in txs {
            self.remove(&tx.hash());
            for k in conflict_keys(tx) {
                if let Some(id) = self.keys.get(&k).copied() {
                    self.remove(&id);
                }
            }
        }
    }

    /// Drops everything that is no longer valid for inclusion at `height`.
    /// PX proofs are not re-verified (module docs).
    pub fn revalidate(&mut self, chain: &impl ChainView, height: u64, rules: &TxRules) {
        let stale: Vec<Hash> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                let r = match &e.tx {
                    Transaction::Px(t) => validate_px_without_proof(t, chain, height, rules),
                    tx => validate_mempool_tx(tx, chain, height, rules),
                };
                r.is_err()
            })
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            self.remove(&id);
        }
    }

    /// Transactions for a block template, highest fee rate first (then first
    /// seen): v1 transactions up to `max_weight`, PX transactions up to the
    /// PX byte budget. `pool` is the PX pool before the block: PX transactions
    /// are taken only while the pool, evolving in block order, stays
    /// non-negative (each was admitted against the chain's pool alone).
    pub fn select(&self, max_weight: u64, mut pool: u128) -> Vec<Transaction> {
        let mut entries: Vec<&Entry> = self.entries.values().collect();
        entries.sort_by(|a, b| b.rate_cmp(a).then(a.seq.cmp(&b.seq)));
        let (mut weight, mut px) = (0u64, 0u64);
        let mut out = Vec::new();
        for e in entries {
            match e.class {
                Class::V1 if weight + e.cost <= max_weight => {
                    weight += e.cost;
                    out.push(e.tx.clone());
                }
                Class::Px if px + e.cost <= MAX_PX_BLOCK_BYTES => {
                    if let Transaction::Px(t) = &e.tx {
                        match (pool + t.bridge_in as u128).checked_sub(t.bridge_out as u128) {
                            Some(p) => pool = p,
                            None => continue,
                        }
                    }
                    px += e.cost;
                    out.push(e.tx.clone());
                }
                _ => {}
            }
        }
        out
    }
}
