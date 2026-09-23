//! Transaction pool (docs/blocks.md §7). Policy, not consensus.

use blacksilk_consensus::Hash;
use blacksilk_tx::params::TxRules;
use blacksilk_tx::types::{Transaction, Transfer};
use blacksilk_tx::validate::{validate_transfer, ChainView, TxError};
use std::collections::HashMap;

/// Maximum total encoded size of pooled transactions.
pub const MEMPOOL_MAX_BYTES: usize = 50_000_000;
/// Weight reserved for the coinbase in block templates.
pub const COINBASE_RESERVE: u64 = 3_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MempoolError {
    AlreadyKnown,
    /// A key image is already spent by another pooled transaction (first seen wins).
    Conflict,
    Coinbase,
    Invalid(TxError),
    /// The pool is full and the fee rate does not beat the cheapest entry.
    FeeTooLowForFullPool,
}

struct Entry {
    tx: Transfer,
    size: usize,
    weight: u64,
    seq: u64,
}

impl Entry {
    /// Fee per weight compared without division: `a.fee·b.weight` vs `b.fee·a.weight`.
    fn rate_cmp(&self, other: &Entry) -> std::cmp::Ordering {
        (self.tx.fee as u128 * other.weight as u128)
            .cmp(&(other.tx.fee as u128 * self.weight as u128))
    }
}

#[derive(Default)]
pub struct Mempool {
    entries: HashMap<Hash, Entry>,
    key_images: HashMap<[u8; 32], Hash>,
    bytes: usize,
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

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn contains(&self, id: &Hash) -> bool {
        self.entries.contains_key(id)
    }

    /// Validates `tx` for inclusion at `height` without adding it. Returns its id.
    pub fn check(
        &self,
        tx: &Transaction,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
    ) -> Result<Hash, MempoolError> {
        let Transaction::Transfer(t) = tx else {
            return Err(MempoolError::Coinbase);
        };
        let id = tx.hash();
        if self.entries.contains_key(&id) {
            return Err(MempoolError::AlreadyKnown);
        }
        if t.inputs
            .iter()
            .any(|i| self.key_images.contains_key(i.key_image.bytes()))
        {
            return Err(MempoolError::Conflict);
        }
        validate_transfer(t, chain, height, rules).map_err(MempoolError::Invalid)?;
        Ok(id)
    }

    /// A pooled transaction by id.
    pub fn get(&self, id: &Hash) -> Option<&Transfer> {
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
        let Transaction::Transfer(t) = tx else {
            return Err(MempoolError::Coinbase);
        };
        let t = *t;
        let id = Transaction::from(t.clone()).hash();
        if self.entries.contains_key(&id) {
            return Err(MempoolError::AlreadyKnown);
        }
        if t.inputs
            .iter()
            .any(|i| self.key_images.contains_key(i.key_image.bytes()))
        {
            return Err(MempoolError::Conflict);
        }
        validate_transfer(&t, chain, height, rules).map_err(MempoolError::Invalid)?;
        let size = t.encoded_len();
        let entry = Entry {
            weight: t.weight(),
            size,
            tx: t,
            seq: self.next_seq,
        };
        // Make room if needed by evicting strictly cheaper transactions.
        while self.bytes + size > MEMPOOL_MAX_BYTES {
            let cheapest = self
                .entries
                .iter()
                .min_by(|a, b| a.1.rate_cmp(b.1).then(b.1.seq.cmp(&a.1.seq)))
                .map(|(id, e)| (*id, e.rate_cmp(&entry)));
            match cheapest {
                Some((victim, std::cmp::Ordering::Less)) => {
                    self.remove(&victim);
                }
                _ => return Err(MempoolError::FeeTooLowForFullPool),
            }
        }
        for i in &entry.tx.inputs {
            self.key_images.insert(*i.key_image.bytes(), id);
        }
        self.bytes += size;
        self.next_seq += 1;
        self.entries.insert(id, entry);
        Ok(id)
    }

    pub fn remove(&mut self, id: &Hash) -> Option<Transfer> {
        let e = self.entries.remove(id)?;
        for i in &e.tx.inputs {
            self.key_images.remove(i.key_image.bytes());
        }
        self.bytes -= e.size;
        Some(e.tx)
    }

    /// Removes the transactions of a newly connected block, and any pooled
    /// transaction that conflicts with it (same key image).
    pub fn remove_block(&mut self, txs: &[Transaction]) {
        for tx in txs {
            if let Transaction::Transfer(t) = tx {
                for i in &t.inputs {
                    if let Some(id) = self.key_images.get(i.key_image.bytes()).copied() {
                        self.remove(&id);
                    }
                }
            }
        }
    }

    /// Drops everything that is no longer valid for inclusion at `height`.
    pub fn revalidate(&mut self, chain: &impl ChainView, height: u64, rules: &TxRules) {
        let stale: Vec<Hash> = self
            .entries
            .iter()
            .filter(|(_, e)| validate_transfer(&e.tx, chain, height, rules).is_err())
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            self.remove(&id);
        }
    }

    /// Transactions for a block template: highest fee per weight first (then first
    /// seen), up to `max_weight`.
    pub fn select(&self, max_weight: u64) -> Vec<Transfer> {
        let mut entries: Vec<&Entry> = self.entries.values().collect();
        entries.sort_by(|a, b| b.rate_cmp(a).then(a.seq.cmp(&b.seq)));
        let mut total = 0u64;
        let mut out = Vec::new();
        for e in entries {
            if total + e.weight <= max_weight {
                total += e.weight;
                out.push(e.tx.clone());
            }
        }
        out
    }
}
