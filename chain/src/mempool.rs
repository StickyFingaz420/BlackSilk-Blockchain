//! Transaction pool (docs/blocks.md §7, docs/px.md §11.5). Policy, not consensus.
//!
//! Holds every kind of non-coinbase transaction. Two classes with separate
//! size caps and fee rates:
//! - **v1** (transfers): fee per weight, bounded by [`MEMPOOL_MAX_BYTES`];
//! - **PX** (PX transactions and deploys): fee per byte, bounded by
//!   [`MEMPOOL_MAX_PX_BYTES`], selected against the block's PX byte budget.
//!
//! Conflicts are first-seen-wins, whatever the fee, on four kinds of key, each
//! in its own namespace ([`ConflictKind`]): key images, PX nullifiers, deploy
//! contract ids, and **output one-time keys**. Two pooled transactions never
//! share any of them, so no block template holds two transactions a block
//! could not hold together (rules C2 and C4, PX2, the contract registry).
//!
//! Output one-time keys are chosen by the sender and consensus requires them to
//! be unique (C4). Before 2026-09-27 they were not conflict keys: an attacker
//! could pool two valid transactions sharing an output key, every template
//! then held both, and every block built from it was invalid (a chain stall at
//! the cost of two unpaid fees). `select` also re-checks uniqueness as a second
//! line of defence; it is not a substitute for admission.
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
use blacksilk_tx::validate::{
    revalidate_after_extension, validate_mempool_tx, validate_px_without_proof, ChainView, TxError,
};
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
    /// Conflict keys (`conflict_keys`).
    keys: Vec<ConflictKey>,
}

/// The namespace of a conflict key. The same 32 bytes in two namespaces are
/// different keys: an output one-time key is chosen freely by its sender, and
/// must not be able to block, say, a key image with the same bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConflictKind {
    KeyImage,
    Nullifier,
    ContractId,
    OutputKey,
}

pub type ConflictKey = (ConflictKind, [u8; 32]);

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

/// The conflict keys of a transaction: what it spends or registers (key
/// images, nullifiers, a contract id) and the one-time keys of every output it
/// creates, including PX payouts, deploy outputs and coinbase outputs.
pub fn conflict_keys(tx: &Transaction) -> Vec<ConflictKey> {
    use ConflictKind::*;
    let mut keys: Vec<ConflictKey> = tx
        .key_images()
        .iter()
        .map(|k| (KeyImage, *k.bytes()))
        .collect();
    let outputs: Vec<[u8; 32]> = match tx {
        Transaction::Coinbase(c) => c.outputs.iter().map(|o| *o.one_time_key.bytes()).collect(),
        Transaction::Transfer(t) => t.outputs.iter().map(|o| *o.one_time_key.bytes()).collect(),
        Transaction::Px(t) => {
            keys.extend(t.nullifiers.iter().map(|n| (Nullifier, digest_bytes(n))));
            t.output_keys()
                .iter()
                .map(|k| *k.one_time_key.bytes())
                .collect()
        }
        Transaction::PxDeploy(t) => {
            keys.push((ContractId, digest_bytes(&t.contract_id())));
            t.outputs.iter().map(|o| *o.one_time_key.bytes()).collect()
        }
    };
    keys.extend(outputs.into_iter().map(|k| (OutputKey, k)));
    keys
}

#[derive(Default)]
pub struct Mempool {
    entries: HashMap<Hash, Entry>,
    keys: HashMap<ConflictKey, Hash>,
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

    fn precheck(&self, tx: &Transaction) -> Result<(Hash, Vec<ConflictKey>), MempoolError> {
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
        keys: Vec<ConflictKey>,
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
        // Make room if needed by evicting strictly cheaper entries of the class,
        // cheapest (then newest) first. The victims are chosen before anything
        // is removed: if the strictly cheaper entries cannot free enough room,
        // the new transaction is refused and the pool is left unchanged.
        let s = Self::slot(class);
        let cap = Self::cap(class);
        if self.bytes[s] + size > cap {
            if size > cap {
                return Err(MempoolError::FeeTooLowForFullPool);
            }
            let mut cheaper: Vec<(&Hash, &Entry)> = self
                .entries
                .iter()
                .filter(|(_, e)| e.class == class && e.rate_cmp(&entry).is_lt())
                .collect();
            cheaper.sort_by(|a, b| a.1.rate_cmp(b.1).then(b.1.seq.cmp(&a.1.seq)));
            let mut freed = 0usize;
            let mut victims = Vec::new();
            for (id, e) in cheaper {
                if self.bytes[s] - freed + size <= cap {
                    break;
                }
                freed += e.size;
                victims.push(*id);
            }
            if self.bytes[s] - freed + size > cap {
                return Err(MempoolError::FeeTooLowForFullPool);
            }
            for victim in victims {
                self.remove(&victim);
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
    /// transaction that shares a conflict key with it (a spent key image or
    /// nullifier, a registered contract, or an output one-time key the block
    /// created, coinbase included).
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
    ///
    /// `after_reorg`: blocks were disconnected since the last revalidation, so
    /// ring members may resolve to different outputs and every rule is checked
    /// again. After a plain extension only the rules an extension can change
    /// are (`revalidate_after_extension`): a full re-check of a full pool
    /// (about 6.8 ms per transfer, measured) would take minutes per block
    /// under the chain lock, a denial-of-service lever.
    pub fn revalidate(
        &mut self,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
        after_reorg: bool,
    ) {
        let stale: Vec<Hash> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                let r = match &e.tx {
                    tx if !after_reorg => revalidate_after_extension(tx, chain),
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
    ///
    /// Defence in depth: a transaction sharing a conflict key with one already
    /// selected is skipped (and logged). Admission already guarantees that no
    /// two pooled transactions share one, so this never fires unless that
    /// invariant is broken; it keeps a broken invariant from making every
    /// template invalid.
    pub fn select(&self, max_weight: u64, mut pool: u128) -> Vec<Transaction> {
        let mut entries: Vec<&Entry> = self.entries.values().collect();
        entries.sort_by(|a, b| b.rate_cmp(a).then(a.seq.cmp(&b.seq)));
        let (mut weight, mut px) = (0u64, 0u64);
        let mut out = Vec::new();
        let mut used: std::collections::HashSet<ConflictKey> = std::collections::HashSet::new();
        for e in entries {
            if e.keys.iter().any(|k| used.contains(k)) {
                log::warn!(
                    "mempool: transaction {} conflicts with one already in the template; skipped",
                    hex_short(&e.tx.hash())
                );
                continue;
            }
            let before = out.len();
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
            if out.len() > before {
                used.extend(e.keys.iter().copied());
            }
        }
        out
    }
}

fn hex_short(id: &Hash) -> String {
    id[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    //! Pool policy (admission order, conflicts, eviction, class caps, template
    //! selection) on synthetic PX transactions. Validation is tested elsewhere
    //! (chain/tests/mempool.rs); `insert` is the step after it.
    use super::*;
    use blacksilk_tx::px::PxTx;

    /// A synthetic PX transaction: `bytes` of proof, the given fee, bridge
    /// amounts, and nullifiers derived from `n` (conflict keys).
    fn px(n: u32, bytes: usize, fee: u64, bridge_in: u64, bridge_out: u64) -> Transaction {
        Transaction::Px(Box::new(PxTx {
            inputs: vec![],
            outputs: vec![],
            payouts: vec![],
            fee,
            bridge_in,
            bridge_out,
            anchor: [0; 8],
            nullifiers: [[n, 0, 0, 0, 0, 0, 0, 1], [n, 0, 0, 0, 0, 0, 0, 2]],
            commitments: [[n; 8], [n + 1; 8]],
            ciphertexts: [vec![], vec![]],
            functions: vec![],
            pseudo_outs: vec![],
            range_proof: None,
            signatures: vec![],
            proof: vec![n as u8; bytes],
        }))
    }

    fn add(m: &mut Mempool, tx: Transaction) -> Result<Hash, MempoolError> {
        let (id, keys) = m.precheck(&tx)?;
        m.insert(id, tx, keys)
    }

    /// Fills the PX class as far as it goes with entries of `size` proof
    /// bytes at fee `fee`; returns their ids.
    fn fill(m: &mut Mempool, from: u32, size: usize, fee: u64) -> Vec<Hash> {
        let mut ids = Vec::new();
        let mut n = from;
        loop {
            let tx = px(n, size, fee, 0, 0);
            if m.bytes[1] + tx.encode().len() > MEMPOOL_MAX_PX_BYTES {
                return ids;
            }
            ids.push(add(m, tx).unwrap());
            n += 2;
        }
    }

    #[test]
    fn duplicates_conflicts_and_coinbases_are_refused() {
        let mut m = Mempool::new();
        let a = px(1, 1000, 10, 0, 0);
        let id = add(&mut m, a.clone()).unwrap();
        assert_eq!(add(&mut m, a), Err(MempoolError::AlreadyKnown));
        // Another transaction spending one of the same nullifiers.
        let mut b = px(1, 1000, 99, 0, 0);
        if let Transaction::Px(t) = &mut b {
            t.nullifiers[1] = [7; 8];
        }
        assert_eq!(
            add(&mut m, b),
            Err(MempoolError::Conflict),
            "first seen wins"
        );
        let cb = Transaction::Coinbase(blacksilk_tx::types::Coinbase {
            height: 1,
            outputs: vec![],
        });
        assert_eq!(m.precheck(&cb).map(|_| ()), Err(MempoolError::Coinbase));
        // Removing it frees its conflict keys.
        m.remove(&id).unwrap();
        assert!(m.is_empty());
        assert_eq!(m.bytes(), 0);
        add(&mut m, px(1, 1000, 1, 0, 0)).unwrap();
    }

    /// A full class admits a transaction only by evicting strictly cheaper
    /// entries, and never evicts when that cannot make enough room (the
    /// partial eviction fixed on 2026-09-27).
    #[test]
    fn a_full_pool_evicts_only_strictly_cheaper_entries_and_only_if_that_suffices() {
        let mut m = Mempool::new();
        let size = 1024 * 1024;
        let cheap = fill(&mut m, 0, size, 100);
        let before = m.len();
        // Same fee rate: refused, nothing evicted.
        assert_eq!(
            add(&mut m, px(1_000_001, size, 100, 0, 0)),
            Err(MempoolError::FeeTooLowForFullPool)
        );
        assert_eq!(m.len(), before);
        // Higher fee rate: as many cheap entries as needed are evicted, newest
        // first among equals.
        let id = add(&mut m, px(1_000_003, size, 1_000, 0, 0)).unwrap();
        assert!(m.contains(&id));
        assert_eq!(m.len(), before);
        assert!(
            !m.contains(cheap.last().unwrap()),
            "newest cheap entry evicted"
        );
        assert!(m.contains(&cheap[0]));
        assert!(m.bytes[1] <= MEMPOOL_MAX_PX_BYTES);

        // Mid-rate entries and one cheap entry: a transaction just below the
        // mid rate (fee per byte, overhead included) beats only the cheap
        // entry, and needs more room than it and the free space give: it is
        // refused, and the pool is unchanged.
        let mut m = Mempool::new();
        let ids = fill(&mut m, 0, size, 500);
        m.remove(&ids[0]).unwrap();
        add(&mut m, px(2_000_001, size, 100, 0, 0)).unwrap();
        let snapshot: Vec<Hash> = m.entries.keys().copied().collect();
        let bytes = m.bytes();
        assert_eq!(
            add(&mut m, px(2_000_003, 3 * size, 1_400, 0, 0)),
            Err(MempoolError::FeeTooLowForFullPool)
        );
        assert_eq!(m.bytes(), bytes);
        assert!(snapshot.iter().all(|id| m.contains(id)), "nothing evicted");
        // Larger than the class cap: refused outright.
        assert_eq!(
            add(
                &mut m,
                px(2_000_005, MEMPOOL_MAX_PX_BYTES + 1, u64::MAX / 2, 0, 0)
            ),
            Err(MempoolError::FeeTooLowForFullPool)
        );
    }

    /// Flooding with cheap entries costs the pool one sort per admission, not
    /// one scan per victim.
    #[test]
    fn eviction_under_a_flood_stays_fast() {
        let mut m = Mempool::new();
        let ids = fill(&mut m, 0, 3_000, 1);
        assert!(ids.len() > 20_000, "{}", ids.len());
        let t = std::time::Instant::now();
        // One transaction that must evict ~2 000 flood entries.
        add(&mut m, px(u32::MAX - 10, 6 * 1024 * 1024, 1_000_000, 0, 0)).unwrap();
        assert!(
            t.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            t.elapsed()
        );
        assert!(m.bytes[1] <= MEMPOOL_MAX_PX_BYTES);
    }

    /// Templates: highest fee rate first, then first seen; the PX byte budget;
    /// the PX pool never negative in block order.
    #[test]
    fn selection_orders_by_fee_rate_and_respects_budgets_and_the_pool() {
        let mut m = Mempool::new();
        let low = add(&mut m, px(10, 1000, 10, 0, 0)).unwrap();
        let high = add(&mut m, px(20, 1000, 50, 0, 0)).unwrap();
        let tie_first = add(&mut m, px(30, 1000, 30, 0, 0)).unwrap();
        let tie_second = add(&mut m, px(40, 1000, 30, 0, 0)).unwrap();
        let order: Vec<Hash> = m
            .select(u64::MAX, 0)
            .iter()
            .map(Transaction::hash)
            .collect();
        assert_eq!(order, vec![high, tie_first, tie_second, low]);

        // The PX byte budget: 8 MiB of 3 MiB transactions takes two.
        let mut m = Mempool::new();
        for n in 0..4 {
            add(&mut m, px(100 + 2 * n, 3 * 1024 * 1024, 1_000, 0, 0)).unwrap();
        }
        let sel = m.select(u64::MAX, 0);
        assert_eq!(sel.len(), 2);
        assert!(sel.iter().map(Transaction::px_bytes).sum::<u64>() <= MAX_PX_BLOCK_BYTES);

        // The pool: a withdrawal of 5 from a pool of 3 is skipped until a
        // deposit selected before it covers it.
        let mut m = Mempool::new();
        let withdraw = add(&mut m, px(200, 1000, 90, 0, 5)).unwrap();
        let sel = m.select(u64::MAX, 3);
        assert!(sel.is_empty(), "would make the pool negative");
        let deposit = add(&mut m, px(202, 1000, 95, 4, 0)).unwrap();
        let sel: Vec<Hash> = m
            .select(u64::MAX, 3)
            .iter()
            .map(Transaction::hash)
            .collect();
        assert_eq!(
            sel,
            vec![deposit, withdraw],
            "deposit first, then 3 + 4 - 5"
        );
    }

    /// A connected block removes its transactions and every pooled transaction
    /// that conflicts with them; the byte counts follow.
    #[test]
    fn a_block_removes_its_transactions_and_their_conflicts() {
        let mut m = Mempool::new();
        let a = px(1, 1000, 10, 0, 0);
        add(&mut m, a.clone()).unwrap();
        let b = add(&mut m, px(3, 1000, 10, 0, 0)).unwrap();
        // The block holds `a` and a different transaction spending a nullifier
        // of `b`.
        let mut rival = px(3, 500, 10, 0, 0);
        if let Transaction::Px(t) = &mut rival {
            t.nullifiers[1] = [9; 8];
        }
        m.remove_block(&[a, rival]);
        assert!(m.is_empty(), "{} left", m.len());
        assert!(!m.contains(&b));
        assert_eq!(m.bytes(), 0);
        assert!(m.keys.is_empty());
    }
}
