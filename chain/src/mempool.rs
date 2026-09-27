//! Transaction pool (docs/blocks.md §7, docs/px.md §11.5). Policy, not consensus.
//!
//! Holds every kind of non-coinbase transaction. Two classes with separate
//! size caps and fee rates:
//! - **v1** (transfers): fee per weight, bounded by [`MEMPOOL_MAX_BYTES`];
//! - **PX** (PX transactions and deploys): fee per byte, bounded by
//!   [`MEMPOOL_MAX_PX_BYTES`], selected against the block's PX byte budget.
//!
//! Conflicts are first-seen-wins, whatever the fee, on three kinds of key,
//! each in its own namespace ([`ConflictKind`]): key images, PX nullifiers and
//! deploy contract ids. Two pooled transactions never share any of them, so
//! no block template holds two transactions a block could not hold together
//! (rules C2, PX2, the contract registry).
//!
//! **Output one-time keys are not conflict keys.** Consensus does not require
//! them to be unique across transactions (D8 option B,
//! docs/reviews/v3-consensus-changes.md §1): a key is public once its
//! transaction is relayed, and a first-seen rule on it would let anyone who
//! sees a pending transaction delay it with a copy of one of its keys (the
//! policy form of the front-running veto the consensus rule had). Two pooled
//! transactions sharing an output key are both valid, together, in any block.
//! `select` re-checks the conflict keys as a second line of defence; it is not
//! a substitute for admission.
//!
//! **Expiry.** A transaction leaves the pool [`MEMPOOL_EXPIRY_BLOCKS`] after
//! the height it was admitted for, whatever its kind, and is then refused
//! again for [`RECENTLY_EXPIRED_BLOCKS`] ([`MempoolError::Expired`]), so that
//! no node re-injects it while other nodes still expire it (a re-injection
//! would mark its origin). A transaction returned by a disconnected block is
//! pooled again regardless ([`Mempool::readmit`]).
//!
//! **PX proofs are verified once, on admission.** After a block, pooled PX
//! transactions are revalidated against the new state (anchor, nullifiers,
//! registry, pool, rings) without re-verifying the proof, which depends only
//! on the transaction and its registered programs; a change to those fails
//! the state checks. Re-verifying every pooled proof at every block would be a
//! denial-of-service lever.

use blacksilk_consensus::Hash;
use blacksilk_tx::params::{SigDomain, TxRules, MAX_DEPLOY_BLOCK_BYTES, MAX_PX_BLOCK_BYTES};
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
/// A pooled transaction expires once the next block's height reaches its
/// admission height plus this many blocks (about 3 days at 120 s, Monero's
/// `CRYPTONOTE_MEMPOOL_TX_LIVETIME`). The same value for every kind, deploys
/// included (decisions, Agent 38): a per-kind expiry would itself tell kinds
/// apart. PX transactions leave earlier anyway, when their anchor leaves the
/// 100-block root window. Policy; see [`Mempool::expire`].
pub const MEMPOOL_EXPIRY_BLOCKS: u64 = 2_160;
/// Blocks during which a transaction this node expired is refused again
/// ([`MempoolError::Expired`]): on `/tx`, on relay and on the stem. Every
/// honest node expires a transaction within the same few blocks (it was
/// admitted network-wide within seconds), so within this window no node
/// re-injects it, and a wallet's re-submission cannot mark its node as the
/// origin to a stem peer that still pools it (dossier 38 §3.4, Monero's
/// `m_timed_out_transactions`).
pub const RECENTLY_EXPIRED_BLOCKS: u64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MempoolError {
    AlreadyKnown,
    /// A key image, PX nullifier or contract id is already used by another
    /// pooled transaction (first seen wins, whatever the fee: there is no
    /// replacement).
    Conflict,
    Coinbase,
    Invalid(TxError),
    /// The pool is full and the fee rate does not beat the cheapest entry of
    /// the same class.
    FeeTooLowForFullPool,
    /// This node expired the transaction less than
    /// [`RECENTLY_EXPIRED_BLOCKS`] blocks ago ([`MEMPOOL_EXPIRY_BLOCKS`]);
    /// it is not admitted, relayed or stemmed again until then. Policy: the
    /// transaction may still be valid, and no peer is penalized for it.
    Expired,
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
    /// Block weight (`Transaction::weight`, B6): a transfer's, or the v1
    /// part of a PX or deploy transaction (R12-2).
    weight: u64,
    /// Bytes against the block's PX budget (`Transaction::px_bytes`).
    px_bytes: u64,
    seq: u64,
    /// Conflict keys (`conflict_keys`).
    keys: Vec<ConflictKey>,
    /// The height the transaction was admitted for (the next block's height
    /// at admission); it expires [`MEMPOOL_EXPIRY_BLOCKS`] later.
    admitted: u64,
}

/// The namespace of a conflict key. The same 32 bytes in two namespaces are
/// different keys: a key image never conflicts with a nullifier digest or a
/// contract id that happens to have the same bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConflictKind {
    KeyImage,
    Nullifier,
    ContractId,
}

pub type ConflictKey = (ConflictKind, [u8; 32]);

impl Entry {
    /// Fee per cost unit, compared without division.
    fn rate_cmp(&self, other: &Entry) -> std::cmp::Ordering {
        (self.tx.fee() as u128 * other.cost as u128)
            .cmp(&(other.tx.fee() as u128 * self.cost as u128))
    }

    /// Fee per block-weight unit, compared without division: the order of
    /// transfers and deploys in templates, which compete for the same weight
    /// (one unit, no cross-unit comparison).
    fn weight_rate_cmp(&self, other: &Entry) -> std::cmp::Ordering {
        (self.tx.fee() as u128 * other.weight as u128)
            .cmp(&(other.tx.fee() as u128 * self.weight as u128))
    }
}

fn class_of(tx: &Transaction) -> Class {
    match tx {
        Transaction::Px(_) | Transaction::PxDeploy(_) => Class::Px,
        _ => Class::V1,
    }
}

/// The conflict keys of a transaction: what it spends or registers, the
/// things consensus allows only once (key images, C2; PX nullifiers, PX2; a
/// deploy's contract id). Output one-time keys are not among them (module
/// docs).
pub fn conflict_keys(tx: &Transaction) -> Vec<ConflictKey> {
    use ConflictKind::*;
    let mut keys: Vec<ConflictKey> = tx
        .key_images()
        .iter()
        .map(|k| (KeyImage, *k.bytes()))
        .collect();
    match tx {
        Transaction::Px(t) => {
            keys.extend(t.nullifiers.iter().map(|n| (Nullifier, digest_bytes(n))));
        }
        Transaction::PxDeploy(t) => keys.push((ContractId, digest_bytes(&t.contract_id()))),
        Transaction::Coinbase(_) | Transaction::Transfer(_) => {}
    }
    keys
}

#[derive(Default)]
pub struct Mempool {
    entries: HashMap<Hash, Entry>,
    keys: HashMap<ConflictKey, Hash>,
    bytes: [usize; 2],
    next_seq: u64,
    /// The signature domain (network and branch ids) every pooled transaction
    /// was validated under; `None` before the first admission.
    domain: Option<SigDomain>,
    /// Transactions this node expired: id -> the height they expired at.
    /// Refused while `height < expired_at + RECENTLY_EXPIRED_BLOCKS`
    /// ([`MempoolError::Expired`]); forgotten afterwards ([`Self::expire`]).
    expired: HashMap<Hash, u64>,
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

    /// The signature domain the pooled transactions were validated under.
    pub fn validated_under(&self) -> Option<SigDomain> {
        self.domain
    }

    /// Makes `rules` the pool's rule set. If the pool was validated under
    /// another signature domain (an activation between the old and the new
    /// next height, in either direction), every entry is dropped and their
    /// conflict keys (key images, nullifiers, contract ids) are
    /// released. Returns the number dropped.
    ///
    /// A flush, not a revalidation: every signature message and the PX
    /// binding `h_tx` commit to the branch id, so every pooled v1 or deploy
    /// signature and every pooled PX proof fails under the new domain. A full
    /// revalidation would reach the same verdict after verifying each of them
    /// again (docs/reviews/v3-upgrade-mechanism.md §2.5).
    pub fn enter_rules(&mut self, rules: &TxRules) -> usize {
        let domain = rules.domain();
        if self.domain == Some(domain) {
            return 0;
        }
        let dropped = if self.domain.is_some() {
            let n = self.entries.len();
            self.entries.clear();
            self.keys.clear();
            self.bytes = [0, 0];
            n
        } else {
            0
        };
        self.domain = Some(domain);
        dropped
    }

    /// Whether `tx` shares a conflict key ([`conflict_keys`]) with a pooled
    /// transaction other than itself: [`Self::add`] would refuse it with
    /// [`MempoolError::Conflict`] (first seen wins). Read-only and cheap (no
    /// validation): the P2P layer drops such a transaction before verifying it
    /// or charging the node-wide PX relay budget (docs/p2p.md §10).
    pub fn conflicts(&self, tx: &Transaction) -> bool {
        let id = tx.hash();
        conflict_keys(tx)
            .iter()
            .any(|k| self.keys.get(k).is_some_and(|holder| *holder != id))
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

    /// Cheap admission checks, before any validation: not a coinbase, not
    /// pooled, not expired here recently (for inclusion at `height`), no
    /// conflict key in use.
    fn precheck(
        &self,
        tx: &Transaction,
        height: u64,
    ) -> Result<(Hash, Vec<ConflictKey>), MempoolError> {
        if tx.is_coinbase() {
            return Err(MempoolError::Coinbase);
        }
        let id = tx.hash();
        if self.entries.contains_key(&id) {
            return Err(MempoolError::AlreadyKnown);
        }
        if self.recently_expired(&id, height) {
            return Err(MempoolError::Expired);
        }
        let keys = conflict_keys(tx);
        if keys.iter().any(|k| self.keys.contains_key(k)) {
            return Err(MempoolError::Conflict);
        }
        Ok((id, keys))
    }

    /// Whether this node expired `id` fewer than [`RECENTLY_EXPIRED_BLOCKS`]
    /// blocks before `height` (the height a transaction would be admitted
    /// for). After a reorganization to a lower height the window lasts
    /// longer, never shorter.
    pub fn recently_expired(&self, id: &Hash, height: u64) -> bool {
        self.expired
            .get(id)
            .is_some_and(|&at| height < at.saturating_add(RECENTLY_EXPIRED_BLOCKS))
    }

    /// Validates `tx` for inclusion at `height` without adding it. Returns its id.
    pub fn check(
        &self,
        tx: &Transaction,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
    ) -> Result<Hash, MempoolError> {
        let (id, _) = self.precheck(tx, height)?;
        validate_mempool_tx(tx, chain, height, rules).map_err(MempoolError::Invalid)?;
        Ok(id)
    }

    /// A pooled transaction by id.
    pub fn get(&self, id: &Hash) -> Option<&Transaction> {
        self.entries.get(id).map(|e| &e.tx)
    }

    /// The height a pooled transaction was admitted for; it expires
    /// [`MEMPOOL_EXPIRY_BLOCKS`] later.
    pub fn admitted_at(&self, id: &Hash) -> Option<u64> {
        self.entries.get(id).map(|e| e.admitted)
    }

    /// Validates `tx` for inclusion at `height` and adds it.
    pub fn add(
        &mut self,
        tx: Transaction,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
    ) -> Result<Hash, MempoolError> {
        // Under other rules than the pool's, the pool is flushed first
        // (`enter_rules`): it never mixes transactions of two rule sets.
        self.enter_rules(rules);
        let (id, keys) = self.precheck(&tx, height)?;
        validate_mempool_tx(&tx, chain, height, rules).map_err(MempoolError::Invalid)?;
        self.insert(id, tx, keys, height)
    }

    /// [`Self::add`] for a transaction of a block this node disconnected (a
    /// reorganization returns it to the pool). It is not refused as recently
    /// expired: it was on the best chain, so it is no re-injection by its
    /// origin, and it is not relayed from here. It is pooled with a fresh
    /// admission height (`height`), so it gets a full expiry window again,
    /// and it leaves the recently-expired set.
    pub fn readmit(
        &mut self,
        tx: Transaction,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
    ) -> Result<Hash, MempoolError> {
        self.expired.remove(&tx.hash());
        self.add(tx, chain, height, rules)
    }

    /// Expires every transaction admitted at least [`MEMPOOL_EXPIRY_BLOCKS`]
    /// before `height` (the next block's height): it is removed with its
    /// conflict keys and remembered as recently expired, and refused again
    /// until `height + RECENTLY_EXPIRED_BLOCKS`. Transactions remembered
    /// that long are forgotten. Returns the number expired.
    ///
    /// The count is from this node's admission height, the same for every
    /// kind (policy, not consensus: no expiry field exists in transactions,
    /// whose value would fingerprint the wallet).
    pub fn expire(&mut self, height: u64) -> usize {
        self.expired
            .retain(|_, at| height < at.saturating_add(RECENTLY_EXPIRED_BLOCKS));
        let old: Vec<Hash> = self
            .entries
            .iter()
            .filter(|(_, e)| height >= e.admitted.saturating_add(MEMPOOL_EXPIRY_BLOCKS))
            .map(|(id, _)| *id)
            .collect();
        for id in &old {
            self.remove(id);
            self.expired.insert(*id, height);
        }
        old.len()
    }

    fn insert(
        &mut self,
        id: Hash,
        tx: Transaction,
        keys: Vec<ConflictKey>,
        admitted: u64,
    ) -> Result<Hash, MempoolError> {
        let class = class_of(&tx);
        let size = tx.encode().len();
        let cost = match class {
            Class::V1 => tx.weight(),
            Class::Px => tx.px_bytes(),
        };
        let (weight, px_bytes) = (tx.weight(), tx.px_bytes());
        let entry = Entry {
            tx,
            class,
            size,
            cost,
            weight,
            px_bytes,
            seq: self.next_seq,
            keys,
            admitted,
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
    /// nullifier, a registered contract). A pooled transaction whose output
    /// one-time key the block also created stays: it is still valid.
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
    ///
    /// Across an activation (`rules` in another signature domain than the
    /// pool's) the extension-only check is not enough, since signatures and
    /// PX proofs change verdict: the pool is flushed ([`Self::enter_rules`]).
    pub fn revalidate(
        &mut self,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
        after_reorg: bool,
    ) {
        self.enter_rules(rules);
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

    /// Transactions for a block template. Every candidate is charged against
    /// the block weight budget `max_weight` (`Transaction::weight`: a
    /// transfer's weight, or the v1 part of a PX or deploy transaction,
    /// R12-2), and PX and deploy transactions also against the PX byte budget
    /// (deploys also against the deploy sub-budget): a template never breaks
    /// B6 (docs/reviews/v3-consensus-changes.md#r12-2).
    ///
    /// Order: PX transactions first (by fee per PX byte, then first seen;
    /// their fee is uniform), so v1 congestion cannot keep one with v1 inputs
    /// out; then transfers and deploys, which compete for the same weight, by
    /// fee per weight, then first seen. No two units are compared.
    ///
    /// `pool` is the PX pool before the block: PX transactions are taken
    /// only while the pool, evolving in block order, stays non-negative (each
    /// was admitted against the chain's pool alone). `px_leaves` is the room
    /// left in the PX commitment tree: PX transactions are taken only while
    /// their output commitments, one leaf each, fit (B8).
    ///
    /// Defence in depth: a transaction sharing a conflict key with one already
    /// selected is skipped (and logged). Admission already guarantees that no
    /// two pooled transactions share one, so this never fires unless that
    /// invariant is broken; it keeps a broken invariant from making every
    /// template invalid.
    pub fn select(&self, max_weight: u64, mut pool: u128, px_leaves: u64) -> Vec<Transaction> {
        let (mut px_first, mut rest): (Vec<&Entry>, Vec<&Entry>) = self
            .entries
            .values()
            .partition(|e| matches!(e.tx, Transaction::Px(_)));
        px_first.sort_by(|a, b| b.rate_cmp(a).then(a.seq.cmp(&b.seq)));
        rest.sort_by(|a, b| b.weight_rate_cmp(a).then(a.seq.cmp(&b.seq)));
        let (mut weight, mut px, mut deploy, mut leaves) = (0u64, 0u64, 0u64, 0u64);
        let mut out = Vec::new();
        let mut used: std::collections::HashSet<ConflictKey> = std::collections::HashSet::new();
        for e in px_first.into_iter().chain(rest) {
            if e.keys.iter().any(|k| used.contains(k)) {
                log::warn!(
                    "mempool: transaction {} conflicts with one already in the template; skipped",
                    hex_short(&e.tx.hash())
                );
                continue;
            }
            // Both budgets, for every kind.
            let Some(w) = weight.checked_add(e.weight).filter(|w| *w <= max_weight) else {
                continue;
            };
            let Some(p) = px
                .checked_add(e.px_bytes)
                .filter(|p| *p <= MAX_PX_BLOCK_BYTES)
            else {
                continue;
            };
            match &e.tx {
                Transaction::Px(t) => {
                    let l = leaves + t.commitments.len() as u64;
                    if l > px_leaves {
                        continue;
                    }
                    match (pool + t.bridge_in as u128).checked_sub(t.bridge_out as u128) {
                        Some(next) => pool = next,
                        None => continue,
                    }
                    leaves = l;
                }
                // Deploys also fit the block's deploy sub-budget
                // (`MAX_DEPLOY_BLOCK_BYTES`, a block rule).
                Transaction::PxDeploy(_) => {
                    if deploy + e.px_bytes > MAX_DEPLOY_BLOCK_BYTES {
                        continue;
                    }
                    deploy += e.px_bytes;
                }
                _ => {}
            }
            weight = w;
            px = p;
            out.push(e.tx.clone());
            used.extend(e.keys.iter().copied());
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
        add_at(m, tx, 0)
    }

    /// `add` for inclusion at `height` (the admission height).
    fn add_at(m: &mut Mempool, tx: Transaction, height: u64) -> Result<Hash, MempoolError> {
        let (id, keys) = m.precheck(&tx, height)?;
        m.insert(id, tx, keys, height)
    }

    /// Expiry (policy): a transaction admitted for height `a` stays pooled
    /// while the next height is below `a + MEMPOOL_EXPIRY_BLOCKS`, and is
    /// removed at exactly that height, with its conflict keys and bytes,
    /// whatever its kind. Each entry counts from its own admission height.
    #[test]
    fn a_transaction_expires_exactly_at_its_admission_height_plus_the_expiry() {
        let mut m = Mempool::new();
        let a = 100;
        let kinds = [
            px(1, 1000, 10, 0, 0),
            transfer(&[5], &[10, 11], 10),
            deploy(6, &[12, 13], 0, 10),
        ];
        let ids: Vec<Hash> = kinds
            .iter()
            .map(|tx| add_at(&mut m, tx.clone(), a).unwrap())
            .collect();
        // A later admission expires later.
        let late = add_at(&mut m, px(3, 1000, 10, 0, 0), a + 7).unwrap();
        assert_eq!(m.expire(a + MEMPOOL_EXPIRY_BLOCKS - 1), 0);
        assert_eq!(m.len(), 4);
        assert_eq!(m.expire(a + MEMPOOL_EXPIRY_BLOCKS), 3, "every kind expires");
        assert!(ids.iter().all(|id| !m.contains(id)));
        assert!(m.contains(&late));
        assert_invariants(&m);
        // The conflict keys are free: another transaction spending the same
        // key image is admitted.
        add_at(
            &mut m,
            transfer(&[5], &[20, 21], 10),
            a + MEMPOOL_EXPIRY_BLOCKS + 1,
        )
        .unwrap();
        assert_eq!(m.expire(a + 7 + MEMPOOL_EXPIRY_BLOCKS), 1);
        assert!(!m.contains(&late));
        assert_invariants(&m);
    }

    /// The recently-expired guard: an expired transaction is refused with
    /// `Expired` (before its conflict keys or anything else are looked at)
    /// for exactly `RECENTLY_EXPIRED_BLOCKS` blocks, then admitted again and
    /// forgotten. Only that transaction: another one spending the same key
    /// images is not refused by the guard.
    #[test]
    fn an_expired_transaction_is_refused_for_the_guard_window_only() {
        let mut m = Mempool::new();
        let tx = transfer(&[5], &[10, 11], 10);
        let id = add_at(&mut m, tx.clone(), 0).unwrap();
        let e = MEMPOOL_EXPIRY_BLOCKS;
        assert_eq!(m.expire(e), 1);
        for h in e..e + RECENTLY_EXPIRED_BLOCKS {
            assert!(m.recently_expired(&id, h));
            assert_eq!(m.precheck(&tx, h).map(|_| ()), Err(MempoolError::Expired));
        }
        let rebuilt = transfer(&[5], &[30, 31], 10);
        let other = add_at(&mut m, rebuilt, e + 1).unwrap();
        m.remove(&other).unwrap();
        let end = e + RECENTLY_EXPIRED_BLOCKS;
        assert!(!m.recently_expired(&id, end));
        m.expire(end);
        assert!(m.expired.is_empty(), "forgotten after the window");
        assert_eq!(add_at(&mut m, tx, end), Ok(id));
        // Admitted again: it expires a full window after the new admission.
        assert_eq!(m.expire(end + e - 1), 0);
        assert_eq!(m.expire(end + e), 1);
    }

    /// Reorganizations: after the tip moves down, expiry counts from the
    /// admission height against the new (lower) height, so nothing expires
    /// early, and the guard lasts longer, never shorter. A transaction
    /// returned by a disconnected block (`readmit`) is pooled even while it
    /// is recently expired, with a fresh admission height.
    #[test]
    fn expiry_and_the_guard_follow_the_height_across_reorganizations() {
        let mut m = Mempool::new();
        let e = MEMPOOL_EXPIRY_BLOCKS;
        let a = add_at(&mut m, px(1, 1000, 10, 0, 0), 50).unwrap();
        let b_tx = px(3, 1000, 10, 0, 0);
        let b = add_at(&mut m, b_tx.clone(), 10).unwrap();
        assert_eq!(m.expire(10 + e), 1, "b expires");
        assert!(m.contains(&a));
        // A reorganization lowers the next height by 20 blocks: a is not
        // expired early, b stays refused past its original window.
        assert_eq!(m.expire(10 + e - 20), 0);
        assert!(m.contains(&a));
        assert!(m.recently_expired(&b, 10 + e + RECENTLY_EXPIRED_BLOCKS - 21));
        assert_eq!(
            m.precheck(&b_tx, 10 + e - 19).map(|_| ()),
            Err(MempoolError::Expired)
        );
        // b was meanwhile mined on the other branch and that block is
        // disconnected: the returned transaction is admitted again, with a
        // fresh admission height, and leaves the guard.
        let chain = blacksilk_tx::state::MemoryChain::new();
        let rules = TxRules::at_height(&blacksilk_consensus::ChainParams::regtest(), 0);
        // (A synthetic transaction fails validation; the guard is what is
        // tested here: `readmit` gets past it to validation.)
        assert!(matches!(
            m.readmit(b_tx.clone(), &chain, 10 + e - 19, &rules),
            Err(MempoolError::Invalid(_))
        ));
        assert!(!m.recently_expired(&b, 10 + e - 19));
        assert_eq!(add_at(&mut m, b_tx, 10 + e - 19), Ok(b));
        assert_eq!(m.expire(10 + e - 19 + e - 1), 1, "a expires, b does not");
        assert!(m.contains(&b) && !m.contains(&a));
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
        assert_eq!(m.precheck(&cb, 0).map(|_| ()), Err(MempoolError::Coinbase));
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
            .select(u64::MAX, 0, u64::MAX)
            .iter()
            .map(Transaction::hash)
            .collect();
        assert_eq!(order, vec![high, tie_first, tie_second, low]);

        // The PX byte budget: 8 MiB of 3 MiB transactions takes two.
        let mut m = Mempool::new();
        for n in 0..4 {
            add(&mut m, px(100 + 2 * n, 3 * 1024 * 1024, 1_000, 0, 0)).unwrap();
        }
        let sel = m.select(u64::MAX, 0, u64::MAX);
        assert_eq!(sel.len(), 2);
        assert!(sel.iter().map(Transaction::px_bytes).sum::<u64>() <= MAX_PX_BLOCK_BYTES);

        // The pool: a withdrawal of 5 from a pool of 3 is skipped until a
        // deposit selected before it covers it.
        let mut m = Mempool::new();
        let withdraw = add(&mut m, px(200, 1000, 90, 0, 5)).unwrap();
        let sel = m.select(u64::MAX, 3, u64::MAX);
        assert!(sel.is_empty(), "would make the pool negative");
        let deposit = add(&mut m, px(202, 1000, 95, 4, 0)).unwrap();
        let sel: Vec<Hash> = m
            .select(u64::MAX, 3, u64::MAX)
            .iter()
            .map(Transaction::hash)
            .collect();
        assert_eq!(
            sel,
            vec![deposit, withdraw],
            "deposit first, then 3 + 4 - 5"
        );
    }

    /// `conflicts` answers what `add` would say about conflicts, without
    /// changing the pool: a pooled transaction is not its own conflict, a
    /// rival sharing one nullifier is, and a disjoint one is not.
    #[test]
    fn the_conflict_query_matches_admission() {
        let mut m = Mempool::new();
        let a = px(1, 1000, 10, 0, 0);
        assert!(!m.conflicts(&a), "empty pool");
        add(&mut m, a.clone()).unwrap();
        assert!(
            !m.conflicts(&a),
            "a pooled transaction is not its own conflict"
        );
        let mut rival = px(1, 900, 99, 0, 0);
        if let Transaction::Px(t) = &mut rival {
            t.nullifiers[0] = [5; 8];
        }
        assert!(m.conflicts(&rival));
        let other = px(3, 1000, 10, 0, 0);
        assert!(!m.conflicts(&other));
        let (len, bytes) = (m.len(), m.bytes());
        assert_eq!(add(&mut m, rival), Err(MempoolError::Conflict));
        assert_eq!((m.len(), m.bytes()), (len, bytes));
        add(&mut m, other).unwrap();
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

    // ------------------------------------------------ output one-time keys (D8)
    //
    // Synthetic transactions: only their conflict keys, fee and size matter to
    // the pool. Validation (signatures, proofs) of transactions sharing output
    // keys is exercised with real transactions in
    // chain/tests/mempool_conflicts.rs.

    use blacksilk_crypto::bulletproofs_plus::BppProof;
    use blacksilk_crypto::clsag::{Clsag, RING_SIZE};
    use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
    use blacksilk_tx::px::PxDeploy;
    use blacksilk_tx::types::{Coinbase, CoinbaseOutput, Input, Output, Transfer};
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::collections::{HashMap, HashSet};

    /// A valid, non-identity group element numbered `n`: `(n + 1)·G`.
    fn pt(n: u64) -> Point {
        Point::from_point(RistrettoPoint::mul_base(&Scalar::from(n + 1)))
    }

    fn output(k: u64) -> Output {
        Output {
            one_time_key: pt(k),
            ephemeral: pt(1_000_000),
            view_tag: 0,
            commitment: pt(1_000_001),
            enc_amount: [0; 8],
            enc_anchor: [0; 16],
        }
    }

    fn payout(k: u64) -> CoinbaseOutput {
        CoinbaseOutput {
            one_time_key: pt(k),
            ephemeral: pt(1_000_000),
            view_tag: 0,
            amount: 1,
            enc_anchor: [0; 16],
        }
    }

    fn input(key_image: u64) -> Input {
        Input {
            key_image: pt(key_image),
            ring: [0; RING_SIZE],
        }
    }

    fn bpp() -> BppProof {
        BppProof {
            a: pt(7),
            a1: pt(7),
            b: pt(7),
            r1: Scalar::ZERO,
            s1: Scalar::ZERO,
            d1: Scalar::ZERO,
            l: vec![],
            r: vec![],
        }
    }

    fn clsag() -> Clsag {
        Clsag {
            c0: Scalar::ZERO,
            s: [Scalar::ZERO; RING_SIZE],
            d: pt(7),
        }
    }

    /// A synthetic v1 transfer spending key images `images` and creating
    /// outputs with one-time keys `outs`.
    fn transfer(images: &[u64], outs: &[u64], fee: u64) -> Transaction {
        Transaction::from(Transfer {
            inputs: images.iter().map(|&k| input(k)).collect(),
            outputs: outs.iter().map(|&k| output(k)).collect(),
            fee,
            pseudo_outs: images.iter().map(|_| pt(9)).collect(),
            range_proof: bpp(),
            signatures: images.iter().map(|_| clsag()).collect(),
        })
    }

    /// `px(n, ..)` with hidden outputs `outs` and payouts `payouts`.
    fn px_out(n: u32, outs: &[u64], payouts: &[u64], fee: u64) -> Transaction {
        let mut tx = px(n, 100, fee, 0, 0);
        if let Transaction::Px(t) = &mut tx {
            t.outputs = outs.iter().map(|&k| output(k)).collect();
            t.payouts = payouts.iter().map(|&k| payout(k)).collect();
        }
        tx
    }

    fn deploy(image: u64, outs: &[u64], salt: u8, fee: u64) -> Transaction {
        Transaction::PxDeploy(Box::new(PxDeploy {
            inputs: vec![input(image)],
            outputs: outs.iter().map(|&k| output(k)).collect(),
            fee,
            salt: [salt; 32],
            programs: vec![],
            pseudo_outs: vec![pt(9)],
            range_proof: bpp(),
            signatures: vec![clsag()],
        }))
    }

    fn coinbase(outs: &[u64]) -> Transaction {
        Transaction::from(Coinbase {
            height: 1,
            outputs: outs.iter().map(|&k| payout(k)).collect(),
        })
    }

    /// The pool's invariants: every entry's keys are its conflict keys; no two
    /// entries share one; the key map holds exactly the entries' keys; the
    /// byte counts are the sums of the entry sizes.
    fn assert_invariants(m: &Mempool) {
        let mut owner: HashMap<ConflictKey, Hash> = HashMap::new();
        let mut bytes = [0usize; 2];
        for (id, e) in &m.entries {
            assert_eq!(e.keys, conflict_keys(&e.tx));
            assert_eq!(*id, e.tx.hash());
            for k in &e.keys {
                if let Some(other) = owner.insert(*k, *id) {
                    assert_eq!(other, *id, "two pooled transactions share {k:?}");
                }
            }
            bytes[Mempool::slot(e.class)] += e.size;
        }
        assert_eq!(m.bytes, bytes);
        assert_eq!(m.bytes(), bytes[0] + bytes[1]);
        assert_eq!(m.keys, owner, "key map = keys of the pooled entries");
    }

    /// No two selected transactions share a conflict key.
    fn assert_disjoint(txs: &[Transaction]) {
        let mut seen = HashSet::new();
        for tx in txs {
            for k in conflict_keys(tx) {
                assert!(seen.insert(k), "template shares {k:?}");
            }
        }
    }

    /// Output one-time keys are not conflict keys, for any kind: a
    /// transaction's conflict keys are its key images, nullifiers and
    /// contract id only (D8 option B).
    #[test]
    fn output_one_time_keys_are_not_conflict_keys() {
        for (tx, expected) in [
            (transfer(&[1], &[10, 11], 5), 1),
            (px_out(1, &[10], &[11], 5), 2),
            (deploy(1, &[10, 11], 0, 5), 2),
            (coinbase(&[10, 11]), 0),
        ] {
            let keys = conflict_keys(&tx);
            assert_eq!(keys.len(), expected, "{keys:?}");
            assert_eq!(tx.output_keys().len(), 2);
        }
        let d = deploy(3, &[10, 11], 0, 5);
        assert!(conflict_keys(&d).contains(&(ConflictKind::KeyImage, *pt(3).bytes())));
        assert!(conflict_keys(&d)
            .iter()
            .any(|(k, _)| *k == ConflictKind::ContractId));
    }

    /// Two transactions sharing only an output one-time key are both pooled,
    /// in every combination of kinds and fees, and both selected.
    #[test]
    fn a_shared_output_key_is_not_a_conflict_across_all_kinds() {
        type Maker = fn(u64, u64) -> Transaction;
        let makers: [(&str, Maker); 4] = [
            ("transfer", |salt, k| {
                transfer(&[100 + salt], &[k, 500 + salt], 10)
            }),
            ("px output", |salt, k| {
                px_out(salt as u32 * 2 + 1_000, &[k], &[], 10)
            }),
            ("px payout", |salt, k| {
                px_out(salt as u32 * 2 + 2_000, &[], &[k], 10)
            }),
            ("deploy", |salt, k| {
                deploy(200 + salt, &[k, 600 + salt], salt as u8, 10)
            }),
        ];
        for (a_name, a) in &makers {
            for (b_name, b) in &makers {
                let mut m = Mempool::new();
                let first = add(&mut m, a(1, 42)).unwrap();
                let mut second = b(2, 42);
                match &mut second {
                    Transaction::Transfer(t) => t.fee = u64::MAX / 4,
                    Transaction::Px(t) => t.fee = u64::MAX / 4,
                    Transaction::PxDeploy(t) => t.fee = u64::MAX / 4,
                    Transaction::Coinbase(_) => unreachable!(),
                }
                let second =
                    add(&mut m, second).unwrap_or_else(|e| panic!("{a_name} then {b_name}: {e:?}"));
                assert_eq!(m.len(), 2);
                let sel: Vec<Hash> = m
                    .select(u64::MAX, 0, u64::MAX)
                    .iter()
                    .map(Transaction::hash)
                    .collect();
                assert!(sel.contains(&first) && sel.contains(&second));
                assert_invariants(&m);
            }
        }
    }

    /// Namespaces: bytes equal across kinds of key never conflict (a key
    /// image and a nullifier digest, say); an output key equal to a pooled
    /// key image is not a conflict key at all.
    #[test]
    fn equal_bytes_in_different_namespaces_do_not_conflict() {
        let mut m = Mempool::new();
        // Key image pt(5); then transactions whose output key is pt(5) (a
        // transfer) and pt(6), the key image of a pooled deploy (a PX payout).
        add(&mut m, transfer(&[5], &[10, 11], 10)).unwrap();
        add(&mut m, deploy(6, &[12, 13], 0, 10)).unwrap();
        add(&mut m, transfer(&[7], &[5, 14], 10)).unwrap();
        add(&mut m, px_out(40, &[], &[6], 10)).unwrap();
        assert!(m
            .keys
            .contains_key(&(ConflictKind::KeyImage, *pt(5).bytes())));
        assert_eq!(m.len(), 4);
        assert_invariants(&m);
        assert_eq!(m.select(u64::MAX, 0, u64::MAX).len(), 4);
        // ...while the same kind conflicts, and output keys never do.
        assert_eq!(
            add(&mut m, transfer(&[5], &[30, 31], 10)),
            Err(MempoolError::Conflict),
            "key image vs key image"
        );
        add(&mut m, transfer(&[8], &[5, 32], 10)).expect("output key vs output key");
        assert_eq!(m.len(), 5);
    }

    /// Defence in depth: if the invariant is broken (both inserted past
    /// `precheck`), `select` still returns only one of a conflicting pair, the
    /// better-paying one (then the first seen), in every template.
    #[test]
    fn select_skips_a_conflicting_entry_when_the_invariant_is_broken() {
        for (fee_a, fee_b, winner) in [(10, 10, 0), (10, 99, 1), (99, 10, 0)] {
            // The same key image, different outputs.
            let a = transfer(&[1], &[42, 50], fee_a);
            let b = transfer(&[1], &[43, 51], fee_b);
            let other = transfer(&[3], &[42, 61], 5);
            let mut m = Mempool::new();
            for tx in [a.clone(), b.clone(), other.clone()] {
                let keys = conflict_keys(&tx);
                m.insert(tx.hash(), tx, keys, 0).unwrap();
            }
            let sel = m.select(u64::MAX, 0, u64::MAX);
            assert_disjoint(&sel);
            let ids: Vec<Hash> = sel.iter().map(Transaction::hash).collect();
            assert_eq!(sel.len(), 2, "one of the pair and the unrelated one");
            assert!(ids.contains(&other.hash()));
            let expected = if winner == 0 { a.hash() } else { b.hash() };
            assert!(ids.contains(&expected), "fees {fee_a}/{fee_b}");
        }
    }

    /// A connected block creating the output keys of pooled transactions
    /// (the coinbase's outputs included) evicts none of them: they are still
    /// valid.
    #[test]
    fn a_block_creating_a_pooled_output_key_evicts_nothing() {
        let mut m = Mempool::new();
        let t = add(&mut m, transfer(&[1], &[42, 50], 10)).unwrap();
        let p = add(&mut m, px_out(3, &[], &[43], 10)).unwrap();
        let d = add(&mut m, deploy(4, &[44, 51], 0, 10)).unwrap();
        // The coinbase reuses the transfer's key, a block transfer the PX
        // payout's, a block PX the deploy's.
        m.remove_block(&[
            coinbase(&[42, 90]),
            transfer(&[20], &[43, 91], 1),
            px_out(500, &[44], &[], 1),
        ]);
        assert!(m.contains(&t) && m.contains(&p) && m.contains(&d));
        assert_eq!(m.len(), 3);
        assert_invariants(&m);
    }

    /// Eviction for room never admits a conflicting transaction: the conflict
    /// check comes first, whatever the fee.
    #[test]
    fn a_full_pool_does_not_evict_for_a_conflicting_transaction() {
        let mut m = Mempool::new();
        let size = 1024 * 1024;
        fill(&mut m, 0, size, 1);
        let victim = add(&mut m, px_out(3_000_001, &[], &[42], 1)).unwrap();
        let before: Vec<Hash> = m.entries.keys().copied().collect();
        // The same nullifiers, another payout.
        let mut rich = px_out(3_000_001, &[], &[43], u64::MAX / 4);
        if let Transaction::Px(t) = &mut rich {
            t.proof = vec![1; size];
        }
        assert_eq!(add(&mut m, rich), Err(MempoolError::Conflict));
        assert!(m.contains(&victim));
        assert!(before.iter().all(|id| m.contains(id)), "nothing evicted");
        assert_invariants(&m);
    }

    /// A synthetic deploy of about `bytes` encoded bytes (one program of
    /// that size).
    fn big_deploy(image: u64, salt: u8, bytes: usize, fee: u64) -> Transaction {
        let mut d = deploy(image, &[1_000 + image, 2_000 + image], salt, fee);
        if let Transaction::PxDeploy(t) = &mut d {
            t.programs = vec![blacksilk_tx::px::Registration {
                elf: vec![salt; bytes],
                budget: blacksilk_px::vault::BUDGET,
            }];
        }
        d
    }

    /// R5-1: templates respect the block's deploy sub-budget
    /// (`MAX_DEPLOY_BLOCK_BYTES`) inside the PX byte budget, and fill the
    /// rest of the PX budget with PX transactions.
    #[test]
    fn selection_respects_the_deploy_sub_budget() {
        let mut m = Mempool::new();
        // Three deploys of 400 KB: only two fit the 1 MiB deploy budget.
        for n in 0..3u64 {
            add(&mut m, big_deploy(10 + n, n as u8, 400_000, 1_000_000)).unwrap();
        }
        // PX transactions at a lower fee rate still fill the PX lane.
        let small = add(&mut m, px(500, 3 * 1024 * 1024, 10, 0, 0)).unwrap();
        let sel = m.select(u64::MAX, 0, u64::MAX);
        let deploy_bytes: u64 = sel
            .iter()
            .filter(|t| matches!(t, Transaction::PxDeploy(_)))
            .map(Transaction::px_bytes)
            .sum();
        assert_eq!(
            sel.iter()
                .filter(|t| matches!(t, Transaction::PxDeploy(_)))
                .count(),
            2
        );
        assert!(deploy_bytes <= MAX_DEPLOY_BLOCK_BYTES);
        assert!(sel.iter().map(Transaction::px_bytes).sum::<u64>() <= MAX_PX_BLOCK_BYTES);
        assert!(sel.iter().any(|t| t.hash() == small));
    }

    /// An activation between two validations flushes the pool and releases
    /// every conflict key; the same rules again keep it.
    #[test]
    fn a_new_signature_domain_flushes_the_pool() {
        let p = blacksilk_consensus::ChainParams::regtest();
        let r0 = TxRules::at_height(&p, 0);
        let r1 = TxRules {
            branch_id: r0.branch_id + 1,
            ..r0
        };
        let mut m = Mempool::new();
        assert_eq!(m.enter_rules(&r0), 0, "the first rules flush nothing");
        assert_eq!(m.validated_under(), Some(r0.domain()));
        add(&mut m, px(1, 1000, 10, 0, 0)).unwrap();
        add(&mut m, transfer(&[5], &[10, 11], 10)).unwrap();
        assert_eq!(m.enter_rules(&r0), 0);
        assert_eq!(m.len(), 2);
        assert_eq!(m.enter_rules(&r1), 2);
        assert!(m.is_empty());
        assert_eq!(m.bytes(), 0);
        assert!(m.keys.is_empty());
        assert_eq!(m.validated_under(), Some(r1.domain()));
        // The keys are free again.
        add(&mut m, px(1, 1000, 10, 0, 0)).unwrap();
        assert_invariants(&m);
    }

    /// A random synthetic transaction drawn from a small key space, so that
    /// conflicts (and equal bytes across namespaces) are frequent.
    fn random_tx(rng: &mut ChaCha20Rng) -> Transaction {
        let mut small = |n: u64| rng.next_u64() % n;
        let fee = 1 + small(1_000);
        let mut outs: Vec<u64> = (0..2 + small(2)).map(|_| small(60)).collect();
        outs.sort_unstable();
        outs.dedup();
        match small(4) {
            0 | 1 => {
                let mut images: Vec<u64> = (0..1 + small(2)).map(|_| small(60)).collect();
                images.sort_unstable();
                images.dedup();
                transfer(&images, &outs, fee)
            }
            2 => {
                let split = small(outs.len() as u64 + 1) as usize;
                // Even seeds: `px(n)` nullifiers are (n, .., 1) and (n, .., 2).
                px_out(small(30) as u32, &outs[..split], &outs[split..], fee)
            }
            _ => deploy(small(60), &outs, small(3) as u8, fee),
        }
    }

    /// `px(n, bytes, ..)` spending v1 key images `images` (R12-2: its v1
    /// part weighs `max_weight(images.len(), 0)`).
    fn px_in(n: u32, bytes: usize, images: &[u64], fee: u64) -> Transaction {
        let mut tx = px(n, bytes, fee, 0, 0);
        if let Transaction::Px(t) = &mut tx {
            t.inputs = images.iter().map(|&k| input(k)).collect();
            t.pseudo_outs = images.iter().map(|_| pt(9)).collect();
            t.signatures = images.iter().map(|_| clsag()).collect();
        }
        tx
    }

    /// R12-2 (a′): a template never exceeds the weight budget (which PX and
    /// deploy transactions with v1 inputs now take from), the PX byte
    /// budget, the deploy sub-budget or the pool, over random pools of every
    /// kind and random budgets; and the total weight is the block rule's own
    /// sum (`Transaction::weight`, B6).
    #[test]
    fn templates_respect_both_budgets_for_every_kind() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x122);
        let mut weight_bound_hit = 0;
        for round in 0..60 {
            let mut m = Mempool::new();
            let mut image = 1_000u64 * (round + 1);
            for i in 0..40u32 {
                let fee = 1 + rng.next_u64() % 100_000;
                let n_in = 1 + (rng.next_u64() % 64) as usize;
                let images: Vec<u64> = (0..n_in as u64).map(|j| image + j).collect();
                image += 64;
                let tx = match rng.next_u64() % 5 {
                    0 => transfer(&images[..1], &[image, image + 1], fee),
                    1 => px_in(
                        2 * i + 1,
                        1 + (rng.next_u64() % 400_000) as usize,
                        &images,
                        fee,
                    ),
                    2 => px(
                        2 * i + 1,
                        1 + (rng.next_u64() % 400_000) as usize,
                        fee,
                        0,
                        0,
                    ),
                    3 => big_deploy(image, i as u8, (rng.next_u64() % 200_000) as usize, fee),
                    _ => {
                        let mut d = deploy(image, &[image + 1, image + 2], i as u8, fee);
                        if let Transaction::PxDeploy(t) = &mut d {
                            t.inputs = images.iter().map(|&k| input(k)).collect();
                        }
                        d
                    }
                };
                let _ = add(&mut m, tx);
            }
            let max_weight = rng.next_u64() % 400_000;
            let pool = u128::from(rng.next_u64() % 1_000);
            let sel = m.select(max_weight, pool, u64::MAX);
            let weight: u64 = sel.iter().map(Transaction::weight).sum();
            let px: u64 = sel.iter().map(Transaction::px_bytes).sum();
            let deploys: u64 = sel
                .iter()
                .filter(|t| matches!(t, Transaction::PxDeploy(_)))
                .map(Transaction::px_bytes)
                .sum();
            assert!(
                weight <= max_weight,
                "round {round}: {weight} > {max_weight}"
            );
            assert!(px <= MAX_PX_BLOCK_BYTES, "round {round}");
            assert!(deploys <= MAX_DEPLOY_BLOCK_BYTES, "round {round}");
            let mut p = pool;
            for t in &sel {
                if let Transaction::Px(t) = t {
                    p = (p + t.bridge_in as u128)
                        .checked_sub(t.bridge_out as u128)
                        .expect("pool");
                }
            }
            assert_disjoint(&sel);
            // Something with weight was left out for lack of weight.
            if m.entries.values().any(|e| {
                e.weight > 0
                    && !sel.iter().any(|t| t.hash() == e.tx.hash())
                    && weight + e.weight > max_weight
            }) {
                weight_bound_hit += 1;
            }
        }
        assert!(
            weight_bound_hit > 30,
            "the weight budget bound ({weight_bound_hit})"
        );
    }

    /// PX transactions come first: under v1 congestion (transfers paying far
    /// more per weight filling the budget), a PX transaction with 64 v1
    /// inputs still gets its weight.
    #[test]
    fn px_with_v1_inputs_are_selected_under_v1_congestion() {
        let mut m = Mempool::new();
        let images: Vec<u64> = (0..64).collect();
        let heavy = add(&mut m, px_in(1, 100_000, &images, 10)).unwrap();
        let w = blacksilk_tx::params::max_weight(64, 0);
        for k in 0..200u64 {
            add(
                &mut m,
                transfer(&[1_000 + k], &[5_000 + 2 * k, 5_001 + 2 * k], 1 << 40),
            )
            .unwrap();
        }
        let budget = 100_000;
        let sel = m.select(budget, 0, u64::MAX);
        assert!(sel.iter().any(|t| t.hash() == heavy), "the PX transaction");
        let total: u64 = sel.iter().map(Transaction::weight).sum();
        assert!(total <= budget && total >= w);
        assert!(sel.len() > 1, "transfers fill the rest");
        // Its weight counts: with less than its v1 part left, it is out.
        let sel = m.select(w - 1, 0, u64::MAX);
        assert!(!sel.iter().any(|t| t.hash() == heavy));
    }

    /// B8 in templates: PX transactions are taken only while their output
    /// commitments fit in the tree's free leaves, whatever their fee order.
    #[test]
    fn templates_never_exceed_the_free_leaves() {
        let mut m = Mempool::new();
        for n in 0..6u32 {
            add(&mut m, px(2 * n + 1, 1_000, 1_000, 0, 0)).unwrap();
        }
        for free in 0..=13u64 {
            let sel = m.select(u64::MAX, 0, free);
            let leaves: u64 = sel
                .iter()
                .map(|t| match t {
                    Transaction::Px(t) => t.commitments.len() as u64,
                    _ => 0,
                })
                .sum();
            assert!(leaves <= free, "free {free}: {leaves}");
            assert_eq!(sel.len() as u64, (free / 2).min(6), "free {free}");
        }
    }

    /// Randomized: 2 000 operations (add, remove, remove_block, select) on
    /// synthetic transactions with overlapping keys. After each, the pool's
    /// invariants hold; admission refuses exactly the conflicting and known
    /// transactions; a block removes exactly its transactions and those
    /// sharing a key with it; every selection has pairwise-distinct keys.
    #[test]
    fn randomized_operations_keep_the_conflict_invariants() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xF1);
        let mut m = Mempool::new();
        let (mut admitted, mut conflicts, mut blocks_removed) = (0, 0, 0);
        for step in 0..2_000 {
            match rng.next_u64() % 10 {
                0..=5 => {
                    let tx = random_tx(&mut rng);
                    let id = tx.hash();
                    let expected = if m.contains(&id) {
                        Err(MempoolError::AlreadyKnown)
                    } else if conflict_keys(&tx).iter().any(|k| m.keys.contains_key(k)) {
                        Err(MempoolError::Conflict)
                    } else {
                        Ok(id)
                    };
                    let r = add(&mut m, tx);
                    assert_eq!(r, expected, "step {step}");
                    match r {
                        Ok(_) => admitted += 1,
                        Err(MempoolError::Conflict) => conflicts += 1,
                        _ => {}
                    }
                }
                6 => {
                    let ids: Vec<Hash> = m.entries.keys().copied().collect();
                    if !ids.is_empty() {
                        let id = ids[(rng.next_u64() % ids.len() as u64) as usize];
                        assert!(m.remove(&id).is_some());
                        assert!(!m.contains(&id));
                    }
                }
                7 => {
                    // A block: a coinbase, some pooled transactions and some
                    // foreign ones (which may share keys with pooled ones).
                    let mut block =
                        vec![coinbase(&[rng.next_u64() % 60, 60 + rng.next_u64() % 60])];
                    let ids: Vec<Hash> = m.entries.keys().copied().collect();
                    for _ in 0..rng.next_u64() % 3 {
                        if !ids.is_empty() {
                            let id = ids[(rng.next_u64() % ids.len() as u64) as usize];
                            block.push(m.get(&id).unwrap().clone());
                        }
                    }
                    for _ in 0..rng.next_u64() % 3 {
                        block.push(random_tx(&mut rng));
                    }
                    let block_keys: HashSet<ConflictKey> =
                        block.iter().flat_map(conflict_keys).collect();
                    let block_ids: HashSet<Hash> = block.iter().map(Transaction::hash).collect();
                    let expected: HashSet<Hash> = m
                        .entries
                        .iter()
                        .filter(|(id, e)| {
                            !block_ids.contains(*id)
                                && !e.keys.iter().any(|k| block_keys.contains(k))
                        })
                        .map(|(id, _)| *id)
                        .collect();
                    let before = m.len();
                    m.remove_block(&block);
                    blocks_removed += before - m.len();
                    let after: HashSet<Hash> = m.entries.keys().copied().collect();
                    assert_eq!(after, expected, "step {step}");
                }
                _ => {
                    let max_weight = if rng.next_u64() % 2 == 0 {
                        u64::MAX
                    } else {
                        rng.next_u64() % 20_000
                    };
                    let sel = m.select(max_weight, (rng.next_u64() % 10).into(), u64::MAX);
                    assert_disjoint(&sel);
                    assert!(sel.iter().all(|tx| m.contains(&tx.hash())));
                    if max_weight == u64::MAX {
                        assert_eq!(sel.len(), m.len(), "no budget, no pool: all selected");
                    }
                }
            }
            assert_invariants(&m);
        }
        // The run exercised every path.
        assert!(admitted > 100, "{admitted}");
        assert!(conflicts > 100, "{conflicts}");
        assert!(blocks_removed > 20, "{blocks_removed}");
    }
}
