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
//! again for [`RECENTLY_EXPIRED_BLOCKS`] ([`MempoolError::Expired`]) when this
//! node's own wallet or RPC client submits it ([`Origin::Local`]), so that
//! the node does not re-originate it while other nodes still pool it (a
//! re-injection would mark it as the origin). Relay and stem admission
//! ([`Origin::Peer`]) ignore the guard: a peer that admitted the transaction
//! later is still inside its own window when the origin's ends, and a guard
//! there would silently drop the origin's stem (RTW1B-1). A transaction
//! returned by a disconnected block is pooled again ([`Mempool::readmit`]).
//!
//! **PX proofs are verified once, on admission.** After a block, pooled PX
//! transactions are revalidated against the new state (anchor, nullifiers,
//! registry, pool, rings) without re-verifying the proof, which depends only
//! on the transaction and its registered programs; a change to those fails
//! the state checks. Re-verifying every pooled proof at every block would be a
//! denial-of-service lever.
//!
//! **Reorganizations** ([`reorg`]). After blocks are disconnected, a pooled
//! transaction is kept only if the rules an extension can change still hold
//! and its rings resolve (C1, at the new next height) to the same outputs
//! as when it was verified: a hash of them, the ring digest, is kept per
//! entry. A changed ring drops it unverified. A transaction of a
//! disconnected block, captured with its ring digest while the block was
//! connected ([`Returned`]), is readmitted the same way
//! ([`Mempool::readmit_returned`]), after the pool was revalidated. No
//! signature, range proof or PX proof is verified again on either path
//! ([`Mempool::full_validations`]); a reorganization costs microseconds per
//! input, not a CLSAG per input under the chain lock (dossier 12 M12-1,
//! M12-2). While a bounded drain holds returned transactions, their
//! conflict keys are reserved ([`Mempool::reserve`],
//! [`MempoolError::ReorgPending`]), so a double spend submitted between two
//! drain steps cannot displace them (RTW2A-2).
//!
//! **PX validity windows (PX6).** A PX transaction is valid only at heights
//! inside its window. Admission is for the next block's height, so a
//! premature transaction is refused (`TxError::PxWindow`, contextual: a
//! relaying peer is not penalized, and the wallet keeps it until its window
//! opens). Every revalidation checks the window at the new next height, so a
//! transaction past its `not_after` leaves the pool, after a reorganization
//! too; and [`Mempool::select`] takes only transactions whose window contains
//! the template's height. Neither a proof verified on admission nor the
//! block path's proof cache ever stands in for the window check.
//!
//! **Expiring soon (RTW1C-4).** [`Mempool::add`] and [`Mempool::check`]
//! refuse a PX transaction whose window ends fewer than three blocks after
//! the admission height (`not_after ≠ 0 ∧ not_after < height + 3`,
//! [`MempoolError::ExpiringSoon`], Zcash's threshold), before any
//! validation: it would likely expire while it propagates. Policy only: a
//! pooled transaction stays until its window ends, and one a
//! reorganization returns ([`Mempool::readmit`]) is readmitted without it.

use blacksilk_consensus::Hash;
use blacksilk_tx::params::{SigDomain, TxRules, MAX_DEPLOY_BLOCK_BYTES, MAX_PX_BLOCK_BYTES};
use blacksilk_tx::px::digest_bytes;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::{
    px_expires_soon, revalidate_after_extension, validate_mempool_tx, ChainView, TxError,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

mod reorg;
use reorg::{check_after_reorg, ReorgVerdict};
pub use reorg::{ring_digest, Returned, RingDigest, RING_DIGEST_TAG};

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
/// ([`MempoolError::Expired`]) on the local origination path only
/// ([`Origin::Local`]: `/tx` and the wallets submitting through the node).
/// Every honest node expires a transaction within the same few blocks (it
/// was admitted network-wide within seconds), so within this window the
/// origin does not re-originate it, and a wallet's re-submission cannot mark
/// its node as the origin to a stem peer that still pools it (dossier 38
/// §3.4, Monero's `m_timed_out_transactions`). Peers relaying or stemming it
/// are served normally (RTW1B-1).
pub const RECENTLY_EXPIRED_BLOCKS: u64 = 30;

/// Where a transaction submitted to the pool comes from: whether the
/// recently-expired guard ([`RECENTLY_EXPIRED_BLOCKS`]) applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Originated here: `/tx`, a wallet submitting through this node. The
    /// guard applies.
    Local,
    /// From a peer (relay, stem), or a stem transaction this node fluffs:
    /// admitted like any valid transaction. A guard here would make this
    /// node a Dandelion black hole for an origin whose own window ended
    /// earlier (RTW1B-1).
    Peer,
}

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
    /// it is not originated here again until then ([`Origin::Local`] only).
    /// Policy: the transaction may still be valid.
    Expired,
    /// A PX transaction whose validity window ends fewer than
    /// `PX_EXPIRING_SOON_BLOCKS` (3) blocks after the height it would be
    /// admitted for (`blacksilk_tx::validate::px_expires_soon`, RTW1C-4).
    /// Policy: it is still valid in a block inside its window, but would
    /// likely expire while it propagates. Never scored.
    ExpiringSoon,
    /// A key image, PX nullifier or contract id is reserved for a
    /// transaction of a block a reorganization disconnected, until the
    /// reorganization's bounded drain ends and it is readmitted
    /// ([`Mempool::reserve`], RTW2A-2): the returned transaction wins, as
    /// in an atomic reorganization. Contextual (a later submission may
    /// succeed); never scored.
    ReorgPending,
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
    /// The fee templates rank by against `weight` ([`v1_part_fee`]): a
    /// transfer's fee, or the v1 part of a deploy's (its payload term buys
    /// no priority, RTW1B-3).
    weight_fee: u64,
    /// Bytes against the block's PX budget (`Transaction::px_bytes`).
    px_bytes: u64,
    seq: u64,
    /// Conflict keys (`conflict_keys`).
    keys: Vec<ConflictKey>,
    /// The height the transaction was admitted for (the next block's height
    /// at admission); it expires [`MEMPOOL_EXPIRY_BLOCKS`] later.
    admitted: u64,
    /// What its rings resolved to when its signatures were verified (or its
    /// block connected): the reorganization check ([`reorg`]).
    ring: RingDigest,
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

    /// v1-part fee per block-weight unit, compared without division: the
    /// order of transfers and deploys in templates, which compete for the
    /// same weight (one unit, no cross-unit comparison).
    fn weight_rate_cmp(&self, other: &Entry) -> std::cmp::Ordering {
        (self.weight_fee as u128 * other.weight as u128)
            .cmp(&(other.weight_fee as u128 * self.weight as u128))
    }
}

/// The fee a transaction's block weight is ranked by in templates
/// ([`Mempool::select`]): a transfer's fee; for a deploy, the v1 part of its
/// exact fee, `rules.standard_fee(n_in, n_out)` (never more than the fee
/// paid), without the payload term (`DEPLOY_FEE_PER_BYTE` per payload byte).
/// The payload pays for permanent registration state, not for weight: counted
/// here it would let every deploy with a large program outrank every
/// standard-fee transfer, which cannot pay more (T8), and displace transfers
/// from blocks (RTW1B-3). A PX transaction's fee (it is ranked separately, by
/// fee per PX byte).
fn v1_part_fee(tx: &Transaction, rules: &TxRules) -> u64 {
    match tx {
        Transaction::PxDeploy(t) => rules
            .standard_fee(t.inputs.len(), t.outputs.len())
            .map_or(0, |f| f.min(t.fee)),
        tx => tx.fee(),
    }
}

/// The expiring-soon policy for admission at `height` (RTW1C-4,
/// [`MempoolError::ExpiringSoon`]).
fn expiring_soon(tx: &Transaction, height: u64) -> Result<(), MempoolError> {
    match tx {
        Transaction::Px(t) if px_expires_soon(t, height) => Err(MempoolError::ExpiringSoon),
        _ => Ok(()),
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
    /// The rules every pooled transaction was validated under; `None` before
    /// the first admission. Compared whole, not only their signature domain
    /// ([`Self::enter_rules`]).
    rules: Option<TxRules>,
    /// Transactions this node expired: id -> the height they expired at.
    /// Refused while `height < expired_at + RECENTLY_EXPIRED_BLOCKS`
    /// ([`MempoolError::Expired`]); forgotten afterwards ([`Self::expire`]).
    expired: HashMap<Hash, u64>,
    /// Conflict keys of returned transactions a bounded drain holds, and the
    /// id of the transaction each is reserved for ([`Self::reserve`]);
    /// released by [`Self::readmit_returned`].
    reserved: HashMap<ConflictKey, Hash>,
    /// Full validations run by the pool (`validate_mempool_tx`): admission,
    /// `check` and [`Self::readmit`]. Revalidation and
    /// [`Self::readmit_returned`] run none.
    full_validations: AtomicU64,
}

/// What [`Mempool::revalidate`] dropped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Revalidation {
    /// Entries checked.
    pub checked: usize,
    /// Dropped: a rule fails at the new tip (a key image or nullifier spent,
    /// the PX window, anchor, registry, pool or tree capacity, a contract
    /// registered, a ring member gone or immature).
    pub invalid: usize,
    /// Dropped after a reorganization: a ring resolves to other outputs
    /// (not verified again, [`reorg`]).
    pub ring_changed: usize,
}

/// What [`Mempool::readmit_returned`] did with the transactions of
/// disconnected blocks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Readmission {
    /// Pooled again, with a fresh admission height.
    pub readmitted: usize,
    /// Already pooled.
    pub already_pooled: usize,
    /// Its block was validated under other rules than the pool's (an
    /// activation between them): dropped unverified, it would fail.
    pub other_rules: usize,
    /// A pooled transaction holds one of its conflict keys (a double spend
    /// by the same owner that was pooled first here): the pooled one stays.
    pub conflicts: usize,
    /// A rule fails at the new tip (spent on the new branch, PX window,
    /// anchor, registry, pool, capacity, a ring member gone or immature).
    pub invalid: usize,
    /// A ring resolves to other outputs than when its block was validated.
    pub ring_changed: usize,
    /// The class is full of entries paying at least as much.
    pub no_room: usize,
    /// Beyond the per-reorganization byte budget ([`READMIT_MAX_BYTES`]).
    pub over_budget: usize,
}

/// The chain change [`Mempool::update_after_chain_change`] follows.
#[derive(Clone, Debug, Default)]
pub struct ChainChange {
    /// The transactions of the disconnected blocks, captured while each was
    /// connected ([`Returned::capture`]), tip first.
    pub returned: Vec<Returned>,
    /// Whether any block was disconnected.
    pub reorganized: bool,
}

/// What [`Mempool::update_after_chain_change`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChainUpdate {
    /// Dropped by a change of rules ([`Mempool::enter_rules`]).
    pub flushed: usize,
    /// Expired ([`Mempool::expire`]).
    pub expired: usize,
    pub revalidation: Revalidation,
    pub readmission: Readmission,
}

/// Encoded bytes of returned transactions one reorganization captures
/// (`Returned::capture_within`, RTW2A-6) and examines, per
/// class (v1, PX): the class's cap. More could not be pooled together
/// anyway; the rest (the deepest disconnected blocks', since they come tip
/// first) is dropped unexamined, and wallets rebroadcast (Bitcoin Core
/// bounds its disconnected pool the same way,
/// `MAX_DISCONNECTED_TX_POOL_BYTES`).
pub const READMIT_MAX_BYTES: [usize; 2] = [MEMPOOL_MAX_BYTES, MEMPOOL_MAX_PX_BYTES];

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
        self.rules.as_ref().map(TxRules::domain)
    }

    /// The pooled transactions, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = &Transaction> {
        self.entries.values().map(|e| &e.tx)
    }

    /// Full validations the pool has run (signatures, range proofs and PX
    /// proofs verified): on admission, `check` and [`Self::readmit`]. A
    /// monotone counter, for operators and for tests showing that
    /// revalidation and [`Self::readmit_returned`] verify nothing.
    pub fn full_validations(&self) -> u64 {
        self.full_validations.load(Ordering::Relaxed)
    }

    /// Transactions in the recently-expired set (bounded by what expired in
    /// the last [`RECENTLY_EXPIRED_BLOCKS`] blocks).
    pub fn recently_expired_count(&self) -> usize {
        self.expired.len()
    }

    /// `validate_mempool_tx`, counted ([`Self::full_validations`]).
    fn validate(
        &self,
        tx: &Transaction,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
    ) -> Result<(), MempoolError> {
        self.full_validations.fetch_add(1, Ordering::Relaxed);
        validate_mempool_tx(tx, chain, height, rules).map_err(MempoolError::Invalid)
    }

    /// Makes `rules` the pool's rule set. If the pool was validated under
    /// other rules (an activation between the old and the new next height,
    /// in either direction, changes the signature domain), every entry is
    /// dropped and their conflict keys (key images, nullifiers, contract ids)
    /// are released. Returns the number dropped.
    ///
    /// The whole rule set is compared, not only its signature domain: the
    /// revalidation and readmission paths skip every stateless rule, which
    /// is exact only while the rules are the same (dossier 12 M12-8; today
    /// the fee and weight limits are the same in every epoch, so this flushes
    /// exactly when the domain changes).
    ///
    /// A flush, not a revalidation: every signature message and the PX
    /// binding `h_tx` commit to the branch id, so every pooled v1 or deploy
    /// signature and every pooled PX proof fails under the new domain. A full
    /// revalidation would reach the same verdict after verifying each of them
    /// again (docs/reviews/v3-upgrade-mechanism.md §2.5).
    pub fn enter_rules(&mut self, rules: &TxRules) -> usize {
        if self.rules.as_ref() == Some(rules) {
            return 0;
        }
        let dropped = if self.rules.is_some() {
            let n = self.entries.len();
            self.entries.clear();
            self.keys.clear();
            self.bytes = [0, 0];
            n
        } else {
            0
        };
        self.rules = Some(*rules);
        dropped
    }

    /// Whether `tx` shares a conflict key ([`conflict_keys`]) with a pooled
    /// transaction other than itself, or with a returned transaction a
    /// reorganization is still connecting: [`Self::add`] would refuse it
    /// with [`MempoolError::Conflict`] (first seen wins) or
    /// [`MempoolError::ReorgPending`]. Read-only and cheap (no validation):
    /// the P2P layer drops such a transaction before verifying it or
    /// charging the node-wide PX relay budget (docs/p2p.md §10).
    pub fn conflicts(&self, tx: &Transaction) -> bool {
        let id = tx.hash();
        conflict_keys(tx).iter().any(|k| {
            self.keys.get(k).is_some_and(|holder| *holder != id) || self.reserved_for_other(k, &id)
        })
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
    /// pooled, for a local origination not expired here recently (for
    /// inclusion at `height`), no conflict key in use.
    fn precheck(
        &self,
        tx: &Transaction,
        height: u64,
        origin: Origin,
    ) -> Result<(Hash, Vec<ConflictKey>), MempoolError> {
        if tx.is_coinbase() {
            return Err(MempoolError::Coinbase);
        }
        let id = tx.hash();
        self.precheck_id(tx, id, height, origin)
            .map(|keys| (id, keys))
    }

    /// [`Self::precheck`] of a non-coinbase transaction whose id is known.
    /// A conflict key reserved for another transaction returned by a
    /// reorganization still being connected refuses it with
    /// [`MempoolError::ReorgPending`] ([`Self::reserve`]).
    fn precheck_id(
        &self,
        tx: &Transaction,
        id: Hash,
        height: u64,
        origin: Origin,
    ) -> Result<Vec<ConflictKey>, MempoolError> {
        if tx.is_coinbase() {
            return Err(MempoolError::Coinbase);
        }
        if self.entries.contains_key(&id) {
            return Err(MempoolError::AlreadyKnown);
        }
        if origin == Origin::Local && self.recently_expired(&id, height) {
            return Err(MempoolError::Expired);
        }
        let keys = conflict_keys(tx);
        if keys.iter().any(|k| self.keys.contains_key(k)) {
            return Err(MempoolError::Conflict);
        }
        if keys.iter().any(|k| self.reserved_for_other(k, &id)) {
            return Err(MempoolError::ReorgPending);
        }
        Ok(keys)
    }

    /// Whether `key` is reserved for a returned transaction other than `id`.
    fn reserved_for_other(&self, key: &ConflictKey, id: &Hash) -> bool {
        self.reserved.get(key).is_some_and(|holder| holder != id)
    }

    /// Reserves the conflict keys of `returned`, a transaction of a block a
    /// bounded drain disconnected, until the drain ends and
    /// [`Self::readmit_returned`] examines it (RTW2A-2). Between two drain
    /// steps the node serves other commands; without the reservation a
    /// double spend admitted there would hold the keys, and the returned
    /// transaction would be refused as a conflict at the end, while an
    /// atomic reorganization refuses the double spend and readmits the
    /// returned one. Meanwhile [`Self::add`], [`Self::check`] and
    /// [`Self::conflicts`] refuse a transaction using a reserved key
    /// ([`MempoolError::ReorgPending`]); the returned transaction itself is
    /// not refused.
    pub fn reserve(&mut self, returned: &Returned) {
        for k in conflict_keys(returned.tx()) {
            self.reserved.insert(k, returned.id());
        }
    }

    /// Conflict keys reserved for returned transactions ([`Self::reserve`]).
    pub fn reserved_keys(&self) -> usize {
        self.reserved.len()
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

    /// Validates `tx` from `origin` for inclusion at `height` without adding
    /// it. Returns its id.
    pub fn check(
        &self,
        tx: &Transaction,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
        origin: Origin,
    ) -> Result<Hash, MempoolError> {
        let (id, _) = self.precheck(tx, height, origin)?;
        expiring_soon(tx, height)?;
        self.validate(tx, chain, height, rules)?;
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

    /// Validates `tx` from `origin` for inclusion at `height` and adds it. A
    /// PX transaction expiring soon is refused first
    /// ([`MempoolError::ExpiringSoon`], before any proof work).
    pub fn add(
        &mut self,
        tx: Transaction,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
        origin: Origin,
    ) -> Result<Hash, MempoolError> {
        self.admit(tx, chain, height, rules, origin, true)
    }

    fn admit(
        &mut self,
        tx: Transaction,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
        origin: Origin,
        refuse_expiring_soon: bool,
    ) -> Result<Hash, MempoolError> {
        // Under other rules than the pool's, the pool is flushed first
        // (`enter_rules`): it never mixes transactions of two rule sets.
        self.enter_rules(rules);
        let (id, keys) = self.precheck(&tx, height, origin)?;
        if refuse_expiring_soon {
            expiring_soon(&tx, height)?;
        }
        self.validate(&tx, chain, height, rules)?;
        // The rings just verified (C1 held at `height`, so they resolve).
        let ring = ring_digest(&tx, chain, height).map_err(MempoolError::Invalid)?;
        let weight_fee = v1_part_fee(&tx, rules);
        self.insert(id, tx, keys, height, weight_fee, ring)
    }

    /// [`Self::add`] for a transaction of a block this node disconnected (a
    /// reorganization returns it to the pool). It is not refused as recently
    /// expired ([`Origin::Peer`]): it was on the best chain, so it is no
    /// re-injection by its origin, and it is not relayed from here. It is
    /// pooled with a fresh admission height (`height`), so it gets a full
    /// expiry window again, and it then leaves the recently-expired set. If
    /// it is refused, its guard entry stays (RTW1B-5): the node's wallet
    /// must not re-originate it early because a reorganization tried to
    /// return it. The expiring-soon policy does not apply: the transaction
    /// was already relayed and mined, and may still be mined inside its
    /// window on the new branch.
    ///
    /// Validates in full (signatures, range proof, PX proof): prefer
    /// [`Self::readmit_returned`] with transactions captured before their
    /// block was undone, which verifies nothing.
    pub fn readmit(
        &mut self,
        tx: Transaction,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
    ) -> Result<Hash, MempoolError> {
        let id = self.admit(tx, chain, height, rules, Origin::Peer, false)?;
        self.expired.remove(&id);
        Ok(id)
    }

    /// Expires every transaction admitted at least [`MEMPOOL_EXPIRY_BLOCKS`]
    /// before `height` (the next block's height): it is removed with its
    /// conflict keys and remembered as recently expired, and refused again
    /// until `height + RECENTLY_EXPIRED_BLOCKS`. Transactions remembered
    /// that long are forgotten. Returns the number expired.
    ///
    /// The count is from this node's admission height, the same for every
    /// kind (policy, not consensus). It is independent of a PX transaction's
    /// validity window (PX6), a consensus rule that [`Self::revalidate`] and
    /// [`Self::select`] apply; wallets leave that window unbounded unless a
    /// contract needs one, since its value is public.
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
        weight_fee: u64,
        ring: RingDigest,
    ) -> Result<Hash, MempoolError> {
        let size = tx.encode().len();
        self.insert_sized(id, (tx, size), keys, admitted, weight_fee, ring)
    }

    /// [`Self::insert`] of a transaction with its known encoded size.
    fn insert_sized(
        &mut self,
        id: Hash,
        (tx, size): (Transaction, usize),
        keys: Vec<ConflictKey>,
        admitted: u64,
        weight_fee: u64,
        ring: RingDigest,
    ) -> Result<Hash, MempoolError> {
        let class = class_of(&tx);
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
            weight_fee,
            px_bytes,
            seq: self.next_seq,
            keys,
            admitted,
            ring,
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
    /// Nothing is verified again: no signature, range proof or PX proof.
    ///
    /// After a plain extension only the rules an extension can change are
    /// checked (`revalidate_after_extension`): a full re-check of a full pool
    /// (about 6.8 ms per transfer, measured) would take minutes per block
    /// under the chain lock, a denial-of-service lever.
    ///
    /// `after_reorg`: blocks were disconnected since the last revalidation,
    /// so ring members may resolve to other outputs, or have become
    /// immature. Each entry is then also checked for C1 at `height` and for
    /// its ring digest: an entry whose rings resolve to other outputs is
    /// dropped without verifying it ([`reorg`]).
    ///
    /// Across an activation (`rules` other than the pool's) neither is
    /// enough, since signatures and PX proofs change verdict: the pool is
    /// flushed ([`Self::enter_rules`]).
    pub fn revalidate(
        &mut self,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
        after_reorg: bool,
    ) -> Revalidation {
        self.enter_rules(rules);
        let mut report = Revalidation {
            checked: self.entries.len(),
            ..Revalidation::default()
        };
        let mut stale = Vec::new();
        for (id, e) in &self.entries {
            let verdict = if after_reorg {
                check_after_reorg(&e.tx, &e.ring, chain, height)
            } else if revalidate_after_extension(&e.tx, chain, height).is_ok() {
                ReorgVerdict::Valid
            } else {
                ReorgVerdict::Invalid
            };
            match verdict {
                ReorgVerdict::Valid => continue,
                ReorgVerdict::Invalid => report.invalid += 1,
                ReorgVerdict::RingChanged => report.ring_changed += 1,
            }
            stale.push(*id);
        }
        for id in stale {
            self.remove(&id);
        }
        report
    }

    /// Pools again the transactions of disconnected blocks, captured while
    /// each block was connected ([`Returned::capture`]), for inclusion at
    /// `height` under `rules`, without verifying any of them ([`reorg`]):
    /// - a transaction whose block was validated under other rules than
    ///   `rules` is dropped (it would fail: an activation lies between);
    /// - it is not refused as recently expired, nor as expiring soon (as
    ///   [`Self::readmit`]); an already pooled one stays, and one sharing a
    ///   conflict key with a pooled transaction is refused (both are the
    ///   same owner's spends, and the pooled one was just revalidated);
    /// - then the rules an extension can change, C1 at `height` and the ring
    ///   digest; then admission with the class's normal eviction and
    ///   `height` as its admission height, which clears its
    ///   recently-expired entry.
    ///
    /// Call it after [`Self::revalidate`], so that stale entries neither
    /// take the room nor hold the conflict keys (Bitcoin Core also
    /// revalidates before it trims). At most [`READMIT_MAX_BYTES`] of each
    /// class are examined; the work is a few lookups and one hash per input,
    /// bounded by those bytes.
    ///
    /// It first releases every reservation ([`Self::reserve`]): the drain
    /// that held these transactions has ended, and no transaction using one
    /// of their keys was admitted meanwhile, so they win over any double
    /// spend submitted during the drain (RTW2A-2).
    pub fn readmit_returned(
        &mut self,
        returned: Vec<Returned>,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
    ) -> Readmission {
        self.reserved.clear();
        self.enter_rules(rules);
        let mut report = Readmission::default();
        let mut examined = [0usize; 2];
        for r in returned {
            let tx = r.tx();
            let slot = Self::slot(class_of(tx));
            let size = r.size();
            if examined[slot] + size > READMIT_MAX_BYTES[slot] {
                report.over_budget += 1;
                continue;
            }
            examined[slot] += size;
            if r.rules() != rules {
                report.other_rules += 1;
                continue;
            }
            let id = r.id();
            let keys = match self.precheck_id(tx, id, height, Origin::Peer) {
                Ok(keys) => keys,
                Err(MempoolError::AlreadyKnown) => {
                    report.already_pooled += 1;
                    continue;
                }
                Err(MempoolError::Conflict) => {
                    report.conflicts += 1;
                    continue;
                }
                Err(_) => {
                    // A coinbase (the manager never returns one).
                    report.invalid += 1;
                    continue;
                }
            };
            let Some(ring) = r.ring() else {
                report.invalid += 1;
                continue;
            };
            match check_after_reorg(tx, &ring, chain, height) {
                ReorgVerdict::Valid => {}
                ReorgVerdict::Invalid => {
                    report.invalid += 1;
                    continue;
                }
                ReorgVerdict::RingChanged => {
                    report.ring_changed += 1;
                    continue;
                }
            }
            let weight_fee = v1_part_fee(tx, rules);
            match self.insert_sized(id, (r.into_tx(), size), keys, height, weight_fee, ring) {
                Ok(_) => {
                    self.expired.remove(&id);
                    report.readmitted += 1;
                }
                Err(_) => report.no_room += 1,
            }
        }
        report
    }

    /// Follows a change of the connected chain, once its newly connected
    /// blocks were removed ([`Self::remove_block`]): the rules of the next
    /// block ([`Self::enter_rules`]), expiry at `height` ([`Self::expire`]),
    /// revalidation ([`Self::revalidate`], the reorganization path if
    /// `change.reorganized`), then readmission of the returned transactions
    /// ([`Self::readmit_returned`]). Verifies no signature or proof.
    pub fn update_after_chain_change(
        &mut self,
        change: ChainChange,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
    ) -> ChainUpdate {
        let flushed = self.enter_rules(rules);
        let expired = self.expire(height);
        let revalidation = self.revalidate(chain, height, rules, change.reorganized);
        let readmission = self.readmit_returned(change.returned, chain, height, rules);
        ChainUpdate {
            flushed,
            expired,
            revalidation,
            readmission,
        }
    }

    /// Transactions for a block template at `height`. Every candidate is charged against
    /// the block weight budget `max_weight` (`Transaction::weight`: a
    /// transfer's weight, or the v1 part of a PX or deploy transaction,
    /// R12-2), and PX and deploy transactions also against the PX byte budget
    /// (deploys also against the deploy sub-budget): a template never breaks
    /// B6 (docs/reviews/v3-consensus-changes.md#r12-2).
    ///
    /// Order: PX transactions first (by fee per PX byte, then first seen;
    /// their fee is uniform), so v1 congestion cannot keep one with v1 inputs
    /// out; then transfers and deploys, which compete for the same weight, by
    /// the fee of their v1 part per weight ([`v1_part_fee`]: a deploy's
    /// payload fee buys no priority), then first seen. No fee per byte is
    /// compared with a fee per weight.
    ///
    /// PX transactions are taken only if their validity window contains
    /// `height` (PX6). The pool holds transactions valid for the next block,
    /// so this skips only a transaction the pool has not yet revalidated for
    /// `height`; a template never breaks PX6 either way.
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
    pub fn select(
        &self,
        height: u64,
        max_weight: u64,
        mut pool: u128,
        px_leaves: u64,
    ) -> Vec<Transaction> {
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
                    if !t.window.contains(height) {
                        continue;
                    }
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
            window: Default::default(),
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

    fn rules() -> TxRules {
        TxRules::for_chain(&blacksilk_consensus::ChainParams::regtest())
    }

    /// `add` from a peer for inclusion at `height` (the admission height).
    fn add_at(m: &mut Mempool, tx: Transaction, height: u64) -> Result<Hash, MempoolError> {
        let (id, keys) = m.precheck(&tx, height, Origin::Peer)?;
        let weight_fee = v1_part_fee(&tx, &rules());
        let ring = test_ring(&tx);
        m.insert(id, tx, keys, height, weight_fee, ring)
    }

    /// The ring digest of a synthetic transaction: that of no ring, or a
    /// placeholder for rings that resolve nowhere.
    fn test_ring(tx: &Transaction) -> RingDigest {
        ring_digest(tx, &blacksilk_tx::state::MemoryChain::new(), u64::MAX).unwrap_or([0xa5; 32])
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
    /// `Expired` on the local origination path (before its conflict keys or
    /// anything else are looked at) for exactly `RECENTLY_EXPIRED_BLOCKS`
    /// blocks, then admitted again and forgotten. Only that transaction:
    /// another one spending the same key images is not refused by the
    /// guard. From a peer it is admitted throughout (RTW1B-1).
    #[test]
    fn an_expired_transaction_is_refused_for_the_guard_window_only() {
        let mut m = Mempool::new();
        let tx = transfer(&[5], &[10, 11], 10);
        let id = add_at(&mut m, tx.clone(), 0).unwrap();
        let e = MEMPOOL_EXPIRY_BLOCKS;
        assert_eq!(m.expire(e), 1);
        for h in e..e + RECENTLY_EXPIRED_BLOCKS {
            assert!(m.recently_expired(&id, h));
            assert_eq!(
                m.precheck(&tx, h, Origin::Local).map(|_| ()),
                Err(MempoolError::Expired)
            );
            assert!(m.precheck(&tx, h, Origin::Peer).is_ok(), "peers admit it");
        }
        let rebuilt = transfer(&[5], &[30, 31], 10);
        let other = add_at(&mut m, rebuilt, e + 1).unwrap();
        m.remove(&other).unwrap();
        let end = e + RECENTLY_EXPIRED_BLOCKS;
        assert!(!m.recently_expired(&id, end));
        assert!(m.precheck(&tx, end, Origin::Local).is_ok());
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
            m.precheck(&b_tx, 10 + e - 19, Origin::Local).map(|_| ()),
            Err(MempoolError::Expired)
        );
        // b was meanwhile mined on the other branch and that block is
        // disconnected: the returned transaction is admitted again, with a
        // fresh admission height, and leaves the guard once pooled
        // (chain/tests/mempool_expiry.rs, with a valid transaction).
        let chain = blacksilk_tx::state::MemoryChain::new();
        let rules = TxRules::at_height(&blacksilk_consensus::ChainParams::regtest(), 0);
        // (A synthetic transaction fails validation; the guard is what is
        // tested here: `readmit` gets past it to validation.)
        assert!(matches!(
            m.readmit(b_tx.clone(), &chain, 10 + e - 19, &rules),
            Err(MempoolError::Invalid(_))
        ));
        // RTW1B-5: a failed readmission leaves the guard entry in place.
        assert!(m.recently_expired(&b, 10 + e - 19));
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
        for origin in [Origin::Local, Origin::Peer] {
            assert_eq!(
                m.precheck(&cb, 0, origin).map(|_| ()),
                Err(MempoolError::Coinbase)
            );
        }
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
            .select(1, u64::MAX, 0, u64::MAX)
            .iter()
            .map(Transaction::hash)
            .collect();
        assert_eq!(order, vec![high, tie_first, tie_second, low]);

        // The PX byte budget: 8 MiB of 3 MiB transactions takes two.
        let mut m = Mempool::new();
        for n in 0..4 {
            add(&mut m, px(100 + 2 * n, 3 * 1024 * 1024, 1_000, 0, 0)).unwrap();
        }
        let sel = m.select(1, u64::MAX, 0, u64::MAX);
        assert_eq!(sel.len(), 2);
        assert!(sel.iter().map(Transaction::px_bytes).sum::<u64>() <= MAX_PX_BLOCK_BYTES);

        // The pool: a withdrawal of 5 from a pool of 3 is skipped until a
        // deposit selected before it covers it.
        let mut m = Mempool::new();
        let withdraw = add(&mut m, px(200, 1000, 90, 0, 5)).unwrap();
        let sel = m.select(1, u64::MAX, 3, u64::MAX);
        assert!(sel.is_empty(), "would make the pool negative");
        let deposit = add(&mut m, px(202, 1000, 95, 4, 0)).unwrap();
        let sel: Vec<Hash> = m
            .select(1, u64::MAX, 3, u64::MAX)
            .iter()
            .map(Transaction::hash)
            .collect();
        assert_eq!(
            sel,
            vec![deposit, withdraw],
            "deposit first, then 3 + 4 - 5"
        );
    }

    /// `px` with validity window `[not_before, not_after]`.
    fn windowed(n: u32, not_before: u64, not_after: u64) -> Transaction {
        let mut t = px(n, 1000, 10, 0, 0);
        if let Transaction::Px(p) = &mut t {
            p.window = blacksilk_tx::px::Window {
                not_before,
                not_after,
            };
        }
        t
    }

    /// PX6 in templates: `select(height, ..)` takes a PX transaction only
    /// when its validity window contains `height`, so a template never holds
    /// a premature or expired one, whether or not the pool was revalidated
    /// for that height.
    #[test]
    fn templates_take_only_transactions_whose_window_contains_the_height() {
        let mut m = Mempool::new();
        let early = add(&mut m, windowed(1, 10, 0)).unwrap();
        let late = add(&mut m, windowed(3, 0, 5)).unwrap();
        let edge = add(&mut m, windowed(5, 7, 7)).unwrap();
        let open = add(&mut m, windowed(7, 0, 0)).unwrap();
        let at = |h: u64| -> std::collections::HashSet<Hash> {
            m.select(h, u64::MAX, 0, u64::MAX)
                .iter()
                .map(Transaction::hash)
                .collect()
        };
        assert_eq!(at(5), [late, open].into());
        assert_eq!(at(6), [open].into());
        assert_eq!(at(7), [edge, open].into());
        assert_eq!(at(9), [open].into());
        assert_eq!(at(10), [early, open].into());
    }

    /// A PX transaction (no v1 inputs, fee paid out of the pool) that every
    /// rule but the proof accepts on `chain`, with the given window.
    fn valid_px(
        chain: &blacksilk_tx::state::MemoryChain,
        n: u32,
        not_before: u64,
        not_after: u64,
    ) -> Transaction {
        use blacksilk_tx::params::PX_STANDARD_FEE;
        Transaction::Px(Box::new(PxTx {
            inputs: vec![],
            outputs: vec![],
            payouts: vec![],
            fee: PX_STANDARD_FEE,
            bridge_in: 0,
            bridge_out: PX_STANDARD_FEE,
            window: blacksilk_tx::px::Window {
                not_before,
                not_after,
            },
            anchor: chain.px().root(),
            nullifiers: [[n, 1, 0, 0, 0, 0, 0, 0], [n, 2, 0, 0, 0, 0, 0, 0]],
            commitments: [[n, 3, 0, 0, 0, 0, 0, 0], [n, 4, 0, 0, 0, 0, 0, 0]],
            ciphertexts: [vec![], vec![]],
            functions: vec![],
            pseudo_outs: vec![],
            range_proof: None,
            signatures: vec![],
            proof: vec![],
        }))
    }

    /// PX6 in revalidation (policy side of a consensus rule): after an
    /// extension (`revalidate_after_extension`, which takes the next height)
    /// a pooled PX transaction past its `not_after` is dropped; after a
    /// reorganization to a lower height (full revalidation) one that is
    /// premature again is dropped too; transactions inside their window stay.
    #[test]
    fn revalidation_drops_transactions_outside_their_window() {
        use blacksilk_px::state::State as PxState;
        use blacksilk_tx::state::MemoryChain;
        let chain =
            MemoryChain::with_px_state(PxState::with_uniform_tree_for_tests(4, [7; 8], 1 << 60));
        let rules = rules();
        let mut m = Mempool::new();
        m.enter_rules(&rules);
        let until_12 = valid_px(&chain, 1, 0, 12);
        let from_10 = valid_px(&chain, 3, 10, 0);
        let open = valid_px(&chain, 5, 0, 0);
        let ids: Vec<Hash> = [until_12, from_10, open]
            .into_iter()
            .map(|t| add_at(&mut m, t, 10).unwrap())
            .collect();
        // Extensions up to the next height 12: nothing leaves.
        m.revalidate(&chain, 12, &rules, false);
        assert!(ids.iter().all(|id| m.contains(id)));
        // Next height 13: `until_12` has expired.
        m.revalidate(&chain, 13, &rules, false);
        assert!(!m.contains(&ids[0]));
        assert!(m.contains(&ids[1]) && m.contains(&ids[2]));
        // A reorganization lowers the next height to 9: `from_10` is
        // premature again and leaves (the wallet re-submits it later).
        m.revalidate(&chain, 9, &rules, true);
        assert!(!m.contains(&ids[1]));
        assert!(m.contains(&ids[2]));
    }

    /// RTW1C-4, the expiring-soon policy: `add` and `check` refuse a PX
    /// transaction whose window ends before `height + 3`
    /// (`MempoolError::ExpiringSoon`) before any validation; one ending at
    /// `height + 3` or unbounded goes on to full validation (here refused
    /// for its empty proof, `PxProof`); a transaction a reorganization
    /// returns (`readmit`) is not refused as expiring soon.
    #[test]
    fn transactions_expiring_soon_are_refused_but_readmitted() {
        use blacksilk_px::state::State as PxState;
        use blacksilk_tx::state::MemoryChain;
        let chain =
            MemoryChain::with_px_state(PxState::with_uniform_tree_for_tests(4, [7; 8], 1 << 60));
        let rules = rules();
        let mut m = Mempool::new();
        let h = 20;
        for (n, not_after, soon) in [
            (1, h - 1, true),
            (3, h, true),
            (5, h + 2, true),
            (7, h + 3, false),
            (9, 0, false),
        ] {
            let tx = valid_px(&chain, n, 0, not_after);
            let expected = if soon {
                Err(MempoolError::ExpiringSoon)
            } else {
                Err(MempoolError::Invalid(TxError::PxProof))
            };
            assert_eq!(
                m.add(tx.clone(), &chain, h, &rules, Origin::Peer)
                    .map(|_| ()),
                expected,
                "add, not_after {not_after}"
            );
            assert_eq!(
                m.check(&tx, &chain, h, &rules, Origin::Local).map(|_| ()),
                expected,
                "check, not_after {not_after}"
            );
        }
        // Readmission after a reorganization skips the policy: the
        // transaction goes on to full validation.
        assert_eq!(
            m.readmit(valid_px(&chain, 11, 0, h + 1), &chain, h, &rules)
                .map(|_| ()),
            Err(MempoolError::Invalid(TxError::PxProof))
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
                    .select(1, u64::MAX, 0, u64::MAX)
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
        assert_eq!(m.select(1, u64::MAX, 0, u64::MAX).len(), 4);
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
                let fee = tx.fee();
                let ring = test_ring(&tx);
                m.insert(tx.hash(), tx, keys, 0, fee, ring).unwrap();
            }
            let sel = m.select(1, u64::MAX, 0, u64::MAX);
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
                abi: blacksilk_tx::px::ABI_VERSION,
                out_words: 1,
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
        let sel = m.select(1, u64::MAX, 0, u64::MAX);
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
            let sel = m.select(1, max_weight, pool, u64::MAX);
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
        let sel = m.select(1, budget, 0, u64::MAX);
        assert!(sel.iter().any(|t| t.hash() == heavy), "the PX transaction");
        let total: u64 = sel.iter().map(Transaction::weight).sum();
        assert!(total <= budget && total >= w);
        assert!(sel.len() > 1, "transfers fill the rest");
        // Its weight counts: with less than its v1 part left, it is out.
        let sel = m.select(1, w - 1, 0, u64::MAX);
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
            let sel = m.select(1, u64::MAX, 0, free);
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
                    let sel = m.select(1, max_weight, (rng.next_u64() % 10).into(), u64::MAX);
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

    // ------------------------------------------------ RT-W1b (FX-RTW1B)

    /// RTW1B-1. The origin admits its own transaction first (height `a`); a
    /// stem peer admits it up to `RECENTLY_EXPIRED_BLOCKS` blocks later, so
    /// the peer is still inside its own guard window when the origin's has
    /// ended and the wallet's resubmission is stemmed. The peer must admit
    /// it on the stem (and on relay) like any valid transaction: if it
    /// answered `Expired`, `on_stem_tx` would drop it silently, a Dandelion
    /// black hole whose embargo makes the origin fluff its own transaction.
    /// The guard is for local origination only.
    #[test]
    fn rtw1b_a_later_stem_peer_admits_the_origins_reinjection() {
        let tx = transfer(&[5], &[10, 11], 10);
        let a = 1_000;
        let e = MEMPOOL_EXPIRY_BLOCKS;
        let r = RECENTLY_EXPIRED_BLOCKS;
        let mut black_holes = Vec::new();
        for lag in 0..=r {
            let (mut origin, mut peer) = (Mempool::new(), Mempool::new());
            add_at(&mut origin, tx.clone(), a).unwrap();
            add_at(&mut peer, tx.clone(), a + lag).unwrap();
            // Both follow the chain block by block up to the height at which
            // the origin's guard has ended.
            let reaccept = a + e + r;
            for h in a..=reaccept {
                origin.expire(h);
                peer.expire(h);
            }
            assert!(
                origin.precheck(&tx, reaccept, Origin::Local).is_ok(),
                "origin re-admits its wallet's resubmission"
            );
            let at_peer = peer.precheck(&tx, reaccept, Origin::Peer).map(|_| ());
            // The peer's own wallet is still guarded there.
            if lag > 0 {
                assert_eq!(
                    peer.precheck(&tx, reaccept, Origin::Local).map(|_| ()),
                    Err(MempoolError::Expired),
                    "lag {lag}"
                );
            }
            if at_peer == Err(MempoolError::Expired) {
                black_holes.push(lag);
            } else {
                assert_eq!(at_peer, Ok(()), "lag {lag}");
            }
        }
        assert_eq!(
            black_holes,
            Vec::<u64>::new(),
            "peer admission lags (blocks) at which the stem peer black-holes"
        );
    }

    /// RTW1B-3. Transfers and deploys compete for the block weight, ranked
    /// by the fee of their v1 part per weight. A deploy's exact fee also
    /// holds a payload term (`DEPLOY_FEE_PER_BYTE` x payload bytes) that is
    /// not a weight and must buy no priority: with a vault-sized program,
    /// 64-input deploys would otherwise outrank every standard-fee transfer
    /// (which cannot pay more, T8) and displace them from templates.
    #[test]
    fn rtw1b_deploys_do_not_displace_standard_fee_transfers() {
        let rules = TxRules::for_chain(&blacksilk_consensus::ChainParams::regtest());
        // A realistic transfer: a 2-output range proof of the right length
        // (7 rounds) and a ring of 3-byte varints (all transfers weigh the
        // same).
        let real_transfer = |image: u64, o: u64| {
            let mut tx = transfer(&[image], &[o, o + 1], rules.standard_fee(1, 2).unwrap());
            if let Transaction::Transfer(t) = &mut tx {
                t.range_proof.l = vec![pt(3); 7];
                t.range_proof.r = vec![pt(4); 7];
                t.inputs[0].ring = std::array::from_fn(|j| 500_000 + 3_000 * j as u64);
            }
            tx
        };
        let elf_len = blacksilk_px::vault::VAULT_ELF.len();
        let mut m = Mempool::new();
        for k in 0..400u64 {
            add(&mut m, real_transfer(100_000 + k, 200_000 + 2 * k)).unwrap();
        }
        for d in 0..20u64 {
            let mut tx = deploy(0, &[300_000 + 2 * d, 300_001 + 2 * d], d as u8, 0);
            if let Transaction::PxDeploy(t) = &mut tx {
                t.inputs = (0..64).map(|j| input(1_000 * (d + 1) + j)).collect();
                t.pseudo_outs = vec![pt(9); 64];
                t.signatures = vec![clsag(); 64];
                t.programs = vec![blacksilk_tx::px::Registration {
                    elf: vec![d as u8; elf_len],
                    budget: blacksilk_px::vault::BUDGET,
                    abi: blacksilk_tx::px::ABI_VERSION,
                    out_words: 1,
                }];
                t.fee = t.required_fee(&rules);
            }
            add(&mut m, tx).unwrap();
        }
        let budget = rules.max_block_weight - COINBASE_RESERVE;
        let tw = real_transfer(1, 2).weight();
        let sel = m.select(1, budget, 0, u64::MAX);
        let is_deploy = |t: &&Transaction| matches!(t, Transaction::PxDeploy(_));
        let deploys = sel.iter().filter(is_deploy).count();
        let transfers = (sel.len() - deploys) as u64;
        assert_eq!(
            transfers,
            (budget / tw).min(400),
            "transfers of weight {tw} fill the budget first ({deploys} deploys)"
        );
        let first_deploy = sel.iter().position(|t| is_deploy(&t)).unwrap_or(sel.len());
        assert!(
            sel[first_deploy..].iter().all(|t| is_deploy(&t)),
            "transfers rank above deploys"
        );
    }

    // ------------------------------------------------ W2-12: reorganizations

    use blacksilk_tx::params::SPENDABLE_AGE;

    /// A chain of `n` blocks, each a synthetic coinbase and a synthetic
    /// transfer creating two non-coinbase outputs (salt `salt` keeps the
    /// outputs of two branches apart).
    fn grow(chain: &mut blacksilk_tx::state::MemoryChain, n: u64, salt: u64) {
        for _ in 0..n {
            let h = chain.next_height();
            let k = 10_000 * salt + 10 * h;
            chain
                .apply_block(&[
                    coinbase(&[k]),
                    transfer(&[1_000_000 * salt + h], &[k + 1, k + 2], 1),
                ])
                .unwrap();
        }
    }

    /// A synthetic transfer spending key image `image` with the given ring.
    fn ringed(image: u64, ring: [u64; RING_SIZE]) -> Transaction {
        let mut tx = transfer(&[image], &[image + 7_000_000, image + 7_000_001], 10);
        if let Transaction::Transfer(t) = &mut tx {
            t.inputs[0].ring = ring;
        }
        tx
    }

    /// A ring of the non-coinbase outputs `3h + 1` of blocks `from..from + 16`
    /// (`grow`: three outputs per block).
    fn ring_from(from: u64) -> [u64; RING_SIZE] {
        std::array::from_fn(|j| 3 * (from + j as u64) + 1)
    }

    /// Inserts `tx` as `add` would after validation, with the digest of its
    /// rings on `chain` (the signatures are never verified here: synthetic
    /// transactions carry none that verify).
    fn pool_on(m: &mut Mempool, chain: &impl ChainView, tx: Transaction, height: u64) -> Hash {
        let (id, keys) = m.precheck(&tx, height, Origin::Peer).unwrap();
        let ring = ring_digest(&tx, chain, height).unwrap();
        let fee = v1_part_fee(&tx, &rules());
        m.insert(id, tx, keys, height, fee, ring).unwrap()
    }

    /// W2-12 item 1 (dossier 12 W1). A reorganization above every ring
    /// member keeps a pooled transfer without verifying it: its rings
    /// resolve to the same outputs, so its CLSAG verdict is the one of its
    /// admission. The transfer is synthetic and its signature does not
    /// verify: full validation (the path before W2-12, which failed this
    /// test on the base, C:/bszkeval/w2-pool-scratch/base-demo.log) drops it.
    #[test]
    fn a_reorganization_above_the_rings_keeps_the_entry_without_verifying_it() {
        use blacksilk_tx::state::MemoryChain;
        let mut chain = MemoryChain::new();
        grow(&mut chain, 40, 1);
        let rules = rules();
        let mut m = Mempool::new();
        m.enter_rules(&rules);
        let tx = ringed(90_000_000, ring_from(1));
        let id = pool_on(&mut m, &chain, tx.clone(), chain.next_height());
        assert!(validate_mempool_tx(&tx, &chain, chain.next_height(), &rules).is_err());
        // Two blocks replaced by three.
        assert!(chain.undo_block() && chain.undo_block());
        grow(&mut chain, 3, 2);
        let verified = m.full_validations();
        let r = m.revalidate(&chain, chain.next_height(), &rules, true);
        assert!(m.contains(&id), "{r:?}");
        assert_eq!(
            r,
            Revalidation {
                checked: 1,
                invalid: 0,
                ring_changed: 0
            }
        );
        assert_eq!(m.full_validations(), verified, "nothing verified");
    }

    /// A reorganization below a ring member (its block replaced by one with
    /// other outputs at the same indices) drops the entry as `ring_changed`,
    /// unverified; an entry whose rings lie below the fork stays.
    #[test]
    fn a_reorganization_below_a_ring_drops_the_entry_unverified() {
        use blacksilk_tx::state::MemoryChain;
        let mut chain = MemoryChain::new();
        grow(&mut chain, 45, 1);
        let rules = rules();
        let mut m = Mempool::new();
        let next = chain.next_height();
        let deep = pool_on(&mut m, &chain, ringed(90_000_000, ring_from(1)), next);
        // Members at heights 19..=34, mature at 45 (SPENDABLE_AGE 10).
        let recent = pool_on(&mut m, &chain, ringed(90_000_010, ring_from(19)), next);
        for _ in 0..15 {
            assert!(chain.undo_block());
        }
        grow(&mut chain, 16, 2);
        let r = m.revalidate(&chain, chain.next_height(), &rules, true);
        assert!(m.contains(&deep));
        assert!(!m.contains(&recent));
        assert_eq!((r.ring_changed, r.invalid), (1, 0), "{r:?}");
        assert_invariants(&m);
    }

    /// A reorganization to a lower height makes a ring member immature (C1
    /// at the new next height): the entry is dropped, although its digest is
    /// unchanged. The extension path alone would keep it.
    #[test]
    fn a_ring_member_that_becomes_immature_drops_the_entry() {
        use blacksilk_tx::state::MemoryChain;
        let mut chain = MemoryChain::new();
        grow(&mut chain, 40, 1);
        let rules = rules();
        let next = chain.next_height();
        // The newest member, at height next - SPENDABLE_AGE, matures exactly
        // at `next`.
        let from = next - SPENDABLE_AGE - (RING_SIZE as u64 - 1);
        let tx = ringed(90_000_000, ring_from(from));
        let mut m = Mempool::new();
        let id = pool_on(&mut m, &chain, tx.clone(), next);
        let mut ext = Mempool::new();
        pool_on(&mut ext, &chain, tx, next);
        assert!(chain.undo_block());
        let lower = chain.next_height();
        ext.revalidate(&chain, lower, &rules, false);
        assert!(ext.contains(&id), "the extension check alone keeps it");
        let r = m.revalidate(&chain, lower, &rules, true);
        assert!(!m.contains(&id));
        assert_eq!((r.invalid, r.ring_changed), (1, 0), "{r:?}");
    }

    /// Item 2 (W2): transactions of a disconnected block, captured while it
    /// was connected, come back without verification (their signatures do
    /// not verify here) and with a fresh admission height; one whose ring
    /// changed, one of other rules and one conflicting with a pooled
    /// transaction do not; the guard entry of a readmitted one is cleared.
    #[test]
    fn returned_transactions_are_readmitted_without_verification() {
        use blacksilk_tx::state::MemoryChain;
        let mut chain = MemoryChain::new();
        grow(&mut chain, 45, 1);
        let rules = rules();
        let other = TxRules {
            branch_id: rules.branch_id + 1,
            ..rules
        };
        let keep = ringed(90_000_000, ring_from(1));
        let moved = ringed(90_000_010, ring_from(19));
        let foreign = ringed(90_000_020, ring_from(2));
        let doubled = ringed(90_000_030, ring_from(3));
        let mut rival = ringed(90_000_030, ring_from(4));
        if let Transaction::Transfer(t) = &mut rival {
            t.fee = 11;
        }
        let block = vec![
            coinbase(&[99_000_000]),
            keep.clone(),
            moved.clone(),
            foreign.clone(),
            doubled.clone(),
        ];
        chain.apply_block(&block).unwrap();
        let mut returned: Vec<Returned> = block[1..]
            .iter()
            .map(|tx| Returned::capture(tx.clone(), &chain, &rules))
            .collect();
        returned[2] = Returned::capture(foreign.clone(), &chain, &other);

        let mut m = Mempool::new();
        m.enter_rules(&rules);
        // `keep` expired here earlier: the guard does not stop readmission,
        // and is cleared by it.
        m.expired.insert(keep.hash(), chain.next_height());
        // The block and the blocks below it down to height 31 are
        // disconnected; the new branch has other outputs there.
        for _ in 0..15 {
            assert!(chain.undo_block());
        }
        grow(&mut chain, 17, 2);
        let next = chain.next_height();
        pool_on(&mut m, &chain, rival.clone(), next);
        let verified = m.full_validations();
        let r = m.readmit_returned(returned, &chain, next, &rules);
        assert_eq!(m.full_validations(), verified, "nothing verified");
        assert_eq!(
            r,
            Readmission {
                readmitted: 1,
                other_rules: 1,
                conflicts: 1,
                ring_changed: 1,
                ..Readmission::default()
            }
        );
        assert!(m.contains(&keep.hash()) && m.contains(&rival.hash()));
        assert_eq!(m.admitted_at(&keep.hash()), Some(next));
        assert!(!m.recently_expired(&keep.hash(), next));
        assert_invariants(&m);
        // Mined again on the new branch: its key image is spent, it is not
        // readmitted a second time.
        let again = Returned::capture(keep.clone(), &chain, &rules);
        m.remove(&keep.hash());
        chain.apply_block(&[coinbase(&[99_000_001]), keep]).unwrap();
        let r = m.readmit_returned(vec![again], &chain, chain.next_height(), &rules);
        assert_eq!(r.invalid, 1, "{r:?}");
    }

    /// A PX transaction a reorganization returns is readmitted without its
    /// proof being verified (here it has none: `add` and `readmit` refuse
    /// it with `PxProof`), and still leaves at its window's end.
    #[test]
    fn a_returned_px_transaction_is_readmitted_without_its_proof() {
        use blacksilk_px::state::State as PxState;
        use blacksilk_tx::state::MemoryChain;
        let chain =
            MemoryChain::with_px_state(PxState::with_uniform_tree_for_tests(4, [7; 8], 1 << 60));
        let rules = rules();
        let h = 20;
        let tx = valid_px(&chain, 1, 0, h + 1);
        let mut m = Mempool::new();
        assert_eq!(
            m.readmit(tx.clone(), &chain, h, &rules),
            Err(MempoolError::Invalid(TxError::PxProof))
        );
        let verified = m.full_validations();
        let r = m.readmit_returned(
            vec![Returned::capture(tx.clone(), &chain, &rules)],
            &chain,
            h,
            &rules,
        );
        assert_eq!(r.readmitted, 1, "{r:?}");
        assert_eq!(m.full_validations(), verified);
        m.revalidate(&chain, h + 1, &rules, true);
        assert!(m.contains(&tx.hash()));
        m.revalidate(&chain, h + 2, &rules, false);
        assert!(!m.contains(&tx.hash()), "past its window");
    }

    /// Order: `update_after_chain_change` revalidates before it readmits, so
    /// a returned transaction takes the room of stale entries of a full
    /// class. Readmitting first (the order before W2-12) refuses it.
    #[test]
    fn returned_transactions_take_the_room_of_stale_entries() {
        use blacksilk_px::state::State as PxState;
        use blacksilk_tx::state::MemoryChain;
        let chain =
            MemoryChain::with_px_state(PxState::with_uniform_tree_for_tests(4, [7; 8], 1 << 60));
        let rules = rules();
        let tx = valid_px(&chain, 1_000_001, 0, 0);
        let returned = || vec![Returned::capture(tx.clone(), &chain, &rules)];
        // A PX class full of entries paying more per byte, with an anchor
        // that is no recent root: stale at the next revalidation.
        let full = || {
            let mut m = Mempool::new();
            m.enter_rules(&rules);
            fill(&mut m, 0, 1024 * 1024, u64::MAX / 4);
            // Top it up to the last byte.
            let room = MEMPOOL_MAX_PX_BYTES - m.bytes[1];
            let top = |proof| px(900_001, proof, u64::MAX / 4, 0, 0);
            let mut proof = room - top(0).encode().len();
            while top(proof).encode().len() > room {
                proof -= 1;
            }
            add(&mut m, top(proof)).unwrap();
            assert!(MEMPOOL_MAX_PX_BYTES - m.bytes[1] < tx.encode().len());
            m
        };
        let mut before = full();
        let r = before.readmit_returned(returned(), &chain, 20, &rules);
        assert_eq!(r.no_room, 1, "{r:?}");
        let mut m = full();
        let u = m.update_after_chain_change(
            ChainChange {
                returned: returned(),
                reorganized: true,
            },
            &chain,
            20,
            &rules,
        );
        assert!(u.revalidation.invalid > 0, "{u:?}");
        assert_eq!(u.readmission.readmitted, 1, "{u:?}");
        assert_eq!(m.len(), 1);
    }

    /// Bounded work: one reorganization examines at most a class cap of
    /// returned bytes per class; the rest is dropped unexamined.
    #[test]
    fn readmission_examines_at_most_a_class_cap_per_reorganization() {
        use blacksilk_tx::state::MemoryChain;
        let chain = MemoryChain::new();
        let rules = rules();
        let size = 3 * 1024 * 1024;
        let tx = px(1, size, 1, 0, 0);
        let fits = MEMPOOL_MAX_PX_BYTES / tx.encode().len();
        let returned = vec![Returned::capture(tx, &chain, &rules); fits + 5];
        let mut m = Mempool::new();
        let r = m.readmit_returned(returned, &chain, 1, &rules);
        assert_eq!(r.over_budget, 5, "{r:?}");
        assert_eq!(r.invalid + r.readmitted + r.already_pooled, fits, "{r:?}");
    }

    /// RTW2A-6: capture itself is bounded. A reorganization returning more
    /// PX bytes than `READMIT_MAX_BYTES` (here 30 transactions of 3 MiB,
    /// about 90 MiB, over the 64 MiB class cap) keeps the first ones, tip
    /// first, up to the budget and copies nothing beyond it; the v1 class
    /// has its own budget. The size is the encoded size, computed once.
    #[test]
    fn capture_of_returned_transactions_stops_at_the_class_budget() {
        use blacksilk_tx::state::MemoryChain;
        let chain = MemoryChain::new();
        let rules = rules();
        let txs: Vec<Transaction> = (0..30).map(|n| px(n, 3 * 1024 * 1024, 1, 0, 0)).collect();
        let size = txs[0].encode().len();
        let fits = MEMPOOL_MAX_PX_BYTES / size;
        assert!(fits < txs.len());
        let mut used = [0usize; 2];
        let captured: Vec<Returned> = txs
            .iter()
            .map_while(|tx| Returned::capture_within(tx, &chain, &rules, &mut used))
            .collect();
        assert_eq!(captured.len(), fits);
        assert_eq!(used, [0, fits * size]);
        assert!(captured
            .iter()
            .zip(&txs)
            .all(|(r, tx)| r.id() == tx.hash() && r.size() == size && r.tx() == tx));
        for tx in &txs[fits..] {
            assert!(Returned::capture_within(tx, &chain, &rules, &mut used).is_none());
        }
        let v1 = transfer(&[1], &[2, 3], 1);
        assert!(Returned::capture_within(&v1, &chain, &rules, &mut used).is_some());
        assert_eq!(used[1], fits * size, "a refused capture charges nothing");
    }

    /// RTW2A-2: while a bounded drain holds a returned transaction, its
    /// conflict keys are reserved. A double spend is refused before any
    /// validation (`ReorgPending`, also by `conflicts`, the P2P pre-check),
    /// the returned transaction itself is not, and readmission releases the
    /// keys and pools it: the outcome of an atomic reorganization.
    #[test]
    fn a_returned_transactions_keys_are_reserved_until_its_readmission() {
        use blacksilk_tx::state::MemoryChain;
        let mut chain = MemoryChain::new();
        grow(&mut chain, 45, 1);
        let rules = rules();
        let t1 = ringed(90_000_000, ring_from(1));
        let t2 = ringed(90_000_000, ring_from(2));
        assert_ne!(t1.hash(), t2.hash());
        chain
            .apply_block(&[coinbase(&[99_000_000]), t1.clone()])
            .unwrap();
        let returned = Returned::capture(t1.clone(), &chain, &rules);
        let mut m = Mempool::new();
        m.enter_rules(&rules);
        m.reserve(&returned);
        assert!(chain.undo_block());
        let next = chain.next_height();
        let verified = m.full_validations();
        assert_eq!(
            m.check(&t2, &chain, next, &rules, Origin::Peer),
            Err(MempoolError::ReorgPending)
        );
        assert_eq!(
            m.add(t2.clone(), &chain, next, &rules, Origin::Local),
            Err(MempoolError::ReorgPending)
        );
        assert_eq!(m.full_validations(), verified, "refused before validation");
        assert!(m.conflicts(&t2));
        assert!(!m.conflicts(&t1), "not against itself");
        assert!(m.precheck(&t1, next, Origin::Peer).is_ok());
        let r = m.readmit_returned(vec![returned], &chain, next, &rules);
        assert_eq!(r.readmitted, 1, "{r:?}");
        assert_eq!(m.reserved_keys(), 0);
        assert!(m.contains(&t1.hash()));
        assert_eq!(
            m.precheck(&t2, next, Origin::Peer).map(|_| ()),
            Err(MempoolError::Conflict)
        );
        assert_invariants(&m);
    }

    /// M12-8: the pool is flushed when any rule changes, not only the
    /// signature domain (the reorganization paths skip every stateless
    /// rule, exact only under the same rules).
    #[test]
    fn any_rule_change_flushes_the_pool() {
        let r0 = rules();
        let r1 = TxRules {
            fee_per_weight: r0.fee_per_weight + 1,
            ..r0
        };
        assert_eq!(r0.domain(), r1.domain());
        let mut m = Mempool::new();
        m.enter_rules(&r0);
        add(&mut m, px(1, 1000, 10, 0, 0)).unwrap();
        assert_eq!(m.enter_rules(&r1), 1);
        assert!(m.is_empty());
    }

    /// The digest tag is not a registered consensus tag, and the digest
    /// binds each member and its position.
    #[test]
    fn the_ring_digest_binds_every_member_in_order() {
        use blacksilk_tx::state::MemoryChain;
        assert!(!blacksilk_crypto::hash::tags::ALL.contains(&RING_DIGEST_TAG));
        let mut chain = MemoryChain::new();
        grow(&mut chain, 40, 1);
        let d = |ring| ring_digest(&ringed(1, ring), &chain, 40).unwrap();
        let base = ring_from(1);
        let mut swapped = base;
        swapped.swap(0, 1);
        let mut other = base;
        other[15] += 1;
        assert_ne!(d(base), d(swapped));
        assert_ne!(d(base), d(other));
        assert_eq!(d(base), d(base));
        assert_ne!(d(base), test_ring(&px(1, 10, 1, 0, 0)), "no ring");
    }
}
