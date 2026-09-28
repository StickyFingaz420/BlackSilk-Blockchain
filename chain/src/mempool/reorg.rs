//! Reorganizations: the ring digest, revalidation after blocks were
//! disconnected, and readmission of the transactions of disconnected blocks,
//! without verifying a signature, range proof or PX proof again (dossier 12
//! W1/W2; docs/blocks.md §7). Policy, not consensus.
//!
//! **What changes across a reorganization.** Outputs are records by global
//! index. After blocks are disconnected an index may resolve to another
//! output, or to the same output created at another height, so C1 (ring
//! members exist and are mature) and C3 (every CLSAG verifies over its
//! resolved ring) can change verdict; nothing else a pooled transaction was
//! checked for depends on the disconnected blocks except the rules an
//! extension can also change (`revalidate_after_extension`: key images, the
//! PX window, anchor, nullifiers, registry, pool and tree capacity, deploy
//! contract ids).
//!
//! **The ring digest** ([`RingDigest`]) is a hash of the resolved
//! `(one_time_key, commitment)` of every ring member of every v1 input, in
//! order. `clsag::verify` is a deterministic function of the signature
//! message, the ring, the pseudo-output, the key image and the signature;
//! everything but the ring is the transaction itself (fixed by its id) and
//! the signature domain (fixed while the pool's rules are,
//! [`super::Mempool::enter_rules`]). So:
//! - an **unchanged digest** means an unchanged C3 verdict, exactly: the
//!   signature verified over this ring once and verifies again;
//! - a **changed digest** drops the transaction without verifying it
//!   (decisions, Agent 12): the ring is hashed into the CLSAG aggregation
//!   coefficients and into every round challenge, so a signature valid over
//!   one ring verifies over another only with negligible probability. The
//!   only error is dropping a transaction that would still verify, and the
//!   wallet rebroadcasts it.
//!
//! C1 itself (existence and maturity at the new next height) is checked by
//! resolving the rings with `resolve_input_rings`, the function blocks use.
//! Structure, balance, the range proof and the PX proof are functions of the
//! transaction and the rules alone, and are not re-run.
//!
//! **Readmission.** A transaction of a disconnected block was validated when
//! its block connected, under that block's rules (every signature and proof;
//! a PX proof possibly on admission to this pool, `mempool.contains` in
//! `validate_block_transactions_cached`). [`Returned::capture`] records its
//! ring digest while the block is still connected (outputs are only
//! appended, so the rings then resolve exactly as when the block was
//! validated) with those rules. [`super::Mempool::readmit_returned`] pools it
//! again when its rules are the pool's, the extension rules hold at the new
//! tip, its rings resolve (C1) to the same digest, and the pool has room.
//! None of it verifies a signature or a proof, so a reorganization costs a
//! few microseconds per input, not a CLSAG per input and a PX proof per PX
//! transaction under the chain lock (M12-1, M12-2).

use super::{class_of, ChainView, Mempool, Transaction, TxError, TxRules, READMIT_MAX_BYTES};
use blacksilk_consensus::Hash;
use blacksilk_crypto::clsag::{RingMember, RING_SIZE};
use blacksilk_crypto::hash::h32;
use blacksilk_tx::types::Input;
use blacksilk_tx::validate::resolve_input_rings;

/// Domain tag of [`RingDigest`] (`BlackSilk/v1/mempool/ring-digest`). The
/// digest lives only in this node's memory: it is never sent, stored or
/// compared with another node's, so the tag is policy, not consensus.
/// Registering it in `blacksilk_crypto::hash::tags` (the domain registry) is
/// owed to the registry's owner (decisions, Agent 12 "Digest tag").
pub const RING_DIGEST_TAG: &str = "mempool/ring-digest";

/// A hash of what every ring of a transaction's v1 inputs resolves to (module
/// docs). A transaction without v1 inputs has the digest of no ring.
pub type RingDigest = [u8; 32];

/// The v1 inputs of any transaction kind (none for a coinbase).
fn v1_inputs(tx: &Transaction) -> &[Input] {
    match tx {
        Transaction::Transfer(t) => &t.inputs,
        Transaction::Px(t) => &t.inputs,
        Transaction::PxDeploy(t) => &t.inputs,
        Transaction::Coinbase(_) => &[],
    }
}

/// The digest of resolved rings: the ring count, then each member's one-time
/// key and commitment, in input and ring order (fixed-size fields, so the
/// encoding is unambiguous).
fn digest_rings(rings: &[[RingMember; RING_SIZE]]) -> RingDigest {
    let mut data = Vec::with_capacity(8 + rings.len() * RING_SIZE * 64);
    data.extend_from_slice(&(rings.len() as u64).to_le_bytes());
    for member in rings.iter().flatten() {
        data.extend_from_slice(member.one_time_key.bytes());
        data.extend_from_slice(member.commitment.bytes());
    }
    h32(RING_DIGEST_TAG, &[&data])
}

/// C1 for inclusion at `height` (every ring member exists and is mature,
/// `resolve_input_rings`) and the digest of the resolved rings.
pub fn ring_digest(
    tx: &Transaction,
    chain: &impl ChainView,
    height: u64,
) -> Result<RingDigest, TxError> {
    resolve_input_rings(v1_inputs(tx), chain, height).map(|rings| digest_rings(&rings))
}

/// A transaction of a block being disconnected, with what readmitting it
/// without verification needs ([`super::Mempool::readmit_returned`]).
#[derive(Clone, Debug)]
pub struct Returned {
    tx: Transaction,
    /// Its id and encoded size, computed once at capture.
    id: Hash,
    size: usize,
    /// The digest of its rings while its block was connected; `None` if they
    /// did not resolve then (never for a validated block: it is then not
    /// readmitted).
    ring: Option<RingDigest>,
    /// The rules its block was validated under.
    rules: TxRules,
}

impl Returned {
    /// Captures `tx`, a transaction of a connected block validated under
    /// `rules` (the rules of the block's height), while `chain` still holds
    /// that block: call it before the block is undone. Maturity is not
    /// checked here (the block's validation did, at its own height), only
    /// what the rings resolve to.
    pub fn capture(tx: Transaction, chain: &impl ChainView, rules: &TxRules) -> Self {
        let size = tx.encode().len();
        Self::capture_sized(tx, size, chain, rules)
    }

    fn capture_sized(
        tx: Transaction,
        size: usize,
        chain: &impl ChainView,
        rules: &TxRules,
    ) -> Self {
        // `u64::MAX` as the height: every existing member counts as mature.
        let ring = ring_digest(&tx, chain, u64::MAX).ok();
        Self {
            id: tx.hash(),
            size,
            tx,
            ring,
            rules: *rules,
        }
    }

    /// [`Self::capture`] within a per-class byte budget: `used` holds the
    /// encoded bytes captured so far in this reorganization (v1, PX). A
    /// transaction that would take its class past [`READMIT_MAX_BYTES`] is
    /// not captured (`None`: no copy, no ring digest), so what one
    /// reorganization holds for readmission is bounded, whatever its depth
    /// (RTW2A-6). Called tip first, it keeps the transactions of the blocks
    /// nearest the old tip, as `readmit_returned` examines them.
    pub fn capture_within(
        tx: &Transaction,
        chain: &impl ChainView,
        rules: &TxRules,
        used: &mut [usize; 2],
    ) -> Option<Self> {
        let size = tx.encode().len();
        let slot = Mempool::slot(class_of(tx));
        if used[slot] + size > READMIT_MAX_BYTES[slot] {
            return None;
        }
        used[slot] += size;
        Some(Self::capture_sized(tx.clone(), size, chain, rules))
    }

    pub fn tx(&self) -> &Transaction {
        &self.tx
    }

    pub fn into_tx(self) -> Transaction {
        self.tx
    }

    /// Its id (`Transaction::hash`).
    pub fn id(&self) -> Hash {
        self.id
    }

    /// Its encoded size in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    pub(super) fn ring(&self) -> Option<RingDigest> {
        self.ring
    }

    pub(super) fn rules(&self) -> &TxRules {
        &self.rules
    }
}

/// What a reorganization changed for one transaction the pool checked
/// cheaply, as [`super::Mempool::revalidate`] and
/// [`super::Mempool::readmit_returned`] decide it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReorgVerdict {
    Valid,
    /// A rule an extension can also change fails, or C1 (a ring member is
    /// gone or immature).
    Invalid,
    /// The rings resolve, to other outputs: dropped without verification.
    RingChanged,
}

/// The reorganization check of a transaction validated (or connected) with
/// rings of digest `ring`, for inclusion at `height`: the extension rules,
/// then C1 and the digest (module docs).
pub(super) fn check_after_reorg(
    tx: &Transaction,
    ring: &RingDigest,
    chain: &impl ChainView,
    height: u64,
) -> ReorgVerdict {
    if blacksilk_tx::validate::revalidate_after_extension(tx, chain, height).is_err() {
        return ReorgVerdict::Invalid;
    }
    match ring_digest(tx, chain, height) {
        Ok(d) if d == *ring => ReorgVerdict::Valid,
        Ok(_) => ReorgVerdict::RingChanged,
        Err(_) => ReorgVerdict::Invalid,
    }
}
