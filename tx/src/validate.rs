//! Transaction and block-body validation (spec §8).
//!
//! Rules are evaluated cheap-first. Each rule has its own error variant, so tests
//! can assert that an invalid transaction fails for the intended reason.
//!
//! | Function | Rules |
//! |---|---|
//! | [`check_structure`] | T1, T3–T8, T10 (shape), T11 |
//! | [`check_balance`] | T9 |
//! | [`check_range_proof`] | T10 |
//! | [`resolve_rings`] | C1 |
//! | [`check_signatures`] | C3 |
//! | [`validate_transfer`] | all of T and C (mempool) |
//! | [`validate_block_transactions`] | B1–B7, plus all T and C with block-wide batching |

use crate::params::*;
use crate::types::*;
use blacksilk_crypto::bulletproofs_plus::{self as bpp, BppProof};
use blacksilk_crypto::clsag::{self, RingMember};
use blacksilk_crypto::generators::h;
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use std::collections::HashSet;

/// An output in the chain's global output set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputRecord {
    pub key: OutputKey,
    /// Height of the block that created it.
    pub height: u64,
    pub coinbase: bool,
}

/// Read access to the chain state at the parent of the block being validated.
pub trait ChainView {
    fn output(&self, global_index: u64) -> Option<OutputRecord>;
    fn is_key_image_spent(&self, key_image: &Point) -> bool;
    fn has_one_time_key(&self, key: &Point) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxError {
    /// T1 (for transactions not produced by `decode`).
    TooLarge {
        size: usize,
    },
    /// T2: a coinbase where a transfer is required.
    CoinbaseNotAllowed,
    /// T3.
    InputCount(usize),
    OutputCount(usize),
    /// T4.
    KeyImageIdentity {
        input: usize,
    },
    KeyImagesNotSorted,
    /// T5.
    RingNotIncreasing {
        input: usize,
    },
    /// T6.
    OutputKeyIdentity {
        output: usize,
    },
    EphemeralIdentity {
        output: usize,
    },
    OutputsNotSorted,
    /// T7.
    PseudoOutCount,
    /// T8.
    FeeTooLow {
        fee: u64,
        required: u64,
    },
    WeightOverflow,
    /// T9.
    Unbalanced,
    /// T10.
    RangeProofShape,
    RangeProofInvalid,
    /// T11.
    SignatureCount,
    /// C1.
    UnknownRingMember {
        input: usize,
        index: u64,
    },
    RingMemberTooYoung {
        input: usize,
        index: u64,
    },
    /// C2.
    KeyImageSpent {
        input: usize,
    },
    /// C3.
    InvalidSignature {
        input: usize,
    },
    /// C4.
    DuplicateOneTimeKey {
        output: usize,
    },
}

impl TxError {
    /// Whether the transaction is invalid regardless of chain state (rules T1–T11).
    ///
    /// Contextual failures (C1–C4) depend on the node's view of the chain:
    /// - ring members may not exist yet or be too young on this branch;
    /// - a key image may have just been spent in a block;
    /// - the same ring indices resolve to different outputs on another fork, which
    ///   changes the signature's statement.
    ///
    /// An honest peer can relay a transaction that fails them here. Only stateless
    /// failures prove misbehavior (docs/p2p.md §10).
    pub fn is_stateless(&self) -> bool {
        !matches!(
            self,
            TxError::UnknownRingMember { .. }
                | TxError::RingMemberTooYoung { .. }
                | TxError::KeyImageSpent { .. }
                | TxError::InvalidSignature { .. }
                | TxError::DuplicateOneTimeKey { .. }
        )
    }
}

fn strictly_increasing<T: Ord>(items: impl IntoIterator<Item = T>) -> bool {
    let mut prev: Option<T> = None;
    for item in items {
        if let Some(p) = &prev {
            if *p >= item {
                return false;
            }
        }
        prev = Some(item);
    }
    true
}

/// Cheap structural rules: T1, T3–T8, T10 (shape) and T11.
pub fn check_structure(tx: &Transfer, rules: &TxRules) -> Result<(), TxError> {
    let n = tx.inputs.len();
    let k = tx.outputs.len();
    if n == 0 || n > MAX_INPUTS {
        return Err(TxError::InputCount(n));
    }
    if !(MIN_OUTPUTS..=MAX_OUTPUTS).contains(&k) {
        return Err(TxError::OutputCount(k));
    }
    // T4
    for (i, input) in tx.inputs.iter().enumerate() {
        if input.key_image.is_identity() {
            return Err(TxError::KeyImageIdentity { input: i });
        }
    }
    if !strictly_increasing(tx.inputs.iter().map(|i| i.key_image)) {
        return Err(TxError::KeyImagesNotSorted);
    }
    // T5
    for (i, input) in tx.inputs.iter().enumerate() {
        if !strictly_increasing(input.ring.iter()) {
            return Err(TxError::RingNotIncreasing { input: i });
        }
    }
    // T6
    for (j, o) in tx.outputs.iter().enumerate() {
        if o.one_time_key.is_identity() {
            return Err(TxError::OutputKeyIdentity { output: j });
        }
        if o.ephemeral.is_identity() {
            return Err(TxError::EphemeralIdentity { output: j });
        }
    }
    if !strictly_increasing(tx.outputs.iter().map(|o| o.one_time_key)) {
        return Err(TxError::OutputsNotSorted);
    }
    // T7, T11, T10 shape
    if tx.pseudo_outs.len() != n {
        return Err(TxError::PseudoOutCount);
    }
    if tx.signatures.len() != n {
        return Err(TxError::SignatureCount);
    }
    let rounds = bpp::rounds(k).ok_or(TxError::RangeProofShape)?;
    if tx.range_proof.l.len() != rounds || tx.range_proof.r.len() != rounds {
        return Err(TxError::RangeProofShape);
    }
    // T1
    let size = tx.encoded_len();
    if size > MAX_TX_SIZE {
        return Err(TxError::TooLarge { size });
    }
    // T8
    let required = rules.min_fee(tx.weight()).ok_or(TxError::WeightOverflow)?;
    if tx.fee < required {
        return Err(TxError::FeeTooLow {
            fee: tx.fee,
            required,
        });
    }
    Ok(())
}

/// T9: `Σ C'_k − Σ Cm_j − fee·H = identity`.
pub fn check_balance(tx: &Transfer) -> Result<(), TxError> {
    let inputs: RistrettoPoint = tx.pseudo_outs.iter().map(|p| p.point()).sum();
    let outputs: RistrettoPoint = tx.outputs.iter().map(|o| o.commitment.point()).sum();
    if Point::from_point(inputs - outputs - Scalar::from(tx.fee) * h()).is_identity() {
        Ok(())
    } else {
        Err(TxError::Unbalanced)
    }
}

fn output_commitments(tx: &Transfer) -> Vec<Point> {
    tx.outputs.iter().map(|o| o.commitment).collect()
}

/// T10 for one transaction.
pub fn check_range_proof(tx: &Transfer) -> Result<(), TxError> {
    if bpp::verify(&tx.range_proof, &output_commitments(tx)) {
        Ok(())
    } else {
        Err(TxError::RangeProofInvalid)
    }
}

/// C1: resolves every ring against the chain and checks existence and age for a
/// transaction included at `height`.
pub fn resolve_rings(
    tx: &Transfer,
    chain: &impl ChainView,
    height: u64,
) -> Result<Vec<[RingMember; RING_SIZE]>, TxError> {
    tx.inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let mut ring = [RingMember {
                one_time_key: input.key_image,
                commitment: input.key_image,
            }; RING_SIZE];
            for (slot, &index) in ring.iter_mut().zip(&input.ring) {
                let rec = chain
                    .output(index)
                    .ok_or(TxError::UnknownRingMember { input: i, index })?;
                let min_age = if rec.coinbase {
                    COINBASE_MATURITY
                } else {
                    SPENDABLE_AGE
                };
                if height.saturating_sub(rec.height) < min_age {
                    return Err(TxError::RingMemberTooYoung { input: i, index });
                }
                *slot = RingMember {
                    one_time_key: rec.key.one_time_key,
                    commitment: rec.key.commitment,
                };
            }
            Ok(ring)
        })
        .collect()
}

/// C3: every CLSAG verifies over its resolved ring and the signature message.
pub fn check_signatures(
    tx: &Transfer,
    rings: &[[RingMember; RING_SIZE]],
    rules: &TxRules,
) -> Result<(), TxError> {
    let message = tx.signature_message(rules.network_id);
    for (i, ((input, ring), (pseudo, sig))) in tx
        .inputs
        .iter()
        .zip(rings)
        .zip(tx.pseudo_outs.iter().zip(&tx.signatures))
        .enumerate()
    {
        if !clsag::verify(&message, ring, pseudo, &input.key_image, sig) {
            return Err(TxError::InvalidSignature { input: i });
        }
    }
    Ok(())
}

/// C2 and C4 against the chain (and, for blocks, what earlier transactions of the
/// same block already used).
fn check_uniqueness(
    tx: &Transfer,
    chain: &impl ChainView,
    block_key_images: &mut HashSet<[u8; 32]>,
    block_one_time_keys: &mut HashSet<[u8; 32]>,
) -> Result<(), TxError> {
    for (i, input) in tx.inputs.iter().enumerate() {
        if chain.is_key_image_spent(&input.key_image)
            || !block_key_images.insert(*input.key_image.bytes())
        {
            return Err(TxError::KeyImageSpent { input: i });
        }
    }
    for (j, o) in tx.outputs.iter().enumerate() {
        if chain.has_one_time_key(&o.one_time_key)
            || !block_one_time_keys.insert(*o.one_time_key.bytes())
        {
            return Err(TxError::DuplicateOneTimeKey { output: j });
        }
    }
    Ok(())
}

/// Full validation of one transfer for inclusion at `height` (mempool use).
pub fn validate_transfer(
    tx: &Transfer,
    chain: &impl ChainView,
    height: u64,
    rules: &TxRules,
) -> Result<(), TxError> {
    check_structure(tx, rules)?;
    check_balance(tx)?;
    check_uniqueness(tx, chain, &mut HashSet::new(), &mut HashSet::new())?;
    let rings = resolve_rings(tx, chain, height)?;
    check_signatures(tx, &rings, rules)?;
    check_range_proof(tx)
}

/// Mempool entry point: any decoded transaction. Coinbases are only valid as the
/// first transaction of a block (T2).
pub fn validate_mempool_tx(
    tx: &Transaction,
    chain: &impl ChainView,
    height: u64,
    rules: &TxRules,
) -> Result<(), TxError> {
    match tx {
        Transaction::Coinbase(_) => Err(TxError::CoinbaseNotAllowed),
        Transaction::Transfer(t) => validate_transfer(t, chain, height, rules),
    }
}

/// Inputs to block-body validation that come from the header chain and emission.
#[derive(Clone, Copy, Debug)]
pub struct BlockContext {
    pub height: u64,
    /// `block_reward(height)` from the emission schedule.
    pub reward: u64,
    /// The header's `tx_root`.
    pub tx_root: Hash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    /// B1.
    MissingCoinbase,
    UnexpectedCoinbase {
        index: usize,
    },
    /// B2.
    CoinbaseHeight {
        expected: u64,
        found: u64,
    },
    /// Coinbase structure (spec §4.3, T6 applied to coinbase outputs).
    CoinbaseOutputCount(usize),
    CoinbaseOutputKeyIdentity {
        output: usize,
    },
    CoinbaseEphemeralIdentity {
        output: usize,
    },
    CoinbaseOutputsNotSorted,
    CoinbaseDuplicateOneTimeKey {
        output: usize,
    },
    /// B3.
    CoinbaseAmount {
        claimed: u128,
        allowed: u128,
    },
    /// B5.
    TxRootMismatch,
    /// B6.
    WeightExceeded {
        weight: u128,
        max: u64,
    },
    /// A transfer broke a T or C rule (B4 duplicates surface here as C2/C4).
    Tx {
        index: usize,
        error: TxError,
    },
    /// T10, when block-wide batch verification fails.
    RangeProofBatch,
}

/// Validates the transactions of a block at `ctx.height` against `chain` (the
/// state after the parent block). Checks B1–B7 and every T/C rule. All
/// Bulletproofs+ of the block are batch-verified at the end (spec §7).
pub fn validate_block_transactions<R: RngCore + CryptoRng>(
    txs: &[Transaction],
    ctx: &BlockContext,
    chain: &impl ChainView,
    rules: &TxRules,
    rng: &mut R,
) -> Result<(), BlockError> {
    // B1, B2 and coinbase structure.
    let Some(Transaction::Coinbase(coinbase)) = txs.first() else {
        return Err(BlockError::MissingCoinbase);
    };
    if coinbase.height != ctx.height {
        return Err(BlockError::CoinbaseHeight {
            expected: ctx.height,
            found: coinbase.height,
        });
    }
    let k = coinbase.outputs.len();
    if !(MIN_COINBASE_OUTPUTS..=MAX_COINBASE_OUTPUTS).contains(&k) {
        return Err(BlockError::CoinbaseOutputCount(k));
    }
    for (j, o) in coinbase.outputs.iter().enumerate() {
        if o.one_time_key.is_identity() {
            return Err(BlockError::CoinbaseOutputKeyIdentity { output: j });
        }
        if o.ephemeral.is_identity() {
            return Err(BlockError::CoinbaseEphemeralIdentity { output: j });
        }
    }
    if !strictly_increasing(coinbase.outputs.iter().map(|o| o.one_time_key)) {
        return Err(BlockError::CoinbaseOutputsNotSorted);
    }

    let mut transfers = Vec::with_capacity(txs.len() - 1);
    for (index, tx) in txs.iter().enumerate().skip(1) {
        match tx {
            Transaction::Coinbase(_) => return Err(BlockError::UnexpectedCoinbase { index }),
            Transaction::Transfer(t) => {
                check_structure(t, rules).map_err(|error| BlockError::Tx { index, error })?;
                transfers.push((index, t));
            }
        }
    }

    // B5
    let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
    if blacksilk_consensus::merkle::tx_root(&ids) != ctx.tx_root {
        return Err(BlockError::TxRootMismatch);
    }
    // B6
    let weight: u128 = txs.iter().map(|t| t.weight() as u128).sum();
    if weight > rules.max_block_weight as u128 {
        return Err(BlockError::WeightExceeded {
            weight,
            max: rules.max_block_weight,
        });
    }
    // B3
    let fees: u128 = transfers.iter().map(|(_, t)| t.fee as u128).sum();
    let allowed = ctx.reward as u128 + fees;
    if coinbase.total() != allowed {
        return Err(BlockError::CoinbaseAmount {
            claimed: coinbase.total(),
            allowed,
        });
    }

    // T9, then C2/C4 (with B4 via the block-wide sets).
    for (index, t) in &transfers {
        check_balance(t).map_err(|error| BlockError::Tx {
            index: *index,
            error,
        })?;
    }
    let mut key_images = HashSet::new();
    let mut one_time_keys = HashSet::new();
    for (j, o) in coinbase.outputs.iter().enumerate() {
        if chain.has_one_time_key(&o.one_time_key) || !one_time_keys.insert(*o.one_time_key.bytes())
        {
            return Err(BlockError::CoinbaseDuplicateOneTimeKey { output: j });
        }
    }
    for (index, t) in &transfers {
        check_uniqueness(t, chain, &mut key_images, &mut one_time_keys).map_err(|error| {
            BlockError::Tx {
                index: *index,
                error,
            }
        })?;
    }

    // C1, C3 (expensive).
    for (index, t) in &transfers {
        let rings = resolve_rings(t, chain, ctx.height).map_err(|error| BlockError::Tx {
            index: *index,
            error,
        })?;
        check_signatures(t, &rings, rules).map_err(|error| BlockError::Tx {
            index: *index,
            error,
        })?;
    }

    // T10, batched.
    let commitments: Vec<Vec<Point>> = transfers
        .iter()
        .map(|(_, t)| output_commitments(t))
        .collect();
    let items: Vec<(&BppProof, &[Point])> = transfers
        .iter()
        .zip(&commitments)
        .map(|((_, t), c)| (&t.range_proof, c.as_slice()))
        .collect();
    if !bpp::batch_verify(&items, rng) {
        return Err(BlockError::RangeProofBatch);
    }
    Ok(())
}
