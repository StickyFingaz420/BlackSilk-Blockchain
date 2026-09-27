//! Transaction and block-body validation (spec §8).
//!
//! Rules are evaluated cheap-first. Each rule has its own error variant, so tests
//! can assert that an invalid transaction fails for the intended reason.
//!
//! **Mempool order.** The single-transaction entry points
//! ([`validate_transfer`], [`validate_deploy`], [`validate_px`]) run every
//! stateless rule (structure, balance, range proof) before any contextual
//! one (C1–C4, PX1–PX4). A transaction invalid for a stateless reason is
//! therefore reported with a stateless error ([`TxError::is_stateless`]),
//! whatever else is wrong with it, and costs no ring resolution or CLSAG
//! verification. The order changes only *which* error an invalid
//! transaction gets, never *whether* it is valid: every rule is a pure check
//! and a transaction is valid iff all pass. The PX proof (PX5) runs last: it
//! needs PX3's registered programs and is the most expensive check. Block
//! validation keeps its own order, with the range proofs batched.
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
use crate::px::{
    check_deploy_structure, check_px_balance, check_px_structure, digest_bytes, PxDeploy, PxTx,
};
use crate::types::*;
use blacksilk_crypto::bulletproofs_plus::{self as bpp, BppProof};
use blacksilk_crypto::clsag::{self, Clsag, RingMember};
use blacksilk_crypto::generators::h;
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_px_core::Digest;
use blacksilk_zkvm::air::trace::Budget;
use blacksilk_zkvm::Program;
use rand_core::{CryptoRng, RngCore};
use std::collections::HashSet;
use std::sync::Arc;

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
    // ---- PX (docs/px.md §11) ----
    /// Whether `anchor` is one of the recent PX tree roots (root window).
    fn px_is_recent_root(&self, anchor: &Digest) -> bool;
    fn px_nullifier_spent(&self, nf: &Digest) -> bool;
    /// The BLK value inside PX.
    fn px_pool(&self) -> u128;
    /// The registered function program `program_id` of `contract`, with its
    /// budget.
    fn px_function(
        &self,
        contract: &Digest,
        program_id: &[u8; 32],
    ) -> Option<(Arc<Program>, Budget)>;
    fn px_contract_exists(&self, contract: &Digest) -> bool;
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
    // ---- PX (docs/px.md §11) ----
    /// PX statement shape (function count, sizes).
    PxShape,
    /// A PX transaction's fee differs from `PX_STANDARD_FEE` (a fee that
    /// would fingerprint its wallet; privacy review P-7).
    PxFeeNotStandard {
        fee: u64,
    },
    /// A deploy program binary does not load.
    PxInvalidProgram,
    /// PX1: the anchor is not a recent tree root.
    PxUnknownAnchor,
    /// PX2: a nullifier is spent, or used earlier in the block (a repeat
    /// within the transaction is [`TxError::PxNullifierRepeated`]).
    PxNullifierSpent {
        index: usize,
    },
    /// PX3: a called function is not a registered program of its contract.
    PxUnregistered {
        function: usize,
    },
    /// PX4: the pool would go negative.
    PxPoolUnderflow,
    /// PX5: the proof does not verify. Checked only after the anchor (PX1)
    /// and the registrations (PX3) pass; a registered program is fixed by its
    /// content (the contract id hashes the deploy), so the statement is the
    /// same on every branch and a failing proof is the sender's fault: it is
    /// stateless for peer scoring (docs/p2p.md §10).
    PxProof,
    /// A deploy's contract id exists already.
    DuplicateContract,
    /// A PX transaction repeats a one-time key between its hidden outputs
    /// and its payouts (`output` indexes `PxTx::output_keys`). Such a
    /// transaction also fails C4 on every chain; this variant reports it as
    /// the stateless fault it is.
    PxDuplicateOutputKey {
        output: usize,
    },
    /// A PX transaction's two nullifiers are equal. It also fails PX2 on
    /// every chain; this variant reports it as stateless.
    PxNullifierRepeated,
    /// A deploy registers the same program id twice (`program` indexes the
    /// second occurrence; R5-7).
    PxDuplicateProgram {
        program: usize,
    },
    /// A deploy registers a budget no proof can have: above `MAX_CYCLES`, or
    /// a table above its height limit with the kernel's share (R7-5;
    /// `px::budget_is_provable`).
    PxBudgetTooLarge {
        program: usize,
    },
}

impl TxError {
    /// Whether the transaction is invalid regardless of chain state: on every
    /// branch, at every height. Only such failures prove that the sender (or
    /// the peer relaying it) misbehaved (docs/p2p.md §10). A **contextual**
    /// failure depends on the node's view of the chain and could pass on
    /// another branch or later, so an honest peer can relay it.
    ///
    /// The match is exhaustive: a new variant must be classified here.
    ///
    /// | Variant | Rule | Class | Why |
    /// |---|---|---|---|
    /// | `TooLarge` | T1 | stateless | the encoded size is a function of the transaction |
    /// | `CoinbaseNotAllowed` | T2 | stateless | a coinbase is never a mempool transaction |
    /// | `InputCount`, `OutputCount` | T3 | stateless | counts |
    /// | `KeyImageIdentity`, `KeyImagesNotSorted` | T4 | stateless | the transaction's own key images (also catches a key image repeated within it) |
    /// | `RingNotIncreasing` | T5 | stateless | the ring's index list itself |
    /// | `OutputKeyIdentity`, `EphemeralIdentity`, `OutputsNotSorted` | T6 | stateless | the transaction's own outputs (also catches a one-time key repeated within a transfer or deploy) |
    /// | `PseudoOutCount` | T7 | stateless | counts |
    /// | `FeeTooLow`, `WeightOverflow` | T8 | stateless | fee vs. weight or size, fixed by the transaction and the network's constant rules |
    /// | `Unbalanced` | T9 | stateless | commitments and amounts in the transaction |
    /// | `RangeProofShape`, `RangeProofInvalid` | T10 | stateless | the proof and the transaction's own commitments |
    /// | `SignatureCount` | T11 | stateless | counts |
    /// | `UnknownRingMember`, `RingMemberTooYoung` | C1 | contextual | the output may exist, or be old enough, on another branch or later |
    /// | `KeyImageSpent` | C2 | contextual | spent on this branch (or earlier in this block), possibly not on another |
    /// | `InvalidSignature` | C3 | contextual | see below |
    /// | `DuplicateOneTimeKey` | C4 | contextual | the colliding output is on this branch or earlier in this block; repeats within one transaction are caught first by T6 or `PxDuplicateOutputKey` |
    /// | `PxShape`, `PxFeeNotStandard`, `PxInvalidProgram`, `PxBudgetTooLarge` | PX structure | stateless | the transaction alone |
    /// | `PxDuplicateOutputKey`, `PxNullifierRepeated`, `PxDuplicateProgram` | PX structure | stateless | a repeat within the transaction |
    /// | `PxUnknownAnchor` | PX1 | contextual | the root window moves; the anchor may be recent on another branch |
    /// | `PxNullifierSpent` | PX2 | contextual | spent on this branch or earlier in this block |
    /// | `PxUnregistered` | PX3 | contextual | the contract may be deployed on another branch or later |
    /// | `PxPoolUnderflow` | PX4 | contextual | the pool depends on the branch |
    /// | `PxProof` | PX5 | stateless | checked only after PX1 and PX3 pass; registered programs are fixed by the contract id, so the statement is the same on every branch |
    /// | `DuplicateContract` | deploy | contextual | the same deploy may be on this branch and not on another |
    ///
    /// **Why `InvalidSignature` stays contextual.** A ring names its members
    /// by global output index, and C3 verifies the CLSAG over the outputs
    /// those indices resolve to on *this* branch. On another branch (after a
    /// reorganization, or for a peer that has not seen ours) the same index
    /// can name a different output, so a signature that verifies on the
    /// sender's branch fails here although the sender is honest. Penalizing
    /// it would let a reorganization split honest peers. The cost of garbage
    /// signatures is bounded by the P2P layer (rate limits and accounting of
    /// contextual failures), not by this classification. The mempool paths
    /// run every stateless check, including the range proof, before any ring
    /// is resolved (module docs), so a transaction that is invalid for a
    /// stateless reason always gets the stateless error.
    pub fn is_stateless(&self) -> bool {
        match self {
            TxError::TooLarge { .. }
            | TxError::CoinbaseNotAllowed
            | TxError::InputCount(_)
            | TxError::OutputCount(_)
            | TxError::KeyImageIdentity { .. }
            | TxError::KeyImagesNotSorted
            | TxError::RingNotIncreasing { .. }
            | TxError::OutputKeyIdentity { .. }
            | TxError::EphemeralIdentity { .. }
            | TxError::OutputsNotSorted
            | TxError::PseudoOutCount
            | TxError::FeeTooLow { .. }
            | TxError::WeightOverflow
            | TxError::Unbalanced
            | TxError::RangeProofShape
            | TxError::RangeProofInvalid
            | TxError::SignatureCount
            | TxError::PxShape
            | TxError::PxFeeNotStandard { .. }
            | TxError::PxInvalidProgram
            | TxError::PxDuplicateOutputKey { .. }
            | TxError::PxNullifierRepeated
            | TxError::PxDuplicateProgram { .. }
            | TxError::PxBudgetTooLarge { .. }
            | TxError::PxProof => true,
            TxError::UnknownRingMember { .. }
            | TxError::RingMemberTooYoung { .. }
            | TxError::KeyImageSpent { .. }
            | TxError::InvalidSignature { .. }
            | TxError::DuplicateOneTimeKey { .. }
            | TxError::PxUnknownAnchor
            | TxError::PxNullifierSpent { .. }
            | TxError::PxUnregistered { .. }
            | TxError::PxPoolUnderflow
            | TxError::DuplicateContract => false,
        }
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
    resolve_input_rings(&tx.inputs, chain, height)
}

/// C1 for any list of v1 inputs.
pub fn resolve_input_rings(
    inputs: &[Input],
    chain: &impl ChainView,
    height: u64,
) -> Result<Vec<[RingMember; RING_SIZE]>, TxError> {
    inputs
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
    check_ring_signatures(
        &tx.inputs,
        &tx.pseudo_outs,
        &tx.signatures,
        rings,
        &tx.signature_message(rules.domain()),
    )
}

/// C3 for any list of v1 inputs and a signature message.
pub fn check_ring_signatures(
    inputs: &[Input],
    pseudo_outs: &[Point],
    signatures: &[Clsag],
    rings: &[[RingMember; RING_SIZE]],
    message: &Hash,
) -> Result<(), TxError> {
    for (i, ((input, ring), (pseudo, sig))) in inputs
        .iter()
        .zip(rings)
        .zip(pseudo_outs.iter().zip(signatures))
        .enumerate()
    {
        if !clsag::verify(message, ring, pseudo, &input.key_image, sig) {
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
    let keys: Vec<Point> = tx.outputs.iter().map(|o| o.one_time_key).collect();
    check_uniqueness_of(
        &tx.inputs,
        &keys,
        chain,
        block_key_images,
        block_one_time_keys,
    )
}

fn check_uniqueness_of(
    inputs: &[Input],
    output_keys: &[Point],
    chain: &impl ChainView,
    block_key_images: &mut HashSet<[u8; 32]>,
    block_one_time_keys: &mut HashSet<[u8; 32]>,
) -> Result<(), TxError> {
    for (i, input) in inputs.iter().enumerate() {
        if chain.is_key_image_spent(&input.key_image)
            || !block_key_images.insert(*input.key_image.bytes())
        {
            return Err(TxError::KeyImageSpent { input: i });
        }
    }
    for (j, k) in output_keys.iter().enumerate() {
        if chain.has_one_time_key(k) || !block_one_time_keys.insert(*k.bytes()) {
            return Err(TxError::DuplicateOneTimeKey { output: j });
        }
    }
    Ok(())
}

// ---- PX (docs/px.md §11) ----

/// PX1–PX3 against the chain (and, for blocks, the block's earlier
/// nullifiers): recent anchor, unspent and unrepeated nullifiers, registered
/// functions.
fn check_px_state(
    tx: &PxTx,
    chain: &impl ChainView,
    block_nullifiers: &mut HashSet<[u8; 32]>,
) -> Result<(), TxError> {
    if !chain.px_is_recent_root(&tx.anchor) {
        return Err(TxError::PxUnknownAnchor);
    }
    for (i, nf) in tx.nullifiers.iter().enumerate() {
        if chain.px_nullifier_spent(nf) || !block_nullifiers.insert(digest_bytes(nf)) {
            return Err(TxError::PxNullifierSpent { index: i });
        }
    }
    for (k, f) in tx.functions.iter().enumerate() {
        if chain.px_function(&f.contract, &f.program_id).is_none() {
            return Err(TxError::PxUnregistered { function: k });
        }
    }
    Ok(())
}

/// PX5: the proof verifies for the transaction's statement and binding,
/// with every function's registered program and budget.
pub fn check_px_proof(tx: &PxTx, chain: &impl ChainView, rules: &TxRules) -> Result<(), TxError> {
    let proof = blacksilk_zk::decode_proof(&tx.proof).map_err(|_| TxError::PxProof)?;
    let mut calls = Vec::with_capacity(tx.functions.len());
    for (k, f) in tx.functions.iter().enumerate() {
        let (program, _) = chain
            .px_function(&f.contract, &f.program_id)
            .ok_or(TxError::PxUnregistered { function: k })?;
        calls.push(blacksilk_px::prove::FunctionCall {
            program,
            outputs: f.outputs.clone(),
        });
    }
    blacksilk_px::prove::verify(
        &tx.public(),
        &calls,
        tx.binding(rules.domain()),
        &proof,
        |contract, id| chain.px_function(contract, id).map(|(_, b)| b),
    )
    .map_err(|e| {
        // A malformed proof that panics Plonky3's verifier is contained
        // (zkvm.md §10) and rejected like any invalid proof. It may point at a
        // verifier bug, so operators see it.
        if matches!(
            e,
            blacksilk_px::prove::VerifyError::Proof(blacksilk_zk::ZkError::VerifierPanicked)
        ) {
            log::warn!(
                "a PX proof made the verifier panic (contained, rejected); binding {}",
                hex_id(&tx.binding(rules.domain()))
            );
        }
        TxError::PxProof
    })
}

fn hex_id(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// Full validation of one PX transaction for inclusion at `height` (mempool).
/// The proof, the most expensive check, runs last.
pub fn validate_px(
    tx: &PxTx,
    chain: &impl ChainView,
    height: u64,
    rules: &TxRules,
) -> Result<(), TxError> {
    validate_px_without_proof(tx, chain, height, rules)?;
    check_px_proof(tx, chain, rules)
}

/// Every rule of [`validate_px`] except the proof: for revalidating pooled
/// transactions whose proof was verified on admission.
pub fn validate_px_without_proof(
    tx: &PxTx,
    chain: &impl ChainView,
    height: u64,
    rules: &TxRules,
) -> Result<(), TxError> {
    // Stateless (the transaction alone), cheap to expensive.
    check_px_structure(tx)?;
    check_px_balance(tx)?;
    if let Some(p) = &tx.range_proof {
        let c: Vec<Point> = tx.outputs.iter().map(|o| o.commitment).collect();
        if !bpp::verify(p, &c) {
            return Err(TxError::RangeProofInvalid);
        }
    }
    // Contextual.
    let keys: Vec<Point> = tx.output_keys().iter().map(|k| k.one_time_key).collect();
    check_uniqueness_of(
        &tx.inputs,
        &keys,
        chain,
        &mut HashSet::new(),
        &mut HashSet::new(),
    )?;
    check_px_state(tx, chain, &mut HashSet::new())?;
    if chain.px_pool() + (tx.bridge_in as u128) < (tx.bridge_out as u128) {
        return Err(TxError::PxPoolUnderflow);
    }
    let rings = resolve_input_rings(&tx.inputs, chain, height)?;
    check_ring_signatures(
        &tx.inputs,
        &tx.pseudo_outs,
        &tx.signatures,
        &rings,
        &tx.signature_message(rules.domain()),
    )
}

/// Full validation of one deploy for inclusion at `height` (mempool).
pub fn validate_deploy(
    tx: &PxDeploy,
    chain: &impl ChainView,
    height: u64,
    rules: &TxRules,
) -> Result<(), TxError> {
    // Stateless (the transaction alone), cheap to expensive.
    check_deploy_structure(tx, rules)?;
    let t = tx.as_transfer();
    check_balance(&t)?;
    check_range_proof(&t)?;
    // Contextual.
    check_uniqueness(&t, chain, &mut HashSet::new(), &mut HashSet::new())?;
    if chain.px_contract_exists(&tx.contract_id()) {
        return Err(TxError::DuplicateContract);
    }
    let rings = resolve_input_rings(&tx.inputs, chain, height)?;
    check_ring_signatures(
        &tx.inputs,
        &tx.pseudo_outs,
        &tx.signatures,
        &rings,
        &tx.signature_message(rules.domain()),
    )
}

/// Full validation of one transfer for inclusion at `height` (mempool use).
pub fn validate_transfer(
    tx: &Transfer,
    chain: &impl ChainView,
    height: u64,
    rules: &TxRules,
) -> Result<(), TxError> {
    // Stateless (the transaction alone), cheap to expensive.
    check_structure(tx, rules)?;
    check_balance(tx)?;
    check_range_proof(tx)?;
    // Contextual.
    check_uniqueness(tx, chain, &mut HashSet::new(), &mut HashSet::new())?;
    let rings = resolve_rings(tx, chain, height)?;
    check_signatures(tx, &rings, rules)
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
        Transaction::Px(t) => validate_px(t, chain, height, rules),
        Transaction::PxDeploy(t) => validate_deploy(t, chain, height, rules),
    }
}

/// Re-checks a pooled transaction after the chain was **extended** (blocks
/// connected, none disconnected) since it last passed [`validate_mempool_tx`].
///
/// Only the rules whose verdict an extension can change are checked:
/// - C2 key images and C4 one-time keys (a new block may use them);
/// - PX1-PX3: the anchor window moves, nullifiers get spent (the registry
///   only grows);
/// - PX4, the pool, which new blocks change;
/// - a deploy's contract id (the same contract may have been deployed).
///
/// Every other rule is unchanged by an extension:
/// - structure, balance, range proof and PX proof are functions of the
///   transaction alone;
/// - ring members resolve to the same outputs, because outputs are only
///   appended, so C1 existence and C3 signatures are unchanged;
/// - C1 maturity only improves as the height grows.
///
/// After a reorganization, [`validate_mempool_tx`] must be used again. Policy
/// only: blocks are always validated in full (`validate_block_transactions`).
pub fn revalidate_after_extension(tx: &Transaction, chain: &impl ChainView) -> Result<(), TxError> {
    match tx {
        Transaction::Coinbase(_) => Err(TxError::CoinbaseNotAllowed),
        Transaction::Transfer(t) => {
            check_uniqueness(t, chain, &mut HashSet::new(), &mut HashSet::new())
        }
        Transaction::Px(t) => {
            let keys: Vec<Point> = t.output_keys().iter().map(|k| k.one_time_key).collect();
            check_uniqueness_of(
                &t.inputs,
                &keys,
                chain,
                &mut HashSet::new(),
                &mut HashSet::new(),
            )?;
            check_px_state(t, chain, &mut HashSet::new())?;
            if chain.px_pool() + (t.bridge_in as u128) < (t.bridge_out as u128) {
                return Err(TxError::PxPoolUnderflow);
            }
            Ok(())
        }
        Transaction::PxDeploy(t) => {
            check_uniqueness(
                &t.as_transfer(),
                chain,
                &mut HashSet::new(),
                &mut HashSet::new(),
            )?;
            if chain.px_contract_exists(&t.contract_id()) {
                return Err(TxError::DuplicateContract);
            }
            Ok(())
        }
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
    /// The PX and deploy transactions exceed the block's PX byte budget.
    PxBytesExceeded {
        bytes: u64,
        max: u64,
    },
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
    validate_block_transactions_cached(txs, ctx, chain, rules, rng, &|_| false)
}

/// [`validate_block_transactions`], skipping PX5 for the PX transactions
/// `proof_verified` vouches for: those whose proof this node has already
/// verified, under the same rules (in practice, its mempool, which admits
/// nothing unverified).
///
/// **Why this is sound.** The transaction id commits to the proof bytes (the
/// prunable hash), and the statement is a function of the transaction, the
/// network and the registry entries of its contracts. Registry entries are
/// immutable and fixed by the contract id, which hashes the deploy payload
/// (docs/px.md §11.2); PX3 still checks, here, that they exist. So a proof
/// that verified once verifies for the same id in any block. Every other
/// rule is checked in full.
pub fn validate_block_transactions_cached<R: RngCore + CryptoRng>(
    txs: &[Transaction],
    ctx: &BlockContext,
    chain: &impl ChainView,
    rules: &TxRules,
    rng: &mut R,
    proof_verified: &dyn Fn(&crate::types::Hash) -> bool,
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

    // Structure (cheap), per kind.
    let mut transfers = Vec::with_capacity(txs.len() - 1);
    let mut pxs = Vec::new();
    let mut deploys = Vec::new();
    for (index, tx) in txs.iter().enumerate().skip(1) {
        let err = |error| BlockError::Tx { index, error };
        match tx {
            Transaction::Coinbase(_) => return Err(BlockError::UnexpectedCoinbase { index }),
            Transaction::Transfer(t) => {
                check_structure(t, rules).map_err(err)?;
                transfers.push((index, t.as_ref()));
            }
            Transaction::Px(t) => {
                check_px_structure(t).map_err(err)?;
                pxs.push((index, t.as_ref()));
            }
            Transaction::PxDeploy(t) => {
                check_deploy_structure(t, rules).map_err(err)?;
                deploys.push((index, t.as_ref()));
            }
        }
    }

    // B5
    let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
    if blacksilk_consensus::merkle::tx_root(&ids) != ctx.tx_root {
        return Err(BlockError::TxRootMismatch);
    }
    // B6: v1 weight, and the separate PX byte budget.
    let weight: u128 = txs.iter().map(|t| t.weight() as u128).sum();
    if weight > rules.max_block_weight as u128 {
        return Err(BlockError::WeightExceeded {
            weight,
            max: rules.max_block_weight,
        });
    }
    let px_bytes: u64 = txs.iter().map(Transaction::px_bytes).sum();
    if px_bytes > MAX_PX_BLOCK_BYTES {
        return Err(BlockError::PxBytesExceeded {
            bytes: px_bytes,
            max: MAX_PX_BLOCK_BYTES,
        });
    }
    // B3
    let fees: u128 = txs.iter().skip(1).map(|t| t.fee() as u128).sum();
    let allowed = ctx.reward as u128 + fees;
    if coinbase.total() != allowed {
        return Err(BlockError::CoinbaseAmount {
            claimed: coinbase.total(),
            allowed,
        });
    }

    // T9 (and its PX and deploy forms).
    for (index, t) in &transfers {
        check_balance(t).map_err(|error| BlockError::Tx {
            index: *index,
            error,
        })?;
    }
    for (index, t) in &pxs {
        check_px_balance(t).map_err(|error| BlockError::Tx {
            index: *index,
            error,
        })?;
    }
    for (index, t) in &deploys {
        check_balance(&t.as_transfer()).map_err(|error| BlockError::Tx {
            index: *index,
            error,
        })?;
    }

    // C2/C4 with B4 via block-wide sets; PX1–PX4 with block-wide nullifiers
    // and the pool evolving in block order; unique contract ids.
    let mut key_images = HashSet::new();
    let mut one_time_keys = HashSet::new();
    for (j, o) in coinbase.outputs.iter().enumerate() {
        if chain.has_one_time_key(&o.one_time_key) || !one_time_keys.insert(*o.one_time_key.bytes())
        {
            return Err(BlockError::CoinbaseDuplicateOneTimeKey { output: j });
        }
    }
    let mut nullifiers = HashSet::new();
    let mut contracts = HashSet::new();
    let mut pool = chain.px_pool();
    for (index, tx) in txs.iter().enumerate().skip(1) {
        let err = |error| BlockError::Tx { index, error };
        let keys: Vec<Point> = tx.output_keys().iter().map(|k| k.one_time_key).collect();
        let inputs: &[Input] = match tx {
            Transaction::Transfer(t) => &t.inputs,
            Transaction::Px(t) => &t.inputs,
            Transaction::PxDeploy(t) => &t.inputs,
            Transaction::Coinbase(_) => unreachable!("checked above"),
        };
        check_uniqueness_of(inputs, &keys, chain, &mut key_images, &mut one_time_keys)
            .map_err(err)?;
        match tx {
            Transaction::Px(t) => {
                check_px_state(t, chain, &mut nullifiers).map_err(err)?;
                pool = (pool + t.bridge_in as u128)
                    .checked_sub(t.bridge_out as u128)
                    .ok_or(BlockError::Tx {
                        index,
                        error: TxError::PxPoolUnderflow,
                    })?;
            }
            Transaction::PxDeploy(t) => {
                let id = t.contract_id();
                if chain.px_contract_exists(&id) || !contracts.insert(digest_bytes(&id)) {
                    return Err(err(TxError::DuplicateContract));
                }
            }
            _ => {}
        }
    }

    // C1, C3 (expensive).
    for (index, tx) in txs.iter().enumerate().skip(1) {
        let err = |error| BlockError::Tx { index, error };
        let (inputs, pseudo, sigs, message): (&[Input], &[Point], &[Clsag], Hash) = match tx {
            Transaction::Transfer(t) => (
                &t.inputs,
                &t.pseudo_outs,
                &t.signatures,
                t.signature_message(rules.domain()),
            ),
            Transaction::Px(t) => (
                &t.inputs,
                &t.pseudo_outs,
                &t.signatures,
                t.signature_message(rules.domain()),
            ),
            Transaction::PxDeploy(t) => (
                &t.inputs,
                &t.pseudo_outs,
                &t.signatures,
                t.signature_message(rules.domain()),
            ),
            Transaction::Coinbase(_) => unreachable!("checked above"),
        };
        let rings = resolve_input_rings(inputs, chain, ctx.height).map_err(err)?;
        check_ring_signatures(inputs, pseudo, sigs, &rings, &message).map_err(err)?;
    }

    // T10, batched over every transaction with hidden outputs.
    let mut proofs: Vec<(&BppProof, Vec<Point>)> = Vec::new();
    for (_, t) in &transfers {
        proofs.push((&t.range_proof, output_commitments(t)));
    }
    for (_, t) in &pxs {
        if let Some(p) = &t.range_proof {
            proofs.push((p, t.outputs.iter().map(|o| o.commitment).collect()));
        }
    }
    for (_, t) in &deploys {
        proofs.push((
            &t.range_proof,
            t.outputs.iter().map(|o| o.commitment).collect(),
        ));
    }
    let items: Vec<(&BppProof, &[Point])> =
        proofs.iter().map(|(p, c)| (*p, c.as_slice())).collect();
    if !bpp::batch_verify(&items, rng) {
        return Err(BlockError::RangeProofBatch);
    }

    // PX5: the proofs, last (the most expensive check).
    for (index, t) in &pxs {
        if proof_verified(&txs[*index].hash()) {
            continue;
        }
        check_px_proof(t, chain, rules).map_err(|error| BlockError::Tx {
            index: *index,
            error,
        })?;
    }
    Ok(())
}
