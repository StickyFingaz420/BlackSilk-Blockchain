//! Transaction and block-body validation (spec §8).
//!
//! Rules are evaluated cheap-first. Each rule has its own error variant, so tests
//! can assert that an invalid transaction fails for the intended reason.
//!
//! **Mempool order.** The single-transaction entry points
//! ([`validate_transfer`], [`validate_deploy`], [`validate_px`]) run every
//! stateless rule (structure, balance, range proof) before any contextual
//! one (C1–C3, PX1–PX4), with one exception: PX6 (a height comparison) runs
//! right before a PX transaction's range proof (RTW1C-5), so a transaction
//! outside its validity window costs no Bulletproofs+ verification. A
//! transaction invalid for a stateless reason is therefore reported with a
//! stateless error ([`TxError::is_stateless`]), whatever else is wrong with
//! it, unless it is also outside its window (then `PxWindow`, and the
//! stateless error at a height inside it); it costs no ring resolution or
//! CLSAG verification. The order changes only *which* error an invalid
//! transaction gets, never *whether* it is valid: every rule is a pure check
//! and a transaction is valid iff all pass. The PX proof (PX5) is decoded
//! with the stateless rules and shape-checked once PX3's registered programs
//! are known, both before any ring is resolved; it is verified last, the
//! most expensive check. Block validation keeps its own order, with the
//! range proofs batched, and the same proof steps (dossier 10 F10-2, red
//! team RTW1-2).
//!
//! | Function | Rules |
//! |---|---|
//! | [`check_structure`] | T1, T3–T8, T10 (shape), T11 |
//! | [`check_balance`] | T9 |
//! | [`check_range_proof`] | T10 |
//! | [`resolve_rings`] | C1 |
//! | [`check_signatures`] | C3 |
//! | [`validate_transfer`] | all of T and C (mempool) |
//! | [`validate_block_transactions`] | B1–B8, plus all T and C with block-wide batching |

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

/// A registered function program, as consensus reads it from the contract
/// registry: the program, its row budget, its call ABI (the first word of
/// its function prefix) and the exact number of public output words each
/// call publishes (docs/px.md §11.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PxProgram {
    pub program: Arc<Program>,
    pub budget: Budget,
    pub abi: u32,
    pub out_words: u32,
}

/// Read access to the chain state at the parent of the block being validated.
pub trait ChainView {
    fn output(&self, global_index: u64) -> Option<OutputRecord>;
    fn is_key_image_spent(&self, key_image: &Point) -> bool;
    // ---- PX (docs/px.md §11) ----
    /// Whether `anchor` is one of the recent PX tree roots (root window).
    fn px_is_recent_root(&self, anchor: &Digest) -> bool;
    fn px_nullifier_spent(&self, nf: &Digest) -> bool;
    /// The BLK value inside PX.
    fn px_pool(&self) -> u128;
    /// The registered function program `program_id` of `contract`, with its
    /// budget, call ABI and output-word count.
    fn px_function(&self, contract: &Digest, program_id: &[u8; 32]) -> Option<PxProgram>;
    fn px_contract_exists(&self, contract: &Digest) -> bool;
    /// Leaves in the PX commitment tree (at most `px::tree::CAPACITY`).
    fn px_tree_size(&self) -> u64;
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
    /// T8: the fee differs from the standard fee of the transaction's shape,
    /// `TxRules::standard_fee(n_in, n_out)`, which every transfer pays
    /// exactly (docs/reviews/v3-consensus-changes.md#exact-v1-fee).
    FeeNotExact {
        fee: u64,
        required: u64,
    },
    /// T8: the standard fee overflows (unreachable with the v3 constants).
    WeightOverflow,
    /// T9.
    Unbalanced,
    /// T10.
    RangeProofShape,
    RangeProofInvalid,
    /// T11.
    SignatureCount,
    /// T11: a CLSAG's auxiliary image `D` is the identity (`z = 0`, which
    /// also makes `C' = Cr[π]` reveal the real input; dossier 15 W1).
    AuxKeyImageIdentity {
        input: usize,
    },
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
    /// PX6: the transaction's validity window does not contain the height of
    /// the block that would include it (premature or expired). Contextual:
    /// the same transaction is valid at another height, and heights race at
    /// the window's edges, so it is never scored (docs/px.md §11.2).
    PxWindow,
    /// PX6, stateless part: `not_after ≠ 0` and `not_before > not_after`,
    /// a window no height is in.
    PxWindowInverted,
    /// A deploy registers a program for a call ABI other than
    /// `blacksilk_px_core::call::ABI_VERSION` (`program` indexes it; F-28-1).
    PxUnsupportedAbi {
        program: usize,
    },
    /// A called function publishes a number of output words other than its
    /// program's registered `out_words` (F-28-5; `function` indexes the call).
    /// Checked with PX3. Stateless for scoring for the same reason as
    /// `PxProof`: a registration is fixed by its contract id.
    PxOutputWords {
        function: usize,
    },
    /// PX5: the proof does not decode, does not have its statement's shape,
    /// or does not verify. Decoding needs nothing but the proof bytes and runs
    /// with the stateless rules; the shape and the verification run only
    /// after the anchor (PX1) and the registrations (PX3) pass. A registered
    /// program is fixed by its content (the contract id hashes the deploy),
    /// so the statement is the same on every branch and a failing proof is
    /// the sender's fault: it is stateless for peer scoring (docs/p2p.md
    /// §10), except near an activation ([`TxError::is_stateless_at`]).
    PxProof,
    /// A deploy's contract id exists already.
    DuplicateContract,
    /// The PX commitment tree cannot take the transaction's output
    /// commitments (B8 for a mempool transaction). Contextual: the tree may
    /// have room on another branch.
    PxTreeFull,
    /// A PX transaction repeats a one-time key between its hidden outputs
    /// and its payouts (`output` indexes `PxTx::output_keys`). The only rule
    /// that rejects such a repeat: one-time keys are distinct within every
    /// transaction, but not across transactions (D8 option B,
    /// docs/transactions.md §8.1 T6).
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
    /// A deploy's fee differs from `px::deploy_fee` for its shape and
    /// payload (R5-1, R6 TX-4).
    DeployFeeNotExact {
        fee: u64,
        required: u64,
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
    /// | `OutputKeyIdentity`, `EphemeralIdentity`, `OutputsNotSorted` | T6 | stateless | the transaction's own outputs (also catches a one-time key repeated within a transfer, deploy, or a PX transaction's hidden outputs or payouts) |
    /// | `PseudoOutCount` | T7 | stateless | counts |
    /// | `FeeNotExact`, `WeightOverflow` | T8 | stateless | the fee vs. the standard fee of the shape, fixed by the transaction and the network's constant rules |
    /// | `Unbalanced` | T9 | stateless | commitments and amounts in the transaction |
    /// | `RangeProofShape`, `RangeProofInvalid` | T10 | stateless | the proof and the transaction's own commitments |
    /// | `SignatureCount` | T11 | stateless | counts |
    /// | `AuxKeyImageIdentity` | T11 | stateless | the signature itself (`D = identity`) |
    /// | `UnknownRingMember`, `RingMemberTooYoung` | C1 | contextual | the output may exist, or be old enough, on another branch or later |
    /// | `KeyImageSpent` | C2 | contextual | spent on this branch (or earlier in this block), possibly not on another |
    /// | `InvalidSignature` | C3 | contextual | see below |
    /// | `PxShape`, `PxFeeNotStandard`, `PxInvalidProgram`, `PxBudgetTooLarge`, `DeployFeeNotExact`, `PxUnsupportedAbi`, `PxWindowInverted` | PX structure | stateless | the transaction alone |
    /// | `PxDuplicateOutputKey`, `PxNullifierRepeated`, `PxDuplicateProgram` | PX structure | stateless | a repeat within the transaction (a one-time key shared by a hidden output and a payout) |
    /// | `PxUnknownAnchor` | PX1 | contextual | the root window moves; the anchor may be recent on another branch |
    /// | `PxNullifierSpent` | PX2 | contextual | spent on this branch or earlier in this block |
    /// | `PxUnregistered` | PX3 | contextual | the contract may be deployed on another branch or later |
    /// | `PxPoolUnderflow` | PX4 | contextual | the pool depends on the branch |
    /// | `PxWindow` | PX6 | contextual | the height: the transaction is valid at another height (premature now, or expired only on this branch's height), and relays race at the window's edges; never scored |
    /// | `PxOutputWords` | PX3 | stateless | checked once the registration is found; a registration is fixed by its contract id, so the count is the same on every branch that has it |
    /// | `PxTreeFull` | B8 | contextual | the tree size depends on the branch |
    /// | `PxProof` | PX5 | stateless | decoding needs only the proof bytes; the shape and the verification are checked only after PX1 and PX3 pass, and registered programs are fixed by the contract id, so the statement is the same on every branch |
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
    /// stateless reason gets the stateless error (a PX transaction outside
    /// its window gets `PxWindow` first: PX6 precedes its range proof).
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
            | TxError::FeeNotExact { .. }
            | TxError::WeightOverflow
            | TxError::Unbalanced
            | TxError::RangeProofShape
            | TxError::RangeProofInvalid
            | TxError::SignatureCount
            | TxError::AuxKeyImageIdentity { .. }
            | TxError::PxShape
            | TxError::PxFeeNotStandard { .. }
            | TxError::PxInvalidProgram
            | TxError::PxDuplicateOutputKey { .. }
            | TxError::PxNullifierRepeated
            | TxError::PxDuplicateProgram { .. }
            | TxError::PxBudgetTooLarge { .. }
            | TxError::DeployFeeNotExact { .. }
            | TxError::PxUnsupportedAbi { .. }
            | TxError::PxWindowInverted
            | TxError::PxOutputWords { .. }
            | TxError::PxProof => true,
            TxError::UnknownRingMember { .. }
            | TxError::RingMemberTooYoung { .. }
            | TxError::KeyImageSpent { .. }
            | TxError::InvalidSignature { .. }
            | TxError::PxUnknownAnchor
            | TxError::PxNullifierSpent { .. }
            | TxError::PxUnregistered { .. }
            | TxError::PxPoolUnderflow
            | TxError::PxWindow
            | TxError::PxTreeFull
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

/// T11: no CLSAG's auxiliary image `D` is the identity (dossier 15 W1). A
/// stateless rule, decided from the signature alone before any ring is
/// resolved; `clsag::verify` rejects such a signature too.
pub fn check_aux_images(signatures: &[Clsag]) -> Result<(), TxError> {
    match signatures.iter().position(|s| s.d.is_identity()) {
        Some(input) => Err(TxError::AuxKeyImageIdentity { input }),
        None => Ok(()),
    }
}

/// Cheap structural rules: T1, T3–T8, T10 (shape) and T11.
pub fn check_structure(tx: &Transfer, rules: &TxRules) -> Result<(), TxError> {
    check_shape(tx)?;
    check_fee(tx, rules)
}

/// T8: the fee is exactly the standard fee of the transaction's shape,
/// `rules.standard_fee(n_in, n_out) = FEE_PER_WEIGHT × max_weight(n_in, n_out)`
/// (docs/transactions.md §8.4). The fee is then a function of the public
/// shape alone, as PX and deploy fees are, so it identifies no wallet
/// (docs/reviews/v3-consensus-changes.md#exact-v1-fee). `max_weight` bounds
/// the actual weight, so the fee also covers `min_fee(weight)`.
pub fn check_fee(tx: &Transfer, rules: &TxRules) -> Result<(), TxError> {
    let required = rules
        .standard_fee(tx.inputs.len(), tx.outputs.len())
        .ok_or(TxError::WeightOverflow)?;
    if tx.fee != required {
        return Err(TxError::FeeNotExact {
            fee: tx.fee,
            required,
        });
    }
    Ok(())
}

/// [`check_structure`] without the fee rule (T8): T1, T3–T7, T10 (shape) and
/// T11. For the v1 part of a deploy, whose fee has its own exact rule
/// (`px::check_deploy_structure`).
pub fn check_shape(tx: &Transfer) -> Result<(), TxError> {
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
    check_aux_images(&tx.signatures)?;
    let rounds = bpp::rounds(k).ok_or(TxError::RangeProofShape)?;
    if tx.range_proof.l.len() != rounds || tx.range_proof.r.len() != rounds {
        return Err(TxError::RangeProofShape);
    }
    // T1
    let size = tx.encoded_len();
    if size > MAX_TX_SIZE {
        return Err(TxError::TooLarge { size });
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

/// C2 against the chain (and, for blocks, the key images earlier transactions
/// of the same block already spent).
///
/// There is no chain-wide or block-wide rule on output one-time keys (D8
/// option B, docs/reviews/v3-consensus-changes.md §1): a key is public once
/// its transaction is relayed, so such a rule let anyone invalidate a pending
/// transaction by getting a copy of one of its keys mined first. One-time
/// keys are distinct within each transaction (stateless: T6 and B7 through
/// the strict sort, `PxDuplicateOutputKey`); wallets credit at most one
/// output per key image (docs/transactions.md §12.5).
fn check_key_images(
    inputs: &[Input],
    chain: &impl ChainView,
    block_key_images: &mut HashSet<[u8; 32]>,
) -> Result<(), TxError> {
    for (i, input) in inputs.iter().enumerate() {
        if chain.is_key_image_spent(&input.key_image)
            || !block_key_images.insert(*input.key_image.bytes())
        {
            return Err(TxError::KeyImageSpent { input: i });
        }
    }
    Ok(())
}

// ---- PX (docs/px.md §11) ----

/// PX1–PX3 against the chain (and, for blocks, the block's earlier
/// nullifiers): recent anchor, unspent and unrepeated nullifiers, registered
/// functions, each publishing exactly its registered number of output words.
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
        let Some(registered) = chain.px_function(&f.contract, &f.program_id) else {
            return Err(TxError::PxUnregistered { function: k });
        };
        if f.outputs.len() != registered.out_words as usize {
            return Err(TxError::PxOutputWords { function: k });
        }
    }
    Ok(())
}

/// PX6: a block at `height` may include the transaction only inside its
/// validity window (`blacksilk_px_core::call::Window::contains`; `(0, 0)` is
/// unbounded). Contextual and never scored. It is checked for every PX
/// transaction of a block, whether or not its proof was verified before:
/// a verified proof says nothing about the height (AT-5).
pub fn check_px_window(tx: &PxTx, height: u64) -> Result<(), TxError> {
    if tx.window.contains(height) {
        Ok(())
    } else {
        Err(TxError::PxWindow)
    }
}

/// Blocks of margin the expiring-soon policy asks of a PX transaction's
/// `not_after` ([`px_expires_soon`]); Zcash's `TX_EXPIRING_SOON_THRESHOLD`.
pub const PX_EXPIRING_SOON_BLOCKS: u64 = 3;

/// Expiring-soon policy (not consensus, RTW1C-4): a PX transaction whose
/// window ends fewer than [`PX_EXPIRING_SOON_BLOCKS`] blocks after `next`
/// (the next block's height), `not_after ≠ 0 ∧ not_after < next + 3`, is not
/// admitted to a pool or relayed. It is still valid in a block while its
/// window contains the height, but it would likely expire while it
/// propagates: relaying it spends every node's verification for a
/// transaction that is soon unminable, and a pooled one that expires is
/// dropped anyway. Pooled transactions are not re-checked against it (they
/// stay until their window ends), and a transaction a reorganization returns
/// to the pool is readmitted without it. Wallets build windows that end at
/// least this far ahead.
pub fn px_expires_soon(tx: &PxTx, next: u64) -> bool {
    let not_after = tx.window.not_after;
    not_after != 0 && not_after < next.saturating_add(PX_EXPIRING_SOON_BLOCKS)
}

/// Leaves the PX commitment tree has left: `CAPACITY − size`.
fn px_free_leaves(chain: &impl ChainView) -> u64 {
    blacksilk_px::tree::CAPACITY.saturating_sub(chain.px_tree_size())
}

/// B8 for one transaction (mempool): its output commitments, one leaf each,
/// fit in the PX commitment tree.
fn check_px_capacity(tx: &PxTx, chain: &impl ChainView) -> Result<(), TxError> {
    if tx.commitments.len() as u64 > px_free_leaves(chain) {
        return Err(TxError::PxTreeFull);
    }
    Ok(())
}

/// PX5: the proof verifies for the transaction's statement and binding,
/// with every function's registered program and budget.
pub fn check_px_proof(tx: &PxTx, chain: &impl ChainView, rules: &TxRules) -> Result<(), TxError> {
    let proof = decode_px_proof(tx)?;
    check_px_proof_decoded(tx, chain, rules, &proof)
}

/// PX5, first step: the proof bytes decode strictly (`blacksilk_zk::decode_proof`:
/// size, version, canonical encoding), every vector bounded before it is
/// allocated by caps no valid PX proof exceeds (`blacksilk_px::prove::PROOF_LIMITS`,
/// RT-FUZZ-1). Stateless; its heap and time are proportional to the proof's
/// bytes: about 4 times the size of the 2.4 MB transfer proof, and at most
/// about 6 times the bytes, about 16 MB at `MAX_PROOF_BYTES`, for any proof
/// within the caps (the constructions and measurements are in
/// docs/reviews/v3-consensus-changes.md, "px-proof-decode-bounds"); tens of
/// milliseconds, far below the verification it gates.
pub fn decode_px_proof(tx: &PxTx) -> Result<PxProof, TxError> {
    blacksilk_zk::decode_proof_with(&tx.proof, &blacksilk_px::prove::PROOF_LIMITS)
        .map_err(|_| TxError::PxProof)
}

/// A decoded PX proof ([`decode_px_proof`]), named for callers that hold one
/// without depending on the proof crate (P2P admission decodes off the chain
/// actor and hands the proof to its command).
pub type PxProof = blacksilk_zk::Proof;

/// The registered function calls of `tx` (PX3 must hold).
fn px_calls(
    tx: &PxTx,
    chain: &impl ChainView,
) -> Result<Vec<blacksilk_px::prove::FunctionCall>, TxError> {
    let mut calls = Vec::with_capacity(tx.functions.len());
    for (k, f) in tx.functions.iter().enumerate() {
        let registered = chain
            .px_function(&f.contract, &f.program_id)
            .ok_or(TxError::PxUnregistered { function: k })?;
        calls.push(blacksilk_px::prove::FunctionCall {
            program: registered.program,
            abi: registered.abi,
            outputs: f.outputs.clone(),
        });
    }
    Ok(calls)
}

/// PX5, second step: a decoded proof has exactly the table shape of the
/// transaction's statement with the registered budgets (no cryptography;
/// `blacksilk_px::prove::check_shape`). Needs PX3 to hold. A proof failing
/// it fails [`check_px_proof_decoded`] too.
pub fn check_px_proof_shape(
    tx: &PxTx,
    chain: &impl ChainView,
    rules: &TxRules,
    proof: &blacksilk_zk::Proof,
) -> Result<(), TxError> {
    check_px_proof_shape_bits(tx, chain, rules, &proof.degree_bits)
}

/// [`check_px_proof_shape`] on the decoded proof's degree bits alone (the
/// only part of the proof the shape check reads), so a caller can free the
/// proof first (P2P admission, RT-PXDOS F1). Same verdicts.
pub fn check_px_proof_shape_bits(
    tx: &PxTx,
    chain: &impl ChainView,
    rules: &TxRules,
    degree_bits: &[usize],
) -> Result<(), TxError> {
    let calls = px_calls(tx, chain)?;
    blacksilk_px::prove::check_shape_bits(
        &tx.public(),
        &calls,
        &tx.window,
        tx.binding(rules.domain()),
        degree_bits,
        |contract, id| chain.px_function(contract, id).map(|r| r.budget),
    )
    .map_err(|_| TxError::PxProof)
}

/// PX5 on an already decoded proof ([`decode_px_proof`]).
pub fn check_px_proof_decoded(
    tx: &PxTx,
    chain: &impl ChainView,
    rules: &TxRules,
    proof: &blacksilk_zk::Proof,
) -> Result<(), TxError> {
    let calls = px_calls(tx, chain)?;
    blacksilk_px::prove::verify(
        &tx.public(),
        &calls,
        &tx.window,
        tx.binding(rules.domain()),
        proof,
        |contract, id| chain.px_function(contract, id).map(|r| r.budget),
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

/// Full validation of one PX transaction for inclusion at `height` (mempool,
/// P2P admission, RPC submission, re-admission after a reorganization), in
/// the block path's order (dossier 10 F10-2, red team RTW1-2): the proof is
/// decoded with the stateless rules, before any ring is resolved, and
/// shape-checked once PX3 holds, before any CLSAG; the proof verification,
/// the most expensive check, runs last. A malformed proof (one that fails
/// decoding or shape) therefore gets the stateless `PxProof` at no ring,
/// range proof or CLSAG cost, whatever else is wrong with the transaction's
/// context. A well-formed proof that does not verify still costs every
/// check up to PX5.
pub fn validate_px(
    tx: &PxTx,
    chain: &impl ChainView,
    height: u64,
    rules: &TxRules,
) -> Result<(), TxError> {
    validate_px_checks(tx, chain, height, rules, true)
}

/// Every rule of [`validate_px`] except PX5 (the proof is neither decoded
/// nor checked): for revalidating pooled transactions whose proof was
/// verified on admission.
pub fn validate_px_without_proof(
    tx: &PxTx,
    chain: &impl ChainView,
    height: u64,
    rules: &TxRules,
) -> Result<(), TxError> {
    validate_px_checks(tx, chain, height, rules, false)
}

/// [`validate_px`] (`with_proof`) or [`validate_px_without_proof`].
fn validate_px_checks(
    tx: &PxTx,
    chain: &impl ChainView,
    height: u64,
    rules: &TxRules,
    with_proof: bool,
) -> Result<(), TxError> {
    // Stateless (the transaction alone), cheap to expensive; the proof is
    // decoded (bounded, about 11 to 13 ms for a transfer proof;
    // `decode_px_proof`) before the range proof, as in blocks.
    check_px_structure(tx)?;
    check_px_balance(tx)?;
    let proof = if with_proof {
        Some(decode_px_proof(tx)?)
    } else {
        None
    };
    // PX6, a comparison, before the range proof (RTW1C-5): a transaction
    // outside its window costs no Bulletproofs+ verification. The verdict is
    // unchanged; only a transaction that is also invalid for the range proof
    // is now refused as `PxWindow` (contextual) here, as relay admission
    // already does (its cheap phase checks PX6 and not the range proof). At a
    // height inside its window it gets the stateless error.
    check_px_window(tx, height)?;
    if let Some(p) = &tx.range_proof {
        let c: Vec<Point> = tx.outputs.iter().map(|o| o.commitment).collect();
        if !bpp::verify(p, &c) {
            return Err(TxError::RangeProofInvalid);
        }
    }
    // Contextual.
    check_key_images(&tx.inputs, chain, &mut HashSet::new())?;
    check_px_state(tx, chain, &mut HashSet::new())?;
    if chain.px_pool() + (tx.bridge_in as u128) < (tx.bridge_out as u128) {
        return Err(TxError::PxPoolUnderflow);
    }
    check_px_capacity(tx, chain)?;
    // PX5, second step: PX3 holds, so the statement's shape is known.
    if let Some(proof) = &proof {
        check_px_proof_shape(tx, chain, rules, proof)?;
    }
    let rings = resolve_input_rings(&tx.inputs, chain, height)?;
    check_ring_signatures(
        &tx.inputs,
        &tx.pseudo_outs,
        &tx.signatures,
        &rings,
        &tx.signature_message(rules.domain()),
    )?;
    // PX5, last.
    match &proof {
        Some(proof) => check_px_proof_decoded(tx, chain, rules, proof),
        None => Ok(()),
    }
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
    check_key_images(&tx.inputs, chain, &mut HashSet::new())?;
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
    check_key_images(&tx.inputs, chain, &mut HashSet::new())?;
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
/// connected, none disconnected) since it last passed [`validate_mempool_tx`],
/// for inclusion at `height` (the next block's).
///
/// Only the rules whose verdict an extension can change are checked:
/// - C2 key images (a new block may spend them);
/// - PX6, the validity window: a growing height expires a transaction past
///   its `not_after` (the height is the reason this function takes it);
/// - PX1-PX3: the anchor window moves, nullifiers get spent (the registry
///   only grows);
/// - PX4, the pool, which new blocks change;
/// - B8, the tree capacity, which new blocks use up;
/// - a deploy's contract id (the same contract may have been deployed).
///
/// Every other rule is unchanged by an extension:
/// - structure, balance, range proof and PX proof are functions of the
///   transaction alone;
/// - ring members resolve to the same outputs, because outputs are only
///   appended, so C1 existence and C3 signatures are unchanged;
/// - C1 maturity only improves as the height grows;
/// - output one-time keys: no rule relates them to the chain (D8 option B),
///   so a block creating the same key as a pooled transaction changes
///   nothing.
///
/// After a reorganization, [`validate_mempool_tx`] must be used again. So
/// must it across an activation: signatures (C3) and the PX proof commit to
/// the epoch's branch id, so an extension crossing an activation changes
/// their verdict ([`revalidate_between`] handles both cases). Policy only:
/// blocks are always validated in full (`validate_block_transactions`).
pub fn revalidate_after_extension(
    tx: &Transaction,
    chain: &impl ChainView,
    height: u64,
) -> Result<(), TxError> {
    match tx {
        Transaction::Coinbase(_) => Err(TxError::CoinbaseNotAllowed),
        Transaction::Transfer(t) => check_key_images(&t.inputs, chain, &mut HashSet::new()),
        Transaction::Px(t) => {
            check_px_window(t, height)?;
            check_key_images(&t.inputs, chain, &mut HashSet::new())?;
            check_px_state(t, chain, &mut HashSet::new())?;
            if chain.px_pool() + (t.bridge_in as u128) < (t.bridge_out as u128) {
                return Err(TxError::PxPoolUnderflow);
            }
            check_px_capacity(t, chain)
        }
        Transaction::PxDeploy(t) => {
            check_key_images(&t.inputs, chain, &mut HashSet::new())?;
            if chain.px_contract_exists(&t.contract_id()) {
                return Err(TxError::DuplicateContract);
            }
            Ok(())
        }
    }
}

/// [`revalidate_after_extension`] that is also correct across an activation:
/// the transaction last passed validation for a height whose rules were
/// `from`, and is re-checked for inclusion at `height` under `rules`. When the
/// signature domains differ (an activation lies between the two heights, in
/// either direction), every signature message and the PX binding changed, so
/// the transaction is validated in full, PX proof included; otherwise only
/// the rules an extension can change are checked. Policy only, like
/// `revalidate_after_extension` (the node's pool flushes at an activation
/// instead, `blacksilk_chain::mempool::Mempool::enter_rules`).
pub fn revalidate_between(
    tx: &Transaction,
    chain: &impl ChainView,
    height: u64,
    from: &TxRules,
    rules: &TxRules,
) -> Result<(), TxError> {
    if from.domain() != rules.domain() {
        validate_mempool_tx(tx, chain, height, rules)
    } else {
        revalidate_after_extension(tx, chain, height)
    }
}

/// Blocks on either side of an activation height within which a failing PX
/// proof or ring signature is not taken as proof of misbehaviour (P2P scoring
/// only; consensus is unchanged).
///
/// **N = 60** (about two hours at 120-second blocks):
/// - before an activation, a peer already past it on its branch (or ahead of
///   us by a few blocks) relays transactions bound to the new branch id, which
///   fail here honestly;
/// - after it, transactions proven or signed shortly before (a PX proof takes
///   about 45 s) are still relayed by peers that have not yet seen the
///   activation block, or that are on a branch below it;
/// - 60 blocks is the depth `SIGNATURE_BURIAL` (p2p) already treats as final,
///   and far beyond the 10-block depth that only warns (`DEEP_REORG_WARN_DEPTH`).
///
/// The cost: for 2N blocks around each activation, garbage proofs and
/// signatures cost the sender only the per-peer rate limits, as any
/// contextual failure does.
pub const ACTIVATION_GRACE_BLOCKS: u64 = 60;

/// Whether `height` is within [`ACTIVATION_GRACE_BLOCKS`] of an activation
/// (`A - N <= height < A + N` for some epoch after the first). Always false
/// with a single epoch.
pub fn near_activation(params: &blacksilk_consensus::ChainParams, height: u64) -> bool {
    params.schedule.epochs().iter().skip(1).any(|e| {
        let a = e.activation_height;
        height.saturating_add(ACTIVATION_GRACE_BLOCKS) >= a
            && height < a.saturating_add(ACTIVATION_GRACE_BLOCKS)
    })
}

impl TxError {
    /// [`TxError::is_stateless`] for a transaction checked for inclusion at
    /// `height`: a `PxProof` failure within [`ACTIVATION_GRACE_BLOCKS`] of an
    /// activation is contextual, because the proof's binding `h_tx` commits
    /// to a branch id and an honest proof made for the neighbouring rule set
    /// fails here. With a single epoch this equals `is_stateless`.
    pub fn is_stateless_at(&self, params: &blacksilk_consensus::ChainParams, height: u64) -> bool {
        match self {
            TxError::PxProof if near_activation(params, height) => false,
            e => e.is_stateless(),
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
    /// Also catches a one-time key repeated within the coinbase (the only
    /// one-time-key uniqueness rule for coinbases, D8 option B).
    CoinbaseOutputsNotSorted,
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
    /// A transaction broke a T, C or PX rule (B4 duplicates surface here as
    /// C2, PX2 or `DuplicateContract`).
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
    /// The deploys exceed the block's deploy sub-budget
    /// (`MAX_DEPLOY_BLOCK_BYTES`, R5-1; testnet v3 rule set).
    DeployBytesExceeded {
        bytes: u64,
        max: u64,
    },
    /// B8: the block's PX output commitments (`leaves`, one per commitment)
    /// do not fit in the `free` leaves the PX commitment tree has left
    /// (`CAPACITY − size`; testnet v3 rule set,
    /// docs/reviews/v3-consensus-changes.md#tree-capacity).
    PxTreeFull {
        leaves: u64,
        free: u64,
    },
}

/// Validates the transactions of a block at `ctx.height` against `chain` (the
/// state after the parent block). Checks B1–B8 and every T/C rule, cheap
/// first (docs/transactions.md §8.3): structure, B5, B6, B3, balances, PX
/// proof decoding, C2 and PX1–PX4 and PX6 with each PX proof's shape, every ring
/// (C1), one Bulletproofs+ batch (T10), the CLSAGs (C3), and the PX proofs
/// (PX5) last. The order decides only which error an invalid block reports,
/// never whether it is valid: every rule is a pure check.
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
/// signature domain (network, branch and genesis ids, RT-14) and the
/// registry entries of its contracts. Registry entries are
/// immutable and fixed by the contract id, which hashes the deploy payload
/// (docs/px.md §11.2); PX3 still checks, here, that they exist. So a proof
/// that verified once verifies for the same id in any block. Every other
/// rule is checked in full, PX6 (the validity window) included: whether a
/// transaction may be in a block at this height is not a property of its
/// proof, so the cache never vouches for it (AT-5).
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
    // B6: the block weight (transfers, and the v1 part of PX and deploy
    // transactions: `Transaction::weight`, R12-2), and the separate PX byte
    // budget. Before any cryptography, so a block stuffed with CLSAGs costs
    // a sum here, not a verification.
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
    // Deploys register permanent state and outrank PX transactions per byte:
    // their encoded bytes have their own cap inside the PX budget, so a block
    // always keeps room for PX transactions (R5-1).
    let deploy_bytes: u64 = txs
        .iter()
        .filter(|t| matches!(t, Transaction::PxDeploy(_)))
        .map(Transaction::px_bytes)
        .sum();
    if deploy_bytes > MAX_DEPLOY_BLOCK_BYTES {
        return Err(BlockError::DeployBytesExceeded {
            bytes: deploy_bytes,
            max: MAX_DEPLOY_BLOCK_BYTES,
        });
    }
    // B8: the block's PX output commitments, one tree leaf each, fit in the
    // PX commitment tree (testnet v3; docs/reviews/v3-consensus-changes.md
    // #tree-capacity). `MemoryChain::apply_block` fails exactly past this
    // bound, so a valid block always applies.
    let leaves: u64 = pxs.iter().map(|(_, t)| t.commitments.len() as u64).sum();
    let free = px_free_leaves(chain);
    if leaves > free {
        return Err(BlockError::PxTreeFull { leaves, free });
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

    // PX5, first step: decode every proof this node has not verified yet
    // (stateless and bounded, about 11 to 13 ms and 4 times its size in heap
    // for a transfer proof; `decode_px_proof`), before any ring or signature
    // work, so costless faults (an empty or garbage proof) never cost a CLSAG
    // (dossier 10 F10-2). The decoded proof is kept for PX5 itself.
    let mut decoded: Vec<Option<blacksilk_zk::Proof>> = Vec::with_capacity(pxs.len());
    for (index, t) in &pxs {
        decoded.push(if proof_verified(&ids[*index]) {
            None
        } else {
            Some(decode_px_proof(t).map_err(|error| BlockError::Tx {
                index: *index,
                error,
            })?)
        });
    }

    // C2 with B4 via a block-wide set; PX1–PX4 with block-wide nullifiers
    // and the pool evolving in block order; unique contract ids. Output
    // one-time keys may repeat across the block's transactions and the chain
    // (D8 option B; `check_key_images`). Once PX3 holds, a decoded proof must
    // have its statement's exact shape (PX5, second step; no cryptography).
    let mut key_images = HashSet::new();
    let mut nullifiers = HashSet::new();
    let mut contracts = HashSet::new();
    let mut pool = chain.px_pool();
    let mut px_slot = 0;
    for (index, tx) in txs.iter().enumerate().skip(1) {
        let err = |error| BlockError::Tx { index, error };
        let inputs: &[Input] = match tx {
            Transaction::Transfer(t) => &t.inputs,
            Transaction::Px(t) => &t.inputs,
            Transaction::PxDeploy(t) => &t.inputs,
            Transaction::Coinbase(_) => unreachable!("checked above"),
        };
        check_key_images(inputs, chain, &mut key_images).map_err(err)?;
        match tx {
            Transaction::Px(t) => {
                // PX6 for every PX transaction, cached proof or not (AT-5).
                check_px_window(t, ctx.height).map_err(err)?;
                check_px_state(t, chain, &mut nullifiers).map_err(err)?;
                pool = (pool + t.bridge_in as u128)
                    .checked_sub(t.bridge_out as u128)
                    .ok_or(BlockError::Tx {
                        index,
                        error: TxError::PxPoolUnderflow,
                    })?;
                if let Some(proof) = &decoded[px_slot] {
                    check_px_proof_shape(t, chain, rules, proof).map_err(err)?;
                }
                px_slot += 1;
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

    // C1: every ring of the block is resolved (cheap lookups) before the
    // first CLSAG is verified.
    let mut signed = Vec::with_capacity(txs.len() - 1);
    for (index, tx) in txs.iter().enumerate().skip(1) {
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
        let rings = resolve_input_rings(inputs, chain, ctx.height)
            .map_err(|error| BlockError::Tx { index, error })?;
        signed.push((index, inputs, pseudo, sigs, message, rings));
    }

    // T10, batched over every transaction with hidden outputs: stateless,
    // and cheaper per proof than one CLSAG input, so it runs before them.
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

    // C3 (expensive).
    for (index, inputs, pseudo, sigs, message, rings) in &signed {
        check_ring_signatures(inputs, pseudo, sigs, rings, message).map_err(|error| {
            BlockError::Tx {
                index: *index,
                error,
            }
        })?;
    }

    // PX5: the proofs, last (the most expensive check), on the proofs decoded
    // above; those `proof_verified` vouches for are skipped.
    for ((index, t), proof) in pxs.iter().zip(&decoded) {
        if let Some(proof) = proof {
            check_px_proof_decoded(t, chain, rules, proof).map_err(|error| BlockError::Tx {
                index: *index,
                error,
            })?;
        }
    }
    Ok(())
}
