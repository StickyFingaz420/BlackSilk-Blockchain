//! Consensus constants of the transaction layer (spec §4, §5.3, §8).

use blacksilk_consensus::ChainParams;
use blacksilk_crypto::bulletproofs_plus as bpp;

pub use blacksilk_crypto::clsag::RING_SIZE;

/// The only transaction version (spec §4.2).
pub const TX_VERSION: u64 = 1;
pub const KIND_COINBASE: u8 = 0;
pub const KIND_TRANSFER: u8 = 1;
/// A private-execution transaction (docs/px.md §11).
pub const KIND_PX: u8 = 2;
/// Registration of a private contract and its function programs (docs/px.md §11).
pub const KIND_PX_DEPLOY: u8 = 3;

/// Largest encoded PX transaction: the proof cap plus the public parts.
pub const MAX_PX_TX_SIZE: usize = blacksilk_zk::params::MAX_PROOF_BYTES + 256 * 1024;
/// Largest encoded deploy transaction (program binaries are on chain).
pub const MAX_DEPLOY_TX_SIZE: usize = 1024 * 1024;
/// Bytes of PX and deploy transactions a block may carry, beyond the v1 weight
/// limit (zk.md §11.1: a separate PX budget).
pub const MAX_PX_BLOCK_BYTES: u64 = 8 * 1024 * 1024;
/// Fee per encoded byte of PX transactions (atomic units); it defines
/// [`PX_STANDARD_FEE`].
pub const PX_FEE_PER_BYTE: u64 = 2;
/// Fee per payload byte of a deploy (salt, programs and budgets), on top of
/// the standard v1 fee of its transfer part (`px::deploy_fee`). Registrations
/// are permanent state, so the rate is above the v1 rate (`FEE_PER_WEIGHT`)
/// and 25 times the PX rate (R5-1, R6 TX-4;
/// docs/reviews/v3-upgrade-mechanism.md §7).
pub const DEPLOY_FEE_PER_BYTE: u64 = 50;
/// Encoded deploy bytes one block may carry, within `MAX_PX_BLOCK_BYTES`
/// (R5-1). A block rule (`BlockError::DeployBytesExceeded` in
/// `validate_block_transactions`); block templates respect it
/// (docs/reviews/v3-upgrade-mechanism.md §7.2).
pub const MAX_DEPLOY_BLOCK_BYTES: u64 = 1024 * 1024;
/// The fee of every PX transaction, exactly (docs/px.md §11.5): the per-byte
/// fee of the largest possible PX transaction. A uniform fee reveals nothing
/// about the transaction or the wallet that built it (privacy review P-7).
/// Deploys pay per byte: their size is public anyway.
pub const PX_STANDARD_FEE: u64 = PX_FEE_PER_BYTE * MAX_PX_TX_SIZE as u64;
/// Clear (bridge-out) outputs of one PX transaction.
pub const MAX_PAYOUTS: usize = 16;
/// Public output words a function may publish in a PX transaction.
pub const MAX_FN_OUTPUT_WORDS: usize = 256;
// Every valid deploy fits in a block's deploy budget, which fits in the PX budget.
const _: () = assert!(MAX_DEPLOY_TX_SIZE as u64 <= MAX_DEPLOY_BLOCK_BYTES);
const _: () = assert!(MAX_DEPLOY_BLOCK_BYTES <= MAX_PX_BLOCK_BYTES);
const _: () = assert!(DEPLOY_FEE_PER_BYTE >= FEE_PER_WEIGHT);

/// Programs one deploy may register, and the largest program binary.
pub const MAX_DEPLOY_PROGRAMS: usize = 16;
pub const MAX_PROGRAM_BYTES: usize = 256 * 1024;

/// Deploy-time row caps (record `px-deploy-row-caps`, freeze gate B2), as
/// log2 of a table height. A registered function's own tables: its CPU table
/// (`Budget::cycles`), its memory-init table (`Budget::keys`), and its
/// program and image tables (`program::height`, the padded image length).
pub const PX_FN_LOG_CYCLES: u32 = 15;
pub const PX_FN_LOG_KEYS: u32 = 14;
pub const PX_FN_LOG_PROGRAM: u32 = 14;
pub const PX_FN_LOG_IMAGE: u32 = 14;
/// The tables shared with the kernel: `K.x + MAX_FN·b.x ≤ 2^cap` for the
/// kernel budget `K = kernel_budget(MAX_FN)`, so any pair of registered
/// functions fits together with the kernel.
pub const PX_LOG_ADD: u32 = 16;
pub const PX_LOG_BIT: u32 = 14;
pub const PX_LOG_LT: u32 = 16;
pub const PX_LOG_SHIFT: u32 = 14;
pub const PX_LOG_MUL: u32 = 14;
pub const PX_LOG_POSEIDON: u32 = 11;
// Every capped table stays at or below the tallest PX table,
// `blacksilk_px::prove::PX_MAX_LOG_HEIGHT` (2^16, the byte table), which the
// PX5 shape check enforces.
const PX_MAX_LOG: u32 = blacksilk_px::prove::PX_MAX_LOG_HEIGHT as u32;
const _: () = assert!(
    PX_FN_LOG_CYCLES <= PX_MAX_LOG
        && PX_FN_LOG_KEYS <= PX_MAX_LOG
        && PX_FN_LOG_PROGRAM <= PX_MAX_LOG
        && PX_FN_LOG_IMAGE <= PX_MAX_LOG
        && PX_LOG_ADD <= PX_MAX_LOG
        && PX_LOG_BIT <= PX_MAX_LOG
        && PX_LOG_LT <= PX_MAX_LOG
        && PX_LOG_SHIFT <= PX_MAX_LOG
        && PX_LOG_MUL <= PX_MAX_LOG
        && PX_LOG_POSEIDON <= PX_MAX_LOG
);
// The prover's early stop for a function run (`blacksilk_px::prove::prove`)
// uses the same cycle cap.
const _: () = assert!(PX_FN_LOG_CYCLES == blacksilk_px::prove::FN_RUN_LOG_CYCLES);

/// T1: maximum encoded transaction size in bytes.
pub const MAX_TX_SIZE: usize = 100_000;
/// T3: input and output count bounds of a transfer.
pub const MAX_INPUTS: usize = 64;
pub const MIN_OUTPUTS: usize = 2;
pub const MAX_OUTPUTS: usize = 16;
/// Coinbase output count bounds (spec §4.3).
pub const MIN_COINBASE_OUTPUTS: usize = 1;
pub const MAX_COINBASE_OUTPUTS: usize = 16;

/// Minimum age in blocks of a transfer output used as a ring member (spec §5.3).
pub const SPENDABLE_AGE: u64 = 10;
/// Minimum age in blocks of a coinbase output used as a ring member.
pub const COINBASE_MATURITY: u64 = 60;

/// Fee per weight unit in atomic units (v1 value, docs/blocks.md §5).
pub const FEE_PER_WEIGHT: u64 = 20;
/// Block weight limit (v1 fixed value, docs/blocks.md §5); a dynamic limit is future work.
pub const MAX_BLOCK_WEIGHT: u64 = 600_000;

/// The weight of a transfer with `inputs` inputs and `outputs` outputs with
/// every varint at its 10-byte maximum (docs/transactions.md §8.4): an upper
/// bound on the weight of every transfer of that shape.
///
/// A consensus function: it defines the exact v1 fee (T8,
/// [`TxRules::standard_fee`]) and the v1 part of the exact deploy fee
/// (`px::deploy_fee`). `outputs = 0` (the v1 part of a PX transaction without
/// hidden outputs) has no range proof. Golden values for every shape:
/// `tx/tests/data/max_weight.txt`, from the independent
/// `tools/vectors/max_weight.py`.
///
/// A `const fn`, so that bounds built on it are checked at compile time
/// (below: the PX fee covers the largest PX v1 part).
pub const fn max_weight(inputs: usize, outputs: usize) -> u64 {
    let varint_max = 10u64;
    let n = inputs as u64;
    let k = outputs as u64;
    let prefix = varint_max
        + 1
        + varint_max
        + n * (32 + RING_SIZE as u64 * varint_max)
        + varint_max
        + k * (32 + 32 + 1 + 32 + 8 + 16)
        + varint_max;
    let bp = bpp_proof_len(outputs);
    let size = prefix + 32 * n + bp + n * blacksilk_crypto::clsag::CLSAG_BYTES as u64;
    let m = outputs.next_power_of_two() as u64;
    if m <= 2 {
        size
    } else {
        size + (320 * m).saturating_sub(bp) * 4 / 5
    }
}

/// `bpp::proof_len(outputs)`, or 0 where it is `None` (no range proof: 0 or
/// more than `bpp::MAX_OUTPUTS` outputs), as a `const fn`:
/// `32 × (6 + 2 × rounds)` with `rounds = log2(BITS × outputs.next_power_of_two())`.
/// Equal to the crypto crate's function for every count
/// (`bpp_proof_len_matches_the_crypto_crate`).
const fn bpp_proof_len(outputs: usize) -> u64 {
    if outputs == 0 || outputs > bpp::MAX_OUTPUTS {
        return 0;
    }
    let rounds = (bpp::BITS * outputs.next_power_of_two()).trailing_zeros() as u64;
    32 * (6 + 2 * rounds)
}

// R12-2: the uniform PX fee pays for the v1 part of every PX transaction at
// the v1 rate (its block weight is `max_weight(n_in, n_out)`), so it needs no
// per-shape component, which would fingerprint the input count
// (docs/reviews/v3-consensus-changes.md#r12-2).
const _: () = assert!(max_weight(MAX_INPUTS, MAX_OUTPUTS) * FEE_PER_WEIGHT <= PX_STANDARD_FEE);

/// The PX verifiers this crate implements (`consensus::schedule::Epoch::verifier_id`).
pub const SUPPORTED_VERIFIERS: &[u32] = &[blacksilk_consensus::schedule::VERIFIER_PX_1];

/// What every signature message and the PX binding commit to besides the
/// transaction (spec §4.4): the network, the rule-set branch and the genesis
/// block. A signature or proof is valid on one chain, in one epoch: not on a
/// rehearsal or retired chain that shares the network id and branch id
/// (RT-14, docs/reviews/v3-consensus-changes.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigDomain {
    pub network_id: u32,
    pub branch_id: u32,
    /// `ChainParams::genesis_id` of the chain.
    pub genesis_id: [u8; 32],
}

/// Encoded length of a [`SigDomain`].
pub const SIG_DOMAIN_BYTES: usize = 40;

impl SigDomain {
    /// `LE32(network_id) ‖ LE32(branch_id) ‖ genesis_id` (fixed width).
    pub fn bytes(&self) -> [u8; SIG_DOMAIN_BYTES] {
        let mut b = [0u8; SIG_DOMAIN_BYTES];
        b[..4].copy_from_slice(&self.network_id.to_le_bytes());
        b[4..8].copy_from_slice(&self.branch_id.to_le_bytes());
        b[8..].copy_from_slice(&self.genesis_id);
        b
    }
}

/// Per-network parameters the transaction rules depend on, for one epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxRules {
    /// Committed to by every signature (spec §4.4), so no cross-network replay.
    pub network_id: u32,
    /// The epoch's branch id, committed to next to the network id, so no
    /// replay across rule sets (docs/consensus.md §11).
    pub branch_id: u32,
    /// The chain's genesis id (`ChainParams::genesis_id`), committed to next
    /// to the network and branch ids, so no replay between chains that share
    /// both (RT-14).
    pub genesis_id: [u8; 32],
    pub fee_per_weight: u64,
    pub max_block_weight: u64,
}

impl TxRules {
    /// The rules of a chain whose schedule has a single epoch (every built-in
    /// network).
    ///
    /// # Panics
    /// If the schedule has more than one epoch: the rules then depend on the
    /// height, and the caller must use [`Self::at_height`]. This is a tripwire,
    /// so that no caller silently keeps the first epoch's branch id after an
    /// activation (docs/reviews/v3-upgrade-mechanism.md §2.4).
    pub fn for_chain(params: &ChainParams) -> Self {
        assert!(
            params.schedule.len() == 1,
            "multi-epoch schedule: build TxRules per height with TxRules::at_height"
        );
        Self::at_height(params, 0)
    }

    /// The rules for a transaction included in a block at `height`.
    pub fn at_height(params: &ChainParams, height: u64) -> Self {
        let epoch = params.epoch_at(height);
        Self {
            network_id: params.network_id,
            branch_id: epoch.branch_id,
            genesis_id: params.genesis_id(),
            fee_per_weight: FEE_PER_WEIGHT,
            max_block_weight: MAX_BLOCK_WEIGHT,
        }
    }

    /// What signatures and the PX binding commit to under these rules.
    pub fn domain(&self) -> SigDomain {
        SigDomain {
            network_id: self.network_id,
            branch_id: self.branch_id,
            genesis_id: self.genesis_id,
        }
    }

    /// `min_fee(w) = w · FEE_PER_WEIGHT`; `None` on overflow (no fee can pay it).
    pub fn min_fee(&self, weight: u64) -> Option<u64> {
        weight.checked_mul(self.fee_per_weight)
    }

    /// The fee a transfer with `inputs` inputs and `outputs` outputs pays,
    /// exactly (T8, docs/transactions.md §8.4): `min_fee(max_weight(inputs,
    /// outputs))`. Also the v1 part of the exact deploy fee. `None` on
    /// overflow.
    ///
    /// The one place the v1 fee rule is defined: an epoch that allows fee
    /// tiers later (R-FEE1) changes it here, per `TxRules`, and validation,
    /// wallets and deploys follow (reviews/v3-consensus-changes.md
    /// #exact-v1-fee).
    pub fn standard_fee(&self, inputs: usize, outputs: usize) -> Option<u64> {
        self.min_fee(max_weight(inputs, outputs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RTW1B-9: the `const` range-proof length used by `max_weight` equals
    /// the crypto crate's `proof_len` (0 where it is `None`) for every
    /// output count, valid or not; the golden `max_weight` rows are checked
    /// in tests/max_weight_vectors.rs.
    #[test]
    fn bpp_proof_len_matches_the_crypto_crate() {
        for k in 0..=4 * bpp::MAX_OUTPUTS {
            assert_eq!(
                bpp_proof_len(k),
                bpp::proof_len(k).unwrap_or(0) as u64,
                "{k}"
            );
        }
        // Evaluated at compile time.
        const LARGEST: u64 = max_weight(MAX_INPUTS, MAX_OUTPUTS);
        assert_eq!(LARGEST, 57_439);
    }
}
