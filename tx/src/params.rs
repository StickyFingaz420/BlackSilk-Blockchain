//! Consensus constants of the transaction layer (spec §4, §5.3, §8).

use blacksilk_consensus::ChainParams;

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
/// Fee per encoded byte of PX and deploy transactions (atomic units).
pub const PX_FEE_PER_BYTE: u64 = 2;
/// The fee of every PX transaction, exactly (docs/px.md §11.5): the per-byte
/// fee of the largest possible PX transaction. A uniform fee reveals nothing
/// about the transaction or the wallet that built it (privacy review P-7).
/// Deploys pay per byte: their size is public anyway.
pub const PX_STANDARD_FEE: u64 = PX_FEE_PER_BYTE * MAX_PX_TX_SIZE as u64;
/// Clear (bridge-out) outputs of one PX transaction.
pub const MAX_PAYOUTS: usize = 16;
/// Public output words a function may publish in a PX transaction.
pub const MAX_FN_OUTPUT_WORDS: usize = 256;
/// Programs one deploy may register, and the largest program binary.
pub const MAX_DEPLOY_PROGRAMS: usize = 16;
pub const MAX_PROGRAM_BYTES: usize = 256 * 1024;

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

/// The PX verifiers this crate implements (`consensus::schedule::Epoch::verifier_id`).
pub const SUPPORTED_VERIFIERS: &[u32] = &[blacksilk_consensus::schedule::VERIFIER_PX_1];

/// What every signature message and the PX binding commit to besides the
/// transaction (spec §4.4): the network and the rule-set branch. A signature
/// or proof is valid on one network, in one epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigDomain {
    pub network_id: u32,
    pub branch_id: u32,
}

impl SigDomain {
    /// `LE32(network_id) ‖ LE32(branch_id)`.
    pub fn bytes(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&self.network_id.to_le_bytes());
        b[4..].copy_from_slice(&self.branch_id.to_le_bytes());
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
            fee_per_weight: FEE_PER_WEIGHT,
            max_block_weight: MAX_BLOCK_WEIGHT,
        }
    }

    /// What signatures and the PX binding commit to under these rules.
    pub fn domain(&self) -> SigDomain {
        SigDomain {
            network_id: self.network_id,
            branch_id: self.branch_id,
        }
    }

    /// `min_fee(w) = w · FEE_PER_WEIGHT`; `None` on overflow (no fee can pay it).
    pub fn min_fee(&self, weight: u64) -> Option<u64> {
        weight.checked_mul(self.fee_per_weight)
    }
}
