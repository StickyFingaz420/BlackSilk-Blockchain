//! Consensus constants of the transaction layer (spec §4, §5.3, §8).

use blacksilk_consensus::ChainParams;

pub use blacksilk_crypto::clsag::RING_SIZE;

/// The only transaction version (spec §4.2).
pub const TX_VERSION: u64 = 1;
pub const KIND_COINBASE: u8 = 0;
pub const KIND_TRANSFER: u8 = 1;

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

/// Fee per weight unit (atomic units). **Provisional** until the economics spec
/// fixes it (spec §15).
pub const PROVISIONAL_FEE_PER_WEIGHT: u64 = 20;
/// Block weight limit. **Provisional** (spec §15); a dynamic limit comes later.
pub const PROVISIONAL_MAX_BLOCK_WEIGHT: u64 = 600_000;

/// Per-network parameters the transaction rules depend on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxRules {
    /// Committed to by every signature (spec §4.4), so no cross-network replay.
    pub network_id: u32,
    pub fee_per_weight: u64,
    pub max_block_weight: u64,
}

impl TxRules {
    pub fn for_chain(params: &ChainParams) -> Self {
        Self {
            network_id: params.network_id,
            fee_per_weight: PROVISIONAL_FEE_PER_WEIGHT,
            max_block_weight: PROVISIONAL_MAX_BLOCK_WEIGHT,
        }
    }

    /// `min_fee(w) = w · FEE_PER_WEIGHT`; `None` on overflow (no fee can pay it).
    pub fn min_fee(&self, weight: u64) -> Option<u64> {
        weight.checked_mul(self.fee_per_weight)
    }
}
