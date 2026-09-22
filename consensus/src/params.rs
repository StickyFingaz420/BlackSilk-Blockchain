//! Per-network consensus parameters (spec §1).

use crate::hash::Hash;
use crate::header::{BlockHeader, HEADER_VERSION};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    /// Local testing: difficulty starts at 1.
    Regtest,
}

#[derive(Clone, Debug)]
pub struct ChainParams {
    pub network: Network,
    pub network_id: u32,
    /// Target block time `T` in seconds.
    pub target_block_time: u64,
    /// Difficulty of the genesis block and of block 1 (`D0`).
    pub initial_difficulty: u64,
    /// LWMA window `N`.
    pub difficulty_window: usize,
    /// Median-time-past window.
    pub median_time_window: usize,
    /// Future time limit `FTL` in seconds.
    pub future_time_limit: u64,
    /// RandomX key epoch length `E` (power of two).
    pub seed_epoch: u64,
    /// RandomX key lag `L`.
    pub seed_lag: u64,
    pub genesis: BlockHeader,
}

impl ChainParams {
    pub fn mainnet() -> Self {
        Self::base(Network::Mainnet, 0x000B_1A6C, 100_000, 1_830_297_600) // 2028-01-01, provisional
    }

    pub fn testnet() -> Self {
        Self::base(Network::Testnet, 0x0001_D670, 100, 1_790_812_800) // 2026-10-01, provisional
    }

    pub fn regtest() -> Self {
        Self::base(Network::Regtest, 0x00DE_B06E, 1, 1_700_000_000)
    }

    fn base(network: Network, network_id: u32, initial_difficulty: u64, genesis_time: u64) -> Self {
        let genesis = BlockHeader {
            version: HEADER_VERSION,
            height: 0,
            prev_id: [0; 32],
            timestamp: genesis_time,
            difficulty: initial_difficulty,
            // Provisional: becomes the root of the genesis coinbase once the
            // transaction format is final (spec §1).
            tx_root: [0; 32],
            nonce: 0,
        };
        Self {
            network,
            network_id,
            target_block_time: 120,
            initial_difficulty,
            difficulty_window: 60,
            median_time_window: 11,
            future_time_limit: 360,
            seed_epoch: 2048,
            seed_lag: 64,
            genesis,
        }
    }

    pub fn genesis_id(&self) -> Hash {
        self.genesis.id(self.network_id)
    }
}
