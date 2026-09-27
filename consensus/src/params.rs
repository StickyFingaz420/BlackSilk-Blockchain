//! Per-network consensus parameters (spec §1).

use crate::hash::Hash;
use crate::header::BlockHeader;
use crate::schedule::{Epoch, Schedule, V3};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    /// Local testing: difficulty starts at 1, 10-second blocks.
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
    /// The rule sets by height (header version, branch id, PX verifier).
    pub schedule: Schedule,
    pub genesis: BlockHeader,
}

/// Testnet genesis time: 2026-09-26 00:00:00 UTC (testnet v2, reset with the PX
/// rules, parameter set BS-ZK-2 and the terminal blinding; docs/testnet-reset-plan.md). Testnet v1:
/// 2026-09-23, network id `0x0001_D670`.
pub const TESTNET_GENESIS_TIME: u64 = 1_790_380_800;
/// Mainnet genesis time: **provisional** until the mainnet launch date is fixed.
pub const MAINNET_GENESIS_TIME: u64 = 1_830_297_600;

impl ChainParams {
    pub fn mainnet() -> Self {
        Self::base(
            Network::Mainnet,
            0x000B_1A6C,
            100_000,
            MAINNET_GENESIS_TIME,
            120,
        )
    }

    pub fn testnet() -> Self {
        Self::base(
            Network::Testnet,
            // v2 (2026-09-26). v1 was 0x0001_D670; 0x0001_D671 was used by the
            // 2026-09-25 local reset rehearsal. Never reuse an id for another genesis.
            0x0001_D672,
            100,
            TESTNET_GENESIS_TIME,
            120,
        )
    }

    /// Local testing network. It uses 10-second blocks, so a laptop can run hours of
    /// chain activity (reorgs, RandomX key changes, coinbase maturity) quickly.
    /// Every other rule is identical to testnet and mainnet.
    pub fn regtest() -> Self {
        Self::base(Network::Regtest, 0x00DE_B06E, 1, 1_700_000_000, 10)
    }

    pub fn for_network(network: Network) -> Self {
        match network {
            Network::Mainnet => Self::mainnet(),
            Network::Testnet => Self::testnet(),
            Network::Regtest => Self::regtest(),
        }
    }

    fn base(
        network: Network,
        network_id: u32,
        initial_difficulty: u64,
        genesis_time: u64,
        target_block_time: u64,
    ) -> Self {
        // The genesis body is empty (blocks.md §3): tx_root is the root of the empty
        // list, and there is no coinbase and no premine.
        let schedule = V3;
        let genesis = BlockHeader {
            version: schedule.epoch_at(0).header_version,
            height: 0,
            prev_id: [0; 32],
            timestamp: genesis_time,
            difficulty: initial_difficulty,
            tx_root: [0; 32],
            nonce: 0,
        };
        Self {
            network,
            network_id,
            target_block_time,
            initial_difficulty,
            difficulty_window: 60,
            median_time_window: 11,
            future_time_limit: 360,
            seed_epoch: 2048,
            seed_lag: 64,
            schedule,
            genesis,
        }
    }

    /// The rule set of a block at `height`.
    pub fn epoch_at(&self, height: u64) -> &'static Epoch {
        self.schedule.epoch_at(height)
    }

    pub fn genesis_id(&self) -> Hash {
        self.genesis.id(self.network_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The genesis blocks are consensus constants. Any change to the header format,
    /// id hashing or genesis parameters changes these ids and must be deliberate.
    #[test]
    fn genesis_ids_are_pinned() {
        let id = |p: ChainParams| hex_id(&p.genesis_id());
        assert_eq!(id(ChainParams::testnet()), TESTNET_GENESIS_ID);
        assert_eq!(id(ChainParams::regtest()), REGTEST_GENESIS_ID);
    }

    fn hex_id(h: &Hash) -> String {
        h.iter().map(|b| format!("{b:02x}")).collect()
    }

    const TESTNET_GENESIS_ID: &str =
        "6556f92dee4df050cfb113a2b4ba234794274854b69f7c8a39755ec7a66b037d";
    const REGTEST_GENESIS_ID: &str =
        "087d6fd4efbc45eb0a895dd0680a7fd305208cae239b1b4275d7148b29a569b7";

    #[test]
    fn networks_are_distinct() {
        let ids = [
            ChainParams::mainnet().network_id,
            ChainParams::testnet().network_id,
            ChainParams::regtest().network_id,
        ];
        assert!(ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2]);
        assert_eq!(
            ChainParams::for_network(Network::Testnet).network_id,
            ids[1]
        );
    }
}
