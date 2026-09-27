//! Per-network consensus parameters (spec §1).

use crate::difficulty::{difficulty_ancestors, DIFFICULTY_WARMUP, DIFFICULTY_WINDOW};
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
    /// LWMA window `N` (the rule: `crate::difficulty`).
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
            difficulty_window: DIFFICULTY_WINDOW,
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

    /// Ancestors (ending with the parent) a child's required difficulty is
    /// computed from: the LWMA window plus the counted clock's warm-up
    /// ([`difficulty_ancestors`]). The single count every caller uses.
    pub fn difficulty_ancestors(&self) -> usize {
        difficulty_ancestors(self.difficulty_window)
    }

    /// Checks the invariants the consensus code relies on (dossiers 01 F-06,
    /// 03-F6; red team RT-DAA RT-8). Every built-in network passes;
    /// [`crate::HeaderChain::new`] refuses parameters that do not, and the node
    /// checks them at start-up.
    ///
    /// - `2 ≤ T < 2^51`: the counted clock's step `T/2` is at least 1 s, and the
    ///   difficulty arithmetic stays in `u128` (RT-8's bound at `N = 75`).
    /// - `N ≥ 1` and `T·N·(N + 1) < 2^64`: the exact `u128` bound of the largest
    ///   intermediate `S·T·(n + 1)` with `S < N·2^64` (docs/consensus.md §4).
    ///   The caps are then consistent: `1 ≤ step ≤ 6T`, so every counted solve
    ///   time lies in `[step, 6T]`.
    /// - `1 ≤ median-time-past window ≤ 11`: the counted clock's warm-up covers
    ///   every predecessor a stamp can be low against (RT-DAA RT-1).
    /// - `1 ≤ FTL ≤ 7 200 s`: a future limit exists and is never looser than
    ///   Bitcoin's and Monero's 2 h, beyond which LWMA-family coins were exploited
    ///   (zawy12 issue #30). The LWMA recommendation `FTL ≤ N·T/20` is not
    ///   required: regtest keeps 360 s at T = 10 s (docs/consensus.md §5).
    /// - The RandomX key epoch is a power of two and the lag is below it.
    /// - `D0 ≥ 1`, and the genesis header is well formed: height 0, zero parent
    ///   and body root, difficulty `D0`, and the first epoch's header version.
    ///   The schedule's own ordering is checked when it is built
    ///   ([`Schedule::new`]).
    pub fn check(&self) -> Result<(), ParamsError> {
        let t = self.target_block_time;
        if t < 2 {
            return Err(ParamsError::TargetTooSmall(t));
        }
        if t >= 1 << 51 {
            return Err(ParamsError::TargetTooLarge(t));
        }
        let n = self.difficulty_window as u128;
        if n == 0 {
            return Err(ParamsError::WindowZero);
        }
        if n.saturating_mul(n + 1).saturating_mul(t as u128) >= 1 << 64 {
            return Err(ParamsError::DifficultyOverflow {
                window: self.difficulty_window,
                target: t,
            });
        }
        if self.median_time_window == 0 || self.median_time_window > DIFFICULTY_WARMUP {
            return Err(ParamsError::MedianWindow(self.median_time_window));
        }
        if self.future_time_limit == 0 || self.future_time_limit > MAX_FUTURE_TIME_LIMIT {
            return Err(ParamsError::FutureTimeLimit(self.future_time_limit));
        }
        if !self.seed_epoch.is_power_of_two() || self.seed_lag >= self.seed_epoch {
            return Err(ParamsError::SeedSchedule {
                epoch: self.seed_epoch,
                lag: self.seed_lag,
            });
        }
        if self.initial_difficulty == 0 {
            return Err(ParamsError::InitialDifficultyZero);
        }
        let g = &self.genesis;
        if g.height != 0
            || g.prev_id != [0; 32]
            || g.tx_root != [0; 32]
            || g.difficulty != self.initial_difficulty
            || g.version != self.epoch_at(0).header_version
        {
            return Err(ParamsError::Genesis);
        }
        Ok(())
    }
}

/// The loosest future time limit [`ChainParams::check`] accepts: 2 hours.
pub const MAX_FUTURE_TIME_LIMIT: u64 = 7_200;

/// A violated [`ChainParams`] invariant ([`ChainParams::check`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamsError {
    /// `T < 2`: the counted clock's step `T/2` would be 0.
    TargetTooSmall(u64),
    /// `T ≥ 2^51`.
    TargetTooLarge(u64),
    /// `N = 0`.
    WindowZero,
    /// `T·N·(N + 1) ≥ 2^64`: the difficulty arithmetic could overflow `u128`.
    DifficultyOverflow { window: usize, target: u64 },
    /// The median-time-past window is 0 or longer than the counted clock's
    /// warm-up.
    MedianWindow(usize),
    /// The future time limit is 0 or above [`MAX_FUTURE_TIME_LIMIT`].
    FutureTimeLimit(u64),
    /// The RandomX key epoch is not a power of two, or the lag is not below it.
    SeedSchedule { epoch: u64, lag: u64 },
    /// `D0 = 0`.
    InitialDifficultyZero,
    /// The genesis header is not the one the parameters define.
    Genesis,
}

impl std::fmt::Display for ParamsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for ParamsError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_network_passes_the_check() {
        for n in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            assert_eq!(ChainParams::for_network(n).check(), Ok(()), "{n:?}");
        }
    }

    /// One violation per invariant, each at its boundary, and the value just
    /// inside it.
    #[test]
    fn check_refuses_each_broken_invariant() {
        type Edit = fn(&mut ChainParams);
        let cases: [(Edit, ParamsError); 16] = [
            (|p| p.target_block_time = 1, ParamsError::TargetTooSmall(1)),
            (|p| p.target_block_time = 0, ParamsError::TargetTooSmall(0)),
            (
                |p| p.target_block_time = 1 << 51,
                ParamsError::TargetTooLarge(1 << 51),
            ),
            (|p| p.difficulty_window = 0, ParamsError::WindowZero),
            (
                // 2^30·(2^30 + 1)·120 ≥ 2^64: T < 2^51 alone does not bound a
                // larger window.
                |p| p.difficulty_window = 1 << 30,
                ParamsError::DifficultyOverflow {
                    window: 1 << 30,
                    target: 120,
                },
            ),
            (|p| p.median_time_window = 0, ParamsError::MedianWindow(0)),
            (|p| p.median_time_window = 12, ParamsError::MedianWindow(12)),
            (|p| p.future_time_limit = 0, ParamsError::FutureTimeLimit(0)),
            (
                |p| p.future_time_limit = 7_201,
                ParamsError::FutureTimeLimit(7_201),
            ),
            (
                |p| p.seed_epoch = 2047,
                ParamsError::SeedSchedule {
                    epoch: 2047,
                    lag: 64,
                },
            ),
            (
                |p| p.seed_lag = 2048,
                ParamsError::SeedSchedule {
                    epoch: 2048,
                    lag: 2048,
                },
            ),
            (
                |p| {
                    p.initial_difficulty = 0;
                    p.genesis.difficulty = 0;
                },
                ParamsError::InitialDifficultyZero,
            ),
            (|p| p.genesis.difficulty += 1, ParamsError::Genesis),
            (|p| p.genesis.height = 1, ParamsError::Genesis),
            (|p| p.genesis.tx_root = [1; 32], ParamsError::Genesis),
            (|p| p.genesis.version += 1, ParamsError::Genesis),
        ];
        for (edit, want) in cases {
            let mut p = ChainParams::testnet();
            edit(&mut p);
            assert_eq!(p.check(), Err(want));
        }
        // Just inside the bounds.
        let mut p = ChainParams::testnet();
        p.target_block_time = 2;
        p.median_time_window = 11;
        p.future_time_limit = 7_200;
        p.seed_lag = 2047;
        assert_eq!(p.check(), Ok(()));
        p.target_block_time = (1 << 51) - 1;
        assert_eq!(p.check(), Ok(()));
        // The product bound at its edge: 75·76·T < 2^64 for T < 2^51, and a
        // window of 2^26 at T = 120 is still inside (2^52·120 < 2^64).
        p.target_block_time = 120;
        p.difficulty_window = 1 << 26;
        assert_eq!(p.check(), Ok(()));
        let mut p = ChainParams::testnet();
        p.genesis.prev_id = [1; 32];
        assert_eq!(p.check(), Err(ParamsError::Genesis));
    }

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
