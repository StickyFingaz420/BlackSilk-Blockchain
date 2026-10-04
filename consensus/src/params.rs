//! Per-network consensus parameters (spec §1).

use crate::difficulty::{difficulty_ancestors, DIFFICULTY_WARMUP, DIFFICULTY_WINDOW};
use crate::genesis::{Beacon, GenesisSpec};
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

/// Testnet genesis time: a **placeholder** (2026-09-26 00:00:00 UTC, the retired
/// v2 genesis time) until the v3 launch fixes `T_g` (docs/testnet-v3-genesis.md
/// §4). Testnet v1: 2026-09-23, network id `0x0001_D670`; v2: 2026-09-26,
/// `0x0001_D672`.
pub const TESTNET_GENESIS_TIME: u64 = 1_790_380_800;
/// Mainnet genesis time: **provisional** until the mainnet launch date is fixed.
pub const MAINNET_GENESIS_TIME: u64 = 1_830_297_600;

/// The committed beacon of the testnet genesis (docs/testnet-v3-genesis.md). `None`
/// until the launch: the genesis nonce is then 0 and the network is **not final**
/// ([`ChainParams::genesis_is_final`]). The final commit changes exactly this
/// `None` to `Some(Beacon { .. })` (plus the pinned ids): the nonce is derived in
/// [`crate::genesis`], never pasted, and there is no runtime override.
pub const TESTNET_BEACON: Option<Beacon> = None;
/// The committed beacon of the mainnet genesis. `None`: not final.
pub const MAINNET_BEACON: Option<Beacon> = None;

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
            // v3, the final testnet id (decisions "Agent 40"; its genesis is
            // generated at launch). v1 was 0x0001_D670, 0x0001_D671 the
            // 2026-09-25 local reset rehearsal, v2 0x0001_D672 (retired).
            // Never reuse an id for another genesis.
            0x0001_D673,
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
        // list, and there is no coinbase and no premine. The nonce comes from the
        // network's committed beacon (none yet on any network: nonce 0).
        let schedule = V3;
        let genesis = genesis_spec(network, network_id, genesis_time, initial_difficulty)
            .header(schedule.epoch_at(0).header_version);
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

    /// The genesis specification of these parameters: their network id, genesis
    /// time and `D0`, and the network's committed beacon.
    pub fn genesis_spec(&self) -> GenesisSpec {
        genesis_spec(
            self.network,
            self.network_id,
            self.genesis.timestamp,
            self.initial_difficulty,
        )
    }

    /// Whether this network's genesis is final: regtest always is; testnet and
    /// mainnet only once their beacon is committed. Binaries must refuse a
    /// network whose genesis is not final.
    pub fn genesis_is_final(&self) -> bool {
        self.genesis_spec().is_final()
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
    /// - The RandomX key epoch is a power of two and `1 ≤ lag < epoch`. With
    ///   `lag ≥ 1` a block's key is strictly older than its parent
    ///   (`height - seed_height > lag`); a lag of 0 would let the key be the
    ///   parent itself, known only once the parent exists (RTW1-10).
    /// - `D0 ≥ 1`, and the genesis header is well formed: height 0, zero parent
    ///   and body root, no outputs (count 0, zero output root), the empty PX
    ///   tree's root, difficulty `D0`, the first epoch's header version, and
    ///   the nonce derived from the committed beacon ([`Self::genesis_spec`]): a
    ///   pasted nonce that disagrees with its beacon is refused.
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
        if !self.seed_epoch.is_power_of_two()
            || self.seed_lag == 0
            || self.seed_lag >= self.seed_epoch
        {
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
            || g.output_count != 0
            || g.output_root != [0; 32]
            || g.px_root != crate::genesis::EMPTY_PX_ROOT
            || g.difficulty != self.initial_difficulty
            || g.version != self.epoch_at(0).header_version
            || g.nonce != self.genesis_spec().nonce()
        {
            return Err(ParamsError::Genesis);
        }
        Ok(())
    }
}

/// The genesis specification of `network` with the given fields and the
/// network's committed beacon.
fn genesis_spec(network: Network, network_id: u32, timestamp: u64, difficulty: u64) -> GenesisSpec {
    let (needs_beacon, beacon) = match network {
        Network::Mainnet => (true, MAINNET_BEACON),
        Network::Testnet => (true, TESTNET_BEACON),
        Network::Regtest => (false, None),
    };
    GenesisSpec {
        network_id,
        timestamp,
        difficulty,
        needs_beacon,
        beacon,
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
    /// The RandomX key epoch is not a power of two, or the lag is 0 or not
    /// below it.
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

    /// No network has a committed beacon yet: testnet and mainnet are not final,
    /// regtest needs none. Their genesis ids (pinned above) are unchanged by the
    /// beacon plumbing because the nonce stays 0 without a beacon.
    #[test]
    fn genesis_finality_follows_the_committed_beacon() {
        assert!(!ChainParams::testnet().genesis_is_final());
        assert!(!ChainParams::mainnet().genesis_is_final());
        assert!(ChainParams::regtest().genesis_is_final());
        for n in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            let p = ChainParams::for_network(n);
            assert_eq!(p.genesis.nonce, 0);
            assert_eq!(p.genesis_spec().header(p.genesis.version), p.genesis);
        }
    }

    /// With a (dummy, test-only) committed beacon the genesis nonce is the
    /// derivation of that beacon, the network becomes final, and `check`
    /// accepts exactly that nonce. No real genesis is generated here.
    #[test]
    fn a_committed_beacon_derives_the_nonce() {
        let mut p = ChainParams::testnet();
        let spec = GenesisSpec {
            beacon: Some(Beacon {
                btc_height: 900_000,
                btc_hash_display: [0x5A; 32],
            }),
            ..p.genesis_spec()
        };
        assert!(spec.is_final());
        let g = spec.header(p.genesis.version);
        assert_eq!(
            g.nonce,
            crate::genesis::derive_genesis_nonce(p.network_id, 900_000, &[0x5A; 32])
        );
        // These parameters commit no beacon, so that genesis is refused: the
        // nonce cannot be set apart from the constant beacon.
        p.genesis = g;
        assert_eq!(p.check(), Err(ParamsError::Genesis));
    }

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
        let cases: [(Edit, ParamsError); 18] = [
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
                |p| p.seed_lag = 0,
                ParamsError::SeedSchedule {
                    epoch: 2048,
                    lag: 0,
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
            // A pasted nonce (no beacon is committed, so the nonce must be 0).
            (
                |p| p.genesis.nonce = 0x351e_3bcf_977d_433c,
                ParamsError::Genesis,
            ),
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
        // The exact edge of `N·(N + 1)·T < 2^64` at N = 1000 (Python:
        // (2**64 - 1) // (1000 * 1001) = 18 428 315 757 951). One more second
        // overflows, although N² · T and N·(N − 1)·T are still below 2^64
        // (W4-MUT: `N + 1` mutated to `N − 1` and `N · 1` survived).
        p.difficulty_window = 1000;
        p.target_block_time = 18_428_315_757_951;
        assert_eq!(p.check(), Ok(()));
        p.target_block_time += 1;
        assert_eq!(
            p.check(),
            Err(ParamsError::DifficultyOverflow {
                window: 1000,
                target: 18_428_315_757_952,
            })
        );
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

    /// Testnet v3 before its launch: id `0x0001_D673`, the placeholder genesis
    /// time and nonce 0 (no beacon). Recomputed independently from the spec
    /// (Python `hashlib.blake2b`, `tools/vectors/output_mmr.py`; the 172-byte
    /// header of docs/reviews/v3-consensus-changes.md#output-root). The
    /// launch commit changes it with the beacon.
    const TESTNET_GENESIS_ID: &str =
        "b16090df9c6ad30233696ac8db2030e876dfc9ed6b8ed8af40a42cda0b75a1d0";
    const REGTEST_GENESIS_ID: &str =
        "3dbdba2aca8842cd3e02c7d8c72078f77ff132cc3c84a7f8b87891d0cc106141";

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
