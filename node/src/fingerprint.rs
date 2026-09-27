//! Build and rule identification (docs/testnet.md, operator checks).
//!
//! - [`consensus_fingerprint`]: a hash of every consensus-critical constant
//!   for one network. Two nodes with different fingerprints follow different
//!   rules and will fork, even when their genesis ids match.
//! - [`BUILD_COMMIT`]: the git commit the binary was built from (`build.rs`).
//!
//! The fingerprint covers constants only. Two builds that differ in rule
//! *code* without changing any constant have the same fingerprint; the build
//! commit is what tells them apart, so operators compare both.

use blacksilk_chain::{block, emission};
use blacksilk_consensus::{seed_height, ChainParams, Network};
use blacksilk_px::fingerprint::{px_entries, Manifest};
use blacksilk_tx::params::{self as tx, TxRules};

/// The git commit the sources were built from, `unknown` when neither `.git`
/// nor the `BLACKSILK_BUILD_COMMIT` build-time override was available.
pub const BUILD_COMMIT: &str = env!("BLACKSILK_BUILD_COMMIT");

/// The crate version (the same for every build until releases are versioned).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The hash domain of the fingerprint (under `BlackSilk/v1/`).
pub const DOMAIN: &str = "node/consensus-fingerprint/v1";

/// Every network, in a fixed order.
pub const NETWORKS: [Network; 3] = [Network::Testnet, Network::Regtest, Network::Mainnet];

/// `H64(DOMAIN, manifest(network).encode())[..32]`: the consensus fingerprint
/// of `network` for this build.
///
/// **Its value is pinned per network by `tests/deploy_configs.rs`. Changing
/// it is a consensus change and requires a new network id.**
pub fn consensus_fingerprint(network: Network) -> [u8; 32] {
    manifest(network).digest(DOMAIN)
}

/// The full manifest behind [`consensus_fingerprint`]: the chain-level entries
/// for `network`, then the PX-side entries ([`px_entries`]).
pub fn manifest(network: Network) -> Manifest {
    let mut m = chain_entries(network);
    m.extend(px_entries());
    m
}

/// The chain-level entries: every `ChainParams` field of `network`, its
/// genesis block and id, its `TxRules`, the header, transaction, block and
/// emission constants, and the RandomX configuration.
fn chain_entries(network: Network) -> Manifest {
    let p = ChainParams::for_network(network);
    // Destructured so that a new field fails to compile here until it is added.
    let ChainParams {
        network: n,
        network_id,
        target_block_time,
        initial_difficulty,
        difficulty_window,
        median_time_window,
        future_time_limit,
        seed_epoch,
        seed_lag,
        genesis,
        schedule,
    } = &p;
    let mut m = Manifest::new();
    m.text("chain.network", crate::network_name(*n))
        .u("chain.network_id", *network_id)
        .u("chain.target_block_time", *target_block_time)
        .u("chain.initial_difficulty", *initial_difficulty)
        .size("chain.difficulty_window", *difficulty_window)
        .size("chain.median_time_window", *median_time_window)
        .u("chain.future_time_limit", *future_time_limit)
        .u("chain.seed_epoch", *seed_epoch)
        .u("chain.seed_lag", *seed_lag)
        .bytes("chain.genesis", &genesis.to_bytes())
        .bytes("chain.genesis_id", &p.genesis_id())
        // The RandomX key schedule around the first key change.
        .list(
            "chain.seed_height samples",
            [
                0,
                1,
                seed_epoch + seed_lag,
                seed_epoch + seed_lag + 1,
                10 * seed_epoch,
            ]
            .map(|h| seed_height(h, *seed_epoch, *seed_lag)),
        );
    // The activation table: every epoch, in order (docs/consensus.md §11).
    m.size("schedule.len", schedule.len());
    for (i, e) in schedule.epochs().iter().enumerate() {
        m.list(
            &format!("schedule.epoch[{i}] (activation, header version, branch id, verifier id)"),
            [
                e.activation_height,
                u64::from(e.header_version),
                u64::from(e.branch_id),
                u64::from(e.verifier_id),
            ],
        );
    }
    // The rules at genesis; later epochs differ only in the scheduled fields above.
    let TxRules {
        network_id: rules_network_id,
        branch_id,
        fee_per_weight,
        max_block_weight,
    } = TxRules::at_height(&p, 0);
    m.u("rules.network_id", rules_network_id)
        .u("rules.branch_id", branch_id)
        .u("rules.fee_per_weight", fee_per_weight)
        .u("rules.max_block_weight", max_block_weight);

    m.size("consensus.HEADER_SIZE", blacksilk_consensus::HEADER_SIZE)
        .u(
            "consensus.HEADER_VERSION",
            blacksilk_consensus::HEADER_VERSION,
        )
        .size("consensus.NONCE_OFFSET", blacksilk_consensus::NONCE_OFFSET);
    m.u("tx.TX_VERSION", tx::TX_VERSION)
        .list(
            "tx.KINDS",
            [
                tx::KIND_COINBASE,
                tx::KIND_TRANSFER,
                tx::KIND_PX,
                tx::KIND_PX_DEPLOY,
            ]
            .map(u64::from),
        )
        .size("tx.RING_SIZE", tx::RING_SIZE)
        .size("tx.MAX_TX_SIZE", tx::MAX_TX_SIZE)
        .size("tx.MAX_INPUTS", tx::MAX_INPUTS)
        .size("tx.MIN_OUTPUTS", tx::MIN_OUTPUTS)
        .size("tx.MAX_OUTPUTS", tx::MAX_OUTPUTS)
        .size("tx.MIN_COINBASE_OUTPUTS", tx::MIN_COINBASE_OUTPUTS)
        .size("tx.MAX_COINBASE_OUTPUTS", tx::MAX_COINBASE_OUTPUTS)
        .u("tx.SPENDABLE_AGE", tx::SPENDABLE_AGE)
        .u("tx.COINBASE_MATURITY", tx::COINBASE_MATURITY)
        .u("tx.FEE_PER_WEIGHT", tx::FEE_PER_WEIGHT)
        .u("tx.MAX_BLOCK_WEIGHT", tx::MAX_BLOCK_WEIGHT)
        .size("tx.MAX_PX_TX_SIZE", tx::MAX_PX_TX_SIZE)
        .size("tx.MAX_DEPLOY_TX_SIZE", tx::MAX_DEPLOY_TX_SIZE)
        .u("tx.MAX_PX_BLOCK_BYTES", tx::MAX_PX_BLOCK_BYTES)
        .u("tx.PX_FEE_PER_BYTE", tx::PX_FEE_PER_BYTE)
        .u("tx.PX_STANDARD_FEE", tx::PX_STANDARD_FEE)
        .u("tx.DEPLOY_FEE_PER_BYTE", tx::DEPLOY_FEE_PER_BYTE)
        .u("tx.MAX_DEPLOY_BLOCK_BYTES", tx::MAX_DEPLOY_BLOCK_BYTES)
        .size("tx.MAX_PAYOUTS", tx::MAX_PAYOUTS)
        .size("tx.MAX_FN_OUTPUT_WORDS", tx::MAX_FN_OUTPUT_WORDS)
        .size("tx.MAX_DEPLOY_PROGRAMS", tx::MAX_DEPLOY_PROGRAMS)
        .size("tx.MAX_PROGRAM_BYTES", tx::MAX_PROGRAM_BYTES);
    m.size("chain.MAX_BLOCK_BYTES", block::MAX_BLOCK_BYTES)
        .u("chain.MAX_BLOCK_TXS", block::MAX_BLOCK_TXS);
    m.u("emission.COIN", emission::COIN)
        .u("emission.MONEY_SUPPLY", emission::MONEY_SUPPLY)
        .u("emission.EMISSION_SPEED", emission::EMISSION_SPEED)
        .u("emission.TAIL_REWARD", emission::TAIL_REWARD)
        // The curve itself at a few points: (height, coins generated before it).
        .list(
            "emission.block_reward samples",
            [
                (0, 0),
                (1, 0),
                (2, emission::block_reward(1, 0)),
                (1_000, 1_000 * emission::COIN),
                (1, emission::MONEY_SUPPLY - emission::COIN),
                (1, emission::MONEY_SUPPLY),
            ]
            .map(|(h, g)| emission::block_reward(h, g)),
        );
    randomx_entries(&mut m);
    m
}

/// The RandomX configuration.
///
/// `blacksilk-randomx` keeps its parameters `pub(crate)` (randomx/src/config.rs),
/// so apart from the two public constants these are **copies** of the RandomX
/// v1 values (the reference `configuration.h`) and not read from the crate. A
/// change inside `blacksilk-randomx` alone does not change the fingerprint; the
/// crate's official test vectors are what pin its behaviour, and the build
/// commit identifies the code. Reading them from the crate needs a public
/// accessor in `blacksilk-randomx`.
fn randomx_entries(m: &mut Manifest) {
    m.text(
        "randomx.variant",
        "RandomX v1 (rx/0), light-mode verification",
    )
    .size("randomx.HASH_SIZE", blacksilk_randomx::HASH_SIZE)
    .size("randomx.MAX_KEY_SIZE", blacksilk_randomx::MAX_KEY_SIZE)
    .u("randomx.ARGON_MEMORY_KIB", 262_144u32)
    .u("randomx.ARGON_ITERATIONS", 3u32)
    .u("randomx.ARGON_LANES", 1u32)
    .bytes("randomx.ARGON_SALT", b"RandomX\x03")
    .u("randomx.CACHE_ACCESSES", 8u32)
    .u("randomx.SUPERSCALAR_LATENCY", 170u32)
    .u("randomx.DATASET_BASE_SIZE", 2_147_483_648u64)
    .u("randomx.DATASET_EXTRA_SIZE", 33_554_368u64)
    .u("randomx.PROGRAM_SIZE", 256u32)
    .u("randomx.PROGRAM_ITERATIONS", 2048u32)
    .u("randomx.PROGRAM_COUNT", 8u32)
    .list("randomx.SCRATCHPAD_L3_L2_L1", [2_097_152, 262_144, 16_384])
    .u("randomx.JUMP_BITS", 8u32)
    .u("randomx.JUMP_OFFSET", 8u32)
    // Instruction frequencies per 256 opcodes, in opcode order (IADD_RS
    // .. ISTORE).
    .list(
        "randomx.FREQ",
        [
            16, 7, 16, 7, 16, 4, 4, 1, 4, 1, 8, 2, 15, 5, 8, 2, 4, 4, 16, 5, 16, 5, 6, 32, 4, 6,
            25, 1, 16,
        ],
    );
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `--version` text of the node: crate version, build commit, and for
/// each network the genesis id and the fingerprint (short and full).
pub fn version_text() -> String {
    let mut s = format!("{VERSION}\ncommit {BUILD_COMMIT}\n");
    for n in NETWORKS {
        let f = hex(&consensus_fingerprint(n));
        let g = hex(&ChainParams::for_network(n).genesis_id());
        s.push_str(&format!(
            "{name}: fingerprint {short} ({f})\n{name}: genesis {g}\n",
            name = crate::network_name(n),
            short = &f[..16],
        ));
    }
    s.truncate(s.trim_end().len());
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_across_calls() {
        for n in NETWORKS {
            assert_eq!(consensus_fingerprint(n), consensus_fingerprint(n));
        }
    }

    #[test]
    fn networks_differ() {
        let t = consensus_fingerprint(Network::Testnet);
        let r = consensus_fingerprint(Network::Regtest);
        let m = consensus_fingerprint(Network::Mainnet);
        assert_ne!(t, r);
        assert_ne!(t, m);
        assert_ne!(r, m);
    }

    #[test]
    fn manifest_ends_with_the_px_entries() {
        let m = manifest(Network::Testnet);
        let px = px_entries();
        assert!(m.entries().ends_with(px.entries()));
    }

    #[test]
    fn version_text_names_every_network() {
        let v = version_text();
        assert!(v.contains(BUILD_COMMIT));
        for n in NETWORKS {
            assert!(v.contains(&hex(&consensus_fingerprint(n))));
            assert!(v.contains(&hex(&ChainParams::for_network(n).genesis_id())));
        }
    }
}
