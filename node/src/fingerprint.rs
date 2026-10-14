//! Build and rule identification (docs/testnet.md §2.1, operator checks).
//!
//! The consensus manifest of a network is split in two (fingerprint v3,
//! docs/reviews/v3-consensus-changes.md#fingerprint-v3):
//!
//! - [`rules_manifest`]: every consensus constant (the RandomX configuration
//!   read from `blacksilk-randomx`, the consensus hash tags read from
//!   `blacksilk-crypto`), the **rule samples** (outputs of rule functions on
//!   fixed inputs: difficulty and its lower clamp, median time, the future
//!   time limit, proof-of-work target, block id, Merkle root, signature
//!   domain, weights and fees, the genesis-nonce derivation, emission, the
//!   RandomX key schedule, the PX, crypto and tree samples of
//!   `blacksilk_px::fingerprint`, and the [`transaction_samples`]: weights,
//!   ids and **verdicts** of a pinned fixture transfer and its variants, and
//!   of the golden PX transaction and deploy ([`PxFixture`])), the
//!   pinned RandomX known answer, and the **rule-revision list**
//!   ([`REVISIONS`]). Its digest is [`rules_fingerprint`]. It holds nothing
//!   that names a chain, so a release-candidate build and the final build of
//!   a network have the same rules fingerprint.
//! - [`identity_manifest`]: the network name and id, the genesis block and
//!   id, the initial difficulty (D0) and the branch ids of the schedule. Its
//!   digest is [`identity_fingerprint`].
//!
//! [`consensus_fingerprint`] hashes the two fingerprints together: one value
//! that changes with either. `blacksilk-node --print-manifest` prints both
//! manifests, their encodings and all three digests.
//!
//! The rule samples catch a code change that alters a sampled result, and the
//! revision list names each reviewed rule change; rule code that neither
//! reaches (for example a changed validation order that keeps every sampled
//! verdict, or a rule only a PX proof or a full block exercises) is told
//! apart only by [`BUILD_COMMIT`], so operators compare both, and the build
//! commit is marked `-dirty` when tracked files differ from it (`build.rs`).
//!
//! Every rule sample's **input** is recorded next to its output
//! (fingerprint-sample-inputs), built from the same values the sample is
//! computed from: an entry named `<sample> input` (or `<sample>
//! input.<part>`) holds the sampled numbers, bytes or, for a sampled
//! transaction, [`input_hash`] of its canonical encoding, and a verdict
//! variant that changes the chain view, the height or the rules instead of
//! the transaction records that change too. So a change of a sample's input
//! moves the rules fingerprint even when the rule gives the same output for
//! both inputs. The network's initial difficulty (D0) is an identity entry:
//! it is a per-chain tuning value, not a rule, and it also enters the genesis
//! header.

use blacksilk_chain::build_flags::BuildFlags;
use blacksilk_chain::{block, emission};
use blacksilk_consensus::genesis::{
    derive_genesis_nonce, parse_display_hex, TEST_VECTOR_NETWORK_ID,
};
use blacksilk_consensus::schedule::BRANCH_ID_V3;
use blacksilk_consensus::{
    check_hash, seed_height, BlockHeader, ChainParams, Epoch, Network, DIFFICULTY_RULE_ID,
};
use blacksilk_consensus::{difficulty, merkle, timestamp};
use blacksilk_crypto::Point;
use blacksilk_px::fingerprint::{px_entries, Manifest};
use blacksilk_tx::mmr;
use blacksilk_tx::params::{self as tx, max_weight, SigDomain, TxRules};
use blacksilk_tx::px::{deploy_fee, Registration};
use blacksilk_tx::types::{v1_part_weight, OutputKey};
use blacksilk_tx::validate::{BlockError, OutputRecord};
use blacksilk_tx::{ChainView, Transaction, Transfer, TxError};
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// The git commit the sources were built from, followed by `-dirty` when
/// tracked build inputs differed from it (`build.rs`, RTFP3-9), or `unknown`
/// when neither `.git` nor the `BLACKSILK_BUILD_COMMIT` build-time override
/// was available.
pub const BUILD_COMMIT: &str = env!("BLACKSILK_BUILD_COMMIT");

/// The crate version (the same for every build until releases are versioned).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The test-only code compiled into this binary (W4-GUARD): the markers of
/// chain, tx and px (`blacksilk_chain::build_flags`) and of p2p. Empty for a
/// plain `cargo build --release`; a binary written by `cargo test` (which
/// unifies dev-dependency features) or by a fuzz build is marked. The node
/// prints them in `--version`, `--print-manifest` and the start-up log, and
/// refuses every network but regtest while any is set.
pub fn build_flags() -> BuildFlags {
    BuildFlags::of_chain_layer()
        .with(blacksilk_p2p::TEST_HOOKS_MARKER)
        .with(blacksilk_p2p::FUZZING_MARKER)
}

/// The hash domain of [`consensus_fingerprint`] (under `BlackSilk/v1/`). v2:
/// the hash of the rules and identity fingerprints (fingerprint v3).
pub const DOMAIN: &str = "node/consensus-fingerprint/v2";

/// The hash domain of [`rules_fingerprint`].
pub const RULES_DOMAIN: &str = "node/rules-fingerprint/v1";

/// The hash domain of [`identity_fingerprint`].
pub const IDENTITY_DOMAIN: &str = "node/identity-fingerprint/v1";

/// The hash domain of the sample-input digests ([`input_hash`]): a sampled
/// transaction enters the rules manifest next to its verdict as
/// `H64(SAMPLE_INPUT_DOMAIN, encoding)[..32]` of its canonical encoding
/// (docs/reviews/v3-consensus-changes.md#fingerprint-sample-inputs).
pub const SAMPLE_INPUT_DOMAIN: &str = "node/fingerprint-sample-input/v1";

/// `H64(SAMPLE_INPUT_DOMAIN, encoding)[..32]`: the input entry of a sample
/// whose input is a transaction (`Transaction::encode`).
pub fn input_hash(encoding: &[u8]) -> [u8; 32] {
    let mut h = blacksilk_crypto::hash::Hasher64::new(SAMPLE_INPUT_DOMAIN);
    h.update(encoding);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize()[..32]);
    out
}

/// Every network, in a fixed order.
pub const NETWORKS: [Network; 3] = [Network::Testnet, Network::Regtest, Network::Mainnet];

/// One reviewed consensus rule change of the v3 rule set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Revision {
    /// A short, versioned rule identifier; it enters the rules manifest.
    pub id: &'static str,
    /// Its record in docs/reviews/v3-consensus-changes.md: a heading (`§1`,
    /// `BS-ZK-3`) or an anchor (`r12-2`). Not in the manifest.
    pub record: &'static str,
}

/// The rule-revision list: every reviewed rule change of the v3 genesis base
/// rule set whose effect is a validity or proof-acceptance rule, in record
/// order (docs/reviews/v3-consensus-changes.md). Hand-maintained: a new
/// consensus rule change appends its entry in the same commit, and never
/// edits or reorders an existing one. Records that change no verdict (the
/// header check order, `UnknownUpgrade` scoring, mempool expiry, verifier
/// hardening off the consensus paths), the genesis construction (identity)
/// and program rebuilds (their ids are listed) are not revisions.
pub const REVISIONS: &[Revision] = &[
    Revision {
        id: "D8-B:one-time-keys-unique-within-tx-only",
        record: "§1",
    },
    Revision {
        id: "CLSAG:D-not-identity",
        record: "§2",
    },
    Revision {
        id: "RT-14:sig-domain-network-branch-genesis",
        record: "§3",
    },
    Revision {
        id: "F24-1:eight-random-codewords",
        record: "BS-ZK-3",
    },
    Revision {
        id: "I2:exact-hidden-openings-one-cap-root",
        record: "Canonical proof shape",
    },
    Revision {
        id: "03-F1:lwma75-step-t/2-warm11",
        record: "daa-lwma75-warm",
    },
    Revision {
        id: "T8:exact-v1-fee",
        record: "exact-v1-fee",
    },
    Revision {
        id: "R12-2:a-prime-v1-part-weight",
        record: "r12-2",
    },
    Revision {
        id: "I3:px-tree-capacity",
        record: "tree-capacity",
    },
    Revision {
        id: "F-20-1:approval-conflict",
        record: "approval-conflict",
    },
    Revision {
        id: "F-28-1:abi-word-and-registry-out-words",
        record: "px-call-abi",
    },
    Revision {
        id: "PX6:validity-window",
        record: "px6-validity-window",
    },
    Revision {
        id: "RTW1C-1:kernel-budgets-cover-every-shape",
        record: "kernel-budget-shapes",
    },
    Revision {
        id: "PX-R:ciphertext-r-canonical-not-identity",
        record: "px-ciphertext-r",
    },
    Revision {
        id: "RX-SALT:blacksilk-randomx-argon2-salt",
        record: "rx-salt",
    },
    Revision {
        id: "OMR:header-output-mmr-px-root-and-mining-blob",
        record: "output-root",
    },
    Revision {
        id: "ZK:BS-ZK-4-query-grinding-20",
        record: "bs-zk-4",
    },
    Revision {
        id: "B2:px-deploy-row-caps",
        record: "px-deploy-row-caps",
    },
];

/// The three digests of one network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fingerprints {
    pub rules: [u8; 32],
    pub identity: [u8; 32],
    pub consensus: [u8; 32],
}

/// The fingerprints of `network`, computed once per process.
pub fn fingerprints(network: Network) -> Fingerprints {
    static ALL: OnceLock<[Fingerprints; 3]> = OnceLock::new();
    let all = ALL.get_or_init(|| NETWORKS.map(compute));
    let i = NETWORKS
        .iter()
        .position(|n| *n == network)
        .expect("every network is in NETWORKS");
    all[i]
}

fn compute(network: Network) -> Fingerprints {
    let rules = rules_manifest(network).digest(RULES_DOMAIN);
    let identity = identity_manifest(network).digest(IDENTITY_DOMAIN);
    Fingerprints {
        rules,
        identity,
        consensus: combine(&rules, &identity),
    }
}

/// `H64(DOMAIN, encode([rules, identity]))[..32]`.
fn combine(rules: &[u8; 32], identity: &[u8; 32]) -> [u8; 32] {
    let mut m = Manifest::new();
    m.bytes("rules_fingerprint", rules)
        .bytes("identity_fingerprint", identity);
    m.digest(DOMAIN)
}

/// The consensus fingerprint of `network` for this build: the hash of its
/// [`rules_fingerprint`] and [`identity_fingerprint`]. Two nodes with
/// different values follow different rules or different chains.
///
/// **Its value is pinned per network by `tests/deploy_configs.rs`. Changing
/// it is a consensus change** (docs/reviews/v3-consensus-changes.md).
pub fn consensus_fingerprint(network: Network) -> [u8; 32] {
    fingerprints(network).consensus
}

/// `H64(RULES_DOMAIN, rules_manifest(network).encode())[..32]`.
pub fn rules_fingerprint(network: Network) -> [u8; 32] {
    fingerprints(network).rules
}

/// `H64(IDENTITY_DOMAIN, identity_manifest(network).encode())[..32]`.
pub fn identity_fingerprint(network: Network) -> [u8; 32] {
    fingerprints(network).identity
}

/// Both manifests of `network`, identity first (diagnostics and tests).
pub fn manifest(network: Network) -> Manifest {
    let mut m = identity_manifest(network);
    m.extend(rules_manifest(network));
    m
}

/// The identity entries: the network name and id, the genesis block and id,
/// the initial difficulty (D0), the branch id of every epoch, and the ids
/// `TxRules` carries at genesis.
pub fn identity_manifest(network: Network) -> Manifest {
    let p = ChainParams::for_network(network);
    let mut m = Manifest::new();
    m.text("chain.network", crate::network_name(p.network))
        .u("chain.network_id", p.network_id)
        .bytes("chain.genesis", &p.genesis.to_bytes())
        .bytes("chain.genesis_id", &p.genesis_id())
        // A per-chain tuning value, not a rule (fingerprint-sample-inputs);
        // it is also the genesis header's difficulty.
        .u("chain.initial_difficulty", p.initial_difficulty);
    m.list(
        "schedule.branch_ids",
        p.schedule.epochs().iter().map(|e| u64::from(e.branch_id)),
    );
    let r = TxRules::at_height(&p, 0);
    m.u("rules.network_id", r.network_id)
        .u("rules.branch_id", r.branch_id);
    m
}

/// The rules entries: the chain-level constants and rule samples of
/// `network`, the PX-side entries ([`px_entries`]) and the rule-revision
/// list ([`REVISIONS`]).
pub fn rules_manifest(network: Network) -> Manifest {
    let mut m = chain_entries(network);
    m.extend(px_entries());
    m.extend(rule_samples(network));
    m.size("rules.revision.len", REVISIONS.len());
    for (i, r) in REVISIONS.iter().enumerate() {
        m.text(&format!("rules.revision[{i}]"), r.id);
    }
    m
}

/// The chain-level constants: every `ChainParams` field except the identity
/// ones, the activation table without its branch ids, the `TxRules` at
/// genesis, the header, transaction, block and emission constants, and the
/// RandomX configuration.
fn chain_entries(network: Network) -> Manifest {
    let p = ChainParams::for_network(network);
    // Destructured so that a new field fails to compile here until it is
    // placed in the rules or the identity manifest.
    let ChainParams {
        // Identity (identity_manifest).
        network: _,
        network_id: _,
        genesis: _,
        initial_difficulty: _,
        target_block_time,
        difficulty_window,
        median_time_window,
        future_time_limit,
        seed_epoch,
        seed_lag,
        schedule,
    } = &p;
    let mut m = Manifest::new();
    m.u("chain.target_block_time", *target_block_time)
        .size("chain.difficulty_window", *difficulty_window)
        .text("chain.difficulty_rule", DIFFICULTY_RULE_ID)
        .size("chain.DIFFICULTY_WARMUP", difficulty::DIFFICULTY_WARMUP)
        .size("chain.median_time_window", *median_time_window)
        .u("chain.future_time_limit", *future_time_limit)
        .u("chain.seed_epoch", *seed_epoch)
        .u("chain.seed_lag", *seed_lag);
    // The RandomX key schedule (E = seed_epoch, L = seed_lag): around the
    // first key change (E + L), at the lag itself, at the later key changes
    // 2E + L and 10E + L (the first heights where a dropped `- 1` in
    // `seed_height` moves the key: `h - L` is a multiple of E there), and at
    // the top of the height range.
    let (e, l) = (*seed_epoch, *seed_lag);
    let heights = [
        0,
        1,
        e + l,
        e + l + 1,
        10 * e,
        l,
        l + 1,
        2 * e + l,
        2 * e + l + 1,
        10 * e + l,
        10 * e + l + 1,
        u64::MAX,
    ];
    m.list(
        "chain.seed_height samples",
        heights.map(|h| seed_height(h, e, l)),
    )
    .list("chain.seed_height samples input (heights)", heights);
    // The activation table: every epoch, in order (docs/consensus.md §11);
    // the branch ids are identity.
    m.size("schedule.len", schedule.len());
    for (i, e) in schedule.epochs().iter().enumerate() {
        // Destructured so that a new field fails to compile here until it is
        // placed in the rules or the identity manifest (RTFP3-12).
        let Epoch {
            // A log label, not consensus data.
            name: _,
            activation_height,
            header_version,
            // Identity (identity_manifest).
            branch_id: _,
            verifier_id,
        } = *e;
        m.list(
            &format!("schedule.epoch[{i}] (activation, header version, verifier id)"),
            [
                activation_height,
                u64::from(header_version),
                u64::from(verifier_id),
            ],
        );
    }
    // The rules at genesis; later epochs differ only in the scheduled fields above.
    let TxRules {
        // Identity (identity_manifest).
        network_id: _,
        branch_id: _,
        genesis_id: _,
        fee_per_weight,
        max_block_weight,
    } = TxRules::at_height(&p, 0);
    m.u("rules.fee_per_weight", fee_per_weight)
        .u("rules.max_block_weight", max_block_weight);

    m.size("consensus.HEADER_SIZE", blacksilk_consensus::HEADER_SIZE)
        .u(
            "consensus.HEADER_VERSION",
            blacksilk_consensus::HEADER_VERSION,
        )
        .size("consensus.NONCE_OFFSET", blacksilk_consensus::NONCE_OFFSET)
        .bytes(
            "consensus.EMPTY_PX_ROOT",
            &blacksilk_consensus::genesis::EMPTY_PX_ROOT,
        )
        .size(
            "consensus.POW_BLOB_SIZE",
            blacksilk_consensus::POW_BLOB_SIZE,
        )
        .size(
            "consensus.POW_NONCE_OFFSET",
            blacksilk_consensus::POW_NONCE_OFFSET,
        )
        .bytes(
            "consensus.POW_BLOB_TAG",
            blacksilk_consensus::header::POW_BLOB_TAG,
        );
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
        .size("tx.MAX_PROGRAM_BYTES", tx::MAX_PROGRAM_BYTES)
        // px-deploy-row-caps: log2 caps of a registered function's own
        // tables, and of the tables it shares with the kernel.
        .list(
            "tx.PX_FN_LOG_CYCLES_KEYS_PROGRAM_IMAGE",
            [
                tx::PX_FN_LOG_CYCLES,
                tx::PX_FN_LOG_KEYS,
                tx::PX_FN_LOG_PROGRAM,
                tx::PX_FN_LOG_IMAGE,
            ]
            .map(u64::from),
        )
        .list(
            "tx.PX_LOG_ADD_BIT_LT_SHIFT_MUL_POSEIDON",
            [
                tx::PX_LOG_ADD,
                tx::PX_LOG_BIT,
                tx::PX_LOG_LT,
                tx::PX_LOG_SHIFT,
                tx::PX_LOG_MUL,
                tx::PX_LOG_POSEIDON,
            ]
            .map(u64::from),
        )
        .size("tx.SIG_DOMAIN_BYTES", tx::SIG_DOMAIN_BYTES)
        .list(
            "tx.SUPPORTED_VERIFIERS",
            tx::SUPPORTED_VERIFIERS.iter().map(|&v| u64::from(v)),
        );
    m.size("chain.MAX_BLOCK_BYTES", block::MAX_BLOCK_BYTES)
        .u("chain.MAX_BLOCK_TXS", block::MAX_BLOCK_TXS);
    m.u("emission.COIN", emission::COIN)
        .u("emission.MONEY_SUPPLY", emission::MONEY_SUPPLY)
        .u("emission.EMISSION_SPEED", emission::EMISSION_SPEED)
        .u("emission.TAIL_REWARD", emission::TAIL_REWARD);
    // The curve itself at a few points: (height, coins generated before it).
    let rewards = [
        (0, 0),
        (1, 0),
        (2, emission::block_reward(1, 0)),
        (1_000, 1_000 * emission::COIN),
        (1, emission::MONEY_SUPPLY - emission::COIN),
        (1, emission::MONEY_SUPPLY),
    ];
    m.list(
        "emission.block_reward samples",
        rewards.map(|(h, g)| emission::block_reward(h, g)),
    )
    .list(
        "emission.block_reward samples input (height, generated)",
        rewards.iter().flat_map(|&(h, g)| [h, g]),
    );
    randomx_entries(&mut m);
    m
}

/// The chain-side rule samples: outputs of consensus rule functions on fixed
/// inputs, independent of the network except where the rule reads the
/// network's own parameters (the fees read its `TxRules`).
fn rule_samples(network: Network) -> Manifest {
    let mut m = Manifest::new();

    // Difficulty (docs/consensus.md §4): the golden case of
    // consensus/tests/lwma_warm.rs at T = 120 and the v3 window: 87 on-target
    // blocks at 10^6, then the window-oldest stamp 1 300 s low (warmed clock:
    // 999 824), then only the window's stamps (no warm-up: 998 248); a
    // genesis-only history (D0), and the clock step and ancestor count.
    let (t, n) = (120, difficulty::DIFFICULTY_WINDOW);
    let steady: Vec<u64> = (0..87).map(|i| 1_000_000 + i * t).collect();
    let cd: Vec<u128> = (0..87u128).map(|i| (i + 1) * 1_000_000).collect();
    let mut ts = steady.clone();
    ts[11] -= 1_300;
    let cases: [(&[u64], &[u128], u64); 4] = [
        (&steady, &cd, 1),
        (&ts, &cd, 1),
        (&ts[11..], &cd[11..], 1),
        (&ts[..1], &cd[..1], 777),
    ];
    let name = "rules.sample.next_difficulty (T 120, N 75)";
    m.list(
        name,
        cases.map(|(ts, cd, d0)| difficulty::next_difficulty(ts, cd, t, n, d0)),
    );
    for (i, (ts, cd, d0)) in cases.into_iter().enumerate() {
        difficulty_input(&mut m, &format!("{name} input[{i}]"), ts, cd, (t, n, d0));
    }
    let steps = [120, 10, 2, 1];
    m.list(
        "rules.sample.clock_step (T 120, 10, 2, 1)",
        steps.map(difficulty::clock_step),
    )
    .list("rules.sample.clock_step (T 120, 10, 2, 1) input", steps)
    .size(
        "rules.sample.difficulty_ancestors(75)",
        difficulty::difficulty_ancestors(n),
    )
    .size("rules.sample.difficulty_ancestors(75) input", n);
    // The lower clamp (RTFP3-6): a tiny difficulty over a slow window gives
    // a result below 1, which the rule raises to 1.
    let (clamp_ts, clamp_cd, clamp_d0) = ([0, 1_000], [1, 2], 1);
    let name = "rules.sample.next_difficulty([0, 1000], [1, 2], T 120, N 75, D0 1)";
    m.u(
        name,
        difficulty::next_difficulty(&clamp_ts, &clamp_cd, t, n, clamp_d0),
    );
    difficulty_input(
        &mut m,
        &format!("{name} input"),
        &clamp_ts,
        &clamp_cd,
        (t, n, clamp_d0),
    );

    // Median time past (strict, lower median for an even count).
    let recent = [100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200];
    let four = [4, 1, 3, 2];
    let candidates = [150, 151];
    m.list(
        "rules.sample.median (11 stamps, 4 stamps)",
        [timestamp::median(&recent), timestamp::median(&four)],
    )
    .list("rules.sample.median (11 stamps, 4 stamps) input[0]", recent)
    .list("rules.sample.median (11 stamps, 4 stamps) input[1]", four)
    .list(
        "rules.sample.after_median_time_past (150, 151)",
        candidates.map(|s| u64::from(timestamp::after_median_time_past(s, &recent))),
    )
    .list(
        "rules.sample.after_median_time_past (150, 151) input.stamps",
        candidates,
    )
    .list(
        "rules.sample.after_median_time_past (150, 151) input.recent",
        recent,
    );
    // The future time limit at its boundary (RTFP3-5): now 1 000, FTL 360.
    let (stamps, now, ftl) = ([1_359, 1_360, 1_361], 1_000, 360);
    m.list(
        "rules.sample.within_future_limit (1359, 1360, 1361; now 1000, FTL 360)",
        stamps.map(|s| u64::from(timestamp::within_future_limit(s, now, ftl))),
    )
    .list(
        "rules.sample.within_future_limit (1359, 1360, 1361; now 1000, FTL 360) input.stamps",
        stamps,
    )
    .list(
        "rules.sample.within_future_limit (1359, 1360, 1361; now 1000, FTL 360) input (now, FTL)",
        [now, ftl],
    );

    // The proof-of-work target at its boundary: hash · d < 2^256.
    let mut half = [0u8; 32];
    half[31] = 0x80; // 2^255 (little-endian)
    let mut below = [0xffu8; 32];
    below[31] = 0x7f; // 2^255 − 1
    let hashes = [
        ([0xff; 32], 1),
        (half, 2),
        (below, 2),
        ([0; 32], 0),
        ([0; 32], u64::MAX),
    ];
    let name = "rules.sample.check_hash (max*1, 2^255*2, (2^255-1)*2, 0*0, 0*u64::MAX)";
    m.list(name, hashes.map(|(h, d)| u64::from(check_hash(&h, d))))
        .bytes(
            &format!("{name} input.hashes"),
            &hashes.map(|(h, _)| h).concat(),
        )
        .list(
            &format!("{name} input.difficulties"),
            hashes.map(|(_, d)| d),
        );

    // The block id and the transaction Merkle root.
    let header = BlockHeader {
        version: 1,
        height: 7,
        prev_id: [1; 32],
        timestamp: 1_700_000_000,
        difficulty: 1_000,
        tx_root: [2; 32],
        output_count: 5,
        output_root: [3; 32],
        px_root: [4; 32],
        nonce: 42,
    };
    let id_network = TEST_VECTOR_NETWORK_ID;
    m.bytes(
        "rules.sample.block_id (test-vector network id)",
        &header.id(id_network),
    )
    .bytes(
        "rules.sample.block_id (test-vector network id) input.header",
        &header.to_bytes(),
    )
    .u(
        "rules.sample.block_id (test-vector network id) input.network",
        id_network,
    )
    // The proof-of-work input of the same header (docs/consensus.md §3).
    .bytes(
        "rules.sample.pow_blob (test-vector network id)",
        &header.pow_blob(id_network),
    );
    let three = [[1; 32], [2; 32], [3; 32]];
    m.bytes("rules.sample.tx_root([])", &merkle::tx_root(&[]))
        .bytes(
            "rules.sample.tx_root([1; 32], [2; 32], [3; 32])",
            &merkle::tx_root(&three),
        )
        .bytes(
            "rules.sample.tx_root([1; 32], [2; 32], [3; 32]) input",
            &three.concat(),
        );

    // The output range (B-OMR, docs/consensus.md §7.1): a leaf, and the
    // roots over the first n leaves of key [i; 32], commitment [i + 100; 32],
    // height i / 2, coinbase for even i (the empty range, one peak, two and
    // three peaks).
    let one_leaf = ([1; 32], [2; 32], 3, true);
    m.bytes(
        "rules.sample.output_mmr.leaf ([1; 32], [2; 32], 3, coinbase)",
        &mmr::leaf(&one_leaf.0, &one_leaf.1, one_leaf.2, one_leaf.3),
    );
    leaf_input(
        &mut m,
        "rules.sample.output_mmr.leaf ([1; 32], [2; 32], 3, coinbase) input",
        &[one_leaf],
    );
    let mut outputs = mmr::OutputFrontier::new();
    let mut pushed = Vec::new();
    for n in 0u8..=7 {
        if [0, 1, 2, 3, 7].contains(&n) {
            let name = format!("rules.sample.output_mmr.root ({n} leaves)");
            m.bytes(&name, &outputs.root());
            leaf_input(&mut m, &format!("{name} input"), &pushed);
        }
        let leaf = ([n; 32], [n + 100; 32], u64::from(n / 2), n % 2 == 0);
        outputs.push(mmr::leaf(&leaf.0, &leaf.1, leaf.2, leaf.3));
        pushed.push(leaf);
    }

    // The genesis-nonce derivation (Bitcoin block 0, H = 0, test-vector id).
    let btc0 =
        parse_display_hex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("Bitcoin block 0's hash");
    let (nonce_network, nonce_height) = (TEST_VECTOR_NETWORK_ID, 0);
    m.u(
        "rules.sample.genesis_nonce (Bitcoin block 0, test-vector id)",
        derive_genesis_nonce(nonce_network, nonce_height, &btc0),
    )
    .bytes(
        "rules.sample.genesis_nonce (Bitcoin block 0, test-vector id) input.beacon",
        &btc0,
    )
    .list(
        "rules.sample.genesis_nonce (Bitcoin block 0, test-vector id) input (network, height)",
        [u64::from(nonce_network), nonce_height],
    );

    // The signature domain layout (RT-14): network id, branch id, genesis id.
    let domain = SigDomain {
        network_id: 0x0102_0304,
        branch_id: 0x0506_0708,
        genesis_id: [9; 32],
    };
    m.bytes(
        "rules.sample.sig_domain (0x01020304, 0x05060708, [9; 32])",
        &domain.bytes(),
    )
    .list(
        "rules.sample.sig_domain (0x01020304, 0x05060708, [9; 32]) input (network, branch)",
        [domain.network_id, domain.branch_id].map(u64::from),
    )
    .bytes(
        "rules.sample.sig_domain (0x01020304, 0x05060708, [9; 32]) input.genesis",
        &domain.genesis_id,
    );

    // Weights and fees (T8, R12-2): max_weight over transfer shapes; the v1
    // part of PX and deploy transactions (0 without v1 inputs); the exact v1
    // fee; the deploy fee at three program sizes (the vault's budget and
    // output words).
    let shapes = [(1, 2), (2, 2), (1, 16), (64, 16), (1, 0), (64, 2)];
    let px_shapes = [(0, 2), (1, 0), (64, 16), (1, 2), (64, 2)];
    let name = "rules.sample.max_weight (1,2) (2,2) (1,16) (64,16) (1,0) (64,2)";
    m.list(name, shapes.map(|(i, o)| max_weight(i, o)))
        .list(&format!("{name} input (inputs, outputs)"), pairs(&shapes));
    let name = "rules.sample.px_v1_part_weight (0,2) (1,0) (64,16) (1,2) (64,2)";
    m.list(name, px_shapes.map(|(i, o)| v1_part_weight(i, o)))
        .list(
            &format!("{name} input (inputs, outputs)"),
            pairs(&px_shapes),
        );
    let rules = TxRules::at_height(&ChainParams::for_network(network), 0);
    let name = "rules.sample.standard_fee (1,2) (2,2) (1,16) (64,16) (1,0) (64,2)";
    m.list(
        name,
        shapes.map(|(i, o)| rules.standard_fee(i, o).unwrap_or(u64::MAX)),
    )
    .list(&format!("{name} input (inputs, outputs)"), pairs(&shapes));
    let (ins, outs) = (1, 2);
    let lens = [1, 4_096, tx::MAX_PROGRAM_BYTES];
    let (b, out_words) = (blacksilk_px::vault::BUDGET, blacksilk_px::vault::OUT_WORDS);
    let registration = |len: usize| Registration::new(vec![0; len], b, out_words);
    let name = "rules.sample.deploy_fee (1 in, 2 out; 1, 4 096, MAX_PROGRAM_BYTES)";
    m.list(
        name,
        lens.map(|len| deploy_fee(ins, outs, &[registration(len)], &rules)),
    )
    .list(
        &format!("{name} input (inputs, outputs)"),
        pairs(&[(ins, outs)]),
    )
    .list(
        &format!("{name} input.program_lengths"),
        lens.map(|len| len as u64),
    )
    .list(
        &format!("{name} input.budget (cycles, keys, add, bit, lt, shift, mul, poseidon)"),
        [
            b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
        ]
        .map(|w| w as u64),
    )
    .u(&format!("{name} input.out_words"), out_words);
    m.extend(transaction_samples().clone());
    m
}

/// The input entries of a difficulty sample: its timestamps, its cumulative
/// difficulties (each fits in 64 bits) and `(T, N, D0)`.
fn difficulty_input(
    m: &mut Manifest,
    name: &str,
    timestamps: &[u64],
    cumulative: &[u128],
    (t, n, d0): (u64, usize, u64),
) {
    m.list(&format!("{name}.timestamps"), timestamps.iter().copied())
        .list(
            &format!("{name}.cumulative_difficulties"),
            cumulative.iter().map(|&c| {
                u64::try_from(c).expect("a sampled cumulative difficulty fits in 64 bits")
            }),
        )
        .list(&format!("{name} (T, N, D0)"), [t, n as u64, d0]);
}

/// The input entry of an output-range sample: per leaf `key ‖ commitment ‖
/// LE64(height) ‖ u8(coinbase)`, in push order (empty for no leaf).
fn leaf_input(m: &mut Manifest, name: &str, leaves: &[([u8; 32], [u8; 32], u64, bool)]) {
    let mut bytes = Vec::new();
    for (key, commitment, height, coinbase) in leaves {
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(commitment);
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.push(u8::from(*coinbase));
    }
    m.bytes(name, &bytes);
}

/// `(inputs, outputs)` shapes as a flat list.
fn pairs(shapes: &[(usize, usize)]) -> Vec<u64> {
    shapes
        .iter()
        .flat_map(|&(i, o)| [i as u64, o as u64])
        .collect()
}

/// The RandomX configuration, read from the crate
/// (`blacksilk_randomx::config_entries`, RTFP3-2; BlackSilk's Argon2 salt,
/// record #rx-salt), and its pinned known answer
/// (`blacksilk_randomx::FINGERPRINT_KAT`, BlackSilk's vector bs-1a).
/// No hash is computed here: a light-mode hash needs a 256 MiB cache, too
/// costly for `/info` and `--version`. The known answer is a pinned copy that
/// the crate's vector test requires the crate to compute, as
/// `zkvm.CIRCUIT_DIGEST` is for the circuit.
fn randomx_entries(m: &mut Manifest) {
    use blacksilk_randomx::ConfigValue;
    m.text(
        "randomx.variant",
        "RandomX v1, BlackSilk Argon2 salt, light-mode verification",
    )
    .size("randomx.HASH_SIZE", blacksilk_randomx::HASH_SIZE)
    .size("randomx.MAX_KEY_SIZE", blacksilk_randomx::MAX_KEY_SIZE);
    for (name, value) in blacksilk_randomx::config_entries() {
        let name = format!("randomx.{name}");
        match value {
            ConfigValue::Int(v) => m.u(&name, v),
            ConfigValue::Bytes(b) => m.bytes(&name, b),
            ConfigValue::Ints(l) => m.list(&name, l),
        };
    }
    let kat = blacksilk_randomx::FINGERPRINT_KAT;
    m.bytes("randomx.KAT.key", kat.key)
        .bytes("randomx.KAT.input", kat.input)
        .text("randomx.KAT.hash", kat.hash);
}

/// The fixture of the transaction samples: a regtest-shaped transfer with two
/// inputs and three outputs (so the Bulletproofs+ clawback of the weight
/// applies), the coinbase that created its first real input, and the ring
/// members' records, signed under [`fixture_rules`]. Generated by
/// `tests/fingerprint_fixture.rs` (an ignored test that rewrites the file);
/// regenerate it only with a reviewed rule change that invalidates it.
const FIXTURE: &str = include_str!("fingerprint_fixture.txt");

/// The rules the fixture transfer is signed and validated under: the
/// test-vector network id and a fixed genesis id (network-independent, so
/// the samples are the same on every network), the v3 branch id, and the
/// fee and block-weight constants.
pub fn fixture_rules() -> TxRules {
    TxRules {
        network_id: TEST_VECTOR_NETWORK_ID,
        branch_id: BRANCH_ID_V3,
        genesis_id: [0x5a; 32],
        fee_per_weight: tx::FEE_PER_WEIGHT,
        max_block_weight: tx::MAX_BLOCK_WEIGHT,
    }
}

/// The parsed [`FIXTURE`].
pub struct Fixture {
    /// The height the transfer is validated at.
    pub height: u64,
    pub transfer: Transfer,
    pub coinbase: Transaction,
    /// The ring members' records, by global index.
    pub outputs: BTreeMap<u64, OutputRecord>,
}

impl Fixture {
    /// Parses the fixture text: `height <h>`, `coinbase <hex>`, `transfer
    /// <hex>` and `output <index> <height> <coinbase 0|1> <key hex>
    /// <commitment hex>` lines; `#` starts a comment.
    pub fn parse(text: &str) -> Option<Self> {
        let point = |h: &str| {
            let b: [u8; 32] = hex_bytes(h)?.try_into().ok()?;
            Point::decode(&b)
        };
        let (mut height, mut transfer, mut coinbase) = (None, None, None);
        let mut outputs = BTreeMap::new();
        for line in text.lines().map(str::trim) {
            let f: Vec<&str> = line.split_whitespace().collect();
            match f.as_slice() {
                [] => {}
                [c, ..] if c.starts_with('#') => {}
                ["height", h] => height = Some(h.parse().ok()?),
                ["transfer", t] => match Transaction::decode(&hex_bytes(t)?).ok()? {
                    Transaction::Transfer(t) => transfer = Some(*t),
                    _ => return None,
                },
                ["coinbase", c] => coinbase = Some(Transaction::decode(&hex_bytes(c)?).ok()?),
                ["output", i, h, cb, key, cm] => {
                    let rec = OutputRecord {
                        key: OutputKey {
                            one_time_key: point(key)?,
                            commitment: point(cm)?,
                        },
                        height: h.parse().ok()?,
                        coinbase: *cb == "1",
                    };
                    outputs.insert(i.parse().ok()?, rec);
                }
                _ => return None,
            }
        }
        Some(Fixture {
            height: height?,
            transfer: transfer?,
            coinbase: coinbase?,
            outputs,
        })
    }

    /// The checked-in fixture.
    pub fn get() -> &'static Fixture {
        static F: OnceLock<Fixture> = OnceLock::new();
        F.get_or_init(|| Fixture::parse(FIXTURE).expect("the fingerprint fixture parses"))
    }
}

/// The golden PX fixture (decisions RES-FREEZE item 2 and "Run E
/// follow-ups"; docs/reviews/v3-consensus-changes.md#px-ciphertext-r): a
/// proven PX transaction (`px_fixture.bin`, its encoding) that bridges value
/// in from the fixture's first coinbase output (its ring is the fixture
/// transfer's first ring), anchored at the empty PX tree, and a deploy of the
/// reference vault (`px_fixture.txt`) spending the second coinbase output.
/// Both are signed under [`fixture_rules`] and valid at the fixture's height
/// on [`FixtureChain`]. Generated by `tests/px_fixture.rs` (an ignored test
/// that proves the transaction and rewrites both files); regenerate them
/// only with a reviewed rule change that invalidates them.
const PX_FIXTURE_TX: &[u8] = include_bytes!("px_fixture.bin");
const PX_FIXTURE_TEXT: &str = include_str!("px_fixture.txt");

/// The parsed golden PX fixture.
pub struct PxFixture {
    pub px: blacksilk_tx::px::PxTx,
    pub deploy: blacksilk_tx::px::PxDeploy,
}

impl PxFixture {
    /// Parses the encoded PX transaction and the fixture text (a `deploy
    /// <hex>` line; `#` starts a comment).
    pub fn parse(px: &[u8], text: &str) -> Option<Self> {
        let Transaction::Px(px) = Transaction::decode(px).ok()? else {
            return None;
        };
        let mut deploy = None;
        for line in text.lines().map(str::trim) {
            let f: Vec<&str> = line.split_whitespace().collect();
            match f.as_slice() {
                [] => {}
                [c, ..] if c.starts_with('#') => {}
                ["deploy", d] => match Transaction::decode(&hex_bytes(d)?).ok()? {
                    Transaction::PxDeploy(d) => deploy = Some(*d),
                    _ => return None,
                },
                _ => return None,
            }
        }
        Some(PxFixture {
            px: *px,
            deploy: deploy?,
        })
    }

    /// The checked-in golden PX fixture.
    pub fn get() -> &'static PxFixture {
        static F: OnceLock<PxFixture> = OnceLock::new();
        F.get_or_init(|| {
            PxFixture::parse(PX_FIXTURE_TX, PX_FIXTURE_TEXT).expect("the golden PX fixture parses")
        })
    }
}

/// Full validation of the golden PX transaction on the fixture chain at the
/// fixture's height, with or without PX5 (the proof verification). Not a
/// manifest entry (verifying the proof costs about 0.2 s and is not run for
/// `--version`); `tests/px_fixture.rs` checks it.
pub fn px_fixture_verdict(px: &blacksilk_tx::px::PxTx, with_proof: bool) -> Result<(), TxError> {
    let f = Fixture::get();
    let chain = FixtureChain::new(&f.outputs);
    let rules = fixture_rules();
    if with_proof {
        blacksilk_tx::validate::validate_px(px, &chain, f.height, &rules)
    } else {
        blacksilk_tx::validate::validate_px_without_proof(px, &chain, f.height, &rules)
    }
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    ::hex::decode(s).ok()
}

/// The chain view of the verdict samples: the fixture's ring members, with
/// some removed or some key images spent, and the PX state of a chain with
/// no PX transaction yet (its one recent root is the empty tree's, the
/// golden PX transaction's anchor; no nullifier is spent; no contract is
/// deployed), except for the PX pool and the tree size, which a sample may
/// set (`pool`, `tree_size`; 0 in the fixture's context, record
/// `fingerprint-px-samples`).
struct FixtureChain<'a> {
    outputs: &'a BTreeMap<u64, OutputRecord>,
    missing: Option<u64>,
    spent: Option<Point>,
    /// The PX pool (PX4).
    pool: u128,
    /// The PX tree's size (B8). Only the capacity rule reads it:
    /// `px_root_after` appends to the empty tree whatever the size, so a
    /// block sample on a non-empty size still commits to the empty tree's
    /// root after its leaves (`BlockContext::committing` reads the same
    /// view, so B-PXR holds).
    tree_size: u64,
}

impl<'a> FixtureChain<'a> {
    fn new(outputs: &'a BTreeMap<u64, OutputRecord>) -> Self {
        FixtureChain {
            outputs,
            missing: None,
            spent: None,
            pool: 0,
            tree_size: 0,
        }
    }
}

/// The anchor of the golden PX transaction: the root of the empty PX tree.
pub fn px_fixture_anchor() -> blacksilk_px::core::Digest {
    static ROOT: OnceLock<blacksilk_px::core::Digest> = OnceLock::new();
    *ROOT.get_or_init(|| blacksilk_px::state::State::new().root())
}

impl ChainView for FixtureChain<'_> {
    fn output(&self, global_index: u64) -> Option<OutputRecord> {
        (self.missing != Some(global_index))
            .then(|| self.outputs.get(&global_index).copied())
            .flatten()
    }
    fn is_key_image_spent(&self, key_image: &Point) -> bool {
        self.spent == Some(*key_image)
    }
    fn px_is_recent_root(&self, anchor: &blacksilk_px::core::Digest) -> bool {
        *anchor == px_fixture_anchor()
    }
    fn px_nullifier_spent(&self, _: &blacksilk_px::core::Digest) -> bool {
        false
    }
    fn px_pool(&self) -> u128 {
        self.pool
    }
    fn px_function(
        &self,
        _: &blacksilk_px::core::Digest,
        _: &[u8; 32],
    ) -> Option<blacksilk_tx::validate::PxProgram> {
        None
    }
    fn px_contract_exists(&self, _: &blacksilk_px::core::Digest) -> bool {
        false
    }
    fn px_tree_size(&self) -> u64 {
        self.tree_size
    }
    fn px_root_after(
        &self,
        leaves: &[blacksilk_px::core::Digest],
    ) -> Option<blacksilk_px::core::Digest> {
        blacksilk_px::state::State::new().root_after(leaves)
    }
    /// No block is validated on this view (only transactions): the fixture's
    /// outputs are sparse ring members, not a range, so the range is empty.
    fn output_frontier(&self) -> blacksilk_tx::mmr::OutputFrontier {
        blacksilk_tx::mmr::OutputFrontier::new()
    }
}

/// The transaction samples (network-independent, computed once per process):
///
/// - `Transaction::weight` of the fixture transfer and coinbase, and of a PX
///   transaction with the transfer's v1 part and with none (RTFP3-3);
/// - the transfer's id and signature message, and the coinbase's id (RTFP3-1);
/// - the PX and deploy samples of the golden PX fixture
///   ([`px_transaction_samples`]: ids, the PX binding, signature messages,
///   stateless PX verdicts including the ciphertext `R` rule, deploy
///   verdicts);
/// - **verdict samples** (RTFP3-4): `validate_transfer` on the fixture and on
///   one variant per `TxError` class a transfer can reach (each variant
///   changes one field, or the chain view, or the validation height), as
///   [`verdict_text`] of the result (never its `Debug` text, which the
///   standard library does not keep stable across Rust versions;
///   `fingerprint-stable-verdicts`). Not sampled: `TooLarge` (no transfer shape
///   within the count limits reaches `MAX_TX_SIZE`) and `WeightOverflow`
///   (the fee of every bounded shape fits in 64 bits).
pub fn transaction_samples() -> &'static Manifest {
    static M: OnceLock<Manifest> = OnceLock::new();
    M.get_or_init(compute_transaction_samples)
}

fn compute_transaction_samples() -> Manifest {
    use blacksilk_crypto::generators::G;
    use blacksilk_crypto::RistrettoPoint;
    use blacksilk_tx::validate::validate_transfer;
    let f = Fixture::get();
    let rules = fixture_rules();
    let t = &f.transfer;
    let mut m = Manifest::new();

    let px = |inputs: Vec<blacksilk_tx::Input>| {
        Transaction::Px(Box::new(blacksilk_tx::px::PxTx {
            inputs,
            outputs: t.outputs.clone(),
            payouts: Vec::new(),
            fee: 0,
            bridge_in: 0,
            bridge_out: 0,
            window: blacksilk_px::core::call::Window::UNBOUNDED,
            anchor: [0; 8],
            nullifiers: [[0; 8]; 2],
            commitments: [[0; 8]; 2],
            ciphertexts: [Vec::new(), Vec::new()],
            functions: Vec::new(),
            pseudo_outs: Vec::new(),
            range_proof: None,
            signatures: Vec::new(),
            proof: Vec::new(),
        }))
    };
    let weighed = [
        Transaction::from(t.clone()),
        f.coinbase.clone(),
        px(t.inputs.clone()),
        px(Vec::new()),
    ];
    let name =
        "rules.sample.weight (fixture transfer 2-in 3-out, coinbase, PX 2-in 3-out, PX 0-in 3-out)";
    m.list(name, weighed.iter().map(Transaction::weight)).bytes(
        &format!("{name} input"),
        &weighed
            .iter()
            .flat_map(|tx| input_hash(&tx.encode()))
            .collect::<Vec<u8>>(),
    );
    m.bytes(
        "rules.sample.tx_hash (fixture transfer)",
        &Transaction::from(t.clone()).hash(),
    )
    .bytes(
        "rules.sample.signature_message (fixture transfer, fixture rules)",
        &t.signature_message(rules.domain()),
    )
    .bytes(
        "rules.sample.tx_hash (fixture coinbase)",
        &f.coinbase.hash(),
    );

    // B-OMR and B-PXR: the header commitments of a block holding only the
    // fixture coinbase on the genesis state (no output, the empty PX tree),
    // as `BlockContext::committing` computes them: LE64(output_count) ‖
    // output_root ‖ px_root. And the PX root after two fixed commitments.
    let height = match &f.coinbase {
        Transaction::Coinbase(c) => c.height,
        _ => unreachable!("the fixture coinbase"),
    };
    let genesis_state = blacksilk_tx::state::MemoryChain::new();
    let ctx = blacksilk_tx::BlockContext::committing(
        height,
        0,
        std::slice::from_ref(&f.coinbase),
        &genesis_state,
    );
    let mut commitments = ctx.output_count.to_le_bytes().to_vec();
    commitments.extend_from_slice(&ctx.output_root);
    commitments.extend_from_slice(&ctx.px_root);
    m.bytes(
        "rules.sample.block_commitments (fixture coinbase on the genesis state)",
        &commitments,
    )
    .u(
        "rules.sample.block_commitments (fixture coinbase on the genesis state) input.height",
        height,
    );
    let leaves = [[1, 2, 3, 4, 5, 6, 7, 8], [9; 8]];
    let name = "rules.sample.px_root_after ([1, 2, 3, 4, 5, 6, 7, 8], [9; 8]; empty tree)";
    m.bytes(
        name,
        &blacksilk_tx::px::digest_bytes(
            &genesis_state
                .px()
                .root_after(&leaves)
                .expect("two leaves fit"),
        ),
    )
    .list(
        &format!("{name} input"),
        leaves.iter().flatten().map(|&x| u64::from(x)),
    );

    // One variant per error class; each changes one thing of the valid case.
    let identity = Point::from_point(RistrettoPoint::default());
    let plus_g = |p: &Point| Point::from_point(p.point() + G);
    let full = FixtureChain::new(&f.outputs);
    // The verdict, the input hash of the transfer, and what the case changes
    // besides the transfer ([`verdict_context`]).
    let verdict =
        |tx: &Transfer, chain: &FixtureChain, height: u64, case_rules: &TxRules| Sampled {
            verdict: verdict_text(validate_transfer(tx, chain, height, case_rules)),
            input: input_hash(&Transaction::from(tx.clone()).encode()),
            context: verdict_context(chain, height, case_rules),
        };
    let variant = |change: &dyn Fn(&mut Transfer)| {
        let mut v = t.clone();
        change(&mut v);
        verdict(&v, &full, f.height, &rules)
    };
    let last_ring_member = *t.inputs[1].ring.last().expect("a full ring");
    let other_branch = TxRules {
        branch_id: rules.branch_id ^ 1,
        ..rules
    };
    let cases: [(&str, Sampled); 21] = [
        ("valid", verdict(t, &full, f.height, &rules)),
        ("no inputs", variant(&|v| v.inputs.clear())),
        ("one output", variant(&|v| v.outputs.truncate(1))),
        (
            "identity key image",
            variant(&|v| v.inputs[0].key_image = identity),
        ),
        (
            "key images unsorted",
            variant(&|v| {
                v.inputs.swap(0, 1);
                v.pseudo_outs.swap(0, 1);
                v.signatures.swap(0, 1);
            }),
        ),
        ("ring unsorted", variant(&|v| v.inputs[0].ring.swap(0, 1))),
        (
            "identity output key",
            variant(&|v| v.outputs[0].one_time_key = identity),
        ),
        (
            "identity ephemeral",
            variant(&|v| v.outputs[0].ephemeral = identity),
        ),
        ("outputs unsorted", variant(&|v| v.outputs.swap(0, 1))),
        (
            "missing pseudo-output",
            variant(&|v| {
                v.pseudo_outs.pop();
            }),
        ),
        (
            "missing signature",
            variant(&|v| {
                v.signatures.pop();
            }),
        ),
        (
            "identity auxiliary image",
            variant(&|v| v.signatures[0].d = identity),
        ),
        (
            "short range proof",
            variant(&|v| {
                v.range_proof.l.pop();
            }),
        ),
        ("fee + 1", variant(&|v| v.fee += 1)),
        (
            "unbalanced",
            variant(&|v| v.pseudo_outs[0] = plus_g(&v.pseudo_outs[0])),
        ),
        (
            "balanced, range proof invalid",
            variant(&|v| {
                v.pseudo_outs[0] = plus_g(&v.pseudo_outs[0]);
                v.outputs[0].commitment = plus_g(&v.outputs[0].commitment);
            }),
        ),
        (
            "key image spent",
            verdict(
                t,
                &FixtureChain {
                    spent: Some(t.inputs[1].key_image),
                    ..full
                },
                f.height,
                &rules,
            ),
        ),
        (
            "ring member unknown",
            verdict(
                t,
                &FixtureChain {
                    missing: Some(last_ring_member),
                    ..full
                },
                f.height,
                &rules,
            ),
        ),
        (
            "coinbase ring member immature (height 60)",
            verdict(t, &full, 60, &rules),
        ),
        (
            "other branch id",
            verdict(t, &full, f.height, &other_branch),
        ),
        (
            "signature of the other input",
            variant(&|v| v.signatures[0] = v.signatures[1].clone()),
        ),
    ];
    // The context every case shares (the fixture's height and rules).
    m.list(
        "rules.sample.verdict input.fixture (height, fee per weight, max block weight)",
        [f.height, rules.fee_per_weight, rules.max_block_weight],
    )
    .bytes(
        "rules.sample.verdict input.fixture signature domain",
        &rules.domain().bytes(),
    );
    for (name, v) in cases {
        v.record(&mut m, &format!("rules.sample.verdict ({name})"));
    }
    px_transaction_samples(&mut m);
    m
}

/// The context entries of a verdict case validated on `chain` at `height`
/// under `rules`: what differs from the fixture's context (the full fixture
/// view, the fixture's height and [`fixture_rules`]); empty for a case in the
/// fixture's context. `FixtureChain` and `TxRules` are destructured, so a new
/// field fails to compile here until its context entry is written.
fn verdict_context(chain: &FixtureChain, height: u64, rules: &TxRules) -> Manifest {
    let f = Fixture::get();
    let FixtureChain {
        outputs,
        missing,
        spent,
        pool,
        tree_size,
    } = chain;
    let TxRules {
        network_id,
        branch_id,
        genesis_id,
        fee_per_weight,
        max_block_weight,
    } = *rules;
    let fixture = fixture_rules();
    // Every case reads the fixture's ring members; a case that removes one
    // says so in `missing`.
    assert!(
        std::ptr::eq(*outputs, &f.outputs),
        "a verdict case reads other outputs than the fixture's"
    );
    let mut context = Manifest::new();
    if let Some(k) = spent {
        context.bytes("spent key image", k.bytes());
    }
    if let Some(i) = missing {
        context.u("missing ring member", *i);
    }
    if *pool != 0 {
        context.u(
            "pool",
            u64::try_from(*pool).expect("a sampled pool fits in 64 bits"),
        );
    }
    if *tree_size != 0 {
        context.u("tree size", *tree_size);
    }
    if height != f.height {
        context.u("height", height);
    }
    let domain = SigDomain {
        network_id,
        branch_id,
        genesis_id,
    };
    if domain != fixture.domain() {
        context.bytes("signature domain", &domain.bytes());
    }
    if (fee_per_weight, max_block_weight) != (fixture.fee_per_weight, fixture.max_block_weight) {
        context.list(
            "fees (fee per weight, max block weight)",
            [fee_per_weight, max_block_weight],
        );
    }
    context
}

/// The text of a sampled verdict: `Ok(())`, or `Err(<text>)` with
/// [`TxError::fingerprint_text`]. The same text the derived `Debug` printed
/// when the samples were pinned, written out so that the rules fingerprint
/// does not depend on the toolchain (record `fingerprint-stable-verdicts`).
/// Never `format!("{:?}")`.
fn verdict_text(r: Result<(), TxError>) -> String {
    match r {
        Ok(()) => "Ok(())".to_string(),
        Err(e) => format!("Err({})", e.fingerprint_text()),
    }
}

/// The text of a sampled block verdict: `Ok(())`, or `Err(<text>)` with
/// [`BlockError::fingerprint_text`] (record `fingerprint-px-samples`; as
/// [`verdict_text`], never `format!("{:?}")`).
fn block_verdict_text(r: Result<(), BlockError>) -> String {
    match r {
        Ok(()) => "Ok(())".to_string(),
        Err(e) => format!("Err({})", e.fingerprint_text()),
    }
}

/// A sampled verdict and its input (fingerprint-sample-inputs): the
/// [`input_hash`] of the sampled transaction's encoding, and the context
/// entries of a case that changes the chain view, the height or the rules
/// instead of the transaction (empty otherwise).
struct Sampled {
    verdict: String,
    input: [u8; 32],
    context: Manifest,
}

impl Sampled {
    /// A stateless verdict of `tx` (no chain view, height or rules: no
    /// context entry).
    fn of(verdict: String, tx: &Transaction) -> Self {
        Sampled {
            verdict,
            input: input_hash(&tx.encode()),
            context: Manifest::new(),
        }
    }

    /// `<name> = verdict`, `<name> input = input hash`, and one `<name>
    /// input.<part>` entry per context entry.
    fn record(self, m: &mut Manifest, name: &str) {
        use blacksilk_px::fingerprint::Value;
        m.text(name, &self.verdict)
            .bytes(&format!("{name} input"), &self.input);
        for (part, value) in self.context.entries() {
            let entry = format!("{name} input.{part}");
            match value {
                Value::U64(x) => m.u(&entry, *x),
                Value::I64(x) => m.i(&entry, *x),
                Value::Text(t) => m.text(&entry, t),
                Value::Bytes(b) => m.bytes(&entry, b),
                Value::List(l) => m.list(&entry, l.iter().copied()),
            };
        }
    }
}

/// The PX and deploy samples on the golden PX fixture ([`PxFixture`]):
///
/// - the PX transaction's id, its proof binding `h_tx` and signature message
///   under [`fixture_rules`], its weight and encoded size;
/// - **stateless PX verdicts** (structure, balance and the strict proof
///   decoding, in full validation's order) on the transaction and on one
///   variant per stateless class, including the ciphertext `R` rule
///   (`px-ciphertext-r`): an identity `R`, a non-canonical `R` (`p`) and the
///   top bit set. The proof is decoded, not verified: verification (PX5)
///   costs about 0.2 s, too much for `--version`; `tests/px_fixture.rs`
///   checks the full verdicts;
/// - the deploy's id, contract id and signature message, and full
///   `validate_deploy` verdicts on it and its variants (no proof involved).
fn px_transaction_samples(m: &mut Manifest) {
    use blacksilk_tx::px::{check_px_balance, check_px_structure, PxDeploy, PxTx};
    use blacksilk_tx::validate::{decode_px_proof, validate_deploy};
    let p = PxFixture::get();
    let f = Fixture::get();
    let rules = fixture_rules();
    let px_tx = Transaction::Px(Box::new(p.px.clone()));
    m.bytes("rules.sample.px.tx_hash (golden PX)", &px_tx.hash())
        .bytes(
            "rules.sample.px.binding (golden PX, fixture rules)",
            &p.px.binding(rules.domain()),
        )
        .bytes(
            "rules.sample.px.signature_message (golden PX, fixture rules)",
            &p.px.signature_message(rules.domain()),
        )
        .u("rules.sample.px.weight (golden PX)", px_tx.weight())
        .size(
            "rules.sample.px.encoded_len (golden PX)",
            p.px.encoded_len(),
        );

    let stateless = |t: &PxTx| {
        Sampled::of(
            verdict_text(
                check_px_structure(t)
                    .and_then(|_| check_px_balance(t))
                    .and_then(|_| decode_px_proof(t).map(|_| ())),
            ),
            &Transaction::Px(Box::new(t.clone())),
        )
    };
    let variant = |change: &dyn Fn(&mut PxTx)| {
        let mut v = p.px.clone();
        change(&mut v);
        stateless(&v)
    };
    // `p = 2^255 − 19`: a non-canonical encoding of zero.
    let mut p_bytes = [0xff; 32];
    p_bytes[0] = 0xed;
    p_bytes[31] = 0x7f;
    let px_cases: [(&str, Sampled); 10] = [
        ("valid", stateless(&p.px)),
        (
            "identity R in ciphertext 0",
            variant(&|v| v.ciphertexts[0][..32].fill(0)),
        ),
        (
            "non-canonical R (p) in ciphertext 1",
            variant(&|v| v.ciphertexts[1][..32].copy_from_slice(&p_bytes)),
        ),
        (
            "R with the top bit set in ciphertext 0",
            variant(&|v| v.ciphertexts[0][31] |= 0x80),
        ),
        ("fee + 1", variant(&|v| v.fee += 1)),
        (
            "equal nullifiers",
            variant(&|v| v.nullifiers[1] = v.nullifiers[0]),
        ),
        (
            "inverted window",
            variant(&|v| {
                v.window.not_before = 10;
                v.window.not_after = 9;
            }),
        ),
        ("bridge_in + 1", variant(&|v| v.bridge_in += 1)),
        (
            "missing signature",
            variant(&|v| {
                v.signatures.pop();
            }),
        ),
        (
            "truncated proof",
            variant(&|v| {
                let half = v.proof.len() / 2;
                v.proof.truncate(half);
            }),
        ),
    ];
    for (name, v) in px_cases {
        v.record(m, &format!("rules.sample.px.stateless_verdict ({name})"));
    }

    let d = &p.deploy;
    m.bytes(
        "rules.sample.deploy.tx_hash (golden deploy)",
        &Transaction::PxDeploy(Box::new(d.clone())).hash(),
    )
    .list(
        "rules.sample.deploy.contract_id (golden deploy)",
        d.contract_id().map(u64::from),
    )
    .bytes(
        "rules.sample.deploy.signature_message (golden deploy, fixture rules)",
        &d.signature_message(rules.domain()),
    );
    let chain = FixtureChain::new(&f.outputs);
    // Every deploy case is validated in the fixture's context (the transfer
    // verdicts' `input.fixture` entries), so its context is empty; it is
    // computed by the same `verdict_context`, which fails to compile when
    // `FixtureChain` or `TxRules` gains a field.
    let deploy_verdict = |change: &dyn Fn(&mut PxDeploy)| {
        let mut v = d.clone();
        change(&mut v);
        Sampled {
            verdict: verdict_text(validate_deploy(&v, &chain, f.height, &rules)),
            input: input_hash(&Transaction::PxDeploy(Box::new(v)).encode()),
            context: verdict_context(&chain, f.height, &rules),
        }
    };
    let deploy_cases: [(&str, Sampled); 5] = [
        ("valid", deploy_verdict(&|_| {})),
        ("fee + 1", deploy_verdict(&|v| v.fee += 1)),
        (
            "unsupported ABI",
            deploy_verdict(&|v| v.programs[0].abi += 1),
        ),
        ("other salt", deploy_verdict(&|v| v.salt[0] ^= 1)),
        // px-deploy-row-caps: one row above the shared bit-table cap
        // (2,000 + 2·7,193 > 2^14); the same varint length, so the fee holds.
        (
            "bit budget above its cap",
            deploy_verdict(&|v| v.programs[0].budget.bit = 7_193),
        ),
    ];
    for (name, v) in deploy_cases {
        v.record(m, &format!("rules.sample.deploy.verdict ({name})"));
    }
    px_context_samples(m);
}

/// The golden PX transaction with `bridge_out = bridge_in + 1` and its first
/// pseudo-output lowered by `(bridge_in + 1)·H`: it still balances
/// (`check_px_balance`: `Σ pseudo_outs − Σ outputs = (fee + bridge_in +
/// Σ payouts − bridge_out)·H`), so it passes every stateless rule, and takes
/// one unit out of the pool (PX4: `pool + bridge_in ≥ bridge_out` holds
/// exactly from a pool of 1). The CLSAG signs `bridge_out`, so a case that
/// passes PX4 fails at the signature.
fn px_bridge_out_variant(px: &blacksilk_tx::px::PxTx) -> blacksilk_tx::px::PxTx {
    let mut v = px.clone();
    v.bridge_out = v.bridge_in + 1;
    let shift = blacksilk_crypto::Scalar::from(v.bridge_out) * blacksilk_crypto::generators::h();
    v.pseudo_outs[0] = Point::from_point(v.pseudo_outs[0].point() - shift);
    v
}

/// The contextual PX samples on the golden PX transaction (record
/// `fingerprint-px-samples`), as boundary pairs: one case on each side of
/// the rule's bound, the passing one reaching a later, distinct verdict.
///
/// - **Transaction verdicts** (`rules.sample.px.verdict`):
///   `validate_px_without_proof` at the fixture's height `h` on the fixture
///   chain, every rule of `validate_px` but PX5, in its order: PX6 (the
///   validity window, `Window::contains`): `(h + 1, 0)` and `(0, h − 1)` are
///   refused, `(h, h)` passes it and fails at the CLSAG, which signs the
///   window; PX4 (the pool) on [`px_bridge_out_variant`]: refused on a pool
///   of 0, passing on a pool of 1 (then the CLSAG); B8 (the tree capacity,
///   two commitments): refused with one free leaf, valid with two.
/// - **Block verdicts** (`rules.sample.block.verdict`):
///   `validate_block_transactions_cached` on the block of the fixture
///   coinbase and one PX transaction, at the coinbase's height `b`, with the
///   header commitments of `BlockContext::committing` and the reward that
///   balances the coinbase (B3), every PX proof vouched for by the cache
///   (`proof_verified` true: PX6 must still be checked, AT-5): PX6 `(b + 1,
///   0)` refused, `(b, 0)` passing; PX4 on a pool of 0 and 1; B8 with one and
///   two free leaves (`PxTreeFull { leaves: 2, free: 1 }`). A case that
///   passes the sampled rule fails at C1: the fixture's ring members are
///   immature at height `b`, so no block sample reaches the range proofs or a
///   signature.
fn px_context_samples(m: &mut Manifest) {
    use blacksilk_px::tree::CAPACITY;
    use blacksilk_tx::px::PxTx;
    use blacksilk_tx::validate::validate_px_without_proof;
    let p = PxFixture::get();
    let f = Fixture::get();
    let rules = fixture_rules();
    let h = f.height;
    let window = |not_before: u64, not_after: u64| {
        let mut v = p.px.clone();
        v.window.not_before = not_before;
        v.window.not_after = not_after;
        v
    };
    let bridge_out = px_bridge_out_variant(&p.px);
    let on = |pool: u128, tree_size: u64| FixtureChain {
        pool,
        tree_size,
        ..FixtureChain::new(&f.outputs)
    };
    let tx_verdict = |t: &PxTx, chain: &FixtureChain| Sampled {
        verdict: verdict_text(validate_px_without_proof(t, chain, h, &rules)),
        input: input_hash(&Transaction::Px(Box::new(t.clone())).encode()),
        context: verdict_context(chain, h, &rules),
    };
    let tx_cases: [(&str, Sampled); 8] = [
        ("valid", tx_verdict(&p.px, &on(0, 0))),
        (
            "window (h + 1, 0)",
            tx_verdict(&window(h + 1, 0), &on(0, 0)),
        ),
        (
            "window (0, h - 1)",
            tx_verdict(&window(0, h - 1), &on(0, 0)),
        ),
        ("window (h, h)", tx_verdict(&window(h, h), &on(0, 0))),
        (
            "bridge_out = bridge_in + 1, pool 0",
            tx_verdict(&bridge_out, &on(0, 0)),
        ),
        (
            "bridge_out = bridge_in + 1, pool 1",
            tx_verdict(&bridge_out, &on(1, 0)),
        ),
        (
            "tree size CAPACITY - 1",
            tx_verdict(&p.px, &on(0, CAPACITY - 1)),
        ),
        (
            "tree size CAPACITY - 2",
            tx_verdict(&p.px, &on(0, CAPACITY - 2)),
        ),
    ];
    for (name, v) in tx_cases {
        v.record(m, &format!("rules.sample.px.verdict ({name})"));
    }

    // The block samples: the fixture coinbase and one PX transaction.
    m.bytes(
        "rules.sample.block.verdict input.coinbase",
        &input_hash(&Fixture::get().coinbase.encode()),
    );
    // A fixed seed: the samples never draw from it (every case stops before
    // the batched range proofs; `block_samples_never_draw_randomness`).
    let mut rng =
        <rand_chacha::ChaCha20Rng as rand_chacha::rand_core::SeedableRng>::from_seed([0; 32]);
    for (name, v) in block_samples(&mut rng) {
        v.record(m, &format!("rules.sample.block.verdict ({name})"));
    }
}

/// The block verdict samples of [`px_context_samples`]:
/// `validate_block_transactions_cached` on the fixture coinbase and one
/// variant of the golden PX transaction, at the coinbase's height `b`, with
/// `rng` for the batched range proofs, which no case reaches (each stops at
/// the sampled rule or at C1, before T10).
fn block_samples<R>(rng: &mut R) -> [(&'static str, Sampled); 6]
where
    R: rand_chacha::rand_core::RngCore + rand_chacha::rand_core::CryptoRng,
{
    use blacksilk_px::tree::CAPACITY;
    use blacksilk_tx::px::PxTx;
    use blacksilk_tx::validate::validate_block_transactions_cached;
    let p = PxFixture::get();
    let f = Fixture::get();
    let rules = fixture_rules();
    let coinbase = &f.coinbase;
    let (b, paid) = match coinbase {
        Transaction::Coinbase(c) => (c.height, c.total()),
        _ => unreachable!("the fixture coinbase"),
    };
    let window = |not_before: u64, not_after: u64| {
        let mut v = p.px.clone();
        v.window.not_before = not_before;
        v.window.not_after = not_after;
        v
    };
    let bridge_out = px_bridge_out_variant(&p.px);
    let on = |pool: u128, tree_size: u64| FixtureChain {
        pool,
        tree_size,
        ..FixtureChain::new(&f.outputs)
    };
    let mut block_verdict = |t: &PxTx, chain: &FixtureChain| {
        let px = Transaction::Px(Box::new(t.clone()));
        let reward = u64::try_from(paid - u128::from(px.fee()))
            .expect("the fixture coinbase pays the reward and the PX fee");
        let txs = [coinbase.clone(), px];
        let ctx = blacksilk_tx::BlockContext::committing(b, reward, &txs, chain);
        let r = validate_block_transactions_cached(&txs, &ctx, chain, &rules, rng, &|_| true);
        Sampled {
            verdict: block_verdict_text(r),
            input: input_hash(&txs[1].encode()),
            context: verdict_context(chain, b, &rules),
        }
    };
    [
        (
            "window (b + 1, 0), cached proof",
            block_verdict(&window(b + 1, 0), &on(0, 0)),
        ),
        (
            "window (b, 0), cached proof",
            block_verdict(&window(b, 0), &on(0, 0)),
        ),
        (
            "bridge_out = bridge_in + 1, pool 0",
            block_verdict(&bridge_out, &on(0, 0)),
        ),
        (
            "bridge_out = bridge_in + 1, pool 1",
            block_verdict(&bridge_out, &on(1, 0)),
        ),
        (
            "tree size CAPACITY - 1",
            block_verdict(&p.px, &on(0, CAPACITY - 1)),
        ),
        (
            "tree size CAPACITY - 2",
            block_verdict(&p.px, &on(0, CAPACITY - 2)),
        ),
    ]
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The network with this name (`testnet`, `regtest`, `mainnet`).
pub fn network_by_name(name: &str) -> Option<Network> {
    NETWORKS
        .into_iter()
        .find(|n| crate::network_name(*n) == name)
}

/// The `--version` text of the node: crate version, build commit, build
/// flags ([`build_flags`]), and for each network the consensus fingerprint
/// (short and full), the rules and identity fingerprints, and the genesis id.
pub fn version_text() -> String {
    let mut s = format!(
        "{VERSION}\ncommit {BUILD_COMMIT}\n{}\n",
        build_flags().line()
    );
    for n in NETWORKS {
        let f = fingerprints(n);
        let c = hex(&f.consensus);
        let g = hex(&ChainParams::for_network(n).genesis_id());
        s.push_str(&format!(
            "{name}: fingerprint {short} ({c})\n\
             {name}: rules {rules}\n\
             {name}: identity {identity}\n\
             {name}: genesis {g}\n",
            name = crate::network_name(n),
            short = &c[..16],
            rules = hex(&f.rules),
            identity = hex(&f.identity),
        ));
    }
    s.truncate(s.trim_end().len());
    s
}

/// The `--print-manifest` text of `network`: the three fingerprints, how
/// they are computed, and each manifest as `name = value` lines followed by
/// its canonical encoding in hex, so a second implementation can recompute
/// every digest (docs/testnet.md §2.1).
pub fn manifest_text(network: Network) -> String {
    let f = fingerprints(network);
    let rules = rules_manifest(network);
    let identity = identity_manifest(network);
    format!(
        "# BlackSilk consensus manifest: {name}, build {VERSION} commit {BUILD_COMMIT}\n\
         # {flags}\n\
         # H64(d, x) = BLAKE2b-512(u8(len(p ‖ d)) ‖ p ‖ d ‖ x), p = crypto.DOMAIN_PREFIX (below); digests are its first 32 bytes\n\
         # rules_fingerprint     = H64({RULES_DOMAIN:?}, rules_encoding)\n\
         # identity_fingerprint  = H64({IDENTITY_DOMAIN:?}, identity_encoding)\n\
         # consensus_fingerprint = H64({DOMAIN:?}, encoding of [rules_fingerprint, identity_fingerprint])\n\
         # encoding: u32le(count), then per entry u32le(len) ‖ name ‖ tag ‖ value (px/src/fingerprint.rs)\n\
         consensus_fingerprint = {c}\n\
         rules_fingerprint = {r}\n\
         identity_fingerprint = {i}\n\
         \n\
         [identity]\n\
         {identity_render}\
         identity_encoding = {identity_hex}\n\
         \n\
         [rules]\n\
         {rules_render}\
         rules_encoding = {rules_hex}\n",
        flags = build_flags().line(),
        name = crate::network_name(network),
        c = hex(&f.consensus),
        r = hex(&f.rules),
        i = hex(&f.identity),
        identity_render = identity.render(),
        identity_hex = hex(&identity.encode()),
        rules_render = rules.render(),
        rules_hex = hex(&rules.encode()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use blacksilk_px::fingerprint::Value;

    /// The start-up cost of the fingerprints (computed at node start, in
    /// `--version` and `/info`): every network's manifests from a cold process
    /// (the Bulletproofs+ generators, the fixture's verdicts), then warm.
    /// Timing, so ignored; run alone:
    /// `cargo test --release -p blacksilk-node --lib fingerprint_cost -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn fingerprint_cost() {
        let t = std::time::Instant::now();
        let cold = NETWORKS.map(compute);
        let cold_time = t.elapsed();
        let t = std::time::Instant::now();
        let samples = compute_transaction_samples();
        let samples_time = t.elapsed();
        let t = std::time::Instant::now();
        assert_eq!(NETWORKS.map(compute), cold);
        let warm_time = t.elapsed();
        println!(
            "fingerprints of {} networks: cold {cold_time:?}; transaction samples ({} \
             entries) recomputed {samples_time:?}; all networks warm {warm_time:?}",
            NETWORKS.len(),
            samples.entries().len()
        );
        assert!(cold_time < std::time::Duration::from_secs(1));
    }

    #[test]
    fn stable_across_calls() {
        for n in NETWORKS {
            assert_eq!(consensus_fingerprint(n), consensus_fingerprint(n));
            assert_eq!(fingerprints(n), compute(n));
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
        for (a, b) in [
            (Network::Testnet, Network::Regtest),
            (Network::Testnet, Network::Mainnet),
            (Network::Regtest, Network::Mainnet),
        ] {
            assert_ne!(identity_fingerprint(a), identity_fingerprint(b));
        }
    }

    /// The consensus fingerprint is the hash of the other two.
    #[test]
    fn consensus_combines_rules_and_identity() {
        for n in NETWORKS {
            let f = fingerprints(n);
            assert_eq!(f.consensus, combine(&f.rules, &f.identity));
            assert_ne!(f.consensus, combine(&f.identity, &f.rules));
        }
    }

    /// F40-7: nothing in the rules manifest names a chain. Changing only the
    /// genesis (its time, the beacon's nonce) or the network id changes the
    /// identity manifest and not the rules manifest; the rules manifest has
    /// no entry whose value is the network id or the genesis id.
    #[test]
    fn rules_fingerprint_excludes_identity() {
        for n in NETWORKS {
            let p = ChainParams::for_network(n);
            let rules = rules_manifest(n);
            for (name, value) in rules.entries() {
                assert!(
                    !name.contains("network_id")
                        && !name.contains("genesis_id")
                        && !name.contains("branch_id")
                        && name != "chain.genesis"
                        && name != "chain.network",
                    "{name} is identity"
                );
                assert_ne!(*value, Value::Bytes(p.genesis_id().to_vec()), "{name}");
                assert_ne!(
                    *value,
                    Value::Bytes(p.genesis.to_bytes().to_vec()),
                    "{name}"
                );
            }
            // The identity manifest holds the identity, and only it.
            let text = identity_manifest(n).render();
            assert!(text.contains(&format!("chain.network_id = {}", p.network_id)));
            assert!(text.contains(&hex(&p.genesis_id())));
            // D0 is identity (fingerprint-sample-inputs): in the identity
            // manifest, not in the rules manifest.
            assert!(text.contains(&format!(
                "chain.initial_difficulty = {}",
                p.initial_difficulty
            )));
            assert!(rules
                .entries()
                .iter()
                .all(|(name, _)| name != "chain.initial_difficulty"));
            assert_eq!(identity_manifest(n).entries().len(), 8);
        }
        // Testnet and mainnet differ only in identity fields (D0 among them),
        // so they share the rules manifest exactly; regtest's rules differ.
        assert_eq!(
            rules_manifest(Network::Testnet).entries(),
            rules_manifest(Network::Mainnet).entries()
        );
        assert_eq!(
            rules_fingerprint(Network::Testnet),
            rules_fingerprint(Network::Mainnet)
        );
        assert_ne!(
            rules_manifest(Network::Testnet).entries(),
            rules_manifest(Network::Regtest).entries()
        );
    }

    /// One record section of docs/reviews/v3-consensus-changes.md: the keys
    /// it can be cited by (its `<a id>` anchor, the heading text before the
    /// first `:`, and a leading `§N`) and its `Revision:` lines.
    struct Section {
        heading: String,
        keys: Vec<String>,
        revisions: Vec<String>,
    }

    fn record_sections() -> Vec<Section> {
        let doc = include_str!("../../docs/reviews/v3-consensus-changes.md");
        let mut sections: Vec<Section> = Vec::new();
        let mut anchor: Option<String> = None;
        for line in doc.lines().map(|l| l.trim_end_matches('\r')) {
            if let Some(rest) = line.strip_prefix("<a id=\"") {
                anchor = rest.split('"').next().map(str::to_string);
            } else if let Some(head) = line.strip_prefix("## ") {
                let mut keys: Vec<String> = anchor.take().into_iter().collect();
                keys.push(head.split(':').next().unwrap_or(head).to_string());
                if let Some(first) = head.split_whitespace().next() {
                    if first.starts_with('§') {
                        keys.push(first.to_string());
                    }
                }
                sections.push(Section {
                    heading: head.to_string(),
                    keys,
                    revisions: Vec::new(),
                });
            } else if let Some(rev) = line.strip_prefix("Revision: ") {
                sections
                    .last_mut()
                    .expect("no Revision: line before the first record")
                    .revisions
                    .push(rev.to_string());
            } else if !line.trim().is_empty() {
                anchor = None;
            }
        }
        sections
    }

    /// RTFP3-8: every record section has exactly one `Revision:` line; the
    /// records' revision ids, in record order, are [`REVISIONS`]; and each
    /// entry's `record` is exactly a key of the section that carries its id
    /// (no prefix match: `§1` never matches a heading `§10`).
    #[test]
    fn revision_lines_are_the_revision_list() {
        let sections = record_sections();
        assert!(sections.len() >= REVISIONS.len());
        let mut ids = Vec::new();
        for s in &sections {
            assert_eq!(
                s.revisions.len(),
                1,
                "record {:?} needs exactly one `Revision:` line (the record template)",
                s.heading
            );
            let r = &s.revisions[0];
            if let Some(reason) = r.strip_prefix("none") {
                assert!(
                    reason.starts_with(" (") && reason.ends_with(')') && reason.len() > 3,
                    "{:?}: `Revision: none (<reason>)`",
                    s.heading
                );
            } else {
                ids.push(r.as_str());
            }
        }
        let listed: Vec<&str> = REVISIONS.iter().map(|r| r.id).collect();
        assert_eq!(
            ids, listed,
            "the records' Revision ids and REVISIONS differ"
        );
        for r in REVISIONS {
            let matching: Vec<&Section> = sections
                .iter()
                .filter(|s| s.keys.iter().any(|k| k == r.record))
                .collect();
            assert_eq!(matching.len(), 1, "{}: record key {:?}", r.id, r.record);
            assert_eq!(matching[0].revisions[0], r.id, "{}", r.record);
        }
    }

    /// Every rule revision is unique and names an existing record.
    #[test]
    fn every_revision_is_unique_and_recorded() {
        for (i, r) in REVISIONS.iter().enumerate() {
            assert!(
                REVISIONS[i + 1..]
                    .iter()
                    .all(|o| o.id != r.id && o.record != r.record),
                "{} is listed twice",
                r.id
            );
        }
        let m = rules_manifest(Network::Regtest);
        let ids: Vec<&Value> = m
            .entries()
            .iter()
            .filter(|(n, _)| n.starts_with("rules.revision["))
            .map(|(_, v)| v)
            .collect();
        assert_eq!(ids.len(), REVISIONS.len());
    }

    /// The samples are the pinned golden values of their own suites (the DAA
    /// golden case, the exact-fee and R12-2 anchors, the genesis-nonce known
    /// answer), so a sample cannot drift from its vector unnoticed.
    #[test]
    fn samples_are_the_golden_values() {
        let m = rules_manifest(Network::Testnet);
        let get = |name: &str| {
            m.entries()
                .iter()
                .find(|(n, _)| n == name)
                .unwrap_or_else(|| panic!("{name}"))
                .1
                .clone()
        };
        assert_eq!(
            get("rules.sample.next_difficulty (T 120, N 75)"),
            Value::List(vec![1_000_000, 999_824, 998_248, 777])
        );
        // fingerprint-sample-inputs: the inputs of the DAA golden case (87
        // on-target stamps at T = 120 from 10^6, cumulative difficulties
        // (i + 1) * 10^6, the window-oldest stamp 1 300 s low; D0 1, then 777
        // for the genesis-only history).
        let steady: Vec<u64> = (0..87).map(|i| 1_000_000 + i * 120).collect();
        let mut low = steady.clone();
        low[11] = 1_000_020;
        let cd: Vec<u64> = (1..=87).map(|i| i * 1_000_000).collect();
        let n = difficulty::DIFFICULTY_WINDOW as u64;
        for (i, ts, cd, d0) in [
            (0, &steady[..], &cd[..], 1),
            (1, &low[..], &cd[..], 1),
            (2, &low[11..], &cd[11..], 1),
            (3, &low[..1], &cd[..1], 777),
        ] {
            let name = format!("rules.sample.next_difficulty (T 120, N 75) input[{i}]");
            assert_eq!(get(&format!("{name}.timestamps")), Value::List(ts.to_vec()));
            assert_eq!(
                get(&format!("{name}.cumulative_difficulties")),
                Value::List(cd.to_vec())
            );
            assert_eq!(
                get(&format!("{name} (T, N, D0)")),
                Value::List(vec![120, n, d0])
            );
        }
        // The RandomX key schedule (E = 2048, L = 64): the heights and their
        // keys. A dropped `- 1` in `seed_height` moves the key at 2E + L and
        // 10E + L (4 096 and 20 480 instead of 2 048 and 18 432).
        let (e, l) = (2_048u64, 64u64);
        assert_eq!(
            get("chain.seed_height samples input (heights)"),
            Value::List(vec![
                0,
                1,
                e + l,
                e + l + 1,
                10 * e,
                l,
                l + 1,
                4_160,
                4_161,
                20_544,
                20_545,
                u64::MAX
            ])
        );
        assert_eq!(
            get("chain.seed_height samples"),
            Value::List(vec![
                0,
                0,
                0,
                2_048,
                18_432,
                0,
                0,
                2_048,
                4_096,
                18_432,
                20_480,
                (u64::MAX - 65) & !2_047
            ])
        );
        assert_eq!(
            get("emission.block_reward samples input (height, generated)"),
            Value::List(vec![
                0,
                0,
                1,
                0,
                2,
                emission::block_reward(1, 0),
                1_000,
                1_000 * emission::COIN,
                1,
                emission::MONEY_SUPPLY - emission::COIN,
                1,
                emission::MONEY_SUPPLY
            ])
        );
        assert_eq!(
            get("rules.sample.max_weight (1,2) (2,2) (1,16) (64,16) (1,0) (64,2)"),
            Value::List(vec![
                1_723,
                max_weight(2, 2),
                max_weight(1, 16),
                57_439,
                841,
                52_123
            ])
        );
        assert_eq!(
            get("rules.sample.px_v1_part_weight (0,2) (1,0) (64,16) (1,2) (64,2)"),
            Value::List(vec![0, 841, 57_439, 1_723, 52_123])
        );
        assert_eq!(
            get("rules.sample.genesis_nonce (Bitcoin block 0, test-vector id)"),
            Value::U64(0x220a_7227_0a81_8150)
        );
        assert_eq!(
            get("rules.sample.check_hash (max*1, 2^255*2, (2^255-1)*2, 0*0, 0*u64::MAX)"),
            Value::List(vec![1, 0, 1, 0, 1])
        );
        assert_eq!(
            get("chain.difficulty_rule"),
            Value::Text(DIFFICULTY_RULE_ID.to_string())
        );
        // RT-FP3: the lower clamp, the FTL boundary (inclusive), the empty
        // leaf, the RandomX reference answer, and the verdicts named by their
        // error classes (the fixture is a valid transfer).
        assert_eq!(
            get("rules.sample.next_difficulty([0, 1000], [1, 2], T 120, N 75, D0 1)"),
            Value::U64(1)
        );
        assert_eq!(
            get("rules.sample.within_future_limit (1359, 1360, 1361; now 1000, FTL 360)"),
            Value::List(vec![1, 1, 0])
        );
        assert_eq!(get("px.sample.tree.empty[0]"), Value::List(vec![0; 8]));
        assert_eq!(
            get("randomx.KAT.hash"),
            Value::Text(
                "424838440b398cd20d703905167a6d07b19816b0ab246b678218649fa7d70802".to_string()
            )
        );
        assert_eq!(get("randomx.PROGRAM_ITERATIONS"), Value::U64(2048));
        assert_eq!(
            get("randomx.ARGON_SALT"),
            Value::Bytes(b"BlackSilk/RandomX/v1".to_vec())
        );
        // The verdicts, by their full text (record
        // `fingerprint-stable-verdicts`: `verdict_text`, never `Debug`): the
        // fixture transfer and its variants, the golden PX fixture's stateless
        // verdicts (the ciphertext `R` rule included), and the deploy's full
        // verdicts.
        // A block sample that passes its rule fails at C1: the first ring
        // member of the PX transaction's input is immature at height 1.
        const BLOCK_IMMATURE: &str =
            "Err(Tx { index: 1, error: RingMemberTooYoung { input: 0, index: 0 } })";
        let text = |name: &str| match get(name) {
            Value::Text(t) => t,
            other => panic!("{other:?}"),
        };
        for (prefix, cases) in [
            (
                "rules.sample.verdict",
                &[
                    ("valid", "Ok(())"),
                    ("no inputs", "Err(InputCount(0))"),
                    ("one output", "Err(OutputCount(1))"),
                    ("identity key image", "Err(KeyImageIdentity { input: 0 })"),
                    ("key images unsorted", "Err(KeyImagesNotSorted)"),
                    ("ring unsorted", "Err(RingNotIncreasing { input: 0 })"),
                    (
                        "identity output key",
                        "Err(OutputKeyIdentity { output: 0 })",
                    ),
                    ("identity ephemeral", "Err(EphemeralIdentity { output: 0 })"),
                    ("outputs unsorted", "Err(OutputsNotSorted)"),
                    ("missing pseudo-output", "Err(PseudoOutCount)"),
                    ("missing signature", "Err(SignatureCount)"),
                    (
                        "identity auxiliary image",
                        "Err(AuxKeyImageIdentity { input: 0 })",
                    ),
                    ("short range proof", "Err(RangeProofShape)"),
                    (
                        "fee + 1",
                        "Err(FeeNotExact { fee: 63361, required: 63360 })",
                    ),
                    ("unbalanced", "Err(Unbalanced)"),
                    ("balanced, range proof invalid", "Err(RangeProofInvalid)"),
                    ("key image spent", "Err(KeyImageSpent { input: 1 })"),
                    (
                        "ring member unknown",
                        "Err(UnknownRingMember { input: 1, index: 31 })",
                    ),
                    (
                        "coinbase ring member immature (height 60)",
                        "Err(RingMemberTooYoung { input: 0, index: 0 })",
                    ),
                    ("other branch id", "Err(InvalidSignature { input: 0 })"),
                    (
                        "signature of the other input",
                        "Err(InvalidSignature { input: 0 })",
                    ),
                ][..],
            ),
            (
                "rules.sample.px.stateless_verdict",
                &[
                    ("valid", "Ok(())"),
                    (
                        "identity R in ciphertext 0",
                        "Err(PxCiphertextRIdentity { ciphertext: 0 })",
                    ),
                    (
                        "non-canonical R (p) in ciphertext 1",
                        "Err(PxCiphertextRNonCanonical { ciphertext: 1 })",
                    ),
                    (
                        "R with the top bit set in ciphertext 0",
                        "Err(PxCiphertextRNonCanonical { ciphertext: 0 })",
                    ),
                    ("fee + 1", "Err(PxFeeNotStandard { fee: 8912897 })"),
                    ("equal nullifiers", "Err(PxNullifierRepeated)"),
                    ("inverted window", "Err(PxWindowInverted)"),
                    ("bridge_in + 1", "Err(Unbalanced)"),
                    ("missing signature", "Err(SignatureCount)"),
                    ("truncated proof", "Err(PxProof)"),
                ][..],
            ),
            (
                "rules.sample.deploy.verdict",
                &[
                    ("valid", "Ok(())"),
                    (
                        "fee + 1",
                        "Err(DeployFeeNotExact { fee: 709261, required: 709260 })",
                    ),
                    ("unsupported ABI", "Err(PxUnsupportedAbi { program: 0 })"),
                    ("other salt", "Err(InvalidSignature { input: 0 })"),
                    (
                        "bit budget above its cap",
                        "Err(PxBudgetTooLarge { program: 0 })",
                    ),
                ][..],
            ),
            (
                // fingerprint-px-samples: PX6, PX4 and B8 as boundary pairs.
                "rules.sample.px.verdict",
                &[
                    ("valid", "Ok(())"),
                    ("window (h + 1, 0)", "Err(PxWindow)"),
                    ("window (0, h - 1)", "Err(PxWindow)"),
                    ("window (h, h)", "Err(InvalidSignature { input: 0 })"),
                    ("bridge_out = bridge_in + 1, pool 0", "Err(PxPoolUnderflow)"),
                    (
                        "bridge_out = bridge_in + 1, pool 1",
                        "Err(InvalidSignature { input: 0 })",
                    ),
                    ("tree size CAPACITY - 1", "Err(PxTreeFull)"),
                    ("tree size CAPACITY - 2", "Ok(())"),
                ][..],
            ),
            (
                "rules.sample.block.verdict",
                &[
                    (
                        "window (b + 1, 0), cached proof",
                        "Err(Tx { index: 1, error: PxWindow })",
                    ),
                    ("window (b, 0), cached proof", BLOCK_IMMATURE),
                    (
                        "bridge_out = bridge_in + 1, pool 0",
                        "Err(Tx { index: 1, error: PxPoolUnderflow })",
                    ),
                    ("bridge_out = bridge_in + 1, pool 1", BLOCK_IMMATURE),
                    (
                        "tree size CAPACITY - 1",
                        "Err(PxTreeFull { leaves: 2, free: 1 })",
                    ),
                    ("tree size CAPACITY - 2", BLOCK_IMMATURE),
                ][..],
            ),
        ] {
            for (case, golden) in cases {
                assert_eq!(
                    text(&format!("{prefix} ({case})")),
                    *golden,
                    "{prefix} ({case})"
                );
            }
        }
        // Every verdict entry of the manifest is in the table above.
        let n_verdicts = m
            .entries()
            .iter()
            .filter(|(name, _)| {
                [
                    "rules.sample.verdict (",
                    "rules.sample.px.stateless_verdict (",
                    "rules.sample.deploy.verdict (",
                    "rules.sample.px.verdict (",
                    "rules.sample.block.verdict (",
                ]
                .iter()
                .any(|p| name.starts_with(p))
                    && !name.contains(") input")
            })
            .count();
        assert_eq!(n_verdicts, 50);
        // fingerprint-px-samples: the context of the PX and block samples
        // (the block's height is the fixture coinbase's, 1).
        for (name, value) in [
            (
                "rules.sample.px.verdict (bridge_out = bridge_in + 1, pool 1) input.pool",
                Value::U64(1),
            ),
            (
                "rules.sample.px.verdict (tree size CAPACITY - 1) input.tree size",
                Value::U64(blacksilk_px::tree::CAPACITY - 1),
            ),
            (
                "rules.sample.px.verdict (tree size CAPACITY - 2) input.tree size",
                Value::U64(blacksilk_px::tree::CAPACITY - 2),
            ),
            (
                "rules.sample.block.verdict (bridge_out = bridge_in + 1, pool 1) input.pool",
                Value::U64(1),
            ),
            (
                "rules.sample.block.verdict (tree size CAPACITY - 1) input.tree size",
                Value::U64(blacksilk_px::tree::CAPACITY - 1),
            ),
            (
                "rules.sample.block.verdict (tree size CAPACITY - 2) input.tree size",
                Value::U64(blacksilk_px::tree::CAPACITY - 2),
            ),
            (
                "rules.sample.block.verdict (window (b + 1, 0), cached proof) input.height",
                Value::U64(1),
            ),
        ] {
            assert_eq!(get(name), value, "{name}");
        }
    }

    /// fingerprint-sample-inputs: every verdict variant records an input that
    /// differs from the valid case's. A variant of the transaction has another
    /// input hash; a variant of the chain view, the height or the rules keeps
    /// the valid transaction (the same hash) and records what it changes in
    /// `input.<part>` entries, which differ from the fixture's context.
    #[test]
    fn every_verdict_variant_records_a_distinct_input() {
        let m = rules_manifest(Network::Regtest);
        let e = m.entries();
        let get = |name: &str| e.iter().find(|(n, _)| n == name).map(|(_, v)| v);
        let f = Fixture::get();
        let rules = fixture_rules();
        let mut context_only = Vec::new();
        for family in [
            "rules.sample.verdict",
            "rules.sample.px.stateless_verdict",
            "rules.sample.deploy.verdict",
            "rules.sample.px.verdict",
        ] {
            let valid = get(&format!("{family} (valid) input")).expect("the valid input");
            assert!(matches!(valid, Value::Bytes(b) if b.len() == 32));
            assert!(
                e.iter()
                    .all(|(n, _)| !n.starts_with(&format!("{family} (valid) input."))),
                "{family}: the valid case has no context entry"
            );
            let cases: Vec<&str> = e
                .iter()
                .filter_map(|(n, _)| n.strip_prefix(&format!("{family} (")))
                .filter_map(|n| n.strip_suffix(") input"))
                .collect();
            assert!(cases.len() >= 5, "{family}: {cases:?}");
            for case in cases.into_iter().filter(|c| *c != "valid") {
                let input = get(&format!("{family} ({case}) input")).expect("an input");
                if input != valid {
                    continue;
                }
                // The same transaction: the case must change its context.
                let prefix = format!("{family} ({case}) input.");
                let parts: Vec<(&str, &Value)> = e
                    .iter()
                    .filter_map(|(n, v)| n.strip_prefix(&prefix).map(|p| (p, v)))
                    .collect();
                assert!(!parts.is_empty(), "{family} ({case}): no distinct input");
                for (part, v) in parts {
                    match part {
                        "height" => assert_ne!(*v, Value::U64(f.height)),
                        "signature domain" => {
                            assert_ne!(*v, Value::Bytes(rules.domain().bytes().to_vec()))
                        }
                        "pool" | "tree size" => assert_ne!(*v, Value::U64(0)),
                        "spent key image" | "missing ring member" => {}
                        other => panic!("{family} ({case}): unexpected part {other}"),
                    }
                }
                context_only.push(format!("{family} ({case})"));
            }
        }
        assert_eq!(
            context_only,
            [
                "rules.sample.verdict (key image spent)",
                "rules.sample.verdict (ring member unknown)",
                "rules.sample.verdict (coinbase ring member immature (height 60))",
                "rules.sample.verdict (other branch id)",
                "rules.sample.px.verdict (tree size CAPACITY - 1)",
                "rules.sample.px.verdict (tree size CAPACITY - 2)",
            ]
        );
        // fingerprint-px-samples: within each family, no two cases record
        // the same input (the input hash with every context entry), so the
        // two cases of a boundary pair differ in their input, not only in
        // their names.
        for family in [
            "rules.sample.verdict",
            "rules.sample.px.stateless_verdict",
            "rules.sample.deploy.verdict",
            "rules.sample.px.verdict",
            "rules.sample.block.verdict",
        ] {
            let mut inputs: Vec<Vec<(&str, &Value)>> = Vec::new();
            for (n, _) in e {
                let Some(case) = n
                    .strip_prefix(&format!("{family} ("))
                    .and_then(|c| c.strip_suffix(") input"))
                else {
                    continue;
                };
                let prefix = format!("{family} ({case}) input");
                let input: Vec<(&str, &Value)> = e
                    .iter()
                    .filter(|(k, _)| *k == prefix || k.starts_with(&format!("{prefix}.")))
                    .map(|(k, v)| (&k[prefix.len()..], v))
                    .collect();
                assert!(
                    !inputs.contains(&input),
                    "{family} ({case}): the input of another case"
                );
                inputs.push(input);
            }
            assert!(inputs.len() >= 5, "{family}");
        }
        // The other-branch case records the branch it signs under, not
        // the fixture's.
        let other = fixture_rules().domain();
        let other_branch = SigDomain {
            branch_id: other.branch_id ^ 1,
            ..other
        };
        assert_eq!(
            get("rules.sample.verdict (other branch id) input.signature domain"),
            Some(&Value::Bytes(other_branch.bytes().to_vec()))
        );
        assert_eq!(
            get("rules.sample.verdict (valid) input"),
            Some(&Value::Bytes(
                input_hash(&Transaction::from(f.transfer.clone()).encode()).to_vec()
            ))
        );
    }

    /// The rules fingerprint is the digest of the rules manifest, and a
    /// changed sample value (another difficulty; a PX v1 part without inputs
    /// weighing `max_weight` instead of 0) changes it. This substitutes values;
    /// it does not mutate rule code.
    #[test]
    fn a_changed_sample_changes_the_rules_fingerprint() {
        let base = rules_manifest(Network::Regtest);
        let mutate = |name: &str, v: Value| {
            let mut m = Manifest::new();
            for (n, value) in base.entries() {
                if n == name {
                    m.extend(one(n, v.clone()));
                } else {
                    m.extend(one(n, value.clone()));
                }
            }
            m.digest(RULES_DOMAIN)
        };
        let d = base.digest(RULES_DOMAIN);
        assert_eq!(d, rules_fingerprint(Network::Regtest));
        assert_ne!(
            d,
            mutate(
                "rules.sample.next_difficulty (T 120, N 75)",
                Value::List(vec![1_000_001, 999_824, 998_248, 777])
            )
        );
        assert_ne!(
            d,
            mutate(
                "rules.sample.px_v1_part_weight (0,2) (1,0) (64,16) (1,2) (64,2)",
                Value::List(vec![max_weight(0, 2), 841, 57_439, 1_723, 52_123])
            )
        );
    }

    fn one(name: &str, v: Value) -> Manifest {
        let mut m = Manifest::new();
        match v {
            Value::U64(x) => m.u(name, x),
            Value::I64(x) => m.i(name, x),
            Value::Text(s) => m.text(name, &s),
            Value::Bytes(b) => m.bytes(name, &b),
            Value::List(l) => m.list(name, l),
        };
        m
    }

    /// Every name and text value is printable ASCII and every name is unique,
    /// so the printed manifest is unambiguous for a second implementation.
    #[test]
    fn entry_names_are_unique_printable_ascii() {
        for n in NETWORKS {
            let m = manifest(n);
            let mut names: Vec<&str> = m.entries().iter().map(|(k, _)| k.as_str()).collect();
            for (k, v) in m.entries() {
                let printable = |s: &str| s.bytes().all(|b| (0x20..0x7f).contains(&b));
                assert!(printable(k), "{k:?}");
                if let Value::Text(s) = v {
                    assert!(printable(s), "{k}: {s:?}");
                }
            }
            let len = names.len();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), len, "a repeated entry name");
        }
    }

    #[test]
    fn rules_manifest_holds_the_px_entries_and_samples() {
        let rules = rules_manifest(Network::Testnet);
        let px = px_entries();
        let e = rules.entries();
        assert!(e.windows(px.entries().len()).any(|w| w == px.entries()));
    }

    #[test]
    fn version_text_names_every_network() {
        let v = version_text();
        assert!(v.contains(BUILD_COMMIT));
        assert!(v.lines().any(|l| l == build_flags().line()), "{v}");
        for n in NETWORKS {
            assert!(v.contains(&hex(&consensus_fingerprint(n))));
            assert!(v.contains(&hex(&rules_fingerprint(n))));
            assert!(v.contains(&hex(&identity_fingerprint(n))));
            assert!(v.contains(&hex(&ChainParams::for_network(n).genesis_id())));
        }
    }

    /// The case RT-STATEFUL found: this crate's tests enable chain's
    /// `test-hooks` (a dev-dependency), and cargo unifies it into the build,
    /// so the build is marked (and with it the binary those tests run).
    #[test]
    fn a_test_build_is_marked() {
        let flags = build_flags();
        for m in ["+test-hooks:chain", "+test-hooks:tx", "+test-hooks:px"] {
            assert!(flags.markers().contains(&m), "{flags:?}");
        }
        assert_eq!(
            flags.markers().contains(&"+test-hooks:p2p"),
            blacksilk_p2p::TEST_HOOKS
        );
        assert!(flags.check_network("node", Network::Testnet).is_err());
        assert!(flags.check_network("node", Network::Mainnet).is_err());
        assert!(flags.check_network("node", Network::Regtest).is_ok());
    }

    /// `--print-manifest` prints every digest and both encodings, and the
    /// printed encodings hash to the printed digests.
    #[test]
    fn manifest_text_recomputes() {
        for n in NETWORKS {
            let t = manifest_text(n);
            let f = fingerprints(n);
            assert!(t.contains(&format!("consensus_fingerprint = {}", hex(&f.consensus))));
            assert!(t.contains(&format!("rules_fingerprint = {}", hex(&f.rules))));
            assert!(t.contains(&format!("identity_fingerprint = {}", hex(&f.identity))));
            let enc = |key: &str| {
                let line = t
                    .lines()
                    .find(|l| l.starts_with(key))
                    .unwrap_or_else(|| panic!("{key}"));
                line[key.len()..].to_string()
            };
            assert_eq!(enc("rules_encoding = "), hex(&rules_manifest(n).encode()));
            assert_eq!(
                enc("identity_encoding = "),
                hex(&identity_manifest(n).encode())
            );
            assert!(t.contains("\"BlackSilk/v1/\""));
            // The build flags are a comment line: no digest covers them.
            assert_eq!(
                t.lines().nth(1),
                Some(format!("# {}", build_flags().line())).as_deref()
            );
            assert_eq!(network_by_name(crate::network_name(n)), Some(n));
        }
        assert_eq!(network_by_name("x"), None);
    }

    /// fingerprint-px-samples: the block samples never draw from their RNG
    /// (each stops at its rule or at C1, before the batched range proofs),
    /// so its fixed seed cannot reach the manifest; and they record the
    /// manifest's verdicts.
    #[test]
    fn block_samples_never_draw_randomness() {
        use rand_chacha::rand_core::{CryptoRng, Error, RngCore, SeedableRng};
        struct Counting(rand_chacha::ChaCha20Rng, u64);
        impl RngCore for Counting {
            fn next_u32(&mut self) -> u32 {
                self.1 += 1;
                self.0.next_u32()
            }
            fn next_u64(&mut self) -> u64 {
                self.1 += 1;
                self.0.next_u64()
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                self.1 += 1;
                self.0.fill_bytes(dest)
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
                self.1 += 1;
                self.0.try_fill_bytes(dest)
            }
        }
        impl CryptoRng for Counting {}
        let mut rng = Counting(rand_chacha::ChaCha20Rng::seed_from_u64(7), 0);
        let cases = block_samples(&mut rng);
        assert_eq!(rng.1, 0, "a block sample drew from the RNG");
        let m = rules_manifest(Network::Regtest);
        for (name, v) in cases {
            let entry = format!("rules.sample.block.verdict ({name})");
            assert!(
                m.entries()
                    .iter()
                    .any(|(n, x)| *n == entry && *x == Value::Text(v.verdict.clone())),
                "{entry}"
            );
        }
    }

    /// Blank and whitespace-only lines are skipped by both fixture parsers:
    /// the checked-in texts with an empty line before them, between their
    /// entries and a whitespace-only line after them parse to the same
    /// fixtures (G7 survivors 721:17 and 788:17: without the `[]` arm such a
    /// line made the parser return `None`).
    #[test]
    fn fixture_parsers_skip_blank_lines() {
        let spaced = |text: &str| {
            let mut s = String::from("\n");
            for line in text.lines() {
                s.push_str(line);
                s.push_str("\n\n");
            }
            s.push_str(" \t \n");
            s
        };
        let f = Fixture::get();
        let g = Fixture::parse(&spaced(FIXTURE)).expect("the spaced fixture parses");
        assert_eq!(g.height, f.height);
        assert_eq!(g.transfer, f.transfer);
        assert_eq!(g.coinbase, f.coinbase);
        assert_eq!(g.outputs, f.outputs);

        let p = PxFixture::get();
        let q = PxFixture::parse(PX_FIXTURE_TX, &spaced(PX_FIXTURE_TEXT))
            .expect("the spaced PX fixture parses");
        assert_eq!(q.px, p.px);
        assert_eq!(q.deploy, p.deploy);
    }
}
