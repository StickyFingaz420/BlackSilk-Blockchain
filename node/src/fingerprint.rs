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
//!   ids and **verdicts** of a pinned fixture transfer and its variants), the
//!   pinned RandomX known answer, and the **rule-revision list**
//!   ([`REVISIONS`]). Its digest is [`rules_fingerprint`]. It holds nothing
//!   that names a chain, so a release-candidate build and the final build of
//!   a network have the same rules fingerprint.
//! - [`identity_manifest`]: the network name and id, the genesis block and
//!   id, and the branch ids of the schedule. Its digest is
//!   [`identity_fingerprint`].
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
use blacksilk_tx::params::{self as tx, max_weight, SigDomain, TxRules};
use blacksilk_tx::px::{deploy_fee, Registration};
use blacksilk_tx::types::{v1_part_weight, OutputKey};
use blacksilk_tx::validate::OutputRecord;
use blacksilk_tx::{ChainView, Transaction, Transfer};
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
/// the branch id of every epoch, and the ids `TxRules` carries at genesis.
pub fn identity_manifest(network: Network) -> Manifest {
    let p = ChainParams::for_network(network);
    let mut m = Manifest::new();
    m.text("chain.network", crate::network_name(p.network))
        .u("chain.network_id", p.network_id)
        .bytes("chain.genesis", &p.genesis.to_bytes())
        .bytes("chain.genesis_id", &p.genesis_id());
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
        target_block_time,
        initial_difficulty,
        difficulty_window,
        median_time_window,
        future_time_limit,
        seed_epoch,
        seed_lag,
        schedule,
    } = &p;
    let mut m = Manifest::new();
    m.u("chain.target_block_time", *target_block_time)
        .u("chain.initial_difficulty", *initial_difficulty)
        .size("chain.difficulty_window", *difficulty_window)
        .text("chain.difficulty_rule", DIFFICULTY_RULE_ID)
        .size("chain.DIFFICULTY_WARMUP", difficulty::DIFFICULTY_WARMUP)
        .size("chain.median_time_window", *median_time_window)
        .u("chain.future_time_limit", *future_time_limit)
        .u("chain.seed_epoch", *seed_epoch)
        .u("chain.seed_lag", *seed_lag)
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
        .size("tx.MAX_PROGRAM_BYTES", tx::MAX_PROGRAM_BYTES)
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
    let mut ts: Vec<u64> = (0..87).map(|i| 1_000_000 + i * t).collect();
    let cd: Vec<u128> = (0..87u128).map(|i| (i + 1) * 1_000_000).collect();
    let steady = difficulty::next_difficulty(&ts, &cd, t, n, 1);
    ts[11] -= 1_300;
    m.list(
        "rules.sample.next_difficulty (T 120, N 75)",
        [
            steady,
            difficulty::next_difficulty(&ts, &cd, t, n, 1),
            difficulty::next_difficulty(&ts[11..], &cd[11..], t, n, 1),
            difficulty::next_difficulty(&ts[..1], &cd[..1], t, n, 777),
        ],
    )
    .list(
        "rules.sample.clock_step (T 120, 10, 2, 1)",
        [120, 10, 2, 1].map(difficulty::clock_step),
    )
    .size(
        "rules.sample.difficulty_ancestors(75)",
        difficulty::difficulty_ancestors(n),
    )
    // The lower clamp (RTFP3-6): a tiny difficulty over a slow window gives
    // a result below 1, which the rule raises to 1.
    .u(
        "rules.sample.next_difficulty([0, 1000], [1, 2], T 120, N 75, D0 1)",
        difficulty::next_difficulty(&[0, 1_000], &[1, 2], t, n, 1),
    );

    // Median time past (strict, lower median for an even count).
    let recent = [100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200];
    m.list(
        "rules.sample.median (11 stamps, 4 stamps)",
        [timestamp::median(&recent), timestamp::median(&[4, 1, 3, 2])],
    )
    .list(
        "rules.sample.after_median_time_past (150, 151)",
        [150, 151].map(|s| u64::from(timestamp::after_median_time_past(s, &recent))),
    )
    // The future time limit at its boundary (RTFP3-5): now 1 000, FTL 360.
    .list(
        "rules.sample.within_future_limit (1359, 1360, 1361; now 1000, FTL 360)",
        [1_359, 1_360, 1_361].map(|s| u64::from(timestamp::within_future_limit(s, 1_000, 360))),
    );

    // The proof-of-work target at its boundary: hash · d < 2^256.
    let mut half = [0u8; 32];
    half[31] = 0x80; // 2^255 (little-endian)
    let mut below = [0xffu8; 32];
    below[31] = 0x7f; // 2^255 − 1
    m.list(
        "rules.sample.check_hash (max*1, 2^255*2, (2^255-1)*2, 0*0, 0*u64::MAX)",
        [
            check_hash(&[0xff; 32], 1),
            check_hash(&half, 2),
            check_hash(&below, 2),
            check_hash(&[0; 32], 0),
            check_hash(&[0; 32], u64::MAX),
        ]
        .map(u64::from),
    );

    // The block id and the transaction Merkle root.
    let header = BlockHeader {
        version: 1,
        height: 7,
        prev_id: [1; 32],
        timestamp: 1_700_000_000,
        difficulty: 1_000,
        tx_root: [2; 32],
        nonce: 42,
    };
    m.bytes(
        "rules.sample.block_id (test-vector network id)",
        &header.id(TEST_VECTOR_NETWORK_ID),
    )
    .bytes("rules.sample.tx_root([])", &merkle::tx_root(&[]))
    .bytes(
        "rules.sample.tx_root([1; 32], [2; 32], [3; 32])",
        &merkle::tx_root(&[[1; 32], [2; 32], [3; 32]]),
    );

    // The genesis-nonce derivation (Bitcoin block 0, H = 0, test-vector id).
    let btc0 =
        parse_display_hex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("Bitcoin block 0's hash");
    m.u(
        "rules.sample.genesis_nonce (Bitcoin block 0, test-vector id)",
        derive_genesis_nonce(TEST_VECTOR_NETWORK_ID, 0, &btc0),
    );

    // The signature domain layout (RT-14): network id, branch id, genesis id.
    m.bytes(
        "rules.sample.sig_domain (0x01020304, 0x05060708, [9; 32])",
        &SigDomain {
            network_id: 0x0102_0304,
            branch_id: 0x0506_0708,
            genesis_id: [9; 32],
        }
        .bytes(),
    );

    // Weights and fees (T8, R12-2): max_weight over transfer shapes; the v1
    // part of PX and deploy transactions (0 without v1 inputs); the exact v1
    // fee; the deploy fee at three program sizes (the vault's budget and
    // output words).
    let shapes = [(1, 2), (2, 2), (1, 16), (64, 16), (1, 0), (64, 2)];
    m.list(
        "rules.sample.max_weight (1,2) (2,2) (1,16) (64,16) (1,0) (64,2)",
        shapes.map(|(i, o)| max_weight(i, o)),
    )
    .list(
        "rules.sample.px_v1_part_weight (0,2) (1,0) (64,16) (1,2) (64,2)",
        [(0, 2), (1, 0), (64, 16), (1, 2), (64, 2)].map(|(i, o)| v1_part_weight(i, o)),
    );
    let rules = TxRules::at_height(&ChainParams::for_network(network), 0);
    m.list(
        "rules.sample.standard_fee (1,2) (2,2) (1,16) (64,16) (1,0) (64,2)",
        shapes.map(|(i, o)| rules.standard_fee(i, o).unwrap_or(u64::MAX)),
    )
    .list(
        "rules.sample.deploy_fee (1 in, 2 out; 1, 4 096, MAX_PROGRAM_BYTES)",
        [1, 4_096, tx::MAX_PROGRAM_BYTES].map(|len| {
            let r = Registration::new(
                vec![0; len],
                blacksilk_px::vault::BUDGET,
                blacksilk_px::vault::OUT_WORDS,
            );
            deploy_fee(1, 2, &[r], &rules)
        }),
    );
    m.extend(transaction_samples().clone());
    m
}

/// The RandomX configuration, read from the crate
/// (`blacksilk_randomx::config_entries`, RTFP3-2), and its pinned known
/// answer (`blacksilk_randomx::FINGERPRINT_KAT`, the reference vector 1a).
/// No hash is computed here: a light-mode hash needs a 256 MiB cache, too
/// costly for `/info` and `--version`. The known answer is a pinned copy that
/// the crate's vector test requires the crate to compute, as
/// `zkvm.CIRCUIT_DIGEST` is for the circuit.
fn randomx_entries(m: &mut Manifest) {
    use blacksilk_randomx::ConfigValue;
    m.text(
        "randomx.variant",
        "RandomX v1 (rx/0), light-mode verification",
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

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    ::hex::decode(s).ok()
}

/// The chain view of the verdict samples: the fixture's ring members, with
/// some removed or some key images spent. No PX state.
struct FixtureChain<'a> {
    outputs: &'a BTreeMap<u64, OutputRecord>,
    missing: Option<u64>,
    spent: Option<Point>,
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
    fn px_is_recent_root(&self, _: &blacksilk_px::core::Digest) -> bool {
        false
    }
    fn px_nullifier_spent(&self, _: &blacksilk_px::core::Digest) -> bool {
        false
    }
    fn px_pool(&self) -> u128 {
        0
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
        0
    }
}

/// The transaction samples (network-independent, computed once per process):
///
/// - `Transaction::weight` of the fixture transfer and coinbase, and of a PX
///   transaction with the transfer's v1 part and with none (RTFP3-3);
/// - the transfer's id and signature message, and the coinbase's id (RTFP3-1);
/// - **verdict samples** (RTFP3-4): `validate_transfer` on the fixture and on
///   one variant per `TxError` class a transfer can reach (each variant
///   changes one field, or the chain view, or the validation height), as the
///   `Debug` text of the result. Not sampled: `TooLarge` (no transfer shape
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
    m.list(
        "rules.sample.weight (fixture transfer 2-in 3-out, coinbase, PX 2-in 3-out, PX 0-in 3-out)",
        [
            Transaction::from(t.clone()).weight(),
            f.coinbase.weight(),
            px(t.inputs.clone()).weight(),
            px(Vec::new()).weight(),
        ],
    )
    .bytes(
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

    // One variant per error class; each changes one thing of the valid case.
    let identity = Point::from_point(RistrettoPoint::default());
    let plus_g = |p: &Point| Point::from_point(p.point() + G);
    let full = FixtureChain {
        outputs: &f.outputs,
        missing: None,
        spent: None,
    };
    let verdict = |tx: &Transfer, chain: &FixtureChain, height: u64, rules: &TxRules| {
        format!("{:?}", validate_transfer(tx, chain, height, rules))
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
    let cases: [(&str, String); 21] = [
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
    for (name, v) in cases {
        m.text(&format!("rules.sample.verdict ({name})"), &v);
    }
    m
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
            assert_eq!(identity_manifest(n).entries().len(), 7);
        }
        // Two networks that differ only in their identity fields (testnet and
        // mainnet also differ in D0) share every rule except D0.
        let strip = |n: Network| {
            rules_manifest(n)
                .entries()
                .iter()
                .filter(|(name, _)| name != "chain.initial_difficulty")
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(strip(Network::Testnet), strip(Network::Mainnet));
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
                "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f".to_string()
            )
        );
        assert_eq!(get("randomx.PROGRAM_ITERATIONS"), Value::U64(2048));
        let verdict = |case: &str| match get(&format!("rules.sample.verdict ({case})")) {
            Value::Text(t) => t,
            other => panic!("{other:?}"),
        };
        assert_eq!(verdict("valid"), "Ok(())");
        for (case, class) in [
            ("no inputs", "InputCount"),
            ("one output", "OutputCount"),
            ("identity key image", "KeyImageIdentity"),
            ("key images unsorted", "KeyImagesNotSorted"),
            ("ring unsorted", "RingNotIncreasing"),
            ("identity output key", "OutputKeyIdentity"),
            ("identity ephemeral", "EphemeralIdentity"),
            ("outputs unsorted", "OutputsNotSorted"),
            ("missing pseudo-output", "PseudoOutCount"),
            ("missing signature", "SignatureCount"),
            ("identity auxiliary image", "AuxKeyImageIdentity"),
            ("short range proof", "RangeProofShape"),
            ("fee + 1", "FeeNotExact"),
            ("unbalanced", "Unbalanced"),
            ("balanced, range proof invalid", "RangeProofInvalid"),
            ("key image spent", "KeyImageSpent"),
            ("ring member unknown", "UnknownRingMember"),
            (
                "coinbase ring member immature (height 60)",
                "RingMemberTooYoung",
            ),
            ("other branch id", "InvalidSignature"),
            ("signature of the other input", "InvalidSignature"),
        ] {
            assert!(
                verdict(case).starts_with(&format!("Err({class}")),
                "{case}: {}",
                verdict(case)
            );
        }
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
}
