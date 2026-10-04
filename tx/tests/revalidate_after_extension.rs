//! `revalidate_after_extension` against a chain view whose state the test
//! controls (finding F3).
//!
//! The mempool re-checks pooled transactions after a plain extension with
//! [`revalidate_after_extension`] instead of full validation. The function
//! must re-check exactly the rules an extension can change: C2 key images,
//! PX1 (anchor window), PX2 (nullifiers), PX3 (registered functions), PX4
//! (the pool) and a deploy's contract id. (Output one-time keys are not
//! related to the chain by any rule since D8 option B: the chain view has no
//! query for them, and chain/tests/revalidation.rs shows a mined copy of a
//! pooled key leaving the transaction valid.) Each test below
//! starts from a state in which the transaction passes, changes ONE piece of
//! state the way a connected block would, and asserts the specific error; and
//! for state changes an extension makes that must not matter, that the verdict
//! stays `Ok`.
//!
//! The transactions are synthetic: the function by design does not look at
//! signatures, range proofs, PX proofs, balance or structure (intrinsic rules,
//! checked once at admission), which the last test documents.

use blacksilk_crypto::bulletproofs_plus::{self as bpp, BppProof};
use blacksilk_crypto::janus::ANCHOR_BYTES;
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_px_core::Digest;
use blacksilk_tx::params::{TxRules, RING_SIZE};
use blacksilk_tx::px::{digest_bytes, PxDeploy, PxFunction, PxTx, Registration};
use blacksilk_tx::types::{Coinbase, CoinbaseOutput, Input, Output, Transaction, Transfer};
use blacksilk_tx::validate::{
    revalidate_after_extension, validate_mempool_tx, ChainView, OutputRecord, PxProgram, TxError,
};
use blacksilk_zkvm::air::trace::Budget;
use blacksilk_zkvm::Program;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

// ------------------------------------------------------------------ mock chain

/// Registered functions: (contract bytes, program id) -> the registration.
type Registry = HashMap<([u8; 32], [u8; 32]), PxProgram>;

/// The height the pooled transactions are re-checked for (the next block's).
const NEXT: u64 = 1;

/// A chain view whose every answer the test sets. Only the state the function
/// may consult is modelled; `output` answers nothing, so any attempt to
/// resolve rings would fail loudly (it must not happen here).
#[derive(Default)]
struct MockChain {
    key_images: HashSet<[u8; 32]>,
    recent_roots: HashSet<[u8; 32]>,
    nullifiers: HashSet<[u8; 32]>,
    pool: u128,
    functions: Registry,
    contracts: HashSet<[u8; 32]>,
}

impl ChainView for MockChain {
    fn output(&self, _: u64) -> Option<OutputRecord> {
        None
    }
    fn is_key_image_spent(&self, key_image: &Point) -> bool {
        self.key_images.contains(key_image.bytes())
    }
    fn px_is_recent_root(&self, anchor: &Digest) -> bool {
        self.recent_roots.contains(&digest_bytes(anchor))
    }
    fn px_nullifier_spent(&self, nf: &Digest) -> bool {
        self.nullifiers.contains(&digest_bytes(nf))
    }
    fn px_pool(&self) -> u128 {
        self.pool
    }
    fn px_function(&self, contract: &Digest, program_id: &[u8; 32]) -> Option<PxProgram> {
        self.functions
            .get(&(digest_bytes(contract), *program_id))
            .cloned()
    }
    fn px_contract_exists(&self, contract: &Digest) -> bool {
        self.contracts.contains(&digest_bytes(contract))
    }
    fn px_tree_size(&self) -> u64 {
        0
    }
    /// No block is validated on this view.
    fn px_root_after(&self, leaves: &[Digest]) -> Option<Digest> {
        blacksilk_px::state::State::new().root_after(leaves)
    }
    fn output_frontier(&self) -> blacksilk_tx::mmr::OutputFrontier {
        blacksilk_tx::mmr::OutputFrontier::new()
    }
}

impl MockChain {
    fn spend_key_image(&mut self, k: &Point) {
        self.key_images.insert(*k.bytes());
    }
    fn register(&mut self, contract: Digest, program_id: [u8; 32]) {
        self.contracts.insert(digest_bytes(&contract));
        self.functions.insert(
            (digest_bytes(&contract), program_id),
            PxProgram {
                program: program(),
                budget: budget(),
                abi: blacksilk_tx::px::ABI_VERSION,
                out_words: 0,
            },
        );
    }
}

// ------------------------------------------------------------------ synthetic data

fn program() -> Arc<Program> {
    Arc::new(Program {
        entry: 0,
        code_base: 0,
        code: vec![],
        data: vec![],
    })
}

fn budget() -> Budget {
    Budget {
        cycles: 0,
        keys: 0,
        add: 0,
        bit: 0,
        lt: 0,
        shift: 0,
        mul: 0,
        poseidon: 0,
    }
}

/// A distinct non-identity point `n·G`.
fn pt(n: u64) -> Point {
    Point::from_point(RistrettoPoint::mul_base(&Scalar::from(n)))
}

/// A well-shaped (but not matching anything) range proof, for the fields that
/// require one.
fn dummy_proof() -> BppProof {
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    bpp::prove(&[1, 2], &[Scalar::from(3u64), Scalar::from(4u64)], &mut rng)
        .unwrap()
        .0
}

fn input(key_image: u64) -> Input {
    Input {
        key_image: pt(key_image),
        ring: std::array::from_fn(|j| j as u64),
    }
}

fn output(one_time_key: u64) -> Output {
    Output {
        one_time_key: pt(one_time_key),
        ephemeral: pt(one_time_key + 1_000_000),
        view_tag: 0,
        commitment: pt(one_time_key + 2_000_000),
        enc_amount: [0; 8],
        enc_anchor: [0; ANCHOR_BYTES],
    }
}

fn payout(one_time_key: u64) -> CoinbaseOutput {
    CoinbaseOutput {
        one_time_key: pt(one_time_key),
        ephemeral: pt(one_time_key + 1_000_000),
        view_tag: 0,
        amount: 5,
        enc_anchor: [0; ANCHOR_BYTES],
    }
}

/// Transfer: key images 100, 101; output keys 200, 201. No signatures.
fn transfer() -> Transfer {
    Transfer {
        inputs: vec![input(100), input(101)],
        outputs: vec![output(200), output(201)],
        fee: 1,
        pseudo_outs: vec![],
        range_proof: dummy_proof(),
        signatures: vec![],
    }
}

const ANCHOR: Digest = [1, 2, 3, 4, 5, 6, 7, 8];
const CONTRACT: Digest = [9, 9, 9, 9, 9, 9, 9, 9];
const PROGRAM_ID: [u8; 32] = [0x42; 32];
const NF: [Digest; 2] = [[11, 0, 0, 0, 0, 0, 0, 0], [12, 0, 0, 0, 0, 0, 0, 0]];

/// A record ciphertext with a valid `R` (the base point), so the PX
/// transaction fails full validation for its intended reasons, not the
/// ciphertext `R` rule.
fn ciphertext() -> Vec<u8> {
    let mut c = vec![0; blacksilk_px::delivery::CIPHERTEXT_BYTES];
    c[..32].copy_from_slice(&blacksilk_crypto::generators::G.compress().to_bytes());
    c
}

/// PX transaction: key image 300; hidden output key 400; payout key 401;
/// anchor ANCHOR; nullifiers NF; one call to CONTRACT/PROGRAM_ID; bridges in
/// and out as given. No proof.
fn px(bridge_in: u64, bridge_out: u64) -> PxTx {
    PxTx {
        inputs: vec![input(300)],
        outputs: vec![output(400)],
        payouts: vec![payout(401)],
        fee: 1,
        bridge_in,
        bridge_out,
        window: Default::default(),
        anchor: ANCHOR,
        nullifiers: NF,
        commitments: [[21; 8], [22; 8]],
        ciphertexts: [ciphertext(), ciphertext()],
        functions: vec![PxFunction {
            contract: CONTRACT,
            program_id: PROGRAM_ID,
            io_hash: [0; 8],
            outputs: vec![],
        }],
        pseudo_outs: vec![],
        range_proof: None,
        signatures: vec![],
        proof: vec![],
    }
}

/// Deploy: key image 500; output keys 600, 601; one (unloadable) program.
fn deploy() -> PxDeploy {
    PxDeploy {
        inputs: vec![input(500)],
        outputs: vec![output(600), output(601)],
        fee: 1,
        salt: [7; 32],
        programs: vec![Registration {
            elf: vec![1, 2, 3],
            budget: budget(),
            abi: blacksilk_tx::px::ABI_VERSION,
            out_words: 1,
        }],
        pseudo_outs: vec![],
        range_proof: dummy_proof(),
        signatures: vec![],
    }
}

/// The chain state in which every synthetic transaction above is valid for
/// the rules this function checks.
fn base_chain() -> MockChain {
    let mut c = MockChain::default();
    c.recent_roots.insert(digest_bytes(&ANCHOR));
    c.register(CONTRACT, PROGRAM_ID);
    c.pool = 1_000;
    // Unrelated history: other key images and nullifiers.
    c.spend_key_image(&pt(1));
    c.nullifiers.insert(digest_bytes(&[99; 8]));
    c
}

fn tx_transfer() -> Transaction {
    Transaction::from(transfer())
}
fn tx_px(bridge_in: u64, bridge_out: u64) -> Transaction {
    Transaction::Px(Box::new(px(bridge_in, bridge_out)))
}
fn tx_deploy() -> Transaction {
    Transaction::PxDeploy(Box::new(deploy()))
}

fn all_txs() -> Vec<Transaction> {
    vec![tx_transfer(), tx_px(0, 0), tx_deploy()]
}

fn assert_all_ok(chain: &MockChain, context: &str) {
    for tx in all_txs() {
        assert_eq!(
            revalidate_after_extension(&tx, chain, NEXT),
            Ok(()),
            "{context}: {tx:?}"
        );
    }
}

// ------------------------------------------------------------------ tests

#[test]
fn baseline_every_kind_passes_and_a_coinbase_is_refused() {
    let c = base_chain();
    assert_all_ok(&c, "baseline");
    let cb = Transaction::Coinbase(Coinbase {
        height: 1,
        outputs: vec![payout(700), payout(701)],
    });
    assert_eq!(
        revalidate_after_extension(&cb, &c, NEXT),
        Err(TxError::CoinbaseNotAllowed)
    );
}

/// PX1: the anchor leaves the recent-root window as blocks are added.
#[test]
fn px_anchor_leaving_the_window_is_detected() {
    let mut c = base_chain();
    let tx = tx_px(0, 0);
    assert_eq!(revalidate_after_extension(&tx, &c, NEXT), Ok(()));
    // An extension adds new roots and evicts the oldest.
    c.recent_roots.insert(digest_bytes(&[50; 8]));
    assert_eq!(
        revalidate_after_extension(&tx, &c, NEXT),
        Ok(()),
        "a new root alone"
    );
    c.recent_roots.remove(&digest_bytes(&ANCHOR));
    assert_eq!(
        revalidate_after_extension(&tx, &c, NEXT),
        Err(TxError::PxUnknownAnchor)
    );
}

/// PX4: blocks drain the pool below what a pooled withdrawal needs; exact
/// boundary included (`pool + bridge_in == bridge_out` is fine).
#[test]
fn px_pool_becoming_insufficient_is_detected() {
    let mut c = base_chain();
    c.pool = 100;
    let withdraw = tx_px(30, 130);
    assert_eq!(
        revalidate_after_extension(&withdraw, &c, NEXT),
        Ok(()),
        "100 + 30 == 130"
    );
    c.pool = 99;
    assert_eq!(
        revalidate_after_extension(&withdraw, &c, NEXT),
        Err(TxError::PxPoolUnderflow)
    );
    // A deposit is unaffected by the pool, even at zero.
    c.pool = 0;
    assert_eq!(revalidate_after_extension(&tx_px(50, 0), &c, NEXT), Ok(()));
    // And a pool that grows back revives the withdrawal: the verdict is a
    // function of the current state only.
    c.pool = 1_000;
    assert_eq!(revalidate_after_extension(&withdraw, &c, NEXT), Ok(()));
}

/// PX2: either nullifier spent by a block.
#[test]
fn px_nullifier_becoming_spent_is_detected() {
    for (i, nf) in NF.iter().enumerate() {
        let mut c = base_chain();
        let tx = tx_px(0, 0);
        assert_eq!(revalidate_after_extension(&tx, &c, NEXT), Ok(()));
        c.nullifiers.insert(digest_bytes(nf));
        assert_eq!(
            revalidate_after_extension(&tx, &c, NEXT),
            Err(TxError::PxNullifierSpent { index: i })
        );
    }
}

/// The contract id registered on chain after the deploy entered the pool.
/// The id binds the deploy's first key image, so in practice this is a copy
/// spending the same input mined from another pool, which C2 also catches;
/// the mock changes only the registry, to show the contract check is live on
/// its own.
#[test]
fn a_contract_deployed_on_chain_makes_the_pooled_deploy_a_duplicate() {
    let mut c = base_chain();
    let tx = tx_deploy();
    let d = deploy();
    assert_eq!(revalidate_after_extension(&tx, &c, NEXT), Ok(()));
    // Another contract registered: no effect.
    c.register([1; 8], [1; 32]);
    assert_eq!(revalidate_after_extension(&tx, &c, NEXT), Ok(()));
    c.contracts.insert(digest_bytes(&d.contract_id()));
    assert_eq!(
        revalidate_after_extension(&tx, &c, NEXT),
        Err(TxError::DuplicateContract)
    );
}

/// C2 for every kind with ring inputs.
#[test]
fn a_key_image_becoming_spent_is_detected() {
    let cases: Vec<(Transaction, u64, usize)> = vec![
        (tx_transfer(), 100, 0),
        (tx_transfer(), 101, 1),
        (tx_px(0, 0), 300, 0),
        (tx_deploy(), 500, 0),
    ];
    for (tx, ki, input) in cases {
        let mut c = base_chain();
        assert_eq!(revalidate_after_extension(&tx, &c, NEXT), Ok(()));
        c.spend_key_image(&pt(ki));
        assert_eq!(
            revalidate_after_extension(&tx, &c, NEXT),
            Err(TxError::KeyImageSpent { input }),
            "key image {ki}"
        );
    }
}

/// PX3: the registry only grows, so a registered function stays registered;
/// the check is still made (an unregistered function is reported).
#[test]
fn registered_functions_stay_registered_as_the_registry_grows() {
    let mut c = base_chain();
    let tx = tx_px(0, 0);
    for n in 0..10u32 {
        c.register([n + 100; 8], [n as u8; 32]);
        assert_eq!(revalidate_after_extension(&tx, &c, NEXT), Ok(()));
    }
    // The check is live: without the registration the verdict is PX3.
    let mut bare = base_chain();
    bare.functions.clear();
    assert_eq!(
        revalidate_after_extension(&tx, &bare, NEXT),
        Err(TxError::PxUnregistered { function: 0 })
    );
}

/// A normal extension: new unrelated key images, nullifiers,
/// roots (the pooled anchor still in the window), contracts and pool inflow.
/// Nothing a pooled transaction depends on changes, so every verdict stays Ok.
#[test]
fn an_unrelated_extension_changes_nothing() {
    let mut c = base_chain();
    assert_all_ok(&c, "before");
    for n in 0..50u64 {
        c.spend_key_image(&pt(10_000 + n));
        c.nullifiers.insert(digest_bytes(&[n as u32 + 1000; 8]));
        c.recent_roots.insert(digest_bytes(&[n as u32 + 2000; 8]));
        c.register([n as u32 + 3000; 8], [n as u8; 32]);
        c.pool += 7;
    }
    assert_all_ok(&c, "after 50 unrelated blocks");
}

/// Intended scope: the function checks no intrinsic rule. A transaction with
/// no signatures, no pseudo-outputs, an empty PX proof, an unloadable deploy
/// program and unbalanced amounts passes it, while full validation rejects it.
/// This is correct only because such a transaction never enters the pool
/// (admission runs full validation, including the PX proof), and intrinsic
/// rules cannot change when blocks are added.
#[test]
fn intrinsic_rules_are_not_rechecked_by_design() {
    let c = base_chain();
    let rules = TxRules::for_chain(&blacksilk_consensus::ChainParams::regtest());
    for tx in all_txs() {
        assert_eq!(revalidate_after_extension(&tx, &c, NEXT), Ok(()));
        let full = validate_mempool_tx(&tx, &c, 100, &rules);
        assert!(full.is_err(), "full validation must reject {tx:?}");
        // An intrinsic rule rejects it, never the ciphertext `R` rule (the
        // fixture's `R` is valid).
        assert!(
            !matches!(
                full,
                Err(TxError::PxCiphertextRNonCanonical { .. }
                    | TxError::PxCiphertextRIdentity { .. })
            ),
            "{full:?}"
        );
    }
    // Ring members that resolve to nothing (C1) are not looked at either:
    // outputs are append-only, so an extension cannot change them.
    let mut ring_unresolvable = transfer();
    ring_unresolvable.inputs[0].ring = [u64::MAX - RING_SIZE as u64; RING_SIZE];
    assert_eq!(
        revalidate_after_extension(&Transaction::from(ring_unresolvable), &c, NEXT),
        Ok(())
    );
}
