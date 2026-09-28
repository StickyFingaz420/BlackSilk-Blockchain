//! PX6, the transaction validity window, and the call ABI registration
//! (F-28-1, F-28-5; docs/reviews/v3-consensus-changes.md#px6-validity-window
//! and #px-call-abi), without proofs: a PX transaction carries `[not_before,
//! not_after]` (`(0, 0)` unbounded), covered by `h_tx`; a block at height
//! `h` may include it only when `not_before ≤ h` and (`not_after = 0` or
//! `h ≤ not_after`). The rule is contextual and never scored, the mempool's
//! revalidation applies it at the next height, and the block path applies
//! it to every PX transaction, including those whose proof the node has
//! already verified. The proof binding is exercised with real proofs in
//! `px_consensus.rs` (`a_vault_refund_obeys_its_validity_window_through_consensus`).

mod common;

use blacksilk_px::delivery::CIPHERTEXT_BYTES;
use blacksilk_px::state::State as PxState;
use blacksilk_tx::builder::{BuildError, Payment};
use blacksilk_tx::codec::DecodeError;
use blacksilk_tx::params::{MAX_FN_OUTPUT_WORDS, PX_STANDARD_FEE};
use blacksilk_tx::px::{PxDeploy, PxTx, Registration, Window, ABI_VERSION};
use blacksilk_tx::px_builder::build_deploy;
use blacksilk_tx::state::MemoryChain;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::{
    revalidate_after_extension, validate_block_transactions_cached, validate_px_without_proof,
    BlockError, TxError,
};
use common::*;

const POOL: u128 = 1 << 60;

/// A chain with a PX pool (so fees can be paid out of it) and three blocks.
fn chain(seed: u64) -> TestNet {
    let mut net = TestNet::new(seed, 0);
    net.chain = MemoryChain::with_px_state(PxState::with_uniform_tree_for_tests(4, [7; 8], POOL));
    for _ in 0..3 {
        net.mine(vec![], &mut []).unwrap();
    }
    assert_eq!(net.height(), 3);
    net
}

/// A PX transaction without v1 inputs that every rule but the proof accepts
/// (the fee is paid out of the pool), with validity window `window`.
fn px(net: &TestNet, tag: u32, window: Window) -> PxTx {
    PxTx {
        inputs: vec![],
        outputs: vec![],
        payouts: vec![],
        fee: PX_STANDARD_FEE,
        bridge_in: 0,
        bridge_out: PX_STANDARD_FEE,
        window,
        anchor: net.chain.px().root(),
        nullifiers: [[tag, 1, 0, 0, 0, 0, 0, 0], [tag, 2, 0, 0, 0, 0, 0, 0]],
        commitments: [[tag, 3, 0, 0, 0, 0, 0, 0], [tag, 4, 0, 0, 0, 0, 0, 0]],
        ciphertexts: [vec![0; CIPHERTEXT_BYTES], vec![0; CIPHERTEXT_BYTES]],
        functions: vec![],
        pseudo_outs: vec![],
        range_proof: None,
        signatures: vec![],
        proof: vec![],
    }
}

fn window(not_before: u64, not_after: u64) -> Window {
    Window {
        not_before,
        not_after,
    }
}

/// Validates a block `coinbase ‖ pxs` at the next height with every proof
/// vouched for (the node's verified-proof cache): PX6 must still apply.
fn block_with_cached_proofs(net: &mut TestNet, pxs: &[PxTx]) -> Result<(), BlockError> {
    let fees = pxs.len() as u64 * PX_STANDARD_FEE;
    let mut txs = vec![net.coinbase(fees)];
    txs.extend(pxs.iter().map(|t| Transaction::Px(Box::new(t.clone()))));
    let ctx = net.context(&txs);
    let rules = net.rules;
    validate_block_transactions_cached(&txs, &ctx, &net.chain, &rules, &mut net.rng, &|_| true)
}

#[test]
fn the_window_is_encoded_bound_by_h_tx_and_unbounded_by_default() {
    let net = chain(1);
    let t = px(&net, 1, Window::UNBOUNDED);
    assert_eq!(Window::default(), Window::UNBOUNDED);
    // Round trip, with the window in the prefix (so in h_tx and the id).
    for w in [
        Window::UNBOUNDED,
        window(5, 0),
        window(0, 9),
        window(u64::MAX, u64::MAX),
    ] {
        let mut u = t.clone();
        u.window = w;
        let tx = Transaction::Px(Box::new(u.clone()));
        let back = Transaction::decode(&tx.encode()).expect("decodes");
        assert_eq!(back, tx);
        if w != Window::UNBOUNDED {
            let domain = net.rules.domain();
            assert_ne!(u.binding(domain), t.binding(domain), "{w:?}");
            assert_ne!(u.prefix_hash(), t.prefix_hash());
        }
    }
    // A small window costs no more than the default (two one-byte varints).
    let mut u = t.clone();
    u.window = window(1, 1);
    assert_eq!(u.encoded_len(), t.encoded_len());
}

#[test]
fn an_inverted_window_is_a_stateless_structure_error() {
    let net = chain(2);
    let bad = px(&net, 1, window(10, 9));
    assert_eq!(
        blacksilk_tx::px::check_px_structure(&bad),
        Err(TxError::PxWindowInverted)
    );
    assert!(TxError::PxWindowInverted.is_stateless());
    // Well formed: equal ends, or no upper end.
    for w in [window(9, 9), window(10, 0), window(0, 0), window(0, 1)] {
        assert_eq!(
            blacksilk_tx::px::check_px_structure(&px(&net, 1, w)),
            Ok(())
        );
    }
}

/// The boundaries: `not_before − 1` is premature, `not_before` and
/// `not_after` are valid, `not_after + 1` has expired. `PxWindow` is
/// contextual (never scored: heights race at the edges).
#[test]
fn the_window_holds_exactly_between_its_ends() {
    let net = chain(3);
    let rules = net.rules;
    let t = px(&net, 1, window(20, 30));
    for (h, ok) in [(19, false), (20, true), (25, true), (30, true), (31, false)] {
        let got = validate_px_without_proof(&t, &net.chain, h, &rules);
        assert_eq!(got.is_ok(), ok, "height {h}: {got:?}");
        if !ok {
            assert_eq!(got, Err(TxError::PxWindow));
        }
    }
    assert!(!TxError::PxWindow.is_stateless());
    let params = blacksilk_consensus::ChainParams::regtest();
    assert!(!TxError::PxWindow.is_stateless_at(&params, 25));
    // Unbounded above, and fully unbounded.
    let open = px(&net, 2, window(20, 0));
    assert_eq!(
        validate_px_without_proof(&open, &net.chain, u64::MAX, &rules),
        Ok(())
    );
    let unbounded = px(&net, 3, Window::UNBOUNDED);
    for h in [0, 1, u64::MAX] {
        assert_eq!(
            validate_px_without_proof(&unbounded, &net.chain, h, &rules),
            Ok(())
        );
    }
    // A stateless fault is still reported first.
    let mut both = px(&net, 4, window(20, 30));
    both.fee += 1;
    both.bridge_out += 1;
    assert_eq!(
        validate_px_without_proof(&both, &net.chain, 19, &rules),
        Err(TxError::PxFeeNotStandard { fee: both.fee })
    );
}

/// `revalidate_after_extension` takes the next height: a pooled transaction
/// past its `not_after` is dropped after a plain extension.
#[test]
fn revalidation_after_an_extension_expires_the_window() {
    let net = chain(4);
    let t = Transaction::Px(Box::new(px(&net, 1, window(0, 12))));
    assert_eq!(revalidate_after_extension(&t, &net.chain, 12), Ok(()));
    assert_eq!(
        revalidate_after_extension(&t, &net.chain, 13),
        Err(TxError::PxWindow)
    );
    // A premature one too (after a reorganization, the full path applies the
    // same check; `chain/src/mempool.rs` tests the pool).
    let early = Transaction::Px(Box::new(px(&net, 2, window(14, 0))));
    assert_eq!(
        revalidate_after_extension(&early, &net.chain, 13),
        Err(TxError::PxWindow)
    );
    assert_eq!(revalidate_after_extension(&early, &net.chain, 14), Ok(()));
}

/// The block path checks PX6 for every PX transaction, whether or not its
/// proof was verified before (AT-5, RT-2): the verified-proof cache vouches
/// for a proof, never for a height.
#[test]
fn a_cached_proof_never_skips_the_window() {
    let mut net = chain(5);
    let h = net.height();
    let premature = px(&net, 1, window(h + 1, 0));
    assert_eq!(
        block_with_cached_proofs(&mut net, &[premature]),
        Err(BlockError::Tx {
            index: 1,
            error: TxError::PxWindow
        })
    );
    let expired = px(&net, 2, window(0, h - 1));
    assert_eq!(
        block_with_cached_proofs(&mut net, &[expired]),
        Err(BlockError::Tx {
            index: 1,
            error: TxError::PxWindow
        })
    );
    // At its edges the block is valid.
    let edge = [px(&net, 3, window(h, h)), px(&net, 4, window(0, 0))];
    assert_eq!(block_with_cached_proofs(&mut net, &edge), Ok(()));
}

/// RTW1C-5: in the mempool path PX6 (a comparison) runs before the range
/// proof, so a transaction outside its window costs no Bulletproofs+
/// verification. A PX transaction carrying a real v1 part (inputs, hidden
/// outputs, range proof) with a broken range proof is refused as `PxWindow`
/// outside its window and as `RangeProofInvalid` inside it; the verdict
/// (invalid) is the same. On the base (e986250) the range proof ran first:
/// `RangeProofInvalid` at every height.
#[test]
fn the_window_is_checked_before_the_range_proof() {
    let mut net = TestNet::new(21, 80);
    let alice = Wallet::new(&mut rng(1021));
    let t = net.pay(&net.miner_clone(), &[(alice.primary(), 1_000_000)]);
    let h = net.height();
    let mut tx = px(&net, 1, window(h + 5, 0));
    tx.inputs = t.inputs.clone();
    tx.outputs = t.outputs.clone();
    tx.pseudo_outs = t.pseudo_outs.clone();
    tx.signatures = t.signatures.clone();
    tx.range_proof = Some(t.range_proof.clone());
    // Balance: the v1 part carries the transfer's fee, `fee − bridge_out`.
    tx.bridge_out = PX_STANDARD_FEE - t.fee;
    assert_eq!(blacksilk_tx::px::check_px_structure(&tx), Ok(()));
    assert_eq!(blacksilk_tx::px::check_px_balance(&tx), Ok(()));
    let mut broken = tx.clone();
    broken.range_proof.as_mut().unwrap().d1 += blacksilk_crypto::Scalar::ONE;
    let rules = net.rules;
    // Premature: PX6 first.
    assert_eq!(
        validate_px_without_proof(&broken, &net.chain, h, &rules),
        Err(TxError::PxWindow)
    );
    // Inside the window the range proof refuses it (stateless).
    assert_eq!(
        validate_px_without_proof(&broken, &net.chain, h + 5, &rules),
        Err(TxError::RangeProofInvalid)
    );
    // With the genuine range proof the transaction passes both.
    assert!(!matches!(
        validate_px_without_proof(&tx, &net.chain, h + 5, &rules),
        Err(TxError::PxWindow | TxError::RangeProofInvalid)
    ));
}

/// RTW1C-4: the expiring-soon policy (`px_expires_soon`, margin 3 blocks,
/// Zcash's threshold): a window ending before `next + 3` is refused by pools
/// and relays; an unbounded end never is.
#[test]
fn a_window_ending_within_three_blocks_expires_soon() {
    use blacksilk_tx::validate::{px_expires_soon, PX_EXPIRING_SOON_BLOCKS};
    assert_eq!(PX_EXPIRING_SOON_BLOCKS, 3);
    let net = chain(6);
    let next = 100;
    for (w, soon) in [
        (Window::UNBOUNDED, false),
        (window(500, 0), false),
        (window(0, next - 1), true),
        (window(0, next), true),
        (window(0, next + 2), true),
        (window(0, next + 3), false),
        (window(0, u64::MAX), false),
    ] {
        assert_eq!(px_expires_soon(&px(&net, 1, w), next), soon, "{w:?}");
    }
    // No overflow at the top of the height range.
    assert!(px_expires_soon(
        &px(&net, 1, window(0, u64::MAX - 1)),
        u64::MAX
    ));
    assert!(!px_expires_soon(&px(&net, 1, window(0, 0)), u64::MAX));
}

fn vault() -> Registration {
    Registration::new(
        blacksilk_px::vault::VAULT_ELF.to_vec(),
        blacksilk_px::vault::BUDGET,
        blacksilk_px::vault::OUT_WORDS,
    )
}

/// A signed deploy of `programs` from the miner's first spendable output
/// (the builder self-checks `check_deploy_structure`).
fn deploy(net: &mut TestNet, programs: Vec<Registration>) -> Result<PxDeploy, BuildError> {
    let miner = net.miner_clone();
    let real = miner.spendable(net.height())[0].clone();
    let plan = net.plan(&real);
    let rules = net.rules;
    build_deploy(
        &miner.keys,
        vec![plan],
        &[Payment {
            address: miner.primary(),
            amount: 1,
        }],
        &miner.primary(),
        [3; 32],
        programs,
        &rules,
        &mut net.rng,
    )
}

/// F-28-1 and F-28-5: a registration's ABI and output-word count are part of
/// the deploy payload, so of the contract id (the registry fixed by a
/// contract id includes them); a deploy registering an ABI other than
/// `ABI_VERSION`, or more output words than `MAX_FN_OUTPUT_WORDS`, is refused
/// (stateless), and the latter does not even decode.
#[test]
fn registrations_carry_their_abi_and_output_words() {
    let mut net = TestNet::new(8, 130);
    assert_eq!(vault().abi, ABI_VERSION);
    let base = deploy(&mut net, vec![vault()]).expect("the vault deploys");
    let id = base.contract_id();
    for f in [
        |r: &mut Registration| r.abi += 1,
        |r: &mut Registration| r.out_words += 1,
        |r: &mut Registration| r.budget.cycles += 1,
    ] {
        let mut other = base.clone();
        f(&mut other.programs[0]);
        assert_ne!(other.contract_id(), id);
    }
    // An unsupported ABI.
    let mut v2 = vault();
    v2.abi = ABI_VERSION + 1;
    assert!(matches!(
        deploy(&mut net, vec![v2]),
        Err(BuildError::SelfCheck(TxError::PxUnsupportedAbi {
            program: 0
        }))
    ));
    assert!(TxError::PxUnsupportedAbi { program: 0 }.is_stateless());
    // Too many output words: refused by the structure rule, and a deploy
    // carrying them does not decode.
    let mut wide = vault();
    wide.out_words = MAX_FN_OUTPUT_WORDS as u32 + 1;
    assert!(matches!(
        deploy(&mut net, vec![wide.clone()]),
        Err(BuildError::SelfCheck(TxError::PxShape))
    ));
    let mut forged = base.clone();
    forged.programs[0] = wide;
    assert!(matches!(
        Transaction::decode(&Transaction::PxDeploy(Box::new(forged)).encode()),
        Err(DecodeError::CountOutOfRange { .. })
    ));
    // At the bound it decodes.
    let mut widest = base;
    widest.programs[0].out_words = MAX_FN_OUTPUT_WORDS as u32;
    assert!(Transaction::decode(&Transaction::PxDeploy(Box::new(widest)).encode()).is_ok());
}
