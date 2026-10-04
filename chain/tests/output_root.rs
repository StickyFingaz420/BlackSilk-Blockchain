//! Rules B-OMR and B-PXR (docs/reviews/v3-consensus-changes.md#output-root):
//! the header commits to the v1 output range and to the PX tree root after
//! the block.
//!
//! Adversarial: a wrong count, a wrong root, the right outputs hashed in
//! another order, a wrong PX root (with and without PX commitments), each
//! refused as a body failure that marks the **block** invalid with its
//! descendants, the honest sibling then connecting. And the state: the
//! template's range is the connected tip's after every block, a side-branch
//! template extends the fork point's range with the branch's bodies, and a
//! reorganization across branches of different output counts leaves the
//! state's range equal to the new tip header's.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{ChainManager, SubmitError, Template};
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, HeaderError, PowFunction};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_px::delivery::CIPHERTEXT_BYTES;
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::mmr::{leaf, OutputFrontier};
use blacksilk_tx::params::{TxRules, PX_STANDARD_FEE};
use blacksilk_tx::px::PxTx;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::BlockError;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

/// Zero hash: meets any difficulty (PoW is not under test here).
struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

fn params() -> ChainParams {
    ChainParams::regtest()
}

struct Env {
    m: ChainManager,
    keys: WalletKeys,
    rng: ChaCha20Rng,
}

impl Env {
    fn new() -> Self {
        let m = ChainManager::open(
            params(),
            TxRules::for_chain(&params()),
            Arc::new(ZeroPow),
            Box::<MemoryStore>::default(),
            [7; 32],
        )
        .unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(0x0412);
        let (keys, _) = WalletKeys::generate(&mut rng);
        Env { m, keys, rng }
    }

    /// A coinbase for template `t` with `n` outputs (distinct subaddresses)
    /// paying `t.reward + extra`.
    fn coinbase(&mut self, t: &Template, n: u64, extra: u64) -> Transaction {
        let total = t.reward + extra;
        let payouts: Vec<Payment> = (0..n)
            .map(|i| Payment {
                address: self.keys.address(SubaddressIndex::new(0, i as u32 + 1)),
                amount: total / n + u64::from(i < total % n),
            })
            .collect();
        Transaction::Coinbase(
            build_coinbase(t.height, &payouts, &self.keys.hedge_secret(), &mut self.rng).unwrap(),
        )
    }

    /// The honest block of `t` with body `txs` and the given nonce.
    fn block(&self, t: &Template, txs: Vec<Transaction>, nonce: u64) -> Block {
        let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
        let (output_count, output_root) = t.outputs_after(&txs);
        let header = BlockHeader {
            version: t.version,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t
                .min_timestamp
                .max(params().genesis.timestamp + 10 * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            output_count,
            output_root,
            px_root: t.px_root,
            nonce,
        };
        Block { header, txs }
    }

    /// A coinbase-only block with `n` outputs on `parent`.
    fn child(&mut self, parent: &Hash, n: u64, nonce: u64) -> Block {
        let t = self.m.template_on(parent).unwrap();
        let cb = self.coinbase(&t, n, 0);
        self.block(&t, vec![cb], nonce)
    }

    fn submit(&mut self, b: &Block) -> Result<blacksilk_chain::Submitted, SubmitError> {
        self.m.submit_block(b.clone(), b.header.timestamp)
    }

    /// Mines one coinbase-only block on the tip per entry, with that many
    /// outputs.
    fn extend(&mut self, outputs: &[u64]) {
        for &n in outputs {
            let tip = self.m.tip_id();
            let b = self.child(&tip, n, 0);
            assert!(self.submit(&b).unwrap().on_best_chain);
        }
    }

    /// The tip header's commitments equal the state's, and the template's
    /// range is the tip's.
    fn assert_consistent(&self) {
        let tip = *self.m.tip_header();
        let state = self.m.state();
        assert_eq!(tip.output_count, state.output_count());
        assert_eq!(tip.output_root, state.output_root());
        assert_eq!(
            tip.px_root,
            blacksilk_tx::px::digest_bytes(&state.px().root())
        );
        let t = self.m.template();
        assert_eq!(t.outputs.count(), tip.output_count);
        assert_eq!(t.outputs.root(), tip.output_root);
        assert_eq!(t.px_root, tip.px_root);
    }
}

fn id(b: &Block) -> Hash {
    b.id(params().network_id)
}

/// A refused block is marked invalid (not discarded), its child is refused
/// as the child of an invalid block, and the honest sibling connects.
fn refused_then_sibling_connects(env: &mut Env, bad: Block, want: BlockError) {
    let parent = bad.header.prev_id;
    match env.submit(&bad) {
        Err(SubmitError::Body(e)) => assert_eq!(e, want),
        other => panic!("expected {want:?}, got {other:?}"),
    }
    assert_eq!(env.m.invalid_reason(&id(&bad)), Some(&want));
    assert_eq!(env.m.tip_id(), parent);
    // Its child, whatever its own commitments, is refused at the header.
    let t = env
        .m
        .template_on_range(&parent, OutputFrontier::new())
        .unwrap();
    let mut child = env.block(&t, vec![], 0);
    child.header.height += 1;
    child.header.prev_id = id(&bad);
    assert!(matches!(
        env.submit(&child),
        Err(SubmitError::Header(HeaderError::InvalidParent))
    ));
    // The honest sibling.
    let good = env.child(&parent, 2, 1);
    assert!(env.submit(&good).unwrap().on_best_chain);
    env.assert_consistent();
}

#[test]
fn a_wrong_output_count_makes_the_block_invalid() {
    for delta in [1i64, -1, 1 << 40] {
        let mut env = Env::new();
        env.extend(&[1, 3]);
        let tip = env.m.tip_id();
        let mut b = env.child(&tip, 2, 7);
        let honest = b.header.output_count;
        let found = honest.wrapping_add_signed(delta);
        b.header.output_count = found;
        refused_then_sibling_connects(
            &mut env,
            b,
            BlockError::OutputCountMismatch {
                expected: honest,
                found,
            },
        );
    }
}

#[test]
fn a_wrong_output_root_makes_the_block_invalid() {
    for byte in [0usize, 31] {
        let mut env = Env::new();
        env.extend(&[1, 4, 2]);
        let tip = env.m.tip_id();
        let mut b = env.child(&tip, 3, 11);
        b.header.output_root[byte] ^= 1;
        refused_then_sibling_connects(&mut env, b, BlockError::OutputRootMismatch);
    }
    // The all-zero root (the empty range's) over a non-empty range.
    let mut env = Env::new();
    env.extend(&[1]);
    let tip = env.m.tip_id();
    let mut b = env.child(&tip, 1, 5);
    b.header.output_root = [0; 32];
    refused_then_sibling_connects(&mut env, b, BlockError::OutputRootMismatch);
}

/// The right outputs, the right count, hashed in another order (the
/// coinbase's two outputs swapped, or a wrong height or coinbase flag in a
/// leaf): another root, refused.
#[test]
fn the_root_of_the_right_outputs_in_another_order_or_with_other_fields_is_refused() {
    let mut env = Env::new();
    env.extend(&[1, 1]);
    let tip = env.m.tip_id();
    let t = env.m.template_on(&tip).unwrap();
    let cb = env.coinbase(&t, 2, 0);
    let keys = cb.output_keys();
    let variants: [Vec<(usize, u64, bool)>; 3] = [
        vec![(1, t.height, true), (0, t.height, true)],
        vec![(0, t.height + 1, true), (1, t.height + 1, true)],
        vec![(0, t.height, false), (1, t.height, false)],
    ];
    for (k, leaves) in variants.into_iter().enumerate() {
        let mut env = Env::new();
        env.extend(&[1, 1]);
        let tip = env.m.tip_id();
        let t = env.m.template_on(&tip).unwrap();
        let mut b = env.block(&t, vec![cb.clone()], k as u64 + 1);
        let mut f = t.outputs.clone();
        for (i, h, coinbase) in leaves {
            f.push(leaf(
                keys[i].one_time_key.bytes(),
                keys[i].commitment.bytes(),
                h,
                coinbase,
            ));
        }
        assert_eq!(f.count(), b.header.output_count);
        assert_ne!(f.root(), b.header.output_root);
        b.header.output_root = f.root();
        refused_then_sibling_connects(&mut env, b, BlockError::OutputRootMismatch);
    }
}

#[test]
fn a_wrong_px_root_makes_the_block_invalid() {
    let mut env = Env::new();
    env.extend(&[1]);
    let tip = env.m.tip_id();
    let mut b = env.child(&tip, 1, 9);
    b.header.px_root[5] ^= 0x40;
    refused_then_sibling_connects(&mut env, b, BlockError::PxRootMismatch);
    // The genesis value on a chain that has blocks is still the root: no PX
    // commitment was ever appended (the parent's root carries over).
    assert_eq!(
        env.m.tip_header().px_root,
        blacksilk_consensus::genesis::EMPTY_PX_ROOT
    );
}

/// A PX transaction's commitments enter the root: B-PXR runs before the
/// proof (PX5), so with the honest root this block fails later, at its
/// padding proof; with the root of the tree *without* its commitments, or
/// with one commitment, at B-PXR.
#[test]
fn the_px_root_covers_the_blocks_commitments() {
    let mut env = Env::new();
    env.extend(&[1]);
    let tip = env.m.tip_id();
    let t = env.m.template_on(&tip).unwrap();
    let px = PxTx {
        inputs: vec![],
        outputs: vec![],
        payouts: vec![],
        fee: PX_STANDARD_FEE,
        bridge_in: 0,
        bridge_out: PX_STANDARD_FEE,
        window: Default::default(),
        anchor: env.m.state().px().root(),
        nullifiers: [[1; 8], [2; 8]],
        commitments: [[3; 8], [4; 8]],
        ciphertexts: [ciphertext(), ciphertext()],
        functions: vec![],
        pseudo_outs: vec![],
        range_proof: None,
        signatures: vec![],
        proof: vec![0xA5; 1024],
    };
    let cb = env.coinbase(&t, 1, PX_STANDARD_FEE);
    let txs = vec![cb, Transaction::Px(Box::new(px))];
    let honest = env.m.px_root_with(&txs).unwrap();
    assert_ne!(honest, t.px_root);
    let state = env.m.state().px();
    let one = blacksilk_tx::px::digest_bytes(&state.root_after(&[[3; 8]]).unwrap());
    for (k, root) in [t.px_root, one].into_iter().enumerate() {
        let mut b = env.block(&t, txs.clone(), k as u64);
        b.header.px_root = root;
        match env.submit(&b) {
            Err(SubmitError::Body(e)) => assert_eq!(e, BlockError::PxRootMismatch),
            other => panic!("{other:?}"),
        }
    }
    let mut b = env.block(&t, txs, 9);
    b.header.px_root = honest;
    match env.submit(&b) {
        Err(SubmitError::Body(BlockError::Tx { index: 1, .. })) => {}
        other => panic!("expected the PX transaction's own failure, got {other:?}"),
    }
}

fn ciphertext() -> Vec<u8> {
    let mut c = vec![0u8; CIPHERTEXT_BYTES];
    c[..32].copy_from_slice(
        blacksilk_crypto::Point::from_point(blacksilk_crypto::generators::G).bytes(),
    );
    c
}

/// After every block the tip's commitments are the state's and the
/// template's range is the tip's; blocks with 1 to 16 coinbase outputs cross
/// several peak merges.
#[test]
fn the_template_range_follows_the_tip() {
    let mut env = Env::new();
    env.assert_consistent();
    for n in [1, 16, 3, 7, 1, 2, 9, 4, 1, 1, 5] {
        env.extend(&[n]);
        env.assert_consistent();
    }
    assert_eq!(env.m.tip_header().output_count, 50);
}

/// Two branches from height 2 with different output counts. A template on
/// the side branch extends the fork point's range with the side bodies; when
/// the side branch becomes heavier the chain reorganizes, every block of it
/// is validated against its own branch's range, and the state's range is the
/// new tip's. Then back again.
#[test]
fn a_reorganization_recomputes_the_output_range() {
    let mut env = Env::new();
    env.extend(&[2, 3]);
    let fork = env.m.tip_id();
    env.extend(&[1, 1]);
    let main_tip = env.m.tip_id();
    // The side branch: 5 and 6 outputs per block.
    let mut side = fork;
    let mut side_blocks: Vec<Block> = Vec::new();
    for (i, n) in [5u64, 6].into_iter().enumerate() {
        let t = env.m.template_on(&side).unwrap();
        // The side template's range: the fork's, plus the side bodies so far.
        let mut want = env.m.state().output_frontier_after(2).unwrap();
        for (h, b) in side_blocks.iter().enumerate() {
            want.append_block(3 + h as u64, &b.txs);
        }
        assert_eq!(t.outputs, want, "side template {i}");
        let b = env.child(&side, n, 100 + i as u64);
        env.submit(&b).unwrap();
        side = id(&b);
        side_blocks.push(b);
    }
    assert_eq!(env.m.tip_id(), main_tip, "equal work: no reorganization");
    // One more side block: the side branch is heavier.
    let b = env.child(&side, 2, 200);
    assert!(env.submit(&b).unwrap().on_best_chain);
    assert_eq!(env.m.tip_header().output_count, 2 + 3 + 5 + 6 + 2);
    env.assert_consistent();
    // And back: two more blocks on the old main branch.
    let mut p = main_tip;
    for i in 0..2 {
        let b = env.child(&p, 1, 300 + i);
        env.submit(&b).unwrap();
        p = id(&b);
    }
    assert_eq!(env.m.tip_id(), p);
    assert_eq!(env.m.tip_header().output_count, 2 + 3 + 1 + 1 + 1 + 1);
    env.assert_consistent();
}

/// A template on a parent whose body this manager does not hold has no
/// range: `None`, not a template whose block would fail B-OMR.
#[test]
fn no_template_without_the_branch_bodies() {
    let mut env = Env::new();
    env.extend(&[1]);
    let tip = env.m.tip_id();
    let b = env.child(&tip, 1, 1);
    env.m
        .accept_headers(&[b.header], b.header.timestamp)
        .unwrap();
    assert!(env.m.template_on(&id(&b)).is_none());
    env.submit(&b).unwrap();
    assert!(env.m.template_on(&id(&b)).is_some());
}
