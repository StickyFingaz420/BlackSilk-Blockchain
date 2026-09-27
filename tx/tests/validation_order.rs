//! Validation order and error classification (docs/transactions.md §8).
//!
//! The mempool paths run every stateless rule before any contextual one, and
//! provable intra-transaction faults get stateless errors. These are policy
//! changes (which error, hence which relay penalty), never consensus changes:
//! the differential tests below check, over a corpus of valid and invalid
//! transactions on two chain states, that the verdict (`is_ok`) of the
//! current mempool path equals the verdict of the pre-change mempool path
//! (a verbatim copy in [`old`]) and of block validation.

mod common;

use blacksilk_crypto::hash::{h32, h64, tags};
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_px::delivery::CIPHERTEXT_BYTES;
use blacksilk_px_core::{Digest, P};
use blacksilk_tx::builder::Payment;
use blacksilk_tx::params::PX_STANDARD_FEE;
use blacksilk_tx::px::{PxDeploy, PxFunction, PxTx, Registration};
use blacksilk_tx::px_builder::build_deploy;
use blacksilk_tx::state::MemoryChain;
use blacksilk_tx::types::{CoinbaseOutput, Transaction};
use blacksilk_tx::validate::*;
use blacksilk_tx::{Transfer, TxError};
use blacksilk_zkvm::air::trace::Budget;
use blacksilk_zkvm::Program;
use common::*;
use rand_chacha::rand_core::RngCore;
use std::cell::Cell;
use std::sync::Arc;
use std::time::Instant;

const VAULT_ELF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../px/vault.elf"));
const VAULT_BUDGET: Budget = Budget {
    cycles: 6_000,
    keys: 2_200,
    add: 4_300,
    bit: 250,
    lt: 3_500,
    shift: 200,
    mul: 200,
    poseidon: 22,
};

/// The pre-change mempool functions, copied verbatim from `tx/src/validate.rs`
/// and `tx/src/px.rs` at commit 7826289 (only paths adapted to public items).
/// The reference for the differential tests.
mod old {
    use blacksilk_crypto::bulletproofs_plus as bpp;
    use blacksilk_crypto::Point;
    use blacksilk_px_core::call::MAX_FN;
    use blacksilk_tx::params::*;
    use blacksilk_tx::px::{
        check_deploy_structure, check_px_balance, digest_bytes, PxDeploy, PxTx,
    };
    use blacksilk_tx::types::Input;
    use blacksilk_tx::validate::*;
    use blacksilk_tx::{Transfer, TxError};
    use std::collections::HashSet;

    fn strictly_increasing<T: Ord>(items: impl IntoIterator<Item = T>) -> bool {
        let mut prev: Option<T> = None;
        for item in items {
            if let Some(p) = &prev {
                if *p >= item {
                    return false;
                }
            }
            prev = Some(item);
        }
        true
    }

    fn check_uniqueness_of(
        inputs: &[Input],
        output_keys: &[Point],
        chain: &impl ChainView,
        block_key_images: &mut HashSet<[u8; 32]>,
        block_one_time_keys: &mut HashSet<[u8; 32]>,
    ) -> Result<(), TxError> {
        for (i, input) in inputs.iter().enumerate() {
            if chain.is_key_image_spent(&input.key_image)
                || !block_key_images.insert(*input.key_image.bytes())
            {
                return Err(TxError::KeyImageSpent { input: i });
            }
        }
        // Adapted for D8 option B (docs/reviews/v3-consensus-changes.md §1):
        // the chain-wide one-time-key rule C4 is gone from consensus and from
        // this reference alike (the chain view has no query for it). The
        // part of it that remains a rule, a repeat within the transaction,
        // is kept here, reported with the variant that names it today (the
        // old code returned the removed `DuplicateOneTimeKey`).
        for (j, k) in output_keys.iter().enumerate() {
            if !block_one_time_keys.insert(*k.bytes()) {
                return Err(TxError::PxDuplicateOutputKey { output: j });
            }
        }
        Ok(())
    }

    fn check_uniqueness(tx: &Transfer, chain: &impl ChainView) -> Result<(), TxError> {
        let keys: Vec<Point> = tx.outputs.iter().map(|o| o.one_time_key).collect();
        check_uniqueness_of(
            &tx.inputs,
            &keys,
            chain,
            &mut HashSet::new(),
            &mut HashSet::new(),
        )
    }

    fn check_px_state(
        tx: &PxTx,
        chain: &impl ChainView,
        block_nullifiers: &mut HashSet<[u8; 32]>,
    ) -> Result<(), TxError> {
        if !chain.px_is_recent_root(&tx.anchor) {
            return Err(TxError::PxUnknownAnchor);
        }
        for (i, nf) in tx.nullifiers.iter().enumerate() {
            if chain.px_nullifier_spent(nf) || !block_nullifiers.insert(digest_bytes(nf)) {
                return Err(TxError::PxNullifierSpent { index: i });
            }
        }
        for (k, f) in tx.functions.iter().enumerate() {
            if chain.px_function(&f.contract, &f.program_id).is_none() {
                return Err(TxError::PxUnregistered { function: k });
            }
        }
        Ok(())
    }

    pub fn check_px_structure(tx: &PxTx) -> Result<(), TxError> {
        let n = tx.inputs.len();
        let k = tx.outputs.len();
        if n > MAX_INPUTS {
            return Err(TxError::InputCount(n));
        }
        if k > MAX_OUTPUTS || (k > 0 && n == 0) {
            return Err(TxError::OutputCount(k));
        }
        for (i, input) in tx.inputs.iter().enumerate() {
            if input.key_image.is_identity() {
                return Err(TxError::KeyImageIdentity { input: i });
            }
            if !strictly_increasing(input.ring.iter()) {
                return Err(TxError::RingNotIncreasing { input: i });
            }
        }
        if !strictly_increasing(tx.inputs.iter().map(|i| i.key_image)) {
            return Err(TxError::KeyImagesNotSorted);
        }
        let keys: Vec<(Point, Point)> = tx
            .outputs
            .iter()
            .map(|o| (o.one_time_key, o.ephemeral))
            .chain(tx.payouts.iter().map(|o| (o.one_time_key, o.ephemeral)))
            .collect();
        for (j, (otk, eph)) in keys.iter().enumerate() {
            if otk.is_identity() {
                return Err(TxError::OutputKeyIdentity { output: j });
            }
            if eph.is_identity() {
                return Err(TxError::EphemeralIdentity { output: j });
            }
        }
        if !strictly_increasing(tx.outputs.iter().map(|o| o.one_time_key))
            || !strictly_increasing(tx.payouts.iter().map(|o| o.one_time_key))
        {
            return Err(TxError::OutputsNotSorted);
        }
        if tx.pseudo_outs.len() != n {
            return Err(TxError::PseudoOutCount);
        }
        if tx.signatures.len() != n {
            return Err(TxError::SignatureCount);
        }
        match (&tx.range_proof, k) {
            (None, 0) => {}
            (Some(p), k) if k > 0 => {
                let rounds = bpp::rounds(k).ok_or(TxError::RangeProofShape)?;
                if p.l.len() != rounds || p.r.len() != rounds {
                    return Err(TxError::RangeProofShape);
                }
            }
            _ => return Err(TxError::RangeProofShape),
        }
        if tx.functions.len() > MAX_FN {
            return Err(TxError::PxShape);
        }
        let size = tx.encoded_len();
        if size > MAX_PX_TX_SIZE {
            return Err(TxError::TooLarge { size });
        }
        if tx.fee != PX_STANDARD_FEE {
            return Err(TxError::PxFeeNotStandard { fee: tx.fee });
        }
        Ok(())
    }

    pub fn validate_px_without_proof(
        tx: &PxTx,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
    ) -> Result<(), TxError> {
        check_px_structure(tx)?;
        check_px_balance(tx)?;
        let keys: Vec<Point> = tx.output_keys().iter().map(|k| k.one_time_key).collect();
        check_uniqueness_of(
            &tx.inputs,
            &keys,
            chain,
            &mut HashSet::new(),
            &mut HashSet::new(),
        )?;
        check_px_state(tx, chain, &mut HashSet::new())?;
        if chain.px_pool() + (tx.bridge_in as u128) < (tx.bridge_out as u128) {
            return Err(TxError::PxPoolUnderflow);
        }
        let rings = resolve_input_rings(&tx.inputs, chain, height)?;
        check_ring_signatures(
            &tx.inputs,
            &tx.pseudo_outs,
            &tx.signatures,
            &rings,
            &tx.signature_message(rules.domain()),
        )?;
        if let Some(p) = &tx.range_proof {
            let c: Vec<Point> = tx.outputs.iter().map(|o| o.commitment).collect();
            if !bpp::verify(p, &c) {
                return Err(TxError::RangeProofInvalid);
            }
        }
        Ok(())
    }

    pub fn validate_deploy(
        tx: &PxDeploy,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
    ) -> Result<(), TxError> {
        check_deploy_structure(tx, rules)?;
        let t = tx.as_transfer();
        check_balance(&t)?;
        check_uniqueness(&t, chain)?;
        if chain.px_contract_exists(&tx.contract_id()) {
            return Err(TxError::DuplicateContract);
        }
        let rings = resolve_input_rings(&tx.inputs, chain, height)?;
        check_ring_signatures(
            &tx.inputs,
            &tx.pseudo_outs,
            &tx.signatures,
            &rings,
            &tx.signature_message(rules.domain()),
        )?;
        check_range_proof(&t)
    }

    pub fn validate_transfer(
        tx: &Transfer,
        chain: &impl ChainView,
        height: u64,
        rules: &TxRules,
    ) -> Result<(), TxError> {
        check_structure(tx, rules)?;
        check_balance(tx)?;
        check_uniqueness(tx, chain)?;
        let rings = resolve_rings(tx, chain, height)?;
        check_signatures(tx, &rings, rules)?;
        check_range_proof(tx)
    }
}

/// A chain view that counts every query, optionally opens the PX side (any
/// anchor is recent, the pool is large).
struct View<'a> {
    inner: &'a MemoryChain,
    px_open: bool,
    queries: Cell<usize>,
    ring_lookups: Cell<usize>,
}

impl<'a> View<'a> {
    fn new(inner: &'a MemoryChain) -> Self {
        Self {
            inner,
            px_open: false,
            queries: Cell::new(0),
            ring_lookups: Cell::new(0),
        }
    }
    fn px_open(inner: &'a MemoryChain) -> Self {
        Self {
            px_open: true,
            ..Self::new(inner)
        }
    }
    fn tick(&self) {
        self.queries.set(self.queries.get() + 1);
    }
}

impl ChainView for View<'_> {
    fn output(&self, i: u64) -> Option<OutputRecord> {
        self.tick();
        self.ring_lookups.set(self.ring_lookups.get() + 1);
        self.inner.output(i)
    }
    fn is_key_image_spent(&self, k: &Point) -> bool {
        self.tick();
        self.inner.is_key_image_spent(k)
    }
    fn px_is_recent_root(&self, a: &Digest) -> bool {
        self.tick();
        self.px_open || self.inner.px_is_recent_root(a)
    }
    fn px_nullifier_spent(&self, nf: &Digest) -> bool {
        self.tick();
        self.inner.px_nullifier_spent(nf)
    }
    fn px_pool(&self) -> u128 {
        self.tick();
        if self.px_open {
            u64::MAX as u128
        } else {
            self.inner.px_pool()
        }
    }
    fn px_function(&self, c: &Digest, id: &[u8; 32]) -> Option<(Arc<Program>, Budget)> {
        self.tick();
        self.inner.px_function(c, id)
    }
    fn px_contract_exists(&self, c: &Digest) -> bool {
        self.tick();
        self.inner.px_contract_exists(c)
    }
    fn px_tree_size(&self) -> u64 {
        self.tick();
        self.inner.px_tree_size()
    }
}

fn random_point(r: &mut ChaCha20Rng) -> Point {
    let mut wide = [0u8; 64];
    r.fill_bytes(&mut wide);
    Point::from_point(RistrettoPoint::from_uniform_bytes(&wide))
}

fn digest(x: u32) -> Digest {
    [x, 0, 0, 0, 0, 0, 0, 0]
}

/// A funded chain and a valid 1-input transfer from the miner.
fn setup(seed: u64) -> (TestNet, Transfer) {
    let mut net = TestNet::new(seed, 80);
    let alice = Wallet::new(&mut rng(seed + 1000));
    let tx = net.pay(&net.miner_clone(), &[(alice.primary(), 1_000_000)]);
    (net, tx)
}

/// A payout (clear-amount stealth output) of `amount`, from a fresh coinbase.
fn payout(net: &mut TestNet, amount: u64) -> CoinbaseOutput {
    let Transaction::Coinbase(c) = net.coinbase(0) else {
        unreachable!()
    };
    CoinbaseOutput {
        amount,
        ..c.outputs[0].clone()
    }
}

/// A PX transaction without v1 inputs that passes every rule but the proof
/// (under [`View::px_open`]): one payout funded by the bridge.
fn px_zero_input(net: &mut TestNet) -> PxTx {
    let a = 5_000;
    PxTx {
        inputs: vec![],
        outputs: vec![],
        payouts: vec![payout(net, a)],
        fee: PX_STANDARD_FEE,
        bridge_in: 0,
        bridge_out: PX_STANDARD_FEE + a,
        anchor: digest(7),
        nullifiers: [digest(1), digest(2)],
        commitments: [digest(3), digest(4)],
        ciphertexts: [vec![0; CIPHERTEXT_BYTES], vec![0; CIPHERTEXT_BYTES]],
        functions: vec![],
        pseudo_outs: vec![],
        range_proof: None,
        signatures: vec![],
        proof: vec![],
    }
}

/// A PX transaction with the v1 part of the valid transfer `t` (so balanced,
/// with a valid range proof, but CLSAGs over the wrong message) and a payout.
fn px_from_transfer(net: &mut TestNet, t: &Transfer) -> PxTx {
    let a = 5_000;
    PxTx {
        inputs: t.inputs.clone(),
        outputs: t.outputs.clone(),
        pseudo_outs: t.pseudo_outs.clone(),
        range_proof: Some(t.range_proof.clone()),
        signatures: t.signatures.clone(),
        // v = fee + bridge_in + payouts − bridge_out = t.fee.
        bridge_in: t.fee,
        bridge_out: PX_STANDARD_FEE + a,
        ..px_zero_input(net)
    }
}

fn build_test_deploy(net: &mut TestNet) -> PxDeploy {
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
        [9; 32],
        vec![Registration {
            elf: VAULT_ELF.to_vec(),
            budget: VAULT_BUDGET,
        }],
        &rules,
        &mut net.rng,
    )
    .expect("deploy builds")
}

// ------------------------------------------------------------------ L1

#[test]
fn bad_range_proof_with_bad_signature_is_stateless_and_touches_no_chain_state() {
    let (net, t) = setup(1);
    let mut bad = t.clone();
    bad.range_proof.d1 += Scalar::ONE;
    bad.signatures[0].s[3] += Scalar::ONE;

    let view = View::new(&net.chain);
    let err = validate_transfer(&bad, &view, net.height(), &net.rules).unwrap_err();
    assert_eq!(err, TxError::RangeProofInvalid);
    assert!(err.is_stateless());
    // No ring was resolved, so no CLSAG can have been verified; no chain
    // query happened at all.
    assert_eq!(view.ring_lookups.get(), 0);
    assert_eq!(view.queries.get(), 0);

    // The old order reported a contextual error after resolving the rings
    // and verifying the CLSAG.
    let old_view = View::new(&net.chain);
    assert_eq!(
        old::validate_transfer(&bad, &old_view, net.height(), &net.rules),
        Err(TxError::InvalidSignature { input: 0 })
    );
    assert_eq!(old_view.ring_lookups.get(), 16);

    // Informational timing.
    let n = 20;
    let start = Instant::now();
    for _ in 0..n {
        let _ = validate_transfer(&bad, &View::new(&net.chain), net.height(), &net.rules);
    }
    let new_time = start.elapsed() / n;
    let start = Instant::now();
    for _ in 0..n {
        let _ = old::validate_transfer(&bad, &View::new(&net.chain), net.height(), &net.rules);
    }
    let old_time = start.elapsed() / n;
    println!("bad BP+ and bad CLSAG: new order {new_time:?}/tx (BP+ only), old order {old_time:?}/tx (rings + CLSAG)");
}

#[test]
fn deploy_bad_range_proof_is_stateless_before_chain_state() {
    let mut net = TestNet::new(2, 80);
    let d = build_test_deploy(&mut net);
    let view = View::new(&net.chain);
    assert_eq!(validate_deploy(&d, &view, net.height(), &net.rules), Ok(()));

    let mut bad = d.clone();
    bad.range_proof.d1 += Scalar::ONE;
    bad.signatures[0].s[0] += Scalar::ONE;
    let view = View::new(&net.chain);
    let err = validate_deploy(&bad, &view, net.height(), &net.rules).unwrap_err();
    assert_eq!(err, TxError::RangeProofInvalid);
    assert!(err.is_stateless());
    assert_eq!(view.queries.get(), 0);
    assert_eq!(
        old::validate_deploy(&bad, &View::new(&net.chain), net.height(), &net.rules),
        Err(TxError::InvalidSignature { input: 0 })
    );
}

#[test]
fn px_bad_range_proof_is_stateless_before_chain_state() {
    let (mut net, t) = setup(3);
    let mut bad = px_from_transfer(&mut net, &t);
    assert_eq!(check_px_balance_ok(&bad), Ok(()));
    bad.range_proof.as_mut().unwrap().d1 += Scalar::ONE;
    let view = View::px_open(&net.chain);
    let err = validate_px_without_proof(&bad, &view, net.height(), &net.rules).unwrap_err();
    assert_eq!(err, TxError::RangeProofInvalid);
    assert!(err.is_stateless());
    assert_eq!(view.queries.get(), 0);
    // Its CLSAGs sign the transfer's message, not this one's: the old order
    // reported that, a contextual error.
    assert_eq!(
        old::validate_px_without_proof(&bad, &View::px_open(&net.chain), net.height(), &net.rules),
        Err(TxError::InvalidSignature { input: 0 })
    );
}

fn check_px_balance_ok(tx: &PxTx) -> Result<(), TxError> {
    blacksilk_tx::px::check_px_balance(tx)
}

// ------------------------------------------------------------------ L2

#[test]
fn px_output_and_payout_sharing_a_key_is_stateless() {
    let (mut net, t) = setup(4);
    let mut tx = px_from_transfer(&mut net, &t);
    tx.payouts[0].one_time_key = tx.outputs[0].one_time_key;
    let k = tx.outputs.len();

    let err = blacksilk_tx::px::check_px_structure(&tx).unwrap_err();
    assert_eq!(err, TxError::PxDuplicateOutputKey { output: k });
    assert!(err.is_stateless());
    let view = View::px_open(&net.chain);
    assert_eq!(
        validate_px_without_proof(&tx, &view, net.height(), &net.rules),
        Err(TxError::PxDuplicateOutputKey { output: k })
    );
    assert_eq!(view.queries.get(), 0);
    // Formerly caught only by C4 (contextual, after the chain queries), at
    // the same index of `output_keys()`; since D8 option B removed C4, this
    // stateless rule is the only one rejecting the repeat.
    let old_view = View::px_open(&net.chain);
    assert_eq!(
        old::validate_px_without_proof(&tx, &old_view, net.height(), &net.rules),
        Err(TxError::PxDuplicateOutputKey { output: k })
    );
    assert!(old_view.queries.get() > 0);
    // Blocks reject it too, now with the stateless error.
    let tx = Transaction::Px(Box::new(tx));
    let txs = vec![net.coinbase(tx.fee()), tx];
    let ctx = net.context(&txs);
    assert_eq!(
        validate_block_transactions_cached(
            &txs,
            &ctx,
            &View::px_open(&net.chain),
            &net.rules,
            &mut rng(1),
            &|_| true
        ),
        Err(BlockError::Tx {
            index: 1,
            error: TxError::PxDuplicateOutputKey { output: k }
        })
    );
}

#[test]
fn px_equal_nullifiers_are_stateless() {
    let mut net = TestNet::new(5, 80);
    let good = px_zero_input(&mut net);
    let view = View::px_open(&net.chain);
    assert_eq!(
        validate_px_without_proof(&good, &view, net.height(), &net.rules),
        Ok(())
    );

    let mut tx = good.clone();
    tx.nullifiers[1] = tx.nullifiers[0];
    let err = blacksilk_tx::px::check_px_structure(&tx).unwrap_err();
    assert_eq!(err, TxError::PxNullifierRepeated);
    assert!(err.is_stateless());
    let view = View::px_open(&net.chain);
    assert_eq!(
        validate_px_without_proof(&tx, &view, net.height(), &net.rules),
        Err(TxError::PxNullifierRepeated)
    );
    assert_eq!(view.queries.get(), 0);
    assert_eq!(
        old::validate_px_without_proof(&tx, &View::px_open(&net.chain), net.height(), &net.rules),
        Err(TxError::PxNullifierSpent { index: 1 })
    );
}

/// T11 (dossier 15 W1) for PX transactions and deploys: an identity
/// auxiliary image `D` is a stateless structure error, raised before any
/// chain query.
#[test]
fn px_and_deploy_identity_auxiliary_images_are_stateless() {
    let (mut net, t) = setup(12);
    let identity = Point::decode(&[0; 32]).unwrap();
    let mut px = px_from_transfer(&mut net, &t);
    px.signatures[0].d = identity;
    assert_eq!(
        blacksilk_tx::px::check_px_structure(&px),
        Err(TxError::AuxKeyImageIdentity { input: 0 })
    );
    let view = View::px_open(&net.chain);
    assert_eq!(
        validate_px_without_proof(&px, &view, net.height(), &net.rules),
        Err(TxError::AuxKeyImageIdentity { input: 0 })
    );
    assert_eq!(view.queries.get(), 0);

    let mut d = build_test_deploy(&mut net);
    let view = View::new(&net.chain);
    assert_eq!(validate_deploy(&d, &view, net.height(), &net.rules), Ok(()));
    d.signatures[0].d = identity;
    let view = View::new(&net.chain);
    assert_eq!(
        validate_deploy(&d, &view, net.height(), &net.rules),
        Err(TxError::AuxKeyImageIdentity { input: 0 })
    );
    assert_eq!(view.queries.get(), 0);
}

#[test]
fn transfer_and_deploy_repeated_keys_were_already_stateless() {
    // Within a transfer (and a deploy's v1 part), a repeated one-time key or
    // key image breaks the strict order: T4/T6, stateless.
    let (net, t) = setup(6);
    let mut tx = t.clone();
    tx.outputs[1].one_time_key = tx.outputs[0].one_time_key;
    let err = validate_transfer(&tx, &net.chain, net.height(), &net.rules).unwrap_err();
    assert_eq!(err, TxError::OutputsNotSorted);
    assert!(err.is_stateless());

    let (net, t) = {
        let mut net = TestNet::new(7, 80);
        let alice = Wallet::new(&mut rng(7000));
        let t = net.pay(&net.miner_clone(), &[(alice.primary(), REWARD + 5)]);
        (net, t)
    };
    assert_eq!(t.inputs.len(), 2);
    let mut tx = t.clone();
    tx.inputs[1].key_image = tx.inputs[0].key_image;
    let err = validate_transfer(&tx, &net.chain, net.height(), &net.rules).unwrap_err();
    assert_eq!(err, TxError::KeyImagesNotSorted);
    assert!(err.is_stateless());
}

// ------------------------------------------------------------------ I5

/// The contract id recomputed from its definition, with `first` as the first
/// key image's bytes. The payload is the suffix of the prefix bytes (it is
/// their last field); its length is found by comparing with the same deploy
/// without programs, whose payload is `salt ‖ varint(0)` (33 bytes).
fn reference_contract_id(d: &PxDeploy, first: &[u8; 32]) -> Digest {
    let full = d.prefix_bytes();
    let empty = PxDeploy {
        programs: vec![],
        ..d.clone()
    }
    .prefix_bytes();
    let payload_len = full.len() - empty.len() + 33;
    let payload = &full[full.len() - payload_len..];
    assert_eq!(&payload[..32], &d.salt);
    let payload_hash = h32(tags::PX_DEPLOY_PAYLOAD, &[payload]);
    let wide = h64(tags::PX_CONTRACT_ID, &[first, &d.salt, &payload_hash]);
    let mut out = [0u32; 8];
    for (i, x) in out.iter_mut().enumerate() {
        let v = u64::from_le_bytes(wide[8 * i..8 * i + 8].try_into().unwrap());
        *x = (v % P as u64) as u32;
    }
    out
}

#[test]
fn contract_id_is_total_and_unchanged_for_deploys_with_inputs() {
    let mut net = TestNet::new(8, 80);
    let d = build_test_deploy(&mut net);
    let id = d.contract_id();
    assert_eq!(id, reference_contract_id(&d, d.inputs[0].key_image.bytes()));

    let mut none = d.clone();
    none.inputs.clear();
    // No panic; a fixed, well-defined value, different from the real id.
    let id0 = none.contract_id();
    assert_eq!(id0, none.contract_id());
    assert_eq!(id0, reference_contract_id(&none, &[0; 32]));
    assert_ne!(id0, id);
    // Validation rejects it by T3 before the id matters.
    let err = validate_deploy(&none, &net.chain, net.height(), &net.rules).unwrap_err();
    assert_eq!(err, TxError::InputCount(0));
    assert!(err.is_stateless());
    let tx = Transaction::PxDeploy(Box::new(none));
    assert_eq!(
        validate_mempool_tx(&tx, &net.chain, net.height(), &net.rules),
        Err(TxError::InputCount(0))
    );
}

// ------------------------------------------------------------------ classification

#[test]
fn every_error_variant_is_classified() {
    use TxError::*;
    let stateless = [
        TooLarge { size: 0 },
        CoinbaseNotAllowed,
        InputCount(0),
        OutputCount(0),
        KeyImageIdentity { input: 0 },
        KeyImagesNotSorted,
        RingNotIncreasing { input: 0 },
        OutputKeyIdentity { output: 0 },
        EphemeralIdentity { output: 0 },
        OutputsNotSorted,
        PseudoOutCount,
        FeeNotExact {
            fee: 0,
            required: 1,
        },
        WeightOverflow,
        Unbalanced,
        RangeProofShape,
        RangeProofInvalid,
        SignatureCount,
        AuxKeyImageIdentity { input: 0 },
        PxShape,
        PxFeeNotStandard { fee: 0 },
        PxInvalidProgram,
        PxDuplicateOutputKey { output: 0 },
        PxNullifierRepeated,
        PxDuplicateProgram { program: 1 },
        PxBudgetTooLarge { program: 0 },
        DeployFeeNotExact {
            fee: 0,
            required: 1,
        },
        PxProof,
    ];
    let contextual = [
        UnknownRingMember { input: 0, index: 0 },
        RingMemberTooYoung { input: 0, index: 0 },
        KeyImageSpent { input: 0 },
        InvalidSignature { input: 0 },
        PxUnknownAnchor,
        PxNullifierSpent { index: 0 },
        PxUnregistered { function: 0 },
        PxPoolUnderflow,
        PxTreeFull,
        DuplicateContract,
    ];
    for e in stateless {
        assert!(e.is_stateless(), "{e:?}");
    }
    for e in contextual {
        assert!(!e.is_stateless(), "{e:?}");
    }
    // `is_stateless` is an exhaustive match, so a new variant cannot compile
    // unclassified; these lists cover all 37 variants.
    assert_eq!(stateless.len() + contextual.len(), 37);
}

// ------------------------------------------------------------------ differential validity

/// Which validation path a corpus entry is checked against.
#[derive(Clone, Copy)]
enum ViewKind {
    Plain,
    PxOpen,
}

struct Entry {
    name: String,
    tx: Transaction,
    view: ViewKind,
}

fn entry(name: &str, tx: impl Into<Transaction>, view: ViewKind) -> Entry {
    Entry {
        name: name.into(),
        tx: tx.into(),
        view,
    }
}

fn corpus(net: &mut TestNet, seed: u64) -> Vec<Entry> {
    use ViewKind::*;
    let mut r = rng(seed);
    let alice = Wallet::new(&mut r);
    let t = net.pay(&net.miner_clone(), &[(alice.primary(), 1_000_000)]);
    let t2 = net.pay(&net.miner_clone(), &[(alice.primary(), REWARD + 5)]);
    let d = build_test_deploy(net);
    let mut out = vec![
        entry("transfer valid", t.clone(), Plain),
        entry("transfer 2-in valid", t2.clone(), Plain),
    ];
    let mut v = |name: &str, f: &dyn Fn(&mut Transfer), view: ViewKind| {
        let mut x = t.clone();
        f(&mut x);
        out.push(entry(name, x, view));
    };
    v(
        "bad signature",
        &|x| x.signatures[0].s[7] += Scalar::ONE,
        Plain,
    );
    v(
        "bad range proof",
        &|x| x.range_proof.d1 += Scalar::ONE,
        Plain,
    );
    v(
        "bad range proof + bad signature",
        &|x| {
            x.range_proof.d1 += Scalar::ONE;
            x.signatures[0].c0 += Scalar::ONE;
        },
        Plain,
    );
    v(
        "range proof shape",
        &|x| {
            x.range_proof.l.pop();
        },
        Plain,
    );
    v(
        "unbalanced",
        &|x| x.pseudo_outs[0] = random_point(&mut rng(99)),
        Plain,
    );
    v("fee too low", &|x| x.fee = 0, Plain);
    v("fee raised (unbalanced)", &|x| x.fee += 1, Plain);
    v(
        "random key image",
        &|x| x.inputs[0].key_image = random_point(&mut rng(98)),
        Plain,
    );
    v(
        "unknown ring member",
        &|x| x.inputs[0].ring[15] = u64::MAX - 1,
        Plain,
    );
    let newest = net.chain.output_count() - 1;
    v(
        "ring member too young",
        &move |x| {
            if x.inputs[0].ring[14] < newest {
                x.inputs[0].ring[15] = newest;
            }
        },
        Plain,
    );
    v(
        "ring not increasing",
        &|x| x.inputs[0].ring.swap(0, 1),
        Plain,
    );
    v("outputs not sorted", &|x| x.outputs.swap(0, 1), Plain);
    v(
        "repeated output key",
        &|x| x.outputs[1].one_time_key = x.outputs[0].one_time_key,
        Plain,
    );
    v(
        "signature count",
        &|x| {
            x.signatures.pop();
        },
        Plain,
    );
    v(
        "pseudo-out count",
        &|x| {
            x.pseudo_outs.pop();
        },
        Plain,
    );
    v(
        "encrypted field changed",
        &|x| x.outputs[0].enc_anchor[0] ^= 1,
        Plain,
    );
    let mut t2b = t2.clone();
    t2b.signatures[1].s[0] += Scalar::ONE;
    out.push(entry("2-in second signature bad", t2b, Plain));
    let mut t2c = t2.clone();
    t2c.inputs[1].key_image = t2c.inputs[0].key_image;
    out.push(entry("2-in duplicate key image", t2c, Plain));

    // Deploys.
    out.push(entry(
        "deploy valid",
        Transaction::PxDeploy(Box::new(d.clone())),
        Plain,
    ));
    let mut dv = |name: &str, f: &dyn Fn(&mut PxDeploy)| {
        let mut x = d.clone();
        f(&mut x);
        out.push(entry(name, Transaction::PxDeploy(Box::new(x)), Plain));
    };
    dv("deploy bad signature", &|x| {
        x.signatures[0].s[1] += Scalar::ONE
    });
    dv("deploy bad range proof", &|x| {
        x.range_proof.d1 += Scalar::ONE
    });
    dv("deploy both bad", &|x| {
        x.range_proof.d1 += Scalar::ONE;
        x.signatures[0].c0 += Scalar::ONE;
    });
    dv("deploy fee too low", &|x| x.fee = 1);
    dv("deploy salt changed", &|x| x.salt[0] ^= 1);
    dv("deploy no inputs", &|x| {
        x.inputs.clear();
        x.pseudo_outs.clear();
        x.signatures.clear();
    });
    dv("deploy bad program", &|x| x.programs[0].elf.truncate(10));

    // PX (checked without the proof: the fakes carry none).
    let p0 = px_zero_input(net);
    let p4 = px_from_transfer(net, &t);
    let px = |x: PxTx| Transaction::Px(Box::new(x));
    out.push(entry("px zero-input valid", px(p0.clone()), PxOpen));
    out.push(entry("px zero-input, closed anchor", px(p0.clone()), Plain));
    let mut pv = |name: &str, base: &PxTx, f: &dyn Fn(&mut PxTx)| {
        let mut x = base.clone();
        f(&mut x);
        out.push(entry(name, px(x), PxOpen));
    };
    pv("px equal nullifiers", &p0, &|x| {
        x.nullifiers[1] = x.nullifiers[0]
    });
    pv("px fee not standard", &p0, &|x| x.fee += 1);
    pv("px unbalanced", &p0, &|x| x.bridge_out += 1);
    pv("px unregistered function", &p0, &|x| {
        x.functions.push(PxFunction {
            contract: digest(11),
            program_id: [1; 32],
            io_hash: digest(12),
            outputs: vec![],
        })
    });
    pv("px hidden output without inputs", &p0, &|x| {
        x.outputs.push(p4.outputs[0].clone())
    });
    pv("px with v1 part (bad signatures)", &p4, &|_| {});
    pv("px shared output/payout key", &p4, &|x| {
        x.payouts[0].one_time_key = x.outputs[0].one_time_key
    });
    pv("px bad range proof", &p4, &|x| {
        x.range_proof.as_mut().unwrap().d1 += Scalar::ONE
    });
    pv("px v1 part, equal nullifiers", &p4, &|x| {
        x.nullifiers[1] = x.nullifiers[0]
    });
    pv("px v1 part, shared key + bad range proof", &p4, &|x| {
        x.payouts[0].one_time_key = x.outputs[0].one_time_key;
        x.range_proof.as_mut().unwrap().d1 += Scalar::ONE;
    });
    out
}

struct Verdicts {
    new_err: Option<TxError>,
    old_ok: bool,
    block_ok: bool,
}

fn verdicts(net: &mut TestNet, e: &Entry) -> Verdicts {
    let cb = net.coinbase(e.tx.fee());
    let txs = vec![cb, e.tx.clone()];
    let ctx = net.context(&txs);
    let mk = || match e.view {
        ViewKind::PxOpen => View::px_open(&net.chain),
        ViewKind::Plain => View::new(&net.chain),
    };
    let h = net.height();
    let rules = net.rules;
    let (new, old_ok) = match &e.tx {
        Transaction::Transfer(t) => (
            validate_mempool_tx(&e.tx, &mk(), h, &rules),
            old::validate_transfer(t, &mk(), h, &rules).is_ok(),
        ),
        Transaction::PxDeploy(d) => (
            validate_mempool_tx(&e.tx, &mk(), h, &rules),
            old::validate_deploy(d, &mk(), h, &rules).is_ok(),
        ),
        Transaction::Px(p) => (
            validate_px_without_proof(p, &mk(), h, &rules),
            old::validate_px_without_proof(p, &mk(), h, &rules).is_ok(),
        ),
        Transaction::Coinbase(_) => unreachable!(),
    };
    // Blocks: PX5 is skipped for every PX transaction, matching the
    // without-proof mempool check above.
    let block_ok =
        validate_block_transactions_cached(&txs, &ctx, &mk(), &rules, &mut rng(5), &|_| true)
            .is_ok();
    Verdicts {
        new_err: new.err(),
        old_ok,
        block_ok,
    }
}

#[test]
fn verdicts_are_unchanged_over_a_corpus_on_two_chain_states() {
    let mut net = TestNet::new(9, 80);
    let entries = corpus(&mut net, 900);
    let mut valid = 0;
    let mut invalid = 0;
    for state in 0..2 {
        if state == 1 {
            // Second state: the first transfer is mined, so its key image
            // (shared with most of the corpus) is spent (C2), and the chain
            // is one block higher.
            let Transaction::Transfer(t) = &entries[0].tx else {
                unreachable!()
            };
            net.mine(vec![(**t).clone()], &mut []).unwrap();
        }
        for e in &entries {
            let v = verdicts(&mut net, e);
            let new_ok = v.new_err.is_none();
            println!(
                "state {state} {:<45} new {:<48} old_ok {:<5} block_ok {}",
                e.name,
                format!("{:?}", v.new_err),
                v.old_ok,
                v.block_ok
            );
            assert_eq!(new_ok, v.old_ok, "state {state}: {} (new vs old)", e.name);
            assert_eq!(
                new_ok, v.block_ok,
                "state {state}: {} (mempool vs block)",
                e.name
            );
            if new_ok {
                valid += 1;
            } else {
                invalid += 1;
            }
        }
    }
    println!("{valid} valid, {invalid} invalid verdicts compared");
    // The corpus is not vacuous on either side.
    assert!(valid >= 4, "{valid}");
    assert!(invalid >= 50, "{invalid}");
}

#[test]
fn a_stateless_error_never_follows_a_contextual_check() {
    // For every invalid corpus entry whose new error is stateless, the new
    // path made no chain query: all stateless checks precede contextual ones.
    let mut net = TestNet::new(10, 80);
    let entries = corpus(&mut net, 1000);
    for e in &entries {
        let view = match e.view {
            ViewKind::PxOpen => View::px_open(&net.chain),
            _ => View::new(&net.chain),
        };
        let r = match &e.tx {
            Transaction::Px(p) => validate_px_without_proof(p, &view, net.height(), &net.rules),
            tx => validate_mempool_tx(tx, &view, net.height(), &net.rules),
        };
        if let Err(err) = r {
            if err.is_stateless() {
                assert_eq!(view.queries.get(), 0, "{}: {err:?}", e.name);
            }
        }
    }
}
