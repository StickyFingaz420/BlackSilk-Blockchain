//! Rules the mutation census of run C (docs/evidence/mutation-runC-2026-09-30/)
//! found untested: each test states a rule of tx/src/validate.rs,
//! tx/src/px.rs or tx/src/params.rs at its exact boundary. The transactions
//! are synthetic, shaped only as far as the rule under test needs; no test
//! here builds a PX proof.

mod common;

use blacksilk_crypto::bulletproofs_plus::{self as bpp, BppProof};
use blacksilk_crypto::clsag::{Clsag, RING_SIZE};
use blacksilk_crypto::commitment::commit;
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_px::delivery::CIPHERTEXT_BYTES;
use blacksilk_px_core::call::MAX_FN;
use blacksilk_px_core::Digest;
use blacksilk_tx::builder::Payment;
use blacksilk_tx::params::*;
use blacksilk_tx::px::{
    check_deploy_structure, check_px_balance, check_px_structure, digest_bytes, PxDeploy,
    PxFunction, PxTx, Registration, Window,
};
use blacksilk_tx::px_builder::build_deploy;
use blacksilk_tx::state::MemoryChain;
use blacksilk_tx::types::{CoinbaseOutput, Input, Output, Transaction};
use blacksilk_tx::validate::{
    check_px_proof, check_shape, revalidate_after_extension, validate_block_transactions,
    validate_block_transactions_cached, validate_mempool_tx, validate_px_without_proof,
    OutputRecord, PxProgram,
};
use blacksilk_tx::{BlockError, ChainView, Transfer, TxError};
use common::*;

/// A distinct non-identity point `(n + 1)·G`.
fn pt(n: u64) -> Point {
    Point::from_point(RistrettoPoint::mul_base(&Scalar::from(n + 1)))
}

/// `count` distinct non-identity points from `base` on, in increasing
/// (byte) order, as T4 and T6 require.
fn sorted_points(base: u64, count: usize) -> Vec<Point> {
    let mut v: Vec<Point> = (0..count as u64).map(|i| pt(base + i)).collect();
    v.sort();
    v
}

/// A range proof of the shape T10 requires for `k` outputs (not a valid
/// proof).
fn shaped_range_proof(k: usize) -> BppProof {
    let rounds = bpp::rounds(k).unwrap_or(0);
    BppProof {
        a: pt(1),
        a1: pt(1),
        b: pt(1),
        r1: Scalar::ZERO,
        s1: Scalar::ZERO,
        d1: Scalar::ZERO,
        l: vec![pt(2); rounds],
        r: vec![pt(3); rounds],
    }
}

/// A transfer with `n` inputs and `k` outputs that passes every rule of
/// `check_shape` (T1, T3–T7, T10 shape, T11) when `n` and `k` are within
/// T3; it balances nothing and signs nothing.
fn shaped_transfer(n: usize, k: usize) -> Transfer {
    Transfer {
        inputs: sorted_points(1_000, n)
            .into_iter()
            .map(|key_image| Input {
                key_image,
                ring: std::array::from_fn(|j| j as u64),
            })
            .collect(),
        outputs: sorted_points(2_000, k)
            .into_iter()
            .map(|one_time_key| Output {
                one_time_key,
                ephemeral: pt(3_000),
                view_tag: 0,
                commitment: pt(3_001),
                enc_amount: [0; 8],
                enc_anchor: [0; 16],
            })
            .collect(),
        fee: 0,
        pseudo_outs: vec![pt(4_000); n],
        range_proof: shaped_range_proof(k),
        signatures: vec![
            Clsag {
                c0: Scalar::ZERO,
                s: [Scalar::ZERO; RING_SIZE],
                d: pt(5_000),
            };
            n
        ],
    }
}

/// T3: a transfer has 1 to `MAX_INPUTS` inputs and `MIN_OUTPUTS` to
/// `MAX_OUTPUTS` outputs, both ends included.
#[test]
fn t3_count_bounds_are_inclusive() {
    assert_eq!(check_shape(&shaped_transfer(1, MIN_OUTPUTS)), Ok(()));
    assert_eq!(
        check_shape(&shaped_transfer(MAX_INPUTS, MAX_OUTPUTS)),
        Ok(())
    );
    assert_eq!(
        check_shape(&shaped_transfer(MAX_INPUTS + 1, MAX_OUTPUTS)),
        Err(TxError::InputCount(MAX_INPUTS + 1))
    );
    assert_eq!(
        check_shape(&shaped_transfer(MAX_INPUTS + 2, 2)),
        Err(TxError::InputCount(MAX_INPUTS + 2))
    );
    assert_eq!(
        check_shape(&shaped_transfer(1, MAX_OUTPUTS + 1)),
        Err(TxError::OutputCount(MAX_OUTPUTS + 1))
    );
}

/// A PX transaction without v1 inputs that passes `check_px_structure` and
/// `check_px_balance` (`bridge_out` = the fee), with garbage proof bytes
/// padded so that it encodes to exactly `size` bytes. Nullifiers and
/// commitments are made unique by `tag`.
fn px_of_size(tag: u32, size: usize) -> PxTx {
    let mut tx = PxTx {
        inputs: vec![],
        outputs: vec![],
        payouts: vec![],
        fee: PX_STANDARD_FEE,
        bridge_in: 0,
        bridge_out: PX_STANDARD_FEE,
        window: Default::default(),
        anchor: [7; 8],
        nullifiers: [[tag; 8], [tag + 1_000_000; 8]],
        commitments: [[tag + 2; 8], [tag + 3; 8]],
        ciphertexts: [vec![0; CIPHERTEXT_BYTES], vec![0; CIPHERTEXT_BYTES]],
        functions: vec![],
        pseudo_outs: vec![],
        range_proof: None,
        signatures: vec![],
        proof: vec![],
    };
    // The proof's length prefix is a varint, so converge on the size (in
    // at most a few steps; bounded, so that a broken encoder fails here
    // instead of looping).
    for _ in 0..8 {
        if tx.encoded_len() == size {
            break;
        }
        let len = tx.proof.len() as i64 + size as i64 - tx.encoded_len() as i64;
        assert!(len >= 0, "{size} is below the size without a proof");
        tx.proof = vec![0xA5; len as usize];
    }
    assert_eq!(tx.encoded_len(), size, "no PX transaction of {size} bytes");
    assert_eq!(check_px_structure(&tx), Ok(()));
    assert_eq!(check_px_balance(&tx), Ok(()));
    tx
}

/// B6's PX byte budget: a block may carry exactly `MAX_PX_BLOCK_BYTES`
/// bytes of PX transactions, not one more. At the bound the block passes
/// the budget and fails later, at the first proof (garbage here).
#[test]
fn the_px_byte_budget_is_inclusive() {
    let mut net = TestNet::new(81, 1);
    let half = (MAX_PX_BLOCK_BYTES / 2) as usize;
    let block = |net: &mut TestNet, last: usize| {
        let pxs = [px_of_size(1, half), px_of_size(2, last)];
        let mut txs = vec![net.coinbase(2 * PX_STANDARD_FEE)];
        txs.extend(pxs.into_iter().map(|t| Transaction::Px(Box::new(t))));
        let ctx = net.context(&txs);
        let px_bytes: u64 = txs.iter().map(Transaction::px_bytes).sum();
        let got = validate_block_transactions(&txs, &ctx, &net.chain, &net.rules, &mut rng(1));
        (px_bytes, got)
    };
    let (bytes, got) = block(&mut net, half);
    assert_eq!(bytes, MAX_PX_BLOCK_BYTES);
    assert_eq!(
        got,
        Err(BlockError::Tx {
            index: 1,
            error: TxError::PxProof
        })
    );
    let (bytes, got) = block(&mut net, half + 1);
    assert_eq!(bytes, MAX_PX_BLOCK_BYTES + 1);
    assert_eq!(
        got,
        Err(BlockError::PxBytesExceeded {
            bytes,
            max: MAX_PX_BLOCK_BYTES
        })
    );
}

/// PX5 through `check_px_proof`, the single-call form of the proof rule
/// (decode, then verify): proof bytes that do not decode are refused with
/// the stateless `PxProof`, whatever else holds.
#[test]
fn check_px_proof_refuses_proof_bytes_that_do_not_decode() {
    let net = TestNet::new(82, 1);
    for proof in [vec![], vec![blacksilk_zk::PROOF_VERSION], vec![0xA5; 4096]] {
        let mut tx = px_of_size(1, 8_000);
        tx.proof = proof;
        assert_eq!(
            check_px_proof(&tx, &net.chain, &net.rules),
            Err(TxError::PxProof)
        );
    }
}

/// The chain at the parent, with every PX anchor recent, the PX pool set by
/// the test, and optionally one contract id registered that `inner` does
/// not have; everything else is `inner`'s.
struct PoolView<'a> {
    inner: &'a MemoryChain,
    pool: u128,
    registered: Option<Digest>,
}

impl ChainView for PoolView<'_> {
    fn output(&self, i: u64) -> Option<OutputRecord> {
        self.inner.output(i)
    }
    fn is_key_image_spent(&self, k: &Point) -> bool {
        self.inner.is_key_image_spent(k)
    }
    fn px_is_recent_root(&self, _: &Digest) -> bool {
        true
    }
    fn px_nullifier_spent(&self, nf: &Digest) -> bool {
        self.inner.px_nullifier_spent(nf)
    }
    fn px_pool(&self) -> u128 {
        self.pool
    }
    fn px_function(&self, c: &Digest, id: &[u8; 32]) -> Option<PxProgram> {
        self.inner.px_function(c, id)
    }
    fn px_contract_exists(&self, c: &Digest) -> bool {
        self.registered == Some(*c) || self.inner.px_contract_exists(c)
    }
    fn px_tree_size(&self) -> u64 {
        self.inner.px_tree_size()
    }
}

/// A PX withdrawal without v1 inputs paying `amount` out of the pool
/// through one payout: `bridge_out` = the fee + `amount`.
fn withdrawal(tag: u32, amount: u64) -> PxTx {
    let mut tx = px_of_size(tag, 8_000);
    tx.payouts = vec![CoinbaseOutput {
        one_time_key: pt(6_000 + tag as u64),
        ephemeral: pt(7_000),
        view_tag: 0,
        amount,
        enc_anchor: [0; 16],
    }];
    tx.bridge_out = PX_STANDARD_FEE + amount;
    assert_eq!(check_px_balance(&tx), Ok(()));
    tx
}

/// PX4 on the mempool path (`validate_px` without its proof): the pool must
/// cover the withdrawal, `pool + bridge_in >= bridge_out`, the equality
/// included.
#[test]
fn px4_the_pool_must_cover_the_withdrawal_on_the_mempool_path() {
    let net = TestNet::new(83, 1);
    let tx = withdrawal(1, 500);
    let need = (PX_STANDARD_FEE + 500) as u128;
    let h = net.height();
    for (pool, want) in [
        (need, Ok(())),
        (need + 1, Ok(())),
        (need - 1, Err(TxError::PxPoolUnderflow)),
        (0, Err(TxError::PxPoolUnderflow)),
    ] {
        let view = PoolView {
            inner: &net.chain,
            pool,
            registered: None,
        };
        assert_eq!(
            validate_px_without_proof(&tx, &view, h, &net.rules),
            want,
            "pool {pool}"
        );
        assert_eq!(
            revalidate_after_extension(&Transaction::Px(Box::new(tx.clone())), &view, h),
            want,
            "pool {pool}, extension"
        );
    }
}

/// A PX transaction with one (unsigned) v1 input that bridges `bridge_in`
/// into the pool and takes `bridge_out` out of it through a payout; it
/// passes every stateless rule (the pseudo-output commits to `v·H`).
fn bridge_both_ways(bridge_in: u64, bridge_out: u64) -> PxTx {
    let mut tx = px_of_size(1, 8_000);
    let payout = bridge_out - PX_STANDARD_FEE;
    tx.inputs = vec![Input {
        key_image: pt(8_000),
        ring: std::array::from_fn(|j| j as u64),
    }];
    tx.payouts = vec![CoinbaseOutput {
        one_time_key: pt(8_001),
        ephemeral: pt(8_002),
        view_tag: 0,
        amount: payout,
        enc_anchor: [0; 16],
    }];
    tx.bridge_in = bridge_in;
    tx.bridge_out = bridge_out;
    // v = fee + bridge_in + payout - bridge_out = bridge_in.
    tx.pseudo_outs = vec![Point::from_point(commit(bridge_in, &Scalar::ZERO))];
    tx.signatures = vec![Clsag {
        c0: Scalar::ZERO,
        s: [Scalar::ZERO; RING_SIZE],
        d: pt(8_003),
    }];
    assert_eq!(check_px_structure(&tx), Ok(()));
    assert_eq!(check_px_balance(&tx), Ok(()));
    tx
}

/// PX4 counts the transaction's own deposit: `pool + bridge_in >=
/// bridge_out`. Below that it is `PxPoolUnderflow`; at it the transaction
/// passes PX4 and fails later, at its (unsigned) ring.
#[test]
fn px4_counts_the_transactions_own_deposit() {
    let net = TestNet::new(84, 1);
    let tx = bridge_both_ways(300, PX_STANDARD_FEE + 1_000);
    let need = (PX_STANDARD_FEE + 1_000 - 300) as u128;
    let h = net.height();
    let check = |pool: u128| {
        let view = PoolView {
            inner: &net.chain,
            pool,
            registered: None,
        };
        validate_px_without_proof(&tx, &view, h, &net.rules)
    };
    for pool in [need, need + 300] {
        let r = check(pool);
        assert!(
            matches!(
                r,
                Err(TxError::UnknownRingMember { input: 0, .. })
                    | Err(TxError::RingMemberTooYoung { input: 0, .. })
                    | Err(TxError::InvalidSignature { input: 0 })
            ),
            "pool {pool}: {r:?}"
        );
    }
    for pool in [need - 1, 0] {
        assert_eq!(check(pool), Err(TxError::PxPoolUnderflow), "pool {pool}");
    }
}

/// Validates `body` as the body of the next block (after a correct
/// coinbase) against `view`, every PX proof vouched for by the cache, so the
/// proofs themselves (PX5) are not checked.
fn validate_cached_body(
    net: &TestNet,
    view: &PoolView,
    body: Vec<Transaction>,
) -> Result<(), BlockError> {
    let mut net_rng = rng(2);
    let fees: u64 = body.iter().map(Transaction::fee).sum();
    let secret = net.miner.keys.hedge_secret();
    let coinbase = blacksilk_tx::builder::build_coinbase(
        net.height(),
        &[Payment {
            address: net.miner.primary(),
            amount: REWARD + fees,
        }],
        &secret,
        &mut net_rng,
    )
    .unwrap();
    let mut txs = vec![Transaction::Coinbase(coinbase)];
    txs.extend(body);
    let ctx = net.context(&txs);
    validate_block_transactions_cached(&txs, &ctx, view, &net.rules, &mut net_rng, &|_| true)
}

/// [`validate_cached_body`] for a body of PX transactions.
fn validate_cached_block(net: &TestNet, view: &PoolView, pxs: &[PxTx]) -> Result<(), BlockError> {
    let body = pxs
        .iter()
        .map(|t| Transaction::Px(Box::new(t.clone())))
        .collect();
    validate_cached_body(net, view, body)
}

/// PX4 in a block: the pool evolves in block order, each transaction's
/// deposit counted before its withdrawal. Two withdrawals are valid exactly
/// when the pool covers both; a deposit covers its own withdrawal.
#[test]
fn px4_the_pool_evolves_in_block_order() {
    let net = TestNet::new(85, 1);
    let view = |pool| PoolView {
        inner: &net.chain,
        pool,
        registered: None,
    };
    let (a, b) = (withdrawal(10, 500), withdrawal(20, 700));
    let need = (2 * PX_STANDARD_FEE + 1_200) as u128;
    assert_eq!(
        validate_cached_block(&net, &view(need), &[a.clone(), b.clone()]),
        Ok(())
    );
    assert_eq!(
        validate_cached_block(&net, &view(need - 1), &[a.clone(), b.clone()]),
        Err(BlockError::Tx {
            index: 2,
            error: TxError::PxPoolUnderflow
        })
    );
    // The deposit of 300 in the same transaction counts toward its PX4.
    let both = bridge_both_ways(300, PX_STANDARD_FEE + 1_000);
    let need = (PX_STANDARD_FEE + 1_000 - 300) as u128;
    let r = validate_cached_block(&net, &view(need), std::slice::from_ref(&both));
    assert!(
        matches!(
            r,
            Err(BlockError::Tx {
                index: 1,
                error: TxError::UnknownRingMember { input: 0, .. }
                    | TxError::RingMemberTooYoung { input: 0, .. }
            })
        ),
        "passes PX4, fails at its ring: {r:?}"
    );
    assert_eq!(
        validate_cached_block(&net, &view(need - 1), &[both]),
        Err(BlockError::Tx {
            index: 1,
            error: TxError::PxPoolUnderflow
        })
    );
}

/// A valid, signed deploy of the vault program from the miner's first
/// spendable output, with salt `salt`.
fn vault_deploy(net: &mut TestNet, salt: u8) -> PxDeploy {
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
        [salt; 32],
        vec![Registration::new(
            blacksilk_px::vault::VAULT_ELF.to_vec(),
            blacksilk_px::vault::BUDGET,
            1,
        )],
        &rules,
        &mut net.rng,
    )
    .expect("deploy builds")
}

/// A deploy whose contract id the chain already has is invalid in a block
/// (`DuplicateContract`), even with its key image unspent. On a consistent
/// chain the id's first key image is then spent too (C2 fires first); the
/// view here registers the id alone, so the contract rule is shown live on
/// its own, as `revalidate_after_extension`'s test does for the pool.
#[test]
fn a_block_deploy_of_a_registered_contract_id_is_a_duplicate() {
    let mut net = TestNet::new(86, 80);
    let deploy = vault_deploy(&mut net, 5);
    let id = deploy.contract_id();
    let body = || vec![Transaction::PxDeploy(Box::new(deploy.clone()))];
    let view = |registered| PoolView {
        inner: &net.chain,
        pool: 0,
        registered,
    };
    assert_eq!(validate_cached_body(&net, &view(None), body()), Ok(()));
    assert_eq!(
        validate_cached_body(&net, &view(Some(id)), body()),
        Err(BlockError::Tx {
            index: 1,
            error: TxError::DuplicateContract
        })
    );
    // Another contract registered: no effect.
    assert_eq!(
        validate_cached_body(&net, &view(Some([1; 8])), body()),
        Ok(())
    );
}

/// The size and fee constants of the PX layer have their specified values
/// (docs/px.md §11.5, docs/transactions.md T2): each is a consensus rule,
/// and the tests above use them symbolically, so a changed constant would
/// move every boundary with it. (The node's consensus fingerprint pins them
/// too, `tx.*` in node/src/fingerprint.rs.)
#[test]
fn px_size_and_fee_constants_have_their_specified_values() {
    const KIB: usize = 1024;
    const MIB: usize = 1024 * KIB;
    assert_eq!(blacksilk_zk::params::MAX_PROOF_BYTES, 4 * MIB);
    assert_eq!(MAX_PX_TX_SIZE, 4 * MIB + 256 * KIB); // 4 MiB proof cap + 256 KiB
    assert_eq!(MAX_PX_TX_SIZE, 4_456_448);
    assert_eq!(MAX_DEPLOY_TX_SIZE, 1_048_576); // 1 MiB
    assert_eq!(MAX_PX_BLOCK_BYTES, 8_388_608); // 8 MiB
    assert_eq!(MAX_DEPLOY_BLOCK_BYTES, 1_048_576); // 1 MiB
    assert_eq!(MAX_PROGRAM_BYTES, 262_144); // 256 KiB
    assert_eq!(PX_FEE_PER_BYTE, 2);
    assert_eq!(PX_STANDARD_FEE, 8_912_896); // PX_FEE_PER_BYTE × MAX_PX_TX_SIZE
}

/// T1 for PX transactions: at most `MAX_PX_TX_SIZE` encoded bytes, the
/// bound included.
#[test]
fn a_px_transaction_of_exactly_the_size_cap_is_well_formed() {
    let at = px_of_size(1, MAX_PX_TX_SIZE);
    assert_eq!(check_px_structure(&at), Ok(()));
    let mut over = at.clone();
    over.proof.push(0);
    assert_eq!(over.encoded_len(), MAX_PX_TX_SIZE + 1);
    assert_eq!(
        check_px_structure(&over),
        Err(TxError::TooLarge {
            size: MAX_PX_TX_SIZE + 1
        })
    );
}

/// The premise of exemption E8 (docs/reviews/mutation-exemptions.md): a
/// transfer that passes T3–T7, T10's shape and T11 encodes to at most
/// `max_weight(n, k)` bytes (every field has a fixed length but its 4 + 16n
/// varints, which `max_weight` counts at their 10-byte maximum), and no
/// shape reaches T1's `MAX_TX_SIZE`: `check_shape`'s size test cannot fail
/// for a transfer. If a constant changes so that this fails, T1 becomes
/// reachable and E8 must be replaced by a boundary test.
#[test]
fn t1_is_implied_by_the_transfer_shape_rules() {
    let largest = (1..=MAX_INPUTS)
        .flat_map(|n| (MIN_OUTPUTS..=MAX_OUTPUTS).map(move |k| max_weight(n, k)))
        .max()
        .unwrap();
    assert_eq!(largest, max_weight(MAX_INPUTS, MAX_OUTPUTS));
    assert!(largest < MAX_TX_SIZE as u64, "{largest}");
    let t = shaped_transfer(MAX_INPUTS, MAX_OUTPUTS);
    assert!(t.encoded_len() as u64 <= largest);
}

/// A PX transaction with every part present: a v1 input, a hidden output
/// with its range proof, a payout, a called function, a window and proof
/// bytes.
fn full_px() -> PxTx {
    let mut tx = bridge_both_ways(300, PX_STANDARD_FEE + 1_000);
    tx.outputs = shaped_transfer(1, 1).outputs;
    tx.range_proof = Some(shaped_range_proof(1));
    tx.functions = vec![PxFunction {
        contract: [9; 8],
        program_id: [0x42; 32],
        io_hash: [3; 8],
        outputs: vec![1, 2, 3],
    }];
    tx.window = Window {
        not_before: 5,
        not_after: 100,
    };
    tx.proof = vec![0x5A; 64];
    tx
}

/// PX encoding and commitments (docs/px.md §11.1, zk.md §5.2): a PX
/// transaction round-trips through its encoding, part by part; the proof
/// binding `h_tx` covers the prefix and the pseudo-outputs but not the
/// prunable part (range proof, signatures, proof); the CLSAG message covers
/// everything but the signatures; the transaction id covers everything (so
/// the proof cache, keyed by id, commits to the proof bytes).
#[test]
fn px_encoding_round_trips_and_its_hashes_cover_the_specified_parts() {
    let tx = full_px();
    let wire = Transaction::Px(Box::new(tx.clone()));
    assert_eq!(Transaction::decode(&wire.encode()), Ok(wire.clone()));
    let domain = rules().domain();
    let (binding, message, id) = (
        tx.binding(domain),
        tx.signature_message(domain),
        wire.hash(),
    );
    let changed = |f: &dyn Fn(&mut PxTx)| {
        let mut t = tx.clone();
        f(&mut t);
        let w = Transaction::Px(Box::new(t.clone()));
        assert_eq!(
            Transaction::decode(&w.encode()),
            Ok(w.clone()),
            "round trip"
        );
        (
            t.binding(domain) != binding,
            t.signature_message(domain) != message,
            w.hash() != id,
        )
    };
    // (covered by h_tx, by the CLSAG message, by the id)
    assert_eq!(changed(&|t| t.fee += 1), (true, true, true), "prefix");
    assert_eq!(
        changed(&|t| t.window.not_after += 1),
        (true, true, true),
        "window"
    );
    assert_eq!(
        changed(&|t| t.pseudo_outs[0] = pt(9_999)),
        (true, true, true),
        "pseudo-outputs"
    );
    assert_eq!(
        changed(&|t| t.range_proof.as_mut().unwrap().a = pt(9_998)),
        (false, true, true),
        "range proof"
    );
    assert_eq!(changed(&|t| t.proof[0] ^= 1), (false, true, true), "proof");
    assert_eq!(
        changed(&|t| t.signatures[0].d = pt(9_997)),
        (false, false, true),
        "signatures"
    );
}

/// The stealth-output context of a PX transaction's v1 outputs is
/// `H32("input-context/px", nullifiers ‖ key images)` (docs/px.md §11.1), so
/// it changes with either nullifier and with every key image; builder and
/// scanner both take it from `PxTx::output_context`.
#[test]
fn px_output_context_is_the_specified_hash_of_nullifiers_and_key_images() {
    let tx = full_px();
    let nfs: Vec<[u8; 32]> = tx.nullifiers.iter().map(digest_bytes).collect();
    let images: Vec<Point> = tx.inputs.iter().map(|i| i.key_image).collect();
    assert_eq!(
        tx.output_context(),
        blacksilk_crypto::stealth::px_context(&nfs, &images)
    );
    let mut other = tx.clone();
    other.nullifiers[1][0] += 1;
    assert_ne!(other.output_context(), tx.output_context());
    let mut other = tx.clone();
    other.inputs[0].key_image = pt(9_996);
    assert_ne!(other.output_context(), tx.output_context());
    other.inputs.clear();
    assert_ne!(other.output_context(), tx.output_context());
}

/// A deploy's CLSAGs sign its whole prefix, the payload included
/// (`PxDeploy::signature_message`), and its id covers it: another salt or
/// another registration (of the same payload length, so the exact fee is
/// unchanged) is a different transaction whose signatures no longer verify.
#[test]
fn a_deploys_signatures_and_id_cover_its_payload_and_fee() {
    let mut net = TestNet::new(87, 80);
    let d = vault_deploy(&mut net, 6);
    let h = net.height();
    let validate = |d: &PxDeploy| {
        validate_mempool_tx(
            &Transaction::PxDeploy(Box::new(d.clone())),
            &net.chain,
            h,
            &net.rules,
        )
    };
    assert_eq!(validate(&d), Ok(()));
    let id = Transaction::PxDeploy(Box::new(d.clone())).hash();
    let mut salted = d.clone();
    salted.salt[0] ^= 1;
    assert_eq!(salted.required_fee(&net.rules), d.fee);
    assert_eq!(
        validate(&salted),
        Err(TxError::InvalidSignature { input: 0 })
    );
    assert_ne!(Transaction::PxDeploy(Box::new(salted)).hash(), id);
    // Another registration of the same program (output words 1 -> 2, the
    // same payload length).
    let mut words = d.clone();
    words.programs[0].out_words = 2;
    assert_eq!(words.required_fee(&net.rules), d.fee);
    assert_eq!(
        validate(&words),
        Err(TxError::InvalidSignature { input: 0 })
    );
    assert_ne!(Transaction::PxDeploy(Box::new(words)).hash(), id);
}

/// A deploy's CLSAG message (`PxDeploy::signature_message`, spec §4.4 as a
/// transfer's) covers its pseudo-outputs and its range proof, not only its
/// prefix: a signed deploy cannot carry another range proof (RT-MUTE: with
/// either term left out of the message, every tx test passed; run E closed
/// the range-proof gap for transfers only, and the node's pinned
/// fingerprint samples the transfer message, not the deploy's).
#[test]
fn a_deploys_signature_message_covers_its_pseudo_outputs_and_range_proof() {
    let mut net = TestNet::new(88, 80);
    let d = vault_deploy(&mut net, 7);
    let domain = net.rules.domain();
    let message = d.signature_message(domain);
    let other_point = Point::from_point(RistrettoPoint::mul_base(&Scalar::from(5u64)));

    let mut rp = d.clone();
    rp.range_proof.a = other_point;
    assert_eq!(rp.prefix_bytes(), d.prefix_bytes());
    assert_eq!(rp.base_bytes(), d.base_bytes());
    assert_ne!(rp.signature_message(domain), message, "range proof");

    let mut pseudo = d.clone();
    pseudo.pseudo_outs[0] = other_point;
    assert_eq!(pseudo.prefix_bytes(), d.prefix_bytes());
    assert_ne!(pseudo.signature_message(domain), message, "pseudo-outputs");

    // The message is the transfer message's construction over the deploy's
    // prefix (which holds the payload).
    let t = d.as_transfer();
    assert_ne!(t.signature_message(domain), message, "the payload is signed");
}

/// A PX transaction without payouts and with the v1 part of
/// `shaped_transfer(n, k)`, which passes `check_px_structure` while `n`
/// and `k` are within bounds.
fn px_with_v1_part(n: usize, k: usize) -> PxTx {
    let t = shaped_transfer(n, k);
    let mut tx = px_of_size(1, 8_000);
    tx.inputs = t.inputs;
    tx.outputs = t.outputs;
    tx.pseudo_outs = t.pseudo_outs;
    tx.signatures = t.signatures;
    tx.range_proof = (k > 0).then_some(t.range_proof);
    tx
}

/// The PX counterpart of T3: at most `MAX_INPUTS` v1 inputs and
/// `MAX_OUTPUTS` hidden outputs, both bounds included, and hidden outputs
/// only with v1 inputs (their masks must balance against input masks).
#[test]
fn px_v1_counts_are_bounded_inclusively_and_outputs_need_inputs() {
    assert_eq!(check_px_structure(&px_with_v1_part(0, 0)), Ok(()));
    assert_eq!(check_px_structure(&px_with_v1_part(1, 1)), Ok(()));
    assert_eq!(
        check_px_structure(&px_with_v1_part(MAX_INPUTS, MAX_OUTPUTS)),
        Ok(())
    );
    assert_eq!(
        check_px_structure(&px_with_v1_part(MAX_INPUTS + 1, 1)),
        Err(TxError::InputCount(MAX_INPUTS + 1))
    );
    assert_eq!(
        check_px_structure(&px_with_v1_part(1, MAX_OUTPUTS + 1)),
        Err(TxError::OutputCount(MAX_OUTPUTS + 1))
    );
    for k in [1, 2, MAX_OUTPUTS] {
        let mut no_inputs = px_with_v1_part(1, k);
        no_inputs.inputs.clear();
        no_inputs.pseudo_outs.clear();
        no_inputs.signatures.clear();
        assert_eq!(
            check_px_structure(&no_inputs),
            Err(TxError::OutputCount(k)),
            "{k} outputs"
        );
    }
}

/// T10's shape for a PX transaction's hidden outputs: a range proof exactly
/// when there are hidden outputs, with `rounds(k)` points in each of `L`
/// and `R`; either list off by one is refused.
#[test]
fn px_range_proof_shape_is_checked_on_both_point_lists() {
    let ok = px_with_v1_part(1, 2);
    assert_eq!(check_px_structure(&ok), Ok(()));
    let bad = |f: &dyn Fn(&mut BppProof)| {
        let mut t = ok.clone();
        f(t.range_proof.as_mut().unwrap());
        check_px_structure(&t)
    };
    assert_eq!(
        bad(&|p| p.l.truncate(p.l.len() - 1)),
        Err(TxError::RangeProofShape)
    );
    assert_eq!(
        bad(&|p| p.r.truncate(p.r.len() - 1)),
        Err(TxError::RangeProofShape)
    );
    assert_eq!(bad(&|p| p.r.push(pt(1))), Err(TxError::RangeProofShape));
    let mut missing = ok.clone();
    missing.range_proof = None;
    assert_eq!(check_px_structure(&missing), Err(TxError::RangeProofShape));
    let mut spare = px_with_v1_part(1, 0);
    spare.range_proof = Some(shaped_range_proof(1));
    assert_eq!(check_px_structure(&spare), Err(TxError::RangeProofShape));
}

/// A PX transaction calls at most `MAX_FN` functions, the bound included
/// (`PxShape` above it).
#[test]
fn px_function_count_is_bounded_inclusively() {
    let with = |n: usize| {
        let mut t = px_of_size(1, 8_000);
        t.functions = (0..n as u32)
            .map(|i| PxFunction {
                contract: [i + 1; 8],
                program_id: [i as u8; 32],
                io_hash: [0; 8],
                outputs: vec![],
            })
            .collect();
        check_px_structure(&t)
    };
    assert_eq!(MAX_FN, 2);
    assert_eq!(with(MAX_FN), Ok(()));
    assert_eq!(with(MAX_FN + 1), Err(TxError::PxShape));
}

/// The v1-side balance of a PX transaction (tx/src/px.rs module docs): with
/// `v = fee + bridge_in + Σ payouts − bridge_out`, no v1 inputs require no
/// hidden outputs and `v = 0` exactly; with inputs, `Σ pseudo_outs − Σ
/// hidden outputs = v·H`, for `v` of either sign. Every imbalance is
/// `Unbalanced`, on the mempool path too.
#[test]
fn px_v1_balance_holds_exactly_for_either_sign_of_v() {
    // No v1 inputs: v = 0 exactly.
    let base = px_of_size(1, 8_000);
    assert_eq!(check_px_balance(&base), Ok(()));
    for (bridge_out, payout) in [
        (PX_STANDARD_FEE + 1, 0),
        (PX_STANDARD_FEE - 1, 0),
        (PX_STANDARD_FEE, 5),
        (0, 0),
    ] {
        let mut t = base.clone();
        t.bridge_out = bridge_out;
        if payout > 0 {
            t.payouts = withdrawal(1, payout).payouts;
        }
        assert_eq!(
            check_px_balance(&t),
            Err(TxError::Unbalanced),
            "bridge_out {bridge_out}, payout {payout}"
        );
    }
    // Hidden outputs without inputs never balance (no input masks).
    let mut outputs_only = base.clone();
    outputs_only.outputs = shaped_transfer(1, 1).outputs;
    outputs_only.outputs[0].commitment = Point::from_point(commit(0, &Scalar::ZERO));
    assert_eq!(check_px_balance(&outputs_only), Err(TxError::Unbalanced));

    // v1 inputs, v > 0: the pseudo-output must commit to exactly v.
    let pos = bridge_both_ways(300, PX_STANDARD_FEE + 1_000);
    assert_eq!(check_px_balance(&pos), Ok(()));
    let mut t = pos.clone();
    t.pseudo_outs[0] = Point::from_point(commit(301, &Scalar::ZERO));
    assert_eq!(check_px_balance(&t), Err(TxError::Unbalanced));
    let net = TestNet::new(88, 1);
    let view = PoolView {
        inner: &net.chain,
        pool: u64::MAX as u128,
        registered: None,
    };
    assert_eq!(
        validate_px_without_proof(&t, &view, net.height(), &net.rules),
        Err(TxError::Unbalanced)
    );

    // v1 inputs, v < 0: a hidden output of 1 000 masked by m, and a
    // pseudo-output of 1 000 − 200 under the same mask, with v = −200.
    let m = Scalar::from(77u64);
    let mut neg = pos.clone();
    neg.outputs = shaped_transfer(1, 1).outputs;
    neg.outputs[0].commitment = Point::from_point(commit(1_000, &m));
    neg.range_proof = Some(shaped_range_proof(1));
    neg.bridge_in = 0;
    neg.bridge_out = PX_STANDARD_FEE + neg.payouts[0].amount + 200;
    neg.pseudo_outs = vec![Point::from_point(commit(800, &m))];
    assert_eq!(check_px_balance(&neg), Ok(()));
    let mut t = neg.clone();
    t.bridge_out += 1;
    assert_eq!(check_px_balance(&t), Err(TxError::Unbalanced));
    let mut t = neg.clone();
    t.pseudo_outs = vec![Point::from_point(commit(1_200, &m))];
    assert_eq!(check_px_balance(&t), Err(TxError::Unbalanced));
}

/// T1 for deploys: at most `MAX_DEPLOY_TX_SIZE` encoded bytes, the bound
/// included. The vault program is padded with trailing zeros (not part of
/// the loaded program) to reach the bound; the fee is kept exact.
#[test]
fn a_deploy_of_exactly_the_size_cap_is_well_formed() {
    let mut net = TestNet::new(89, 80);
    let d = vault_deploy(&mut net, 7);
    assert_eq!(check_deploy_structure(&d, &net.rules), Ok(()));
    let sized = |target: usize| {
        let mut t = d.clone();
        for _ in 0..8 {
            if t.encoded_len() == target {
                return t;
            }
            let len = t.programs[0].elf.len() as i64 + target as i64 - t.encoded_len() as i64;
            t.programs[0].elf.resize(len as usize, 0);
            t.fee = t.required_fee(&net.rules);
        }
        panic!("no deploy of {target} bytes");
    };
    let at = sized(MAX_DEPLOY_TX_SIZE);
    assert_eq!(check_deploy_structure(&at, &net.rules), Ok(()));
    let over = sized(MAX_DEPLOY_TX_SIZE + 1);
    assert_eq!(
        check_deploy_structure(&over, &net.rules),
        Err(TxError::TooLarge {
            size: MAX_DEPLOY_TX_SIZE + 1
        })
    );
}

/// A deploy registers at most `MAX_FN_OUTPUT_WORDS` public output words per
/// program, the bound included (`PxShape` above it, for deploys not produced
/// by `decode`).
#[test]
fn a_deploys_output_words_are_bounded_inclusively() {
    let mut net = TestNet::new(90, 80);
    let d = vault_deploy(&mut net, 8);
    let with = |words: usize| {
        let mut t = d.clone();
        t.programs[0].out_words = words as u32;
        t.fee = t.required_fee(&net.rules);
        check_deploy_structure(&t, &net.rules)
    };
    assert_eq!(MAX_FN_OUTPUT_WORDS, 256);
    assert_eq!(with(MAX_FN_OUTPUT_WORDS), Ok(()));
    assert_eq!(with(MAX_FN_OUTPUT_WORDS + 1), Err(TxError::PxShape));
}

/// Every digest of a PX transaction (anchor, nullifiers, commitments, each
/// function's contract and io hash) is eight canonical field words: a word
/// equal to or above `P` does not decode (`NonCanonicalField`), and `P − 1`
/// does. A non-canonical word would alias a field element under another
/// byte encoding (another id, another conflict key) and would panic the
/// host permutation (`HostPerm` asserts canonical inputs) on any path that
/// hashed it. RT-MUTC: cargo-mutants generates `>=` → `<` only, so the
/// boundary (`>=` → `>`) and the check itself had no test.
#[test]
fn px_digest_words_must_be_canonical_field_elements() {
    use blacksilk_px_core::P;
    use blacksilk_tx::codec::DecodeError;
    type Edit = (&'static str, fn(&mut PxTx, u32));
    let edits: [Edit; 6] = [
        ("anchor", |t, w| t.anchor[0] = w),
        ("nullifier", |t, w| t.nullifiers[1][7] = w),
        ("commitment", |t, w| t.commitments[0][3] = w),
        ("contract", |t, w| t.functions[0].contract[5] = w),
        ("io hash", |t, w| t.functions[0].io_hash[2] = w),
        ("nullifier 0", |t, w| t.nullifiers[0][0] = w),
    ];
    for (what, edit) in edits {
        let decode = |w: u32| {
            let mut t = full_px();
            edit(&mut t, w);
            let wire = Transaction::Px(Box::new(t));
            (Transaction::decode(&wire.encode()), wire)
        };
        let (got, wire) = decode(P - 1);
        assert_eq!(got, Ok(wire), "{what}: P - 1 is canonical");
        for w in [P, P + 1, u32::MAX] {
            assert_eq!(
                decode(w).0,
                Err(DecodeError::NonCanonicalField),
                "{what}: word {w:#x}"
            );
        }
    }
}
