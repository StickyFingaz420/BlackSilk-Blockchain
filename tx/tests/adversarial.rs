//! Adversarial tests: one negative test per validation rule (spec §8), plus
//! attacks by transaction authors who hold valid keys (inflation, Janus probes).

mod common;

use blacksilk_crypto::bulletproofs_plus as bpp;
use blacksilk_crypto::clsag::{self, RingMember, RING_SIZE};
use blacksilk_crypto::commitment::commit;
use blacksilk_crypto::generators::h;
use blacksilk_crypto::hash::{h32, h64, hash_to_scalar, tags};
use blacksilk_crypto::janus::{self, Anchor};
use blacksilk_crypto::keys::Address;
use blacksilk_crypto::stealth::{create_output, transfer_context, OutputKind, ScanRejection};
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_tx::builder::{standard_fee, InputPlan};
use blacksilk_tx::scan::{scan_transaction, OwnedOutput};
use blacksilk_tx::types::{Output, Transaction};
use blacksilk_tx::validate::*;
use blacksilk_tx::{BlockError, Transfer, TxError};
use common::*;
use rand_chacha::rand_core::RngCore;

fn identity() -> Point {
    Point::decode(&[0; 32]).unwrap()
}

fn random_point(rng: &mut ChaCha20Rng) -> Point {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    Point::from_point(RistrettoPoint::from_uniform_bytes(&wide))
}

/// A funded chain and a valid 1-input transfer from the miner to a fresh wallet.
fn setup(seed: u64) -> (TestNet, Transfer, Wallet) {
    let mut net = TestNet::new(seed, 80);
    let mut r = rng(seed + 1000);
    let alice = Wallet::new(&mut r);
    let tx = net.pay(&net.miner_clone(), &[(alice.primary(), 1_000_000)]);
    (net, tx, alice)
}

fn two_input_transfer(seed: u64) -> (TestNet, Transfer) {
    let mut net = TestNet::new(seed, 80);
    let mut r = rng(seed + 1000);
    let alice = Wallet::new(&mut r);
    let tx = net.pay(&net.miner_clone(), &[(alice.primary(), REWARD + 5)]);
    assert_eq!(tx.inputs.len(), 2);
    (net, tx)
}

fn validate(net: &TestNet, tx: &Transfer) -> Result<(), TxError> {
    validate_transfer(tx, &net.chain, net.height(), &net.rules)
}

// ---------------------------------------------------------------- T rules

#[test]
fn t3_counts() {
    let (net, tx, _) = setup(1);
    assert_eq!(validate(&net, &tx), Ok(()));
    let mut t = tx.clone();
    t.outputs.truncate(1);
    assert_eq!(validate(&net, &t), Err(TxError::OutputCount(1)));
    let mut t = tx.clone();
    t.inputs.clear();
    assert_eq!(validate(&net, &t), Err(TxError::InputCount(0)));
}

#[test]
fn t4_key_images() {
    let (net, tx, _) = setup(2);
    let mut t = tx.clone();
    t.inputs[0].key_image = identity();
    assert_eq!(
        validate(&net, &t),
        Err(TxError::KeyImageIdentity { input: 0 })
    );

    let (net, tx) = two_input_transfer(3);
    let mut t = tx.clone();
    t.inputs.swap(0, 1);
    t.pseudo_outs.swap(0, 1);
    t.signatures.swap(0, 1);
    assert_eq!(validate(&net, &t), Err(TxError::KeyImagesNotSorted));
    // Duplicate key image within one transaction.
    let mut t = tx.clone();
    t.inputs[1].key_image = t.inputs[0].key_image;
    assert_eq!(validate(&net, &t), Err(TxError::KeyImagesNotSorted));
}

#[test]
fn t5_rings() {
    let (net, tx, _) = setup(4);
    let mut t = tx.clone();
    t.inputs[0].ring[3] = t.inputs[0].ring[2];
    assert_eq!(
        validate(&net, &t),
        Err(TxError::RingNotIncreasing { input: 0 })
    );
    let mut t = tx.clone();
    t.inputs[0].ring.swap(0, 1);
    assert_eq!(
        validate(&net, &t),
        Err(TxError::RingNotIncreasing { input: 0 })
    );
}

#[test]
fn t6_outputs() {
    let (net, tx, _) = setup(5);
    let mut t = tx.clone();
    t.outputs[0].one_time_key = identity();
    assert_eq!(
        validate(&net, &t),
        Err(TxError::OutputKeyIdentity { output: 0 })
    );
    let mut t = tx.clone();
    t.outputs[1].ephemeral = identity();
    assert_eq!(
        validate(&net, &t),
        Err(TxError::EphemeralIdentity { output: 1 })
    );
    let mut t = tx.clone();
    t.outputs.swap(0, 1);
    assert_eq!(validate(&net, &t), Err(TxError::OutputsNotSorted));
    let mut t = tx.clone();
    t.outputs[1] = t.outputs[0].clone();
    assert_eq!(
        validate(&net, &t),
        Err(TxError::OutputsNotSorted),
        "duplicate one-time key"
    );
}

#[test]
fn t7_t10_t11_shapes() {
    let (net, tx, _) = setup(6);
    let mut t = tx.clone();
    t.pseudo_outs.pop();
    assert_eq!(validate(&net, &t), Err(TxError::PseudoOutCount));
    let mut t = tx.clone();
    t.signatures.pop();
    assert_eq!(validate(&net, &t), Err(TxError::SignatureCount));
    let mut t = tx.clone();
    t.range_proof.l.pop();
    assert_eq!(validate(&net, &t), Err(TxError::RangeProofShape));
}

#[test]
fn t8_fee() {
    let (net, tx, _) = setup(7);
    // The standard fee is an upper bound, so it is above the exact minimum.
    let required = net.rules.min_fee(tx.weight()).unwrap();
    assert!(tx.fee >= required);
    // One unit below the minimum for the actual weight (checked before balance).
    let mut t = tx.clone();
    t.fee = required - 1;
    let exact = net.rules.min_fee(t.weight()).unwrap();
    assert_eq!(
        validate(&net, &t),
        Err(TxError::FeeTooLow {
            fee: required - 1,
            required: exact
        })
    );
    // The standard fee covers the real weight of every shape.
    for n in [1usize, 2, 16, 64] {
        for k in [2usize, 3, 16] {
            assert!(
                standard_fee(n, k, &net.rules)
                    >= net
                        .rules
                        .min_fee(blacksilk_tx::builder::max_weight(n, k))
                        .unwrap()
            );
        }
    }
}

#[test]
fn t9_balance() {
    let (net, tx, _) = setup(8);
    let mut t = tx.clone();
    t.pseudo_outs[0] = Point::from_point(t.pseudo_outs[0].point() + h());
    assert_eq!(validate(&net, &t), Err(TxError::Unbalanced));
    let mut t = tx.clone();
    t.outputs[0].commitment = Point::from_point(t.outputs[0].commitment.point() - h());
    assert_eq!(validate(&net, &t), Err(TxError::Unbalanced));
    // Raising the fee without changing commitments breaks balance.
    let mut t = tx.clone();
    t.fee += 1;
    assert_eq!(validate(&net, &t), Err(TxError::Unbalanced));
}

#[test]
fn t10_range_proof() {
    let (_, tx, _) = setup(9);
    assert_eq!(check_range_proof(&tx), Ok(()));
    let mut t = tx.clone();
    t.range_proof.d1 += Scalar::ONE;
    assert_eq!(check_range_proof(&t), Err(TxError::RangeProofInvalid));
    let mut t = tx.clone();
    t.range_proof.l.swap(0, 1);
    assert_eq!(check_range_proof(&t), Err(TxError::RangeProofInvalid));
}

// ---------------------------------------------------------------- C rules

#[test]
fn c1_ring_members_must_exist_and_be_old_enough() {
    let (net, tx, _) = setup(10);
    let mut t = tx.clone();
    t.inputs[0].ring[15] = net.chain.output_count() + 100;
    assert_eq!(
        validate(&net, &t),
        Err(TxError::UnknownRingMember {
            input: 0,
            index: net.chain.output_count() + 100
        })
    );
    let mut t = tx.clone();
    let newest = net.chain.output_count() - 1; // coinbase of the previous block
    assert!(newest > t.inputs[0].ring[14]);
    t.inputs[0].ring[15] = newest;
    assert_eq!(
        validate(&net, &t),
        Err(TxError::RingMemberTooYoung {
            input: 0,
            index: newest
        })
    );
}

#[test]
fn c1_age_boundaries() {
    // A coinbase output becomes a valid ring member at exactly 60 blocks.
    let net = TestNet::new(11, 70);
    let first = net.chain.first_output_at(5).unwrap();
    let rec = blacksilk_tx::ChainView::output(&net.chain, first).unwrap();
    assert!(rec.coinbase && rec.height == 5);
    let mut tx_ring = [0u64; RING_SIZE];
    for (i, r) in tx_ring.iter_mut().enumerate() {
        *r = i as u64;
    }
    let t = Transfer {
        inputs: vec![blacksilk_tx::Input {
            key_image: random_point(&mut rng(1)),
            ring: tx_ring,
        }],
        ..setup(12).1
    };
    // Outputs 0..15 were created at heights 0..15; at height 70 the member at 15 is 55 old.
    assert_eq!(
        resolve_rings(&t, &net.chain, 70).unwrap_err(),
        TxError::RingMemberTooYoung {
            input: 0,
            index: 11
        }
    );
    assert!(resolve_rings(&t, &net.chain, 75).is_ok());
}

#[test]
fn c2_spent_key_image() {
    let (mut net, tx, _) = setup(13);
    net.mine(vec![tx.clone()], &mut []).unwrap();
    assert_eq!(
        validate(&net, &tx),
        Err(TxError::KeyImageSpent { input: 0 })
    );
}

#[test]
fn c3_signatures() {
    let (net, tx, _) = setup(14);
    let mut r = rng(15);
    let mut t = tx.clone();
    t.inputs[0].key_image = random_point(&mut r);
    assert_eq!(
        validate(&net, &t),
        Err(TxError::InvalidSignature { input: 0 })
    );
    let mut t = tx.clone();
    t.signatures[0].s[7] += Scalar::ONE;
    assert_eq!(
        validate(&net, &t),
        Err(TxError::InvalidSignature { input: 0 })
    );
    // Replacing a decoy with another (old enough) output breaks the signature:
    // the ring is part of the signed statement.
    let mut t = tx.clone();
    let ring = &mut t.inputs[0].ring;
    if ring[0] > 0 {
        ring[0] -= 1;
    } else {
        ring[0] = 0;
        ring[1] = if ring[1] > 1 { ring[1] - 1 } else { ring[1] };
    }
    if t.inputs[0].ring != tx.inputs[0].ring {
        assert_eq!(
            validate(&net, &t),
            Err(TxError::InvalidSignature { input: 0 })
        );
    }
    // Changing an encrypted field of an output also invalidates (full coverage).
    let mut t = tx.clone();
    t.outputs[0].enc_anchor[0] ^= 1;
    assert_eq!(
        validate(&net, &t),
        Err(TxError::InvalidSignature { input: 0 })
    );
    let mut t = tx.clone();
    t.outputs[1].view_tag ^= 1;
    assert_eq!(
        validate(&net, &t),
        Err(TxError::InvalidSignature { input: 0 })
    );
}

struct KeyExists<'a> {
    inner: &'a blacksilk_tx::state::MemoryChain,
    key: Point,
}

impl ChainView for KeyExists<'_> {
    fn output(&self, i: u64) -> Option<OutputRecord> {
        self.inner.output(i)
    }
    fn is_key_image_spent(&self, k: &Point) -> bool {
        self.inner.is_key_image_spent(k)
    }
    fn has_one_time_key(&self, k: &Point) -> bool {
        *k == self.key || self.inner.has_one_time_key(k)
    }
}

#[test]
fn c4_one_time_keys_are_unique() {
    let (net, tx, _) = setup(16);
    let view = KeyExists {
        inner: &net.chain,
        key: tx.outputs[1].one_time_key,
    };
    assert_eq!(
        validate_transfer(&tx, &view, net.height(), &net.rules),
        Err(TxError::DuplicateOneTimeKey { output: 1 })
    );
}

// ---------------------------------------------------------------- attacks with valid keys

type Opening = (Point, u64, Scalar);

/// Builds and signs a single-input transfer with arbitrary outputs, as an attacker
/// who owns the input would. `make_outputs` gets the tx context and returns the
/// outputs plus the openings (one-time key, amount, mask) the attacker claims in
/// the range proof. The pseudo-output mask is the sum of the claimed masks.
fn assemble(
    net: &mut TestNet,
    owner: &Wallet,
    owned: &OwnedOutput,
    make_outputs: impl FnOnce(&[u8; 32]) -> (Vec<Output>, Vec<Opening>),
    fee: u64,
) -> Transfer {
    let plan: InputPlan = net.plan(owned);
    let p = owner
        .keys
        .one_time_secret(owned.received.subaddress, &owned.received.output_key_offset);
    let ki = clsag::key_image(&p, &owned.key.one_time_key);
    let ctx = transfer_context(&[ki]);
    let (mut outputs, openings) = make_outputs(&ctx);
    outputs.sort_by_key(|o| o.one_time_key);
    let mask_sum: Scalar = openings.iter().map(|o| o.2).sum();
    let range_proof = proof_over(&outputs, &openings, &mut rng(99));

    let pseudo = Point::from_point(commit(owned.received.amount, &mask_sum));
    let mut members: Vec<(u64, RingMember)> = plan
        .decoys
        .iter()
        .map(|d| {
            (
                d.global_index,
                RingMember {
                    one_time_key: d.key.one_time_key,
                    commitment: d.key.commitment,
                },
            )
        })
        .collect();
    members.push((
        owned.global_index,
        RingMember {
            one_time_key: owned.key.one_time_key,
            commitment: owned.key.commitment,
        },
    ));
    members.sort_by_key(|m| m.0);
    let pos = members
        .iter()
        .position(|m| m.0 == owned.global_index)
        .unwrap();
    let ring: [RingMember; RING_SIZE] = std::array::from_fn(|i| members[i].1);
    let mut tx = Transfer {
        inputs: vec![blacksilk_tx::Input {
            key_image: ki,
            ring: std::array::from_fn(|i| members[i].0),
        }],
        outputs,
        fee,
        pseudo_outs: vec![pseudo],
        range_proof,
        signatures: vec![],
    };
    let msg = tx.signature_message(net.rules.network_id);
    let z = owned.received.mask - mask_sum;
    let (sig, _) = clsag::sign(&msg, &ring, &pseudo, pos, &p, &z, &mut net.rng).unwrap();
    tx.signatures.push(sig);
    tx
}

fn honest_output(
    address: &Address,
    amount: u64,
    ctx: &[u8; 32],
    r: &mut ChaCha20Rng,
) -> (Output, u64, Scalar) {
    let mut a = [0u8; 16];
    r.fill_bytes(&mut a);
    let o = create_output(address, amount, ctx, &Anchor(a), OutputKind::Transfer).unwrap();
    (
        Output {
            one_time_key: o.one_time_key,
            ephemeral: o.ephemeral,
            view_tag: o.view_tag,
            commitment: o.commitment,
            enc_amount: o.enc_amount,
            enc_anchor: o.enc_anchor,
        },
        amount,
        o.mask,
    )
}

/// Proof over the given (amount, mask) pairs in output order.
fn proof_over(outputs: &[Output], openings: &[Opening], r: &mut ChaCha20Rng) -> bpp::BppProof {
    let ordered: Vec<(u64, Scalar)> = outputs
        .iter()
        .map(|o| {
            let (_, a, y) = openings.iter().find(|x| x.0 == o.one_time_key).unwrap();
            (*a, *y)
        })
        .collect();
    let amounts: Vec<u64> = ordered.iter().map(|x| x.0).collect();
    let masks: Vec<Scalar> = ordered.iter().map(|x| x.1).collect();
    bpp::prove(&amounts, &masks, r).unwrap().0
}

/// Inflation: the attacker balances a large output against a *negative* one.
/// Signatures and balance are valid; only the range proof stops it.
#[test]
fn inflation_with_negative_output_is_rejected() {
    let mut net = TestNet::new(20, 80);
    let miner = net.miner_clone();
    let owned = miner.spendable(net.height())[0].clone();
    let input = owned.received.amount; // REWARD
    let fee = standard_fee(1, 2, &net.rules);

    // Control: the same assembly path with honest outputs produces a valid tx.
    let mut r2 = rng(22);
    let honest = assemble(
        &mut net,
        &miner,
        &owned,
        |ctx| {
            let (a, va, ya) = honest_output(&miner.primary(), 1000, ctx, &mut r2);
            let (b, vb, yb) = honest_output(&miner.primary(), input - 1000 - fee, ctx, &mut r2);
            (
                vec![a.clone(), b.clone()],
                vec![(a.one_time_key, va, ya), (b.one_time_key, vb, yb)],
            )
        },
        fee,
    );
    assert_eq!(validate(&net, &honest), Ok(()));

    // Attack: +2·input to self, and −(input + fee) in a hand-made commitment.
    let mut r3 = rng(23);
    let evil = assemble(
        &mut net,
        &miner,
        &owned,
        |ctx| {
            let (a, va, ya) = honest_output(&miner.primary(), 2 * input, ctx, &mut r3);
            let (mut b, _, yb) = honest_output(&miner.primary(), 0, ctx, &mut r3);
            b.commitment =
                Point::from_point(RistrettoPoint::mul_base(&yb) - Scalar::from(input + fee) * h());
            // The best available proof: the attacker proves 0 for output b.
            (
                vec![a.clone(), b.clone()],
                vec![(a.one_time_key, va, ya), (b.one_time_key, 0, yb)],
            )
        },
        fee,
    );
    assert_eq!(check_balance(&evil), Ok(()), "the attack balances");
    let rings = resolve_rings(&evil, &net.chain, net.height()).unwrap();
    assert_eq!(
        check_signatures(&evil, &rings, &net.rules),
        Ok(()),
        "and is properly signed"
    );
    assert_eq!(validate(&net, &evil), Err(TxError::RangeProofInvalid));
    assert_eq!(
        net.mine(vec![evil], &mut []).unwrap_err(),
        BlockError::RangeProofBatch
    );
}

/// Spending more than the input with valid range proofs fails the balance check.
#[test]
fn overspend_is_rejected() {
    let mut net = TestNet::new(24, 80);
    let miner = net.miner_clone();
    let owned = miner.spendable(net.height())[0].clone();
    let fee = standard_fee(1, 2, &net.rules);
    let mut r2 = rng(26);
    let tx = assemble(
        &mut net,
        &miner,
        &owned,
        |ctx| {
            let (a, va, ya) = honest_output(&miner.primary(), REWARD, ctx, &mut r2);
            let (b, vb, yb) = honest_output(&miner.primary(), 1, ctx, &mut r2);
            (
                vec![a.clone(), b.clone()],
                vec![(a.one_time_key, va, ya), (b.one_time_key, vb, yb)],
            )
        },
        fee,
    );
    assert_eq!(validate(&net, &tx), Err(TxError::Unbalanced));
}

/// A Janus probe is valid on chain (consensus cannot see it) but the victim's
/// wallet refuses it, so it never shows up as received.
#[test]
fn janus_probe_on_chain_is_refused_by_the_victim() {
    let mut net = TestNet::new(27, 80);
    let eve = net.miner_clone();
    let mut victim = Wallet::new(&mut rng(28));
    let a = victim.address(0, 2);
    let b = victim.address(1, 7);
    let owned = eve.spendable(net.height())[0].clone();
    let fee = standard_fee(1, 2, &net.rules);
    let amount = 50_000u64;
    let mut r2 = rng(30);
    let tx = assemble(
        &mut net,
        &eve,
        &owned,
        |ctx| {
            // r derived honestly for a; one-time key pointing at b.
            let mut anchor = [0u8; 16];
            r2.fill_bytes(&mut anchor);
            let anchor = Anchor(anchor);
            let rr = janus::ephemeral_secret(&anchor, ctx, &a);
            let s = (rr * a.view().point()).compress().to_bytes();
            let x = hash_to_scalar(tags::OUTPUT_KEY, &[&s]);
            let y = hash_to_scalar(tags::MASK, &[&s]);
            let pad = h64(tags::AMOUNT, &[&s]);
            let apad = h64(tags::ANCHOR, &[&s]);
            let mut enc_amount = amount.to_le_bytes();
            let mut enc_anchor = anchor.0;
            for i in 0..8 {
                enc_amount[i] ^= pad[i];
            }
            for i in 0..16 {
                enc_anchor[i] ^= apad[i];
            }
            let probe = Output {
                one_time_key: Point::from_point(RistrettoPoint::mul_base(&x) + b.spend().point()),
                ephemeral: Point::from_point(rr * a.spend().point()),
                view_tag: h32(tags::VIEW_TAG, &[&s])[0],
                commitment: Point::from_point(commit(amount, &y)),
                enc_amount,
                enc_anchor,
            };
            let (change, vc, yc) =
                honest_output(&eve.primary(), REWARD - amount - fee, ctx, &mut r2);
            let openings = vec![
                (probe.one_time_key, amount, y),
                (change.one_time_key, vc, yc),
            ];
            (vec![probe, change], openings)
        },
        fee,
    );
    // Consensus accepts it: nothing about it is invalid on chain.
    assert_eq!(validate(&net, &tx), Ok(()));
    let t = Transaction::from(tx.clone());
    let report = scan_transaction(victim.keys.view_keys(), &victim.table, &t, net.height(), 0);
    assert!(report.owned.is_empty(), "the probe is not received");
    assert_eq!(report.rejected.len(), 1);
    assert_eq!(report.rejected[0].1, ScanRejection::JanusAnchorMismatch);
    net.mine(vec![tx], &mut [&mut victim]).unwrap();
    assert_eq!(victim.balance(), 0);
}

// ---------------------------------------------------------------- B rules

#[test]
fn block_rules() {
    let (mut net, tx, _) = setup(31);
    let fees = tx.fee;
    let t = Transaction::from(tx.clone());
    let submit = |net: &mut TestNet, txs: Vec<Transaction>| {
        let ctx = net.context(&txs);
        validate_block_transactions(&txs, &ctx, &net.chain, &net.rules, &mut rng(0))
    };

    // B1
    assert_eq!(
        submit(&mut net, vec![t.clone()]),
        Err(BlockError::MissingCoinbase)
    );
    assert_eq!(submit(&mut net, vec![]), Err(BlockError::MissingCoinbase));
    let cb = net.coinbase(fees);
    assert_eq!(
        submit(&mut net, vec![cb.clone(), cb.clone()]),
        Err(BlockError::UnexpectedCoinbase { index: 1 })
    );
    // B2
    let mut wrong_height = cb.clone();
    if let Transaction::Coinbase(c) = &mut wrong_height {
        c.height += 1;
    }
    assert!(matches!(
        submit(&mut net, vec![wrong_height, t.clone()]),
        Err(BlockError::CoinbaseHeight { .. })
    ));
    // B3: claiming one unit too much or too little.
    for delta in [1i64, -1] {
        let mut c = cb.clone();
        if let Transaction::Coinbase(c) = &mut c {
            c.outputs[0].amount = (c.outputs[0].amount as i64 + delta) as u64;
        }
        assert!(matches!(
            submit(&mut net, vec![c, t.clone()]),
            Err(BlockError::CoinbaseAmount { .. })
        ));
    }
    // Forgetting the fee is under-claiming, also invalid.
    let cb_no_fee = net.coinbase(0);
    assert!(matches!(
        submit(&mut net, vec![cb_no_fee, t.clone()]),
        Err(BlockError::CoinbaseAmount { .. })
    ));
    // B5
    let txs = vec![cb.clone(), t.clone()];
    let mut ctx = net.context(&txs);
    ctx.tx_root[0] ^= 1;
    assert_eq!(
        validate_block_transactions(&txs, &ctx, &net.chain, &net.rules, &mut rng(0)),
        Err(BlockError::TxRootMismatch)
    );
    // B6
    let ctx = net.context(&txs);
    let mut small = net.rules;
    small.max_block_weight = 1000;
    assert!(matches!(
        validate_block_transactions(&txs, &ctx, &net.chain, &small, &mut rng(0)),
        Err(BlockError::WeightExceeded { .. })
    ));
    // Coinbase structure.
    let mut bad = cb.clone();
    if let Transaction::Coinbase(c) = &mut bad {
        c.outputs[0].one_time_key = identity();
    }
    assert!(matches!(
        submit(&mut net, vec![bad, t.clone()]),
        Err(BlockError::CoinbaseOutputKeyIdentity { output: 0 })
    ));
    // And the correct block is accepted.
    assert_eq!(submit(&mut net, vec![cb, t]), Ok(()));
}

#[test]
fn coinbase_outputs_must_be_sorted_and_unique() {
    let mut net = TestNet::new(32, 1);
    let miner = net.miner_clone();
    let secret = miner.keys.hedge_secret();
    let h = net.height();
    let payouts = [
        blacksilk_tx::builder::Payment {
            address: miner.address(0, 1),
            amount: REWARD / 2,
        },
        blacksilk_tx::builder::Payment {
            address: miner.address(0, 2),
            amount: REWARD / 2,
        },
    ];
    let cb = blacksilk_tx::builder::build_coinbase(h, &payouts, &secret, &mut rng(33)).unwrap();
    let mut unsorted = cb.clone();
    unsorted.outputs.swap(0, 1);
    let txs = vec![Transaction::Coinbase(unsorted)];
    let ctx = net.context(&txs);
    assert_eq!(
        validate_block_transactions(&txs, &ctx, &net.chain, &net.rules, &mut rng(0)),
        Err(BlockError::CoinbaseOutputsNotSorted)
    );
    net.submit(vec![Transaction::Coinbase(cb)], &mut [])
        .unwrap();
}

// ---------------------------------------------------------------- decoding robustness

#[test]
fn decoder_never_panics_on_garbage() {
    let (_, tx, _) = setup(34);
    let bytes = Transaction::from(tx).encode();
    let mut r = rng(35);
    // Every truncation fails.
    for len in 0..bytes.len() {
        assert!(Transaction::decode(&bytes[..len]).is_err(), "prefix {len}");
    }
    // Appended bytes fail.
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(
        Transaction::decode(&longer),
        Err(blacksilk_tx::codec::DecodeError::TrailingBytes)
    );
    // Random multi-byte corruption and random buffers never panic.
    for _ in 0..2000 {
        let mut b = bytes.clone();
        for _ in 0..(1 + r.next_u32() % 8) {
            let i = r.next_u32() as usize % b.len();
            b[i] = r.next_u32() as u8;
        }
        let _ = Transaction::decode(&b);
        let mut junk = vec![0u8; (r.next_u32() % 4096) as usize];
        r.fill_bytes(&mut junk);
        let _ = Transaction::decode(&junk);
    }
    // Oversized input is refused before parsing.
    assert_eq!(
        Transaction::decode(&vec![0u8; blacksilk_tx::params::MAX_TX_SIZE + 1]),
        Err(blacksilk_tx::codec::DecodeError::TooLarge)
    );
    // Huge declared counts are refused before allocation.
    assert!(matches!(
        Transaction::decode(&[1, 1, 0xff, 0xff, 0xff, 0x0f]),
        Err(blacksilk_tx::codec::DecodeError::CountOutOfRange { .. })
    ));
}

#[test]
fn stateless_and_contextual_errors_are_distinguished() {
    // Contextual: depend on the chain view (honest relays can hit them).
    for e in [
        TxError::UnknownRingMember { input: 0, index: 1 },
        TxError::RingMemberTooYoung { input: 0, index: 1 },
        TxError::KeyImageSpent { input: 0 },
        TxError::InvalidSignature { input: 0 },
        TxError::DuplicateOneTimeKey { output: 0 },
    ] {
        assert!(!e.is_stateless(), "{e:?}");
    }
    // Stateless: invalid everywhere, proof of a faulty or malicious sender.
    for e in [
        TxError::Unbalanced,
        TxError::RangeProofInvalid,
        TxError::KeyImagesNotSorted,
        TxError::FeeTooLow {
            fee: 1,
            required: 2,
        },
        TxError::OutputCount(1),
    ] {
        assert!(e.is_stateless(), "{e:?}");
    }
}
