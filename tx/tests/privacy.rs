//! Privacy-leakage tests (spec §11): what an observer sees must not depend on
//! recipients, change, or which ring member is real.

mod common;

use blacksilk_crypto::keys::{SubaddressTable, ViewKeys};
use blacksilk_tx::codec::Writer;
use blacksilk_tx::scan::scan_block;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::Transfer;
use common::*;
use std::collections::HashSet;

fn ring_bytes(tx: &Transfer) -> usize {
    let mut w = Writer::new();
    for i in &tx.inputs {
        w.varint(i.ring[0]);
        for p in i.ring.windows(2) {
            w.varint(p[1] - p[0]);
        }
    }
    w.len()
}

/// Paying a primary address, a subaddress, or several recipients yields outputs of
/// identical encoding, and transactions whose size depends only on their shape
/// (plus the ring-offset varints).
#[test]
fn output_encoding_does_not_depend_on_recipient_type() {
    let mut net = TestNet::new(50, 80);
    let alice = Wallet::new(&mut rng(51));
    let miner = net.miner_clone();
    let to_primary = net.pay(&miner, &[(alice.primary(), 1000)]);
    let to_sub = net.pay(&miner, &[(alice.address(1, 9), 1000)]);
    let len = |t: &Transfer| Transaction::from(t.clone()).encode().len() - ring_bytes(t);
    assert_eq!(len(&to_primary), len(&to_sub));
    assert_eq!(
        to_primary.fee, to_sub.fee,
        "standard fee depends only on the shape"
    );
    // Every output has the same 121-byte encoding.
    for t in [&to_primary, &to_sub] {
        let base = t.prefix_bytes().len();
        let mut one_less = t.clone();
        one_less.outputs.pop();
        assert_eq!(base - one_less.prefix_bytes().len(), 121);
    }
}

/// The change output's position is not predictable (outputs are sorted by
/// pseudorandom one-time keys).
#[test]
fn change_position_is_uniform() {
    let mut net = TestNet::new(52, 80);
    let alice = Wallet::new(&mut rng(53));
    let miner = net.miner_clone();
    let mut positions = [0u32; 2];
    for _ in 0..40 {
        let tx = net.pay(&miner, &[(alice.primary(), 1000)]);
        let t = Transaction::from(tx);
        let report = scan_block(miner.keys.view_keys(), &miner.table, &[t], net.height(), 0);
        assert_eq!(report.owned.len(), 1);
        positions[report.owned[0].index_in_tx] += 1;
    }
    assert!(positions[0] >= 8 && positions[1] >= 8, "{positions:?}");
}

/// The real input's position within its ring varies across transactions.
#[test]
fn real_ring_position_varies() {
    let mut net = TestNet::new(54, 200);
    let miner = net.miner_clone();
    let mut positions = HashSet::new();
    for o in miner
        .spendable(net.height())
        .into_iter()
        .take(24)
        .cloned()
        .collect::<Vec<_>>()
    {
        let plan = net.plan(&o);
        let mut ring: Vec<u64> = plan.decoys.iter().map(|d| d.global_index).collect();
        ring.push(o.global_index);
        ring.sort_unstable();
        positions.insert(ring.iter().position(|&i| i == o.global_index).unwrap());
    }
    assert!(positions.len() >= 4, "{positions:?}");
}

/// Outsiders (no keys) detect nothing; a view-only wallet sees exactly what the
/// full wallet sees.
#[test]
fn only_the_recipient_detects_outputs() {
    let mut net = TestNet::new(56, 80);
    let mut alice = Wallet::new(&mut rng(57));
    let mut outsider = Wallet::new(&mut rng(58));
    let view_only_keys = ViewKeys::new(
        *alice.keys.view_keys().view_secret(),
        *alice.keys.view_keys().spend_public(),
    )
    .unwrap();
    let view_only_table = SubaddressTable::new(&view_only_keys, 2, 10);

    let miner = net.miner_clone();
    let tx1 = net.pay(
        &miner,
        &[(alice.address(0, 3), 4000), (alice.address(1, 1), 5000)],
    );
    let first = net.chain.output_count() + 1; // after the coinbase
    let txs = vec![Transaction::from(tx1.clone())];
    net.mine(vec![tx1], &mut [&mut alice, &mut outsider])
        .unwrap();

    assert_eq!(outsider.owned.len(), 0);
    assert_eq!(alice.owned.len(), 2);
    let r = scan_block(
        &view_only_keys,
        &view_only_table,
        &txs,
        net.height() - 1,
        first,
    );
    let mut a: Vec<_> = alice
        .owned
        .iter()
        .map(|o| (o.global_index, o.received.amount))
        .collect();
    let mut b: Vec<_> = r
        .owned
        .iter()
        .map(|o| (o.global_index, o.received.amount))
        .collect();
    a.sort();
    b.sort();
    assert_eq!(a, b);
    assert!(r.rejected.is_empty());
}

/// Repeated payments to one address share no public value, and the key image of
/// a spent output does not appear anywhere else.
#[test]
fn repeated_payments_are_unlinkable_on_chain() {
    let mut net = TestNet::new(59, 80);
    let mut alice = Wallet::new(&mut rng(60));
    let miner = net.miner_clone();
    let t1 = net.pay(&miner, &[(alice.primary(), 1000)]);
    let t2 = net.pay(&miner, &[(alice.primary(), 1000)]);
    let fields = |t: &Transfer| -> HashSet<[u8; 32]> {
        t.outputs
            .iter()
            .flat_map(|o| {
                [
                    *o.one_time_key.bytes(),
                    *o.ephemeral.bytes(),
                    *o.commitment.bytes(),
                ]
            })
            .collect()
    };
    assert!(fields(&t1).is_disjoint(&fields(&t2)));
    let addr = alice.primary();
    for t in [&t1, &t2] {
        for o in &t.outputs {
            assert_ne!(o.one_time_key, *addr.spend());
            assert_ne!(o.ephemeral, *addr.view());
        }
    }
    net.mine(vec![t1], &mut [&mut alice]).unwrap();
    let ki = alice.owned[0].key_image(&alice.keys);
    assert!(!fields(&t2).contains(ki.bytes()));
}

/// A "CSPRNG" that always outputs the same byte: a completely broken RNG.
struct ConstRng;
impl rand_core::RngCore for ConstRng {
    fn next_u32(&mut self) -> u32 {
        0x4242_4242
    }
    fn next_u64(&mut self) -> u64 {
        0x4242_4242_4242_4242
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0x42)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        dest.fill(0x42);
        Ok(())
    }
}
impl rand_core::CryptoRng for ConstRng {}

/// R2-C1: with a broken (constant) RNG, two transfers over the same inputs
/// that differ only in a payment amount, a recipient or the fee share no
/// output key, ephemeral key, commitment or pseudo-output: the hedge context
/// binds the whole statement, not only the key images. The same statement
/// rebuilt gives the same transfer (deterministic, which is safe).
#[test]
fn broken_rng_transfers_over_the_same_inputs_share_no_output_secrets() {
    use blacksilk_tx::builder::{build_transfer, standard_fee, InputPlan, Payment};
    let mut net = TestNet::new(61, 80);
    let alice = Wallet::new(&mut rng(62));
    let bob = Wallet::new(&mut rng(63));
    let miner = net.miner_clone();
    let real = miner.spendable(net.height())[0].clone();
    let plans: Vec<InputPlan> = vec![net.plan(&real)];
    let fee = standard_fee(1, 2, &net.rules);
    let build = |to: &Wallet, amount: u64, fee: u64| {
        build_transfer(
            &miner.keys,
            plans.clone(),
            &[Payment {
                address: to.primary(),
                amount,
            }],
            &miner.primary(),
            fee,
            &net.rules,
            &mut ConstRng,
        )
        .expect("build")
    };
    let public = |t: &Transfer| -> HashSet<[u8; 32]> {
        t.outputs
            .iter()
            .flat_map(|o| {
                [
                    *o.one_time_key.bytes(),
                    *o.ephemeral.bytes(),
                    *o.commitment.bytes(),
                ]
            })
            .chain(t.pseudo_outs.iter().map(|p| *p.bytes()))
            .collect()
    };
    let base = build(&alice, 1000, fee);
    // Deterministic for an identical statement.
    assert_eq!(
        Transaction::from(base.clone()).encode(),
        Transaction::from(build(&alice, 1000, fee)).encode()
    );
    for (what, other) in [
        ("amount", build(&alice, 1001, fee)),
        ("recipient", build(&bob, 1000, fee)),
        ("fee", build(&alice, 1000, fee + 1)),
    ] {
        assert!(
            public(&base).is_disjoint(&public(&other)),
            "{what}: a public value repeats"
        );
    }
}
