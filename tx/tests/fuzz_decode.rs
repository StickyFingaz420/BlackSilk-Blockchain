//! Mutation fuzzing of transaction decoding and validation (pure Rust,
//! seeded, repeatable). Every mutant of every seed kind (coinbase, transfer,
//! PX transaction, deploy) and random inputs must decode without a panic; a
//! successful decode must re-encode to the identical bytes (canonical
//! encoding); the stateless rules must not panic, and a sample of PX mutants
//! that still decode goes through full validation including the proof.
//!
//! `BLACKSILK_FUZZ_ITERS` sets the number of mutants per seed (default 3000);
//! long campaigns set it high. This is not coverage-guided fuzzing
//! (docs/reviews/zk-security-review.md §7).

mod common;

use blacksilk_px::wallet::{self as pxw, Account};
use blacksilk_tx::builder::Payment;
use blacksilk_tx::px::{
    check_deploy_structure, check_px_balance, check_px_structure, Registration,
};
use blacksilk_tx::px_builder::{build_deploy, build_px, px_standard_fee, PxPlan};
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::{check_balance, check_structure, validate_mempool_tx};
use blacksilk_zkvm::air::trace::Budget;
use common::*;
use rand_chacha::rand_core::RngCore;

fn iters() -> usize {
    std::env::var("BLACKSILK_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3000)
}

/// One random mutation of `b`.
pub fn mutate(rng: &mut ChaCha20Rng, b: &[u8]) -> Vec<u8> {
    let mut v = b.to_vec();
    let len = v.len().max(1);
    match rng.next_u32() % 8 {
        0 => {
            let i = rng.next_u32() as usize % len;
            if let Some(x) = v.get_mut(i) {
                *x ^= 1 << (rng.next_u32() % 8);
            }
        }
        1 => {
            let i = rng.next_u32() as usize % len;
            if let Some(x) = v.get_mut(i) {
                *x = rng.next_u32() as u8;
            }
        }
        2 => v.truncate(rng.next_u32() as usize % len),
        3 => {
            let n = 1 + rng.next_u32() as usize % 64;
            v.extend((0..n).map(|_| rng.next_u32() as u8));
        }
        4 => {
            let i = rng.next_u32() as usize % (v.len() + 1);
            v.insert(i, rng.next_u32() as u8);
        }
        5 => {
            if !v.is_empty() {
                let i = rng.next_u32() as usize % v.len();
                v.remove(i);
            }
        }
        6 => {
            // Overwrite a run with 0xff (large varints, invalid points).
            let i = rng.next_u32() as usize % len;
            let n = 1 + rng.next_u32() as usize % 10;
            for x in v.iter_mut().skip(i).take(n) {
                *x = 0xff;
            }
        }
        _ => {
            // Splice a chunk from elsewhere (duplicated structures).
            if v.len() > 2 {
                let a = rng.next_u32() as usize % v.len();
                let b2 = rng.next_u32() as usize % v.len();
                let n = 1 + rng.next_u32() as usize % 64;
                let chunk: Vec<u8> = v.iter().skip(a).take(n).copied().collect();
                for (k, x) in chunk.into_iter().enumerate() {
                    if let Some(y) = v.get_mut(b2 + k) {
                        *y = x;
                    }
                }
            }
        }
    }
    v
}

#[test]
fn every_mutant_decodes_canonically_or_fails_cleanly() {
    let mut net = TestNet::new(81, 130);
    let payer = net.miner_clone();
    let alice = Wallet::new(&mut net.rng);
    let transfer = Transaction::from(net.pay(&payer, &[(alice.primary(), 1_000)]));
    let coinbase = net.coinbase(0);

    // A deploy (fast) and a PX bridge-in (one proof).
    let height = net.height();
    let spend = payer.spendable(height);
    let plan = net.plan(spend[1]);
    let rules = net.rules;
    let deploy = build_deploy(
        &payer.keys,
        vec![plan],
        &[Payment {
            address: payer.primary(),
            amount: 1,
        }],
        &payer.primary(),
        [1; 32],
        vec![Registration {
            elf: include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../px/vault.elf")).to_vec(),
            budget: Budget {
                cycles: 6_000,
                keys: 2_200,
                add: 4_300,
                bit: 200,
                lt: 3_400,
                shift: 200,
                mul: 200,
                poseidon: 22,
            },
        }],
        &rules,
        &mut net.rng,
    )
    .unwrap();
    let px = {
        let acct = Account::from_seed(&[9; 32]);
        let fee = px_standard_fee();
        let real = spend
            .iter()
            .find(|o| o.received.amount > 10_000_000 + fee)
            .unwrap();
        let plan = net.plan(real);
        let root = net.chain.px().root();
        let w = pxw::witness(
            root,
            10_000_000,
            0,
            [
                pxw::dummy_input(&mut net.rng),
                pxw::dummy_input(&mut net.rng),
            ],
            [
                pxw::output(&mut net.rng, acct.owner(0), 10_000_000),
                pxw::empty_output(&mut net.rng),
            ],
        );
        build_px(
            PxPlan {
                keys: Some(&payer.keys),
                inputs: vec![plan],
                change: Some(payer.primary()),
                payouts: vec![],
                witness: w,
                recipients: [Some(acct.address(0)), None],
                functions: vec![],
                fee,
            },
            &rules,
            &mut net.rng,
        )
        .unwrap()
    };
    let seeds = [
        ("coinbase", coinbase.encode()),
        ("transfer", transfer.encode()),
        ("px", Transaction::Px(Box::new(px)).encode()),
        ("deploy", Transaction::PxDeploy(Box::new(deploy)).encode()),
    ];
    let mut rng = common::rng(7);
    let (mut decoded, mut proofs_checked) = (0usize, 0usize);
    let n = iters();
    for (name, seed) in &seeds {
        assert!(Transaction::decode(seed).is_ok(), "seed {name} decodes");
        for _ in 0..n {
            let m = mutate(&mut rng, seed);
            let Ok(tx) = Transaction::decode(&m) else {
                continue;
            };
            decoded += 1;
            assert_eq!(tx.encode(), m, "{name}: decode∘encode must be the identity");
            // Cheap rules must not panic, whatever their verdict.
            match &tx {
                Transaction::Transfer(t) => {
                    let _ = check_structure(t, &rules);
                    let _ = check_balance(t);
                }
                Transaction::Px(t) => {
                    let _ = check_px_structure(t);
                    let _ = check_px_balance(t);
                    // A sample goes through full validation (proof included).
                    if proofs_checked < 25 {
                        proofs_checked += 1;
                        assert!(
                            validate_mempool_tx(&tx, &net.chain, net.height(), &rules).is_err(),
                            "a mutated PX transaction must not validate"
                        );
                    }
                }
                Transaction::PxDeploy(t) => {
                    let _ = check_deploy_structure(t, &rules);
                }
                Transaction::Coinbase(_) => {}
            }
        }
    }
    // Pure random inputs.
    for _ in 0..n {
        let len = rng.next_u32() as usize % 4096;
        let v: Vec<u8> = (0..len).map(|_| rng.next_u32() as u8).collect();
        if let Ok(tx) = Transaction::decode(&v) {
            assert_eq!(tx.encode(), v);
        }
    }
    println!(
        "{} mutants per seed, {decoded} still decoded (all canonical), {proofs_checked} PX mutants fully validated and rejected",
        n
    );
}
