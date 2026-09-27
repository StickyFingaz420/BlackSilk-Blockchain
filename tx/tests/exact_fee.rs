//! T8, the exact v1 fee (docs/reviews/v3-consensus-changes.md#exact-v1-fee):
//! a transfer pays exactly `FEE_PER_WEIGHT × max_weight(n_in, n_out)`.

mod common;

use blacksilk_tx::builder::{
    build_transfer, build_transfer_signing, standard_fee, BuildError, InputPlan, Payment,
};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::px::deploy_fee;
use blacksilk_tx::validate::{validate_transfer, BlockError, TxError};
use blacksilk_tx::Transfer;
use common::*;

/// A signed, balanced transfer from the miner paying `fee` (any amount: the
/// builder's own fee rule is bypassed by signing through
/// `build_transfer_signing`, as a third-party wallet could).
fn transfer_paying(net: &mut TestNet, fee: u64) -> Transfer {
    let miner = net.miner_clone();
    let real = miner.spendable(net.height())[0].clone();
    let plan: InputPlan = net.plan(&real);
    let mut r = rng(77);
    let to = Wallet::new(&mut r).primary();
    let domain = net.rules.domain();
    build_transfer_signing(
        &miner.keys,
        vec![plan],
        &[Payment {
            address: to,
            amount: 1_000_000,
        }],
        &miner.primary(),
        fee,
        &net.rules,
        &mut net.rng,
        &[],
        &|t| t.signature_message(domain),
    )
    .expect("signed")
}

/// Demonstration (written before the rule): a transfer paying one unit more
/// or less than the standard fee of its shape, or a "priority" multiple of
/// it, was valid under T8 "fee ≥ min_fee(weight)" and is invalid under the
/// exact rule, in the mempool and in a block. The standard fee stays valid.
#[test]
fn a_transfer_not_paying_exactly_the_standard_fee_is_rejected() {
    let mut net = TestNet::new(91, 80);
    let standard = standard_fee(1, 2, &net.rules);
    let mut accepted = Vec::new();
    for fee in [standard + 1, standard - 1, 2 * standard] {
        let t = transfer_paying(&mut net, fee);
        let r = validate_transfer(&t, &net.chain, net.height(), &net.rules);
        let mined = net.mine(vec![t], &mut []);
        if r.is_ok() || mined.is_ok() {
            accepted.push((fee, r, mined));
        }
    }
    assert!(
        accepted.is_empty(),
        "standard fee {standard}; accepted (fee, mempool, block): {accepted:?}"
    );
    let t = transfer_paying(&mut net, standard);
    assert_eq!(
        validate_transfer(&t, &net.chain, net.height(), &net.rules),
        Ok(())
    );
    assert_eq!(net.mine(vec![t], &mut []), Ok(()));
}

/// The error: `FeeNotExact` with the standard fee of the shape, stateless
/// (the fee and the shape are the transaction's own), in the mempool path and
/// in a block (at the offending transaction's index).
#[test]
fn a_non_standard_fee_is_a_stateless_fee_not_exact() {
    let mut net = TestNet::new(92, 80);
    let standard = standard_fee(1, 2, &net.rules);
    assert_eq!(net.rules.standard_fee(1, 2), Some(standard));
    let t = transfer_paying(&mut net, standard + 7);
    let e = TxError::FeeNotExact {
        fee: standard + 7,
        required: standard,
    };
    assert_eq!(
        validate_transfer(&t, &net.chain, net.height(), &net.rules),
        Err(e)
    );
    assert!(e.is_stateless());
    assert_eq!(
        net.mine(vec![t], &mut []),
        Err(BlockError::Tx { index: 1, error: e })
    );
}

/// The builder refuses a non-standard fee (self-check), so no wallet using
/// it can produce one; the standard fee builds.
#[test]
fn the_builder_refuses_a_non_standard_fee() {
    let mut net = TestNet::new(93, 80);
    let miner = net.miner_clone();
    let real = miner.spendable(net.height())[0].clone();
    let standard = standard_fee(1, 2, &net.rules);
    let mut r = rng(78);
    let to = Wallet::new(&mut r).primary();
    for (fee, ok) in [
        (standard, true),
        (standard + 1, false),
        (standard - 1, false),
    ] {
        let plan = net.plan(&real);
        let built = build_transfer(
            &miner.keys,
            vec![plan],
            &[Payment {
                address: to,
                amount: 5,
            }],
            &miner.primary(),
            fee,
            &net.rules,
            &mut net.rng,
        );
        match built {
            Ok(t) => assert!(ok && t.fee == standard, "fee {fee} built"),
            Err(BuildError::SelfCheck(TxError::FeeNotExact { fee: f, required })) => {
                assert!(!ok && f == fee && required == standard, "fee {fee}")
            }
            Err(e) => panic!("fee {fee}: {e:?}"),
        }
    }
}

/// The deploy fee's v1 part is the transfer's exact fee through the same
/// function (`TxRules::standard_fee`): a rule set with another fee rate moves
/// both together.
#[test]
fn the_deploy_fee_uses_the_same_standard_fee_function() {
    let rules = rules();
    let doubled = TxRules {
        fee_per_weight: 2 * rules.fee_per_weight,
        ..rules
    };
    for (n, k) in [(1, 2), (2, 2), (16, 2), (64, 16), (1, 16)] {
        let base = deploy_fee(n, k, &[], &rules) - rules.standard_fee(n, k).unwrap();
        assert_eq!(
            deploy_fee(n, k, &[], &doubled) - doubled.standard_fee(n, k).unwrap(),
            base,
            "payload part unchanged ({n}, {k})"
        );
        assert_eq!(
            doubled.standard_fee(n, k).unwrap(),
            2 * rules.standard_fee(n, k).unwrap()
        );
    }
}
