//! The upgrade mechanism on the transaction side (docs/consensus.md §11,
//! docs/reviews/v3-upgrade-mechanism.md §3): the branch id of the epoch is
//! bound into every signature message and the PX binding `h_tx`, so a
//! transaction signed in one epoch is invalid in the next.
//!
//! The regtest schedule here is test-only: two epochs identical except the
//! branch id (a no-op activation at [`ACTIVATION`]).

mod common;

use blacksilk_consensus::schedule::{Epoch, Schedule, BRANCH_ID_V3, VERIFIER_PX_1};
use blacksilk_consensus::{ChainParams, Network};
use blacksilk_tx::params::{SigDomain, TxRules, SUPPORTED_VERIFIERS};
use blacksilk_tx::px::{PxDeploy, PxTx};
use blacksilk_tx::validate::{validate_transfer, TxError};
use blacksilk_tx::BlockError;
use common::*;

const ACTIVATION: u64 = 100;
const NEXT_BRANCH: u32 = 0x4253_7634;

static NOOP_UPGRADE: [Epoch; 2] = [
    Epoch {
        name: "v3",
        activation_height: 0,
        header_version: 1,
        branch_id: BRANCH_ID_V3,
        verifier_id: VERIFIER_PX_1,
    },
    Epoch {
        name: "noop",
        activation_height: ACTIVATION,
        header_version: 1,
        branch_id: NEXT_BRANCH,
        verifier_id: VERIFIER_PX_1,
    },
];

fn upgrading_regtest() -> ChainParams {
    let mut p = ChainParams::regtest();
    p.schedule = Schedule::new(&NOOP_UPGRADE);
    p
}

fn domain(network_id: u32, branch_id: u32) -> SigDomain {
    SigDomain {
        network_id,
        branch_id,
    }
}

/// A PX transaction with every list empty: enough to hash.
fn empty_px() -> PxTx {
    PxTx {
        inputs: vec![],
        outputs: vec![],
        payouts: vec![],
        fee: 1,
        bridge_in: 0,
        bridge_out: 0,
        anchor: [1; 8],
        nullifiers: [[2; 8], [3; 8]],
        commitments: [[4; 8], [5; 8]],
        ciphertexts: [vec![], vec![]],
        functions: vec![],
        pseudo_outs: vec![],
        range_proof: None,
        signatures: vec![],
        proof: vec![],
    }
}

#[test]
fn built_in_rules_use_the_v3_branch_and_a_supported_verifier() {
    for n in [Network::Mainnet, Network::Testnet, Network::Regtest] {
        let p = ChainParams::for_network(n);
        let r = TxRules::for_chain(&p);
        assert_eq!(r.branch_id, BRANCH_ID_V3);
        assert_eq!(r.domain(), domain(p.network_id, BRANCH_ID_V3));
        for e in p.schedule.epochs() {
            assert!(
                SUPPORTED_VERIFIERS.contains(&e.verifier_id),
                "{n:?} epoch {} names verifier {} which tx does not implement",
                e.name,
                e.verifier_id
            );
        }
    }
    for e in NOOP_UPGRADE.iter() {
        assert!(SUPPORTED_VERIFIERS.contains(&e.verifier_id));
    }
}

#[test]
fn domain_bytes_are_network_then_branch() {
    let d = domain(0x0102_0304, 0x0A0B_0C0D);
    assert_eq!(d.bytes(), [4, 3, 2, 1, 0x0D, 0x0C, 0x0B, 0x0A]);
}

#[test]
fn rules_follow_the_schedule_at_the_boundary() {
    let p = upgrading_regtest();
    assert_eq!(TxRules::at_height(&p, 0).branch_id, BRANCH_ID_V3);
    assert_eq!(
        TxRules::at_height(&p, ACTIVATION - 1).branch_id,
        BRANCH_ID_V3
    );
    assert_eq!(TxRules::at_height(&p, ACTIVATION).branch_id, NEXT_BRANCH);
    assert_eq!(TxRules::at_height(&p, u64::MAX).branch_id, NEXT_BRANCH);
    let before = TxRules::at_height(&p, ACTIVATION - 1);
    let after = TxRules::at_height(&p, ACTIVATION);
    assert_eq!(
        TxRules {
            branch_id: before.branch_id,
            ..after
        },
        before,
        "the no-op activation changes only the branch id"
    );
}

#[test]
fn for_chain_refuses_a_multi_epoch_schedule() {
    let p = upgrading_regtest();
    let r = std::panic::catch_unwind(|| TxRules::for_chain(&p));
    assert!(r.is_err(), "rules must be built per height");
}

#[test]
fn every_message_and_the_px_binding_commit_to_branch_and_network() {
    let mut net = TestNet::new(21, 80);
    let mut r = rng(22);
    let alice = Wallet::new(&mut r);
    let t = net.pay(&net.miner_clone(), &[(alice.primary(), 1000)]);
    let deploy = PxDeploy {
        inputs: t.inputs.clone(),
        outputs: t.outputs.clone(),
        fee: t.fee,
        salt: [7; 32],
        programs: vec![],
        pseudo_outs: t.pseudo_outs.clone(),
        range_proof: t.range_proof.clone(),
        signatures: t.signatures.clone(),
    };
    let px = empty_px();

    let base = domain(1, BRANCH_ID_V3);
    let other_branch = domain(1, NEXT_BRANCH);
    let other_network = domain(2, BRANCH_ID_V3);
    // Swapping the two ids is a different domain too (fixed-width fields).
    let swapped = domain(BRANCH_ID_V3, 1);
    type Hashes = Vec<[u8; 32]>;
    let hashes = |d: SigDomain| -> Hashes {
        vec![
            t.signature_message(d),
            deploy.signature_message(d),
            px.signature_message(d),
            px.binding(d),
        ]
    };
    let h0 = hashes(base);
    for d in [other_branch, other_network, swapped] {
        let h = hashes(d);
        for (i, (a, b)) in h0.iter().zip(&h).enumerate() {
            assert_ne!(a, b, "hash {i} ignores {d:?}");
        }
    }
    // Deterministic, and the four hashes are distinct from each other.
    assert_eq!(hashes(base), h0);
    for i in 0..h0.len() {
        for j in 0..i {
            assert_ne!(h0[i], h0[j]);
        }
    }
}

/// A no-op activation: a transfer signed under the old branch id is valid
/// before the activation height and invalid from it; the same payment
/// re-signed under the new branch id is the reverse. Checked for mempool
/// validation and for whole blocks.
#[test]
fn transactions_signed_for_the_old_branch_are_invalid_after_activation() {
    let p = upgrading_regtest();
    let old = TxRules::at_height(&p, ACTIVATION - 1);
    let new = TxRules::at_height(&p, ACTIVATION);
    let mut net = TestNet::new(23, 80);
    net.rules = old;
    let mut r = rng(24);
    let alice = Wallet::new(&mut r);

    let old_tx = net.pay(&net.miner_clone(), &[(alice.primary(), 1000)]);
    let h = net.height();
    assert!(h < ACTIVATION);
    assert_eq!(validate_transfer(&old_tx, &net.chain, h, &old), Ok(()));
    assert_eq!(
        validate_transfer(&old_tx, &net.chain, ACTIVATION, &new),
        Err(TxError::InvalidSignature { input: 0 })
    );
    assert!(
        !TxError::InvalidSignature { input: 0 }.is_stateless(),
        "a peer relaying an old-branch transaction near the boundary is not banned"
    );

    // Mine empty blocks, each under the rules of its height, up to the
    // activation.
    while net.height() < ACTIVATION {
        net.rules = TxRules::at_height(&p, net.height());
        net.mine(vec![], &mut []).unwrap();
    }
    assert_eq!(net.height(), ACTIVATION);
    net.rules = TxRules::at_height(&p, ACTIVATION);
    assert_eq!(net.rules, new);

    // The old transaction is refused in the activation block.
    assert!(matches!(
        net.mine(vec![old_tx.clone()], &mut []),
        Err(BlockError::Tx {
            error: TxError::InvalidSignature { input: 0 },
            ..
        })
    ));

    // Re-signed under the new branch: valid now, and it would not have been
    // valid before the activation.
    let new_tx = net.pay(&net.miner_clone(), &[(alice.primary(), 1000)]);
    assert_eq!(
        validate_transfer(&new_tx, &net.chain, ACTIVATION, &new),
        Ok(())
    );
    assert_eq!(
        validate_transfer(&new_tx, &net.chain, ACTIVATION, &old),
        Err(TxError::InvalidSignature { input: 0 })
    );
    net.mine(vec![new_tx], &mut []).unwrap();
}

/// `revalidate_between`: within one epoch it is the extension-only check;
/// across the activation it validates in full, so a pooled transaction of
/// the old branch fails with `InvalidSignature` (which the extension-only
/// check would miss).
#[test]
fn revalidation_across_the_activation_is_a_full_validation() {
    use blacksilk_tx::validate::{revalidate_after_extension, revalidate_between};
    use blacksilk_tx::Transaction;
    let p = upgrading_regtest();
    let old = TxRules::at_height(&p, ACTIVATION - 1);
    let new = TxRules::at_height(&p, ACTIVATION);
    let mut net = TestNet::new(25, 80);
    net.rules = old;
    let mut r = rng(26);
    let alice = Wallet::new(&mut r);
    let tx = Transaction::from(net.pay(&net.miner_clone(), &[(alice.primary(), 1000)]));
    let h = net.height();
    // Same epoch: the extension check, which passes.
    assert_eq!(revalidate_between(&tx, &net.chain, h, &old, &old), Ok(()));
    // The extension-only check cannot see the new branch id...
    assert_eq!(revalidate_after_extension(&tx, &net.chain), Ok(()));
    // ...the cross-activation one does.
    assert_eq!(
        revalidate_between(&tx, &net.chain, ACTIVATION, &old, &new),
        Err(TxError::InvalidSignature { input: 0 })
    );
}

/// The grace window: a `PxProof` failure is contextual within
/// `ACTIVATION_GRACE_BLOCKS` of an activation (either side) and stateless
/// elsewhere; with the built-in one-epoch schedules it is always stateless.
#[test]
fn px_proof_failures_are_contextual_near_an_activation() {
    use blacksilk_tx::validate::{near_activation, ACTIVATION_GRACE_BLOCKS as N};
    let p = upgrading_regtest();
    let e = TxError::PxProof;
    assert!(e.is_stateless());
    for (h, near) in [
        (0, false),
        (ACTIVATION - N - 1, false),
        (ACTIVATION - N, true),
        (ACTIVATION - 1, true),
        (ACTIVATION, true),
        (ACTIVATION + N - 1, true),
        (ACTIVATION + N, false),
        (u64::MAX, false),
    ] {
        assert_eq!(near_activation(&p, h), near, "height {h}");
        assert_eq!(e.is_stateless_at(&p, h), !near, "height {h}");
    }
    // Other failures keep their class.
    assert!(TxError::PxShape.is_stateless_at(&p, ACTIVATION));
    assert!(!TxError::PxUnknownAnchor.is_stateless_at(&p, 0));
    for n in [Network::Mainnet, Network::Testnet, Network::Regtest] {
        let q = ChainParams::for_network(n);
        for h in [0, 1, 1_000, u64::MAX] {
            assert!(!near_activation(&q, h));
            assert!(e.is_stateless_at(&q, h));
        }
    }
}
