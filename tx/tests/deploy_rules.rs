//! Stateless deploy rules of the v3 candidate
//! (docs/reviews/v3-upgrade-mechanism.md §5 to §7).
//!
//! `check_deploy_structure` does not check signatures, so the tests change a
//! valid deploy's payload directly and re-check only the structure.

mod common;

use blacksilk_tx::builder::Payment;
use blacksilk_tx::px::{check_deploy_structure, PxDeploy, Registration};
use blacksilk_tx::px_builder::build_deploy;
use blacksilk_tx::validate::{validate_mempool_tx, TxError};
use blacksilk_tx::Transaction;
use blacksilk_zkvm::air::trace::Budget;
use blacksilk_zkvm::Program;
use common::*;

const VAULT_ELF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../px/vault.elf"));
const VAULT_BUDGET: Budget = Budget {
    cycles: 6_000,
    keys: 2_200,
    add: 4_300,
    bit: 200,
    lt: 3_400,
    shift: 200,
    mul: 200,
    poseidon: 22,
};

fn vault() -> Registration {
    Registration {
        elf: VAULT_ELF.to_vec(),
        budget: VAULT_BUDGET,
    }
}

/// A valid, signed deploy of `programs` from the miner's first coinbase.
fn deploy(net: &mut TestNet, programs: Vec<Registration>) -> PxDeploy {
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
        programs,
        &rules,
        &mut net.rng,
    )
    .expect("deploy builds")
}

/// Re-checks the structure of `d` after `f`, with the fee the rules require
/// for the changed payload (so that only the rule under test can fail).
fn check_after(net: &TestNet, d: &PxDeploy, f: impl Fn(&mut PxDeploy)) -> Result<(), TxError> {
    let mut x = d.clone();
    f(&mut x);
    x.fee = 2 * x.min_fee();
    check_deploy_structure(&x, &net.rules)
}

// ------------------------------------------------------------------ R5-7

#[test]
fn a_deploy_of_distinct_programs_is_valid() {
    let mut net = TestNet::new(31, 80);
    let d = deploy(&mut net, vec![vault()]);
    assert_eq!(check_deploy_structure(&d, &net.rules), Ok(()));
    let h = net.height();
    assert_eq!(
        validate_mempool_tx(
            &Transaction::PxDeploy(Box::new(d)),
            &net.chain,
            h,
            &net.rules
        ),
        Ok(())
    );
}

#[test]
fn a_repeated_program_is_rejected_whatever_its_budget() {
    let mut net = TestNet::new(32, 80);
    let d = deploy(&mut net, vec![vault()]);
    assert_eq!(check_after(&net, &d, |_| {}), Ok(()), "control");
    // The same program with the same budget, and with another budget.
    for budget in [
        VAULT_BUDGET,
        Budget {
            cycles: 7_000,
            ..VAULT_BUDGET
        },
    ] {
        let e = check_after(&net, &d, |x| {
            x.programs.push(Registration {
                elf: VAULT_ELF.to_vec(),
                budget,
            })
        });
        assert_eq!(e, Err(TxError::PxDuplicateProgram { program: 1 }));
        assert!(TxError::PxDuplicateProgram { program: 1 }.is_stateless());
    }
}

/// Different ELF bytes that load to the same program are the same program:
/// the rule compares loaded program ids, not binaries.
#[test]
fn a_repeated_program_in_other_elf_bytes_is_rejected() {
    let mut padded = VAULT_ELF.to_vec();
    padded.extend_from_slice(&[0; 16]);
    assert_ne!(padded, VAULT_ELF);
    assert_eq!(
        Program::from_elf(&padded).unwrap().id(),
        Program::from_elf(VAULT_ELF).unwrap().id(),
        "trailing bytes are not part of the loaded program"
    );
    let mut net = TestNet::new(33, 80);
    let d = deploy(&mut net, vec![vault()]);
    let e = check_after(&net, &d, |x| {
        x.programs.insert(
            0,
            Registration {
                elf: padded.clone(),
                budget: VAULT_BUDGET,
            },
        )
    });
    assert_eq!(e, Err(TxError::PxDuplicateProgram { program: 1 }));
}
