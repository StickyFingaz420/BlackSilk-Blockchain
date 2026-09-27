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

// ------------------------------------------------------------------ R7-5

const MAX_ROWS: usize = 1 << blacksilk_zk::params::MAX_LOG_HEIGHT;

/// Every budget field at its largest provable value, with the kernel's share
/// of the shared tables (`kernel_budget(1)`) subtracted.
fn largest_provable() -> Budget {
    let k = blacksilk_px::prove::kernel_budget(1);
    Budget {
        cycles: blacksilk_zkvm::MAX_CYCLES as usize,
        keys: MAX_ROWS,
        add: MAX_ROWS - k.add,
        bit: MAX_ROWS - k.bit,
        lt: MAX_ROWS - k.lt,
        shift: MAX_ROWS - k.shift,
        mul: MAX_ROWS - k.mul,
        poseidon: MAX_ROWS - k.poseidon,
    }
}

type Field = (&'static str, fn(&mut Budget) -> &mut usize);

const FIELDS: [Field; 8] = [
    ("cycles", |b| &mut b.cycles),
    ("keys", |b| &mut b.keys),
    ("add", |b| &mut b.add),
    ("bit", |b| &mut b.bit),
    ("lt", |b| &mut b.lt),
    ("shift", |b| &mut b.shift),
    ("mul", |b| &mut b.mul),
    ("poseidon", |b| &mut b.poseidon),
];

#[test]
fn provable_budget_boundaries() {
    use blacksilk_tx::px::budget_is_provable;
    assert_eq!(blacksilk_zkvm::MAX_CYCLES, 1 << 21);
    assert_eq!(MAX_ROWS, 1 << 22);
    let top = largest_provable();
    assert!(budget_is_provable(&top));
    assert!(budget_is_provable(&VAULT_BUDGET));
    assert!(budget_is_provable(&Budget {
        cycles: 0,
        keys: 0,
        add: 0,
        bit: 0,
        lt: 0,
        shift: 0,
        mul: 0,
        poseidon: 0,
    }));
    for (name, field) in FIELDS {
        let mut b = top;
        *field(&mut b) += 1;
        assert!(!budget_is_provable(&b), "{name} one above its limit");
        *field(&mut b) = usize::MAX;
        assert!(
            !budget_is_provable(&b),
            "{name} at usize::MAX (no overflow)"
        );
    }
}

#[test]
fn a_deploy_at_the_limits_is_valid_and_one_above_is_rejected() {
    let mut net = TestNet::new(34, 80);
    let d = deploy(&mut net, vec![vault()]);
    let top = largest_provable();
    assert_eq!(
        check_after(&net, &d, |x| x.programs[0].budget = top),
        Ok(()),
        "every field at its limit"
    );
    for (name, field) in FIELDS {
        let e = check_after(&net, &d, |x| {
            let mut b = top;
            *field(&mut b) += 1;
            // A valid program first, so the index is checked too.
            x.programs.push(Registration {
                elf: other_elf(),
                budget: b,
            });
        });
        assert_eq!(
            e,
            Err(TxError::PxBudgetTooLarge { program: 1 }),
            "{name} one above its limit"
        );
    }
    assert!(TxError::PxBudgetTooLarge { program: 0 }.is_stateless());
}

/// A second program that loads to another id than the vault: the kernel.
fn other_elf() -> Vec<u8> {
    blacksilk_px::prove::KERNEL_ELF.to_vec()
}
