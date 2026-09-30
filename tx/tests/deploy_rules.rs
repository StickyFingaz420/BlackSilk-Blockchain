//! Stateless deploy rules of the v3 candidate
//! (docs/reviews/v3-upgrade-mechanism.md §5 to §7).
//!
//! `check_deploy_structure` does not check signatures, so the tests change a
//! valid deploy's payload directly and re-check only the structure.

mod common;

use blacksilk_tx::builder::{max_weight, standard_fee, Payment};
use blacksilk_tx::params::{
    DEPLOY_FEE_PER_BYTE, FEE_PER_WEIGHT, MAX_DEPLOY_BLOCK_BYTES, MAX_PROGRAM_BYTES, PX_FEE_PER_BYTE,
};
use blacksilk_tx::px::{check_deploy_structure, deploy_fee, PxDeploy, Registration};
use blacksilk_tx::px_builder::build_deploy;
use blacksilk_tx::validate::{validate_mempool_tx, TxError};
use blacksilk_tx::Transaction;
use blacksilk_zkvm::air::trace::Budget;
use blacksilk_zkvm::Program;
use common::*;

const VAULT_ELF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../px/vault.elf"));
const VAULT_BUDGET: Budget = blacksilk_px::vault::BUDGET;

fn vault() -> Registration {
    Registration {
        elf: VAULT_ELF.to_vec(),
        budget: VAULT_BUDGET,
        abi: blacksilk_tx::px::ABI_VERSION,
        out_words: 1,
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
    x.fee = x.required_fee(&net.rules);
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
                abi: blacksilk_tx::px::ABI_VERSION,
                out_words: 1,
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
                abi: blacksilk_tx::px::ABI_VERSION,
                out_words: 1,
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
                abi: blacksilk_tx::px::ABI_VERSION,
                out_words: 1,
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

// ------------------------------------------------------------------ R5-1, R6 TX-4

/// The varint length of `v` (LEB128).
fn varint_len(mut v: u64) -> u64 {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

/// The fee formula written out independently of `px::deploy_fee`.
fn expected_fee(inputs: usize, outputs: usize, programs: &[Registration]) -> u64 {
    let mut payload = 32 + varint_len(programs.len() as u64);
    for p in programs {
        let b = p.budget;
        payload += varint_len(p.elf.len() as u64) + p.elf.len() as u64;
        for v in [
            b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
        ] {
            payload += varint_len(v as u64);
        }
        // The call ABI and the output-word count (testnet v3, F-28-1, F-28-5).
        payload += varint_len(p.abi as u64) + varint_len(p.out_words as u64);
    }
    FEE_PER_WEIGHT * max_weight(inputs, outputs) + DEPLOY_FEE_PER_BYTE * payload
}

#[test]
fn the_deploy_fee_is_the_standard_transfer_fee_plus_the_payload_rate() {
    assert_eq!(DEPLOY_FEE_PER_BYTE, 50);
    assert_eq!(MAX_DEPLOY_BLOCK_BYTES, 1024 * 1024);
    let mut net = TestNet::new(35, 80);
    let d = deploy(&mut net, vec![vault()]);
    assert_eq!((d.inputs.len(), d.outputs.len()), (1, 2));
    assert_eq!(d.fee, expected_fee(1, 2, &d.programs));
    assert_eq!(d.fee, d.required_fee(&net.rules));
    assert_eq!(d.fee, deploy_fee(1, 2, &d.programs, &rules()));
    // The transfer part pays exactly what a standard transfer of the shape pays.
    assert_eq!(
        deploy_fee(1, 2, &[], &rules()) - DEPLOY_FEE_PER_BYTE * 33,
        standard_fee(1, 2, &net.rules)
    );
    // Above the pre-v3 minimum (2 per encoded byte), and above the v1 rate
    // for the whole encoded size.
    let size = d.encoded_len() as u64;
    assert!(d.fee >= PX_FEE_PER_BYTE * size);
    assert!(d.fee >= FEE_PER_WEIGHT * size);
    // The vault deploy costs well under 0.01 BLK; a maximal one about 0.52.
    assert!(d.fee < 1_000_000, "{}", d.fee);
    let big = Registration {
        elf: vec![0; MAX_PROGRAM_BYTES],
        budget: VAULT_BUDGET,
        abi: blacksilk_tx::px::ABI_VERSION,
        out_words: 1,
    };
    let four = vec![big.clone(), big.clone(), big.clone(), big];
    let max_fee = deploy_fee(1, 2, &four, &rules());
    assert!((52_000_000..54_000_000).contains(&max_fee), "{max_fee}");
}

#[test]
fn only_the_exact_deploy_fee_is_valid() {
    let mut net = TestNet::new(36, 80);
    let d = deploy(&mut net, vec![vault()]);
    let required = d.required_fee(&net.rules);
    for fee in [0, 1, required - 1, required + 1, 2 * required, u64::MAX] {
        let mut x = d.clone();
        x.fee = fee;
        // The required fee does not depend on the fee (no fixed point).
        assert_eq!(x.required_fee(&net.rules), required);
        assert_eq!(
            check_deploy_structure(&x, &net.rules),
            Err(TxError::DeployFeeNotExact { fee, required }),
            "fee {fee}"
        );
    }
    assert!(TxError::DeployFeeNotExact {
        fee: 0,
        required: 1
    }
    .is_stateless());
}

#[test]
fn the_payload_pays_per_byte_and_the_shape_pays_the_v1_rate() {
    let one = [vault()];
    let two = [
        vault(),
        Registration {
            elf: other_elf(),
            budget: VAULT_BUDGET,
            abi: blacksilk_tx::px::ABI_VERSION,
            out_words: 1,
        },
    ];
    let with = deploy_fee(1, 2, &two, &rules());
    let without = deploy_fee(1, 2, &one, &rules());
    assert_eq!(with, expected_fee(1, 2, &two));
    assert!(with - without > DEPLOY_FEE_PER_BYTE * other_elf().len() as u64);
    for (n, k) in [(1, 2), (2, 2), (1, 16), (64, 16)] {
        assert_eq!(deploy_fee(n, k, &one, &rules()), expected_fee(n, k, &one));
    }
    assert!(deploy_fee(2, 2, &one, &rules()) > deploy_fee(1, 2, &one, &rules()));
    assert!(deploy_fee(1, 3, &one, &rules()) > deploy_fee(1, 2, &one, &rules()));
}

// ------------------------------------------------------------------ R5-1 block rule

/// A valid, signed deploy from the miner's `nth` spendable output.
fn deploy_from(net: &mut TestNet, nth: usize, programs: Vec<Registration>, salt: u8) -> PxDeploy {
    let miner = net.miner_clone();
    let real = miner.spendable(net.height())[nth].clone();
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
        programs,
        &rules,
        &mut net.rng,
    )
    .expect("deploy builds")
}

/// `elf` padded with trailing zeros (ignored by the loader) to the largest
/// program size.
fn padded(elf: &[u8]) -> Registration {
    let mut v = elf.to_vec();
    v.resize(MAX_PROGRAM_BYTES, 0);
    Registration {
        elf: v,
        budget: VAULT_BUDGET,
        abi: blacksilk_tx::px::ABI_VERSION,
        out_words: 1,
    }
}

/// The block's deploy bytes are capped at `MAX_DEPLOY_BLOCK_BYTES`: two
/// valid deploys of two maximal programs each exceed it together, and each
/// fits on its own (`BlockError::DeployBytesExceeded`).
#[test]
fn a_block_over_the_deploy_budget_is_invalid() {
    use blacksilk_tx::validate::validate_block_transactions;
    use blacksilk_tx::BlockError;
    let mut net = TestNet::new(37, 80);
    let programs = || vec![padded(VAULT_ELF), padded(&other_elf())];
    let d0 = deploy_from(&mut net, 0, programs(), 1);
    let d1 = deploy_from(&mut net, 1, programs(), 2);
    let size = |d: &PxDeploy| Transaction::PxDeploy(Box::new(d.clone())).px_bytes();
    assert!(size(&d0) <= MAX_DEPLOY_BLOCK_BYTES);
    assert!(size(&d0) + size(&d1) > MAX_DEPLOY_BLOCK_BYTES);

    let block = |net: &mut TestNet, ds: &[&PxDeploy]| {
        let fees: u64 = ds.iter().map(|d| d.fee).sum();
        let mut txs = vec![net.coinbase(fees)];
        txs.extend(
            ds.iter()
                .map(|d| Transaction::PxDeploy(Box::new((*d).clone()))),
        );
        txs
    };
    let both = block(&mut net, &[&d0, &d1]);
    let ctx = net.context(&both);
    let r = validate_block_transactions(&both, &ctx, &net.chain, &net.rules, &mut net.rng);
    assert_eq!(
        r,
        Err(BlockError::DeployBytesExceeded {
            bytes: size(&d0) + size(&d1),
            max: MAX_DEPLOY_BLOCK_BYTES
        })
    );
    // Either one alone is a valid block.
    let one = block(&mut net, &[&d1]);
    net.submit(one, &mut []).expect("one deploy fits");
}

/// The deploy budget is inclusive: two valid deploys whose encoded bytes sum
/// to exactly `MAX_DEPLOY_BLOCK_BYTES` make a valid block (run C mutation
/// census: no test sat on the bound).
#[test]
fn a_block_of_exactly_the_deploy_budget_is_valid() {
    use blacksilk_tx::validate::validate_block_transactions;
    let mut net = TestNet::new(38, 80);
    let size = |d: &PxDeploy| Transaction::PxDeploy(Box::new(d.clone())).px_bytes();
    let d0 = deploy_from(
        &mut net,
        0,
        vec![padded(VAULT_ELF), padded(&other_elf())],
        1,
    );
    // The second deploy's second program is shortened until the two sum to
    // the budget exactly (its fee and length prefixes are varints, so the
    // size is re-measured after each build).
    let mut len = MAX_PROGRAM_BYTES as i64;
    let mut d1 = None;
    for _ in 0..8 {
        let mut short = padded(&other_elf());
        short.elf.truncate(len as usize);
        let d = deploy_from(&mut net, 1, vec![padded(VAULT_ELF), short], 2);
        let excess = (size(&d0) + size(&d)) as i64 - MAX_DEPLOY_BLOCK_BYTES as i64;
        if excess == 0 {
            d1 = Some(d);
            break;
        }
        len -= excess;
    }
    let d1 = d1.expect("the sizes converge");
    assert_eq!(size(&d0) + size(&d1), MAX_DEPLOY_BLOCK_BYTES);
    let fees = d0.fee + d1.fee;
    let mut txs = vec![net.coinbase(fees)];
    txs.extend([d0, d1].map(|d| Transaction::PxDeploy(Box::new(d))));
    let ctx = net.context(&txs);
    assert_eq!(
        validate_block_transactions(&txs, &ctx, &net.chain, &net.rules, &mut net.rng),
        Ok(())
    );
}
