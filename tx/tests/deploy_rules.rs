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

// ------------------------------------------------------------------ px-deploy-row-caps

use blacksilk_px::prove::kernel_budget;
use blacksilk_px_core::call::MAX_FN;
use blacksilk_tx::params::{
    PX_FN_LOG_CYCLES, PX_FN_LOG_IMAGE, PX_FN_LOG_KEYS, PX_FN_LOG_PROGRAM, PX_LOG_ADD, PX_LOG_BIT,
    PX_LOG_LT, PX_LOG_MUL, PX_LOG_POSEIDON, PX_LOG_SHIFT,
};
use blacksilk_tx::px::{budget_is_provable, program_is_provable};

/// The largest value a shared field may take: `K.x + MAX_FN·b.x ≤ 2^log`.
fn shared_max(kx: usize, log: u32) -> usize {
    ((1usize << log) - kx) / MAX_FN
}

/// Every budget field at its largest allowed value (record
/// `px-deploy-row-caps`), computed here from the caps and the kernel budget,
/// independently of `budget_is_provable`.
fn largest_allowed() -> Budget {
    let k = kernel_budget(MAX_FN);
    Budget {
        cycles: 1 << PX_FN_LOG_CYCLES,
        keys: 1 << PX_FN_LOG_KEYS,
        add: shared_max(k.add, PX_LOG_ADD),
        bit: shared_max(k.bit, PX_LOG_BIT),
        lt: shared_max(k.lt, PX_LOG_LT),
        shift: shared_max(k.shift, PX_LOG_SHIFT),
        mul: shared_max(k.mul, PX_LOG_MUL),
        poseidon: shared_max(k.poseidon, PX_LOG_POSEIDON),
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

/// The per-function maxima of the B2 research (V12), pinned: a cap or
/// kernel-budget change shows up here. The vault fits with room on every
/// field.
#[test]
fn the_largest_allowed_budget_is_the_v12_table() {
    let top = largest_allowed();
    assert_eq!(
        [
            top.cycles,
            top.keys,
            top.add,
            top.bit,
            top.lt,
            top.shift,
            top.mul,
            top.poseidon
        ],
        [32_768, 16_384, 20_168, 7_192, 22_493, 7_367, 7_367, 948]
    );
    for (name, field) in FIELDS {
        let (mut a, mut b) = (VAULT_BUDGET, top);
        assert!(*field(&mut a) < *field(&mut b), "vault {name}");
    }
}

#[test]
fn allowed_budget_boundaries() {
    let top = largest_allowed();
    assert!(budget_is_provable(&top), "every field at its cap");
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
        assert!(!budget_is_provable(&b), "{name} one above its cap");
        *field(&mut b) = usize::MAX;
        assert!(
            !budget_is_provable(&b),
            "{name} at usize::MAX (checked arithmetic)"
        );
        *field(&mut b) = usize::MAX / MAX_FN + 1;
        assert!(!budget_is_provable(&b), "{name}: MAX_FN·b.x overflows");
    }
    // Poseidon: 151 + 2·948 = 2,047 ≤ 2^11; 151 + 2·949 = 2,049.
    assert_eq!(kernel_budget(MAX_FN).poseidon, 151);
    let with = |p| Budget {
        poseidon: p,
        ..VAULT_BUDGET
    };
    assert!(budget_is_provable(&with(948)));
    assert!(!budget_is_provable(&with(949)));
}

#[test]
fn a_deploy_at_the_caps_is_valid_and_one_above_is_rejected() {
    let mut net = TestNet::new(34, 80);
    let d = deploy(&mut net, vec![vault()]);
    let top = largest_allowed();
    assert_eq!(
        check_after(&net, &d, |x| x.programs[0].budget = top),
        Ok(()),
        "every field at its cap"
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
            "{name} one above its cap"
        );
    }
    assert!(TxError::PxBudgetTooLarge { program: 0 }.is_stateless());
}

/// A minimal RV32I executable: `n` instructions `addi x0, x0, 0` loaded at
/// 0x10000, entry at the first. Different `n` give different program ids.
fn nop_elf(n: usize) -> Vec<u8> {
    let base: u32 = 0x1_0000;
    let code = 4 * n as u32;
    let mut e = vec![0u8; 84];
    e[..4].copy_from_slice(b"\x7fELF");
    e[4] = 1; // 32-bit
    e[5] = 1; // little-endian
    e[6] = 1; // version
    e[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    e[18..20].copy_from_slice(&243u16.to_le_bytes()); // EM_RISCV
    e[20..24].copy_from_slice(&1u32.to_le_bytes());
    e[24..28].copy_from_slice(&base.to_le_bytes()); // entry
    e[28..32].copy_from_slice(&52u32.to_le_bytes()); // phoff
    e[40..42].copy_from_slice(&52u16.to_le_bytes()); // ehsize
    e[42..44].copy_from_slice(&32u16.to_le_bytes()); // phentsize
    e[44..46].copy_from_slice(&1u16.to_le_bytes()); // phnum
    let ph = 52;
    e[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    e[ph + 4..ph + 8].copy_from_slice(&84u32.to_le_bytes()); // offset
    e[ph + 8..ph + 12].copy_from_slice(&base.to_le_bytes()); // vaddr
    e[ph + 12..ph + 16].copy_from_slice(&base.to_le_bytes()); // paddr
    e[ph + 16..ph + 20].copy_from_slice(&code.to_le_bytes()); // filesz
    e[ph + 20..ph + 24].copy_from_slice(&code.to_le_bytes()); // memsz
    e[ph + 24..ph + 28].copy_from_slice(&5u32.to_le_bytes()); // R | X
    e[ph + 28..ph + 32].copy_from_slice(&4u32.to_le_bytes());
    for _ in 0..n {
        e.extend_from_slice(&0x0000_0013u32.to_le_bytes());
    }
    e
}

/// The program and image caps, with synthetic programs. The image holds
/// every code word plus the 32 registers, so the image cap (2^14) binds
/// before the program-table cap: 2^14 − 32 instructions are the most a
/// program without data may have.
#[test]
fn program_and_image_caps() {
    use blacksilk_zkvm::air::{program, trace, MIN_HEIGHT};
    assert_eq!((PX_FN_LOG_PROGRAM, PX_FN_LOG_IMAGE), (14, 14));
    let load = |n: usize| Program::from_elf(&nop_elf(n)).expect("the synthetic ELF loads");
    let image = |p: &Program| trace::image(p).len();
    let largest = load((1 << 14) - 32);
    assert_eq!(image(&largest), 1 << 14);
    assert_eq!(program::height(&largest, MIN_HEIGHT), 1 << 14);
    assert!(program_is_provable(&largest));
    let image_over = load((1 << 14) - 31);
    assert_eq!(image(&image_over), (1 << 14) + 1);
    assert_eq!(program::height(&image_over, MIN_HEIGHT), 1 << 14);
    assert!(!program_is_provable(&image_over), "image 2^14 + 1");
    let height_over = load((1 << 14) + 1);
    assert_eq!(program::height(&height_over, MIN_HEIGHT), 1 << 15);
    assert!(!program_is_provable(&height_over), "program height 2^15");
    assert!(program_is_provable(&Program::from_elf(VAULT_ELF).unwrap()));
    assert!(program_is_provable(
        &Program::from_elf(&other_elf()).unwrap()
    ));

    // In a deploy: accepted at the cap, refused with its index above it.
    let mut net = TestNet::new(39, 80);
    let d = deploy(&mut net, vec![vault()]);
    let reg = |n: usize| Registration {
        elf: nop_elf(n),
        budget: VAULT_BUDGET,
        abi: blacksilk_tx::px::ABI_VERSION,
        out_words: 1,
    };
    assert_eq!(
        check_after(&net, &d, |x| x.programs.push(reg((1 << 14) - 32))),
        Ok(())
    );
    for n in [(1 << 14) - 31, (1 << 14) + 1] {
        assert_eq!(
            check_after(&net, &d, |x| x.programs.push(reg(n))),
            Err(TxError::PxProgramTooLarge { program: 1 }),
            "{n} instructions"
        );
    }
    assert!(TxError::PxProgramTooLarge { program: 0 }.is_stateless());
}

/// Any `MAX_FN` registered functions fit together with the kernel: for
/// random allowed budgets (half the fields at their caps) and programs at
/// the caps, every table of the statement (`Statement::shape`, the heights
/// the verifier checks) is at most 2^16 rows, each function's own tables are
/// within their caps, and the shared tables within theirs. No proving.
#[test]
fn any_pair_of_allowed_functions_has_every_table_within_its_cap() {
    use blacksilk_zkvm::air::trace::{Part, Statement};
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use std::sync::Arc;
    assert_eq!(MAX_FN, 2);
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xB2);
    let top = largest_allowed();
    let kernel = blacksilk_px::prove::kernel_program();
    let fns = [
        Arc::new(Program::from_elf(&nop_elf((1 << 14) - 32)).unwrap()),
        Arc::new(Program::from_elf(VAULT_ELF).unwrap()),
    ];
    let random = |rng: &mut rand_chacha::ChaCha20Rng| {
        let mut b = top;
        for (_, field) in FIELDS {
            let max = *field(&mut b);
            *field(&mut b) = if rng.next_u32().is_multiple_of(2) {
                max
            } else {
                (rng.next_u64() % (max as u64 + 1)) as usize
            };
        }
        assert!(budget_is_provable(&b));
        b
    };
    for i in 0..2_000 {
        let budgets = [random(&mut rng), random(&mut rng)];
        let part = |k: usize| Part {
            program: fns[(i + k) % 2].clone(),
            exit_code: 0,
            output: vec![0; blacksilk_tx::params::MAX_FN_OUTPUT_WORDS],
            budget: Some(budgets[k]),
        };
        let st = Statement {
            program: kernel.clone(),
            exit_code: 0,
            output: vec![0; 512],
            binding: [0; 32],
            others: vec![part(0), part(1)],
            budget: Some(kernel_budget(MAX_FN)),
        };
        let shape = st.shape().expect("every execution has a budget");
        assert!(
            shape.iter().all(|&h| h <= 1 << 16),
            "{budgets:?}: {shape:?}"
        );
        // Each function's own tables: program, image, keys, cycles, output.
        for k in 0..2 {
            let own = &shape[12 + 5 * k..12 + 5 * k + 5];
            assert!(own[0] <= 1 << PX_FN_LOG_PROGRAM && own[1] <= 1 << PX_FN_LOG_IMAGE);
            assert!(own[2] <= 1 << PX_FN_LOG_KEYS && own[3] <= 1 << PX_FN_LOG_CYCLES);
        }
        // The shared tables (add, bit, lt, shift, mul; Poseidon2).
        let caps = [PX_LOG_ADD, PX_LOG_BIT, PX_LOG_LT, PX_LOG_SHIFT, PX_LOG_MUL];
        for (j, log) in caps.into_iter().enumerate() {
            assert!(shape[5 + j] <= 1 << log, "shared table {j}: {shape:?}");
        }
        assert!(shape[11] <= 1 << PX_LOG_POSEIDON, "poseidon: {shape:?}");
    }
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
