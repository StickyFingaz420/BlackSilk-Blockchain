//! ALU tables in isolation (docs/zkvm.md §9 items 2–3, 5).
//!
//! A `Driver` table stands in for the CPU: each real row requests one
//! `(op, a, b, c)` on the ALU bus. The ALU tables must provide exactly the
//! correct results; the byte table must balance all range and byte-op lookups.

use blacksilk_zk::config::{ProverConfig, Val, VerifierConfig};
use blacksilk_zkvm::air::byte::ByteCounter;
use blacksilk_zkvm::air::check::{check, MutationChecker, Violation};
use blacksilk_zkvm::air::trace::{blind_trace, with_blinding};
use blacksilk_zkvm::air::util::{alu_op, bytes, matrix, row, ALU, BLIND};
use blacksilk_zkvm::air::{alu_add, alu_bit, alu_lt, alu_mul, alu_shift, Table, MIN_HEIGHT};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use rand_chacha::rand_core::SeedableRng;

#[derive(Clone, Debug)]
enum T {
    Core(Table),
    Driver,
    /// Provides extra 8-element messages (from the driver's tuples) on the
    /// **blinding** bus: an attempt to absorb a false ALU claim there.
    Rogue,
}

const DRIVER_WIDTH: usize = 14;
const ROGUE_WIDTH: usize = 9;

impl BaseAir<Val> for T {
    fn width(&self) -> usize {
        match self {
            T::Core(t) => t.width(),
            T::Driver => DRIVER_WIDTH,
            T::Rogue => ROGUE_WIDTH,
        }
    }
    fn num_periodic_columns(&self) -> usize {
        match self {
            T::Core(t) => t.num_periodic_columns(),
            T::Driver | T::Rogue => 0,
        }
    }
    fn periodic_columns(&self) -> std::borrow::Cow<'_, [Vec<Val>]> {
        match self {
            T::Core(t) => t.periodic_columns(),
            T::Driver | T::Rogue => std::borrow::Cow::Owned(Vec::new()),
        }
    }
}

impl<AB: AirBuilder<F = Val> + InteractionBuilder> Air<AB> for T {
    fn eval(&self, b: &mut AB) {
        match self {
            T::Core(t) => t.eval(b),
            T::Driver => {
                let (r, _) = row(b);
                let real = r[13].clone();
                b.assert_bool(real.clone());
                ALU.lookup_key(b, r[..13].to_vec(), Count::bounded(real, 1));
            }
            T::Rogue => {
                let (r, _) = row(b);
                let real = r[8].clone();
                b.assert_bool(real.clone());
                BLIND.table_entry(b, r[..8].to_vec(), real);
            }
        }
    }
}

const EDGE: [u32; 12] = [
    0,
    1,
    2,
    31,
    33,
    0x7f,
    0x80,
    0xff,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_fffe,
    0xffff_ffff,
];

fn reference(op: u32, a: u32, b: u32) -> u32 {
    match op {
        alu_op::ADD => a.wrapping_add(b),
        alu_op::SUB => a.wrapping_sub(b),
        alu_op::XOR => a ^ b,
        alu_op::OR => a | b,
        alu_op::AND => a & b,
        alu_op::SLL | alu_op::SRL | alu_op::SRA => alu_shift::result(op, a, b),
        alu_op::MUL | alu_op::MULH | alu_op::MULHSU | alu_op::MULHU => alu_mul::result(op, a, b),
        _ => alu_lt::result(op, a, b),
    }
}

/// Builds all traces for `reqs`; `lie` optionally replaces the claimed
/// result of one driver row.
fn build(
    reqs: &[(u32, u32, u32)],
    lie: Option<(usize, u32)>,
) -> (Vec<T>, Vec<RowMajorMatrix<Val>>) {
    let mut counter = ByteCounter::new();
    let by = |set: &[u32]| -> Vec<(u32, u32, u32)> {
        reqs.iter()
            .copied()
            .filter(|r| set.contains(&r.0))
            .collect()
    };
    let add = alu_add::trace(&by(&[alu_op::ADD, alu_op::SUB]), &mut counter, MIN_HEIGHT);
    let bit = alu_bit::trace(
        &by(&[alu_op::XOR, alu_op::OR, alu_op::AND]),
        &mut counter,
        MIN_HEIGHT,
    );
    let lt = alu_lt::trace(
        &by(&[alu_op::SLT, alu_op::SLTU, alu_op::EQ]),
        &mut counter,
        MIN_HEIGHT,
    );
    let mut mul_reqs = by(&[alu_op::MUL, alu_op::MULH, alu_op::MULHSU, alu_op::MULHU]);
    let shift = alu_shift::trace(
        &by(&[alu_op::SLL, alu_op::SRL, alu_op::SRA]),
        &mut counter,
        MIN_HEIGHT,
        &mut mul_reqs,
    );
    let mul = alu_mul::trace(&mul_reqs, &mut counter, MIN_HEIGHT);
    let driver_rows = reqs
        .iter()
        .enumerate()
        .map(|(i, &(op, a, b))| {
            let mut cv = reference(op, a, b);
            if let Some((j, v)) = lie {
                if i == j {
                    cv = v;
                }
            }
            let mut r = vec![Val::from_u32(op)];
            r.extend(bytes(a));
            r.extend(bytes(b));
            r.extend(bytes(cv));
            r.push(Val::ONE);
            r
        })
        .collect();
    let driver = matrix(driver_rows, DRIVER_WIDTH, MIN_HEIGHT);
    (
        vec![
            T::Core(Table::Byte),
            T::Core(Table::AluAdd),
            T::Core(Table::AluBit),
            T::Core(Table::AluLt),
            T::Core(Table::AluShift),
            T::Core(Table::AluMul),
            T::Driver,
            T::Core(Table::Blind),
        ],
        // The core tables carry blinding columns; the test driver does not.
        vec![
            with_blinding(blacksilk_zkvm::air::with_public_columns(
                &Table::Byte,
                counter.trace(),
            )),
            with_blinding(add),
            with_blinding(bit),
            with_blinding(lt),
            with_blinding(shift),
            with_blinding(mul),
            driver,
            blind_trace(6),
        ],
    )
}

fn requests() -> Vec<(u32, u32, u32)> {
    let ops = [
        alu_op::ADD,
        alu_op::SUB,
        alu_op::XOR,
        alu_op::OR,
        alu_op::AND,
        alu_op::SLT,
        alu_op::SLTU,
        alu_op::EQ,
        alu_op::SLL,
        alu_op::SRL,
        alu_op::SRA,
        alu_op::MUL,
        alu_op::MULH,
        alu_op::MULHSU,
        alu_op::MULHU,
    ];
    let mut v = Vec::new();
    for op in ops {
        for a in EDGE {
            for b in EDGE {
                v.push((op, a, b));
            }
        }
    }
    v
}

fn empty_public(n: usize) -> Vec<Vec<Val>> {
    vec![vec![]; n]
}

#[test]
fn honest_alu_traces_satisfy_every_constraint() {
    let (airs, traces) = build(&requests(), None);
    assert_eq!(check(&airs, &traces, &empty_public(airs.len())), vec![]);
}

#[test]
fn a_false_alu_claim_leaves_the_bus_unbalanced() {
    let reqs = requests();
    for (i, lie) in [
        (0usize, 3u32),
        (150, 1),
        (700, 0),
        (1300, 5),
        (1700, 0),
        (reqs.len() - 1, 1),
    ] {
        // Skip lies that happen to be the truth.
        if reference(reqs[i].0, reqs[i].1, reqs[i].2) == lie {
            continue;
        }
        let (airs, traces) = build(&reqs, Some((i, lie)));
        let v = check(&airs, &traces, &empty_public(airs.len()));
        assert!(
            v.iter()
                .any(|x| matches!(x, Violation::Unbalanced { bus, .. } if bus == "bvm/alu")),
            "lie at request {i} accepted: {v:?}"
        );
    }
}

/// Mutation testing: every cell of every real row of each ALU table, changed
/// by +1, must produce a violation. Known free witness cells (the inverse
/// columns of `ALU_LT` and `ALU_SHIFT` when their operand is zero) are listed
/// explicitly.
#[test]
fn every_single_cell_mutation_of_a_real_alu_row_is_caught() {
    let reqs = requests();
    let (airs, traces) = build(&reqs, None);
    let public = empty_public(airs.len());
    let mut m = MutationChecker::new(&airs, &traces, &public);
    let mut accepted = Vec::new();
    let mut tried = 0;
    // (table, number of leading flag columns)
    for (t, flags) in [(1usize, 2usize), (2, 3), (3, 3), (4, 3), (5, 4)] {
        let tr = &traces[t];
        let w = tr.width;
        let real_rows: Vec<usize> = (0..tr.values.len() / w)
            .filter(|&r| {
                tr.values[r * w..r * w + flags]
                    .iter()
                    .any(|x| *x != Val::ZERO)
            })
            .collect();
        for r in real_rows {
            for col in 0..w {
                // ALU_LT column 23 is the inverse witness; it is free when
                // d = 0 (z = 1 regardless), which does not affect the result.
                if t == 3 && col == 23 {
                    let d_sum: Val = (11..15).map(|i| tr.values[r * w + i]).sum();
                    if d_sum == Val::ZERO {
                        continue;
                    }
                }
                // ALU_SHIFT column 33 is the inverse of s; it is free when
                // s = 0 (z = 1, c = a, no product is requested).
                if t == 4 && col == 33 && tr.values[r * w + 21] == Val::ONE {
                    continue;
                }
                for delta in [Val::ONE, Val::from_u32(256), -Val::ONE] {
                    tried += 1;
                    if !m.caught(t, r, col, delta) {
                        accepted.push((t, r, col));
                    }
                }
            }
        }
    }
    assert!(
        accepted.is_empty(),
        "under-constrained cells (table, row, column): {accepted:?}"
    );
    println!("{tried} mutations, all caught");
}

#[test]
fn byte_table_multiplicities_must_match() {
    let (airs, mut traces) = build(&requests(), None);
    let w = traces[0].width;
    traces[0].values[5 * w] += Val::ONE; // range multiplicity of pair (0, 5)
    assert!(!check(&airs, &traces, &empty_public(airs.len())).is_empty());
}

#[test]
fn alu_tables_prove_and_verify() {
    let reqs: Vec<_> = requests().into_iter().step_by(3).collect();
    let (airs, traces) = build(&reqs, None);
    let public = empty_public(airs.len());
    let limits = vec![16; airs.len()];
    // Bind the public byte table (a periodic column) into the transcript.
    let digest = blacksilk_zkvm::prove::statement_digest(&[Table::Byte]);
    let cfg = ProverConfig::for_statement(
        &digest,
        &[9; 32],
        &mut rand_chacha::ChaCha20Rng::seed_from_u64(9),
    );
    let proof = blacksilk_zk::prove(&cfg, &airs, &traces, &public, &limits).expect("proves");
    let bytes_len = blacksilk_zk::encode_proof(&proof).len();
    println!("ALU proof: {bytes_len} bytes");
    assert_eq!(
        blacksilk_zk::verify(
            &VerifierConfig::for_statement(&digest),
            &airs,
            &proof,
            &public,
            &limits
        ),
        Ok(())
    );
}

/// A false ALU claim cannot be absorbed through the blinding bus: a rogue
/// table adds well-formed (8-element) provisions on it. Every table's local
/// constraints hold; only the ALU and blinding buses are unbalanced, and they
/// have distinct offsets, so the release prover produces a proof that the
/// verifier rejects on the terminal sum.
#[test]
fn a_blinding_bus_message_cannot_stand_in_for_an_alu_result() {
    use p3_matrix::Matrix;
    let reqs: Vec<_> = requests().into_iter().step_by(3).collect();
    let lie = (0usize, 12345u32);
    let (mut airs, mut traces) = build(&reqs, Some(lie));
    let driver = traces[6].clone();
    let rows: Vec<Vec<Val>> = (0..driver.height())
        .map(|r| {
            let d = &driver.values[r * DRIVER_WIDTH..(r + 1) * DRIVER_WIDTH];
            let mut v = d[..8].to_vec();
            v.push(d[13]); // real
            v
        })
        .collect();
    airs.push(T::Rogue);
    traces.push(matrix(rows, ROGUE_WIDTH, MIN_HEIGHT));
    let public = empty_public(airs.len());
    let v = check(&airs, &traces, &public);
    assert!(!v.is_empty());
    assert!(
        v.iter().all(|x| matches!(x, Violation::Unbalanced { .. })),
        "only bus balances fail: {v:?}"
    );
    let limits = vec![16; airs.len()];
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(77);
    let cfg = ProverConfig::for_statement(&[0; 32], &[0; 32], &mut rng);
    let proof = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        blacksilk_zk::prove(&cfg, &airs, &traces, &public, &limits)
    }));
    if cfg!(debug_assertions) {
        assert!(!matches!(proof, Ok(Ok(_))), "debug prover accepted it");
        return;
    }
    let p = proof
        .expect("the release prover does not check balances")
        .expect("a proof is produced");
    let v = VerifierConfig::for_statement(&[0; 32]);
    let err = blacksilk_zk::verify(&v, &airs, &p, &public, &limits)
        .expect_err("a proof absorbing a false claim through the blinding bus verified");
    assert!(format!("{err:?}").contains("TerminalSum"), "got {err:?}");
}
