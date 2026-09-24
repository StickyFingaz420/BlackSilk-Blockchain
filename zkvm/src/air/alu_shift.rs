//! `ALU_SHIFT`: SLL, SRL, SRA, reduced to the multiplier (zkvm.md §6.1).
//!
//! For a shift amount `s` (the low five bits of `b`, as RISC-V specifies):
//!
//! ```text
//! SLL(a, s) = MUL(a, 2^s)                      (low 32 bits of the product)
//! SRL(a, s) = MULHU(a, 2^(32−s))   for s ≥ 1    (high 32 bits, unsigned)
//! SRA(a, s) = MULHSU(a, 2^(32−s))  for s ≥ 1    (high 32 bits, a signed)
//! s = 0:      c = a
//! ```
//!
//! The row proves the power of two `P = 2^e` as bytes: with
//! `e = e_lo + 8·e_hi` (`e_lo` three bits, `e_hi` one-hot over four flags),
//! byte `k` of `P` is `[k = e_hi] · 2^e_lo`, and
//! `2^e_lo = Q·(1 + 15·el2)` with the committed `Q = (1 + el0)(1 + 3·el1)`
//! (keeping every constraint at degree ≤ 3). `z = [s = 0]` is proven with an
//! inverse witness: `z·s = 0` and `s·inv = real − z`. The product itself is proven by
//! `ALU_MUL` through one ALU lookup. The shift table therefore contains no
//! bit-level circuit of its own.

use super::byte::ByteCounter;
use super::util::{alu_op, bytes, c, matrix, range_bits, range_pair, range_word, row, ALU};
use blacksilk_zk::config::Val;
use p3_air::AirBuilder;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

const SLL: usize = 0;
const SRL: usize = 1;
const SRA: usize = 2;
const A: usize = 3;
const B: usize = 7;
const C: usize = 11;
const S: usize = 15; // five bits of the shift amount
const HB: usize = 20; // b0 >> 5
const Z: usize = 21; // s = 0
const EL: usize = 22; // three bits of e_lo
const EH: usize = 25; // one-hot e_hi (4 flags)
const P: usize = 29; // bytes of 2^e
const INV: usize = 33; // s⁻¹ (s ≠ 0)
const Q: usize = 34; // (1 + el0)(1 + 3·el1)
pub const WIDTH: usize = 35;

pub fn eval<AB: AirBuilder + InteractionBuilder>(bld: &mut AB) {
    let (r, _) = row(bld);
    let one = AB::Expr::ONE;
    let (sll, srl, sra) = (r[SLL].clone(), r[SRL].clone(), r[SRA].clone());
    for f in [&sll, &srl, &sra] {
        bld.assert_bool(f.clone());
    }
    let real = sll.clone() + srl.clone() + sra.clone();
    bld.assert_bool(real.clone());

    // s: the low five bits of b0.
    let s: Vec<AB::Expr> = (0..5).map(|j| r[S + j].clone()).collect();
    for x in &s {
        bld.assert_bool(x.clone());
    }
    let s_val = (0..5).fold(AB::Expr::ZERO, |acc, j| {
        acc + s[j].clone() * c::<AB>(1 << j)
    });
    bld.assert_zero(r[B].clone() - s_val.clone() - r[HB].clone() * c::<AB>(32));
    range_bits(bld, r[HB].clone(), 3, real.clone());
    range_pair(bld, r[B + 1].clone(), r[B + 2].clone(), real.clone());
    range_pair(bld, r[B + 3].clone(), AB::Expr::ZERO, real.clone());
    range_word(bld, &r[A..A + 4], real.clone());

    // z = (s = 0); padding rows have z = 0.
    let z = r[Z].clone();
    bld.assert_zero(z.clone() * s_val.clone());
    bld.assert_zero(s_val.clone() * r[INV].clone() - real.clone() + z.clone());

    // e and 2^e.
    let el: Vec<AB::Expr> = (0..3).map(|j| r[EL + j].clone()).collect();
    let eh: Vec<AB::Expr> = (0..4).map(|k| r[EH + k].clone()).collect();
    for x in el.iter().chain(eh.iter()) {
        bld.assert_bool(x.clone());
    }
    let eh_sum = eh.iter().fold(AB::Expr::ZERO, |a, x| a + x.clone());
    bld.assert_zero(eh_sum - real.clone());
    let e = (0..3).fold(AB::Expr::ZERO, |acc, j| {
        acc + el[j].clone() * c::<AB>(1 << j)
    }) + (0..4).fold(AB::Expr::ZERO, |acc, k| {
        acc + eh[k].clone() * c::<AB>(8 * k as u32)
    });
    let e_expr =
        sll.clone() * s_val.clone() + (real.clone() - sll.clone()) * (c::<AB>(32) - s_val.clone());
    bld.assert_zero((one.clone() - z.clone()) * (e.clone() - e_expr));
    bld.assert_zero(z.clone() * e);
    let q = r[Q].clone();
    // Q = (1 + el0)(1 + 3·el1) on real rows, 0 on padding.
    bld.assert_zero(
        q.clone() - (real.clone() + el[0].clone()) * (one.clone() + el[1].clone() * c::<AB>(3)),
    );
    let pw = q * (one.clone() + el[2].clone() * c::<AB>(15));
    for k in 0..4 {
        bld.assert_zero(r[P + k].clone() - eh[k].clone() * pw.clone());
    }

    // The product (s ≠ 0), or c = a (s = 0).
    let mul_op = sll.clone() * c::<AB>(alu_op::MUL)
        + srl.clone() * c::<AB>(alu_op::MULHU)
        + sra.clone() * c::<AB>(alu_op::MULHSU);
    let mut q = vec![mul_op];
    q.extend_from_slice(&r[A..A + 4]);
    q.extend_from_slice(&r[P..P + 4]);
    q.extend_from_slice(&r[C..C + 4]);
    ALU.lookup_key(bld, q, Count::bounded(real.clone() * (one - z.clone()), 1));
    for i in 0..4 {
        bld.assert_zero(z.clone() * (r[C + i].clone() - r[A + i].clone()));
    }

    let op = sll * c::<AB>(alu_op::SLL) + srl * c::<AB>(alu_op::SRL) + sra * c::<AB>(alu_op::SRA);
    let mut msg = vec![op];
    msg.extend_from_slice(&r[A..A + 12]);
    ALU.table_entry(bld, msg, real);
}

pub fn result(op: u32, a: u32, b: u32) -> u32 {
    let s = b & 31;
    match op {
        alu_op::SLL => a << s,
        alu_op::SRL => a >> s,
        alu_op::SRA => ((a as i32) >> s) as u32,
        _ => unreachable!("not an ALU_SHIFT op"),
    }
}

/// The multiplier request a shift delegates to, if any.
pub fn mul_request(op: u32, a: u32, b: u32) -> Option<(u32, u32, u32)> {
    let s = b & 31;
    if s == 0 {
        return None;
    }
    Some(match op {
        alu_op::SLL => (alu_op::MUL, a, 1 << s),
        alu_op::SRL => (alu_op::MULHU, a, 1 << (32 - s)),
        alu_op::SRA => (alu_op::MULHSU, a, 1 << (32 - s)),
        _ => unreachable!("not an ALU_SHIFT op"),
    })
}

fn row_for(op: u32, a: u32, b: u32, counter: &mut ByteCounter) -> Vec<Val> {
    let s = b & 31;
    let hb = (b & 0xff) >> 5;
    counter.range_bits(hb, 3);
    counter.range((b >> 8) & 0xff, (b >> 16) & 0xff);
    counter.range(b >> 24, 0);
    counter.word(a);
    let e = if s == 0 {
        0
    } else if op == alu_op::SLL {
        s
    } else {
        32 - s
    };
    let pw = 1u32 << (e & 7);
    let mut r = vec![
        Val::from_bool(op == alu_op::SLL),
        Val::from_bool(op == alu_op::SRL),
        Val::from_bool(op == alu_op::SRA),
    ];
    r.extend(bytes(a));
    r.extend(bytes(b));
    r.extend(bytes(result(op, a, b)));
    r.extend((0..5).map(|j| Val::from_u32((s >> j) & 1)));
    r.push(Val::from_u32(hb));
    r.push(Val::from_bool(s == 0));
    r.extend((0..3).map(|j| Val::from_u32((e >> j) & 1)));
    r.extend((0..4).map(|k| Val::from_bool(e >> 3 == k)));
    r.extend((0..4).map(|k| Val::from_u32(if e >> 3 == k { pw } else { 0 })));
    r.push(if s == 0 {
        Val::ZERO
    } else {
        Val::from_u32(s).inverse()
    });
    r.push(Val::from_u32((1 + (e & 1)) * (1 + 3 * ((e >> 1) & 1))));
    r
}

/// The trace for shift requests. Appends the multiplier requests the rows
/// delegate to onto `mul_requests`.
pub fn trace(
    reqs: &[(u32, u32, u32)],
    counter: &mut ByteCounter,
    min: usize,
    mul_requests: &mut Vec<(u32, u32, u32)>,
) -> RowMajorMatrix<Val> {
    let rows = reqs
        .iter()
        .map(|&(op, a, b)| {
            if let Some(m) = mul_request(op, a, b) {
                mul_requests.push(m);
            }
            row_for(op, a, b, counter)
        })
        .collect();
    matrix(rows, WIDTH, min)
}
