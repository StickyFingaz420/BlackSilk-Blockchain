//! `ALU_SHIFT`: SLL, SRL, SRA by a barrel shifter (zkvm.md §6.1).
//!
//! - `a` is decomposed into 32 boolean bits; the shift amount is the low five
//!   bits `s0..s4` of `b0` (`b0 = Σ s_j·2^j + 32·hb`, `hb < 8`), as RISC-V
//!   specifies (only the low 5 bits count).
//! - Five stages shift right by `2^j` when `s_j = 1`:
//!   `X_{j+1}[i] = s_j · (X_j[i + 2^j] or fill) + (1 − s_j) · X_j[i]`,
//!   where `fill` is the sign bit for SRA and 0 otherwise.
//! - A left shift is a right shift of the bit-reversed input, reversed back.
//!
//! Every stage is a selection between booleans, so every bit, and therefore
//! every result byte, is boolean-valued and in range by construction.

use super::byte::ByteCounter;
use super::util::{alu_op, bytes, c, matrix, range_bits, range_pair, row, ALU};
use blacksilk_zk::config::Val;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

const SLL: usize = 0;
const SRL: usize = 1;
const SRA: usize = 2;
const A: usize = 3;
const B: usize = 7;
const C: usize = 11;
const ABITS: usize = 15;
const S: usize = 47;
const HB: usize = 52;
const STAGES: usize = 53;
pub const WIDTH: usize = STAGES + 5 * 32;

pub fn eval<AB: AirBuilder + InteractionBuilder>(bld: &mut AB) {
    let (r, _) = row(bld);
    let (sll, srl, sra) = (r[SLL].clone(), r[SRL].clone(), r[SRA].clone());
    for f in [&sll, &srl, &sra] {
        bld.assert_bool(f.clone());
    }
    let real = sll.clone() + srl.clone() + sra.clone();
    bld.assert_bool(real.clone());

    // Bits of a.
    let abit: Vec<AB::Expr> = (0..32).map(|i| r[ABITS + i].clone()).collect();
    for x in &abit {
        bld.assert_bool(x.clone());
    }
    for i in 0..4 {
        let byte = (0..8).fold(AB::Expr::ZERO, |acc, j| {
            acc + abit[8 * i + j].clone() * c::<AB>(1 << j)
        });
        bld.assert_zero(r[A + i].clone() - byte);
    }
    // Shift amount: the low five bits of b0.
    let s: Vec<AB::Expr> = (0..5).map(|j| r[S + j].clone()).collect();
    for x in &s {
        bld.assert_bool(x.clone());
    }
    let low = (0..5).fold(AB::Expr::ZERO, |acc, j| {
        acc + s[j].clone() * c::<AB>(1 << j)
    });
    bld.assert_zero(r[B].clone() - low - r[HB].clone() * c::<AB>(32));
    range_bits(bld, r[HB].clone(), 3, real.clone());
    range_pair(bld, r[B + 1].clone(), r[B + 2].clone(), real.clone());
    range_pair(bld, r[B + 3].clone(), AB::Expr::ZERO, real.clone());

    // Stages.
    let not_sll = AB::Expr::ONE - sll.clone();
    let mut x: Vec<AB::Expr> = (0..32)
        .map(|i| sll.clone() * abit[31 - i].clone() + not_sll.clone() * abit[i].clone())
        .collect();
    let fill = sra.clone() * abit[31].clone();
    for (j, sj) in s.iter().enumerate() {
        let d = 1usize << j;
        let next: Vec<AB::Expr> = (0..32).map(|i| r[STAGES + 32 * j + i].clone()).collect();
        for i in 0..32 {
            let shifted = if i + d < 32 {
                x[i + d].clone()
            } else {
                fill.clone()
            };
            bld.assert_zero(
                next[i].clone()
                    - sj.clone() * shifted
                    - (AB::Expr::ONE - sj.clone()) * x[i].clone(),
            );
        }
        x = next;
    }
    // Output (reversed back for SLL) as bytes of c.
    let y: Vec<AB::Expr> = (0..32)
        .map(|i| sll.clone() * x[31 - i].clone() + not_sll.clone() * x[i].clone())
        .collect();
    for i in 0..4 {
        let byte = (0..8).fold(AB::Expr::ZERO, |acc, j| {
            acc + y[8 * i + j].clone() * c::<AB>(1 << j)
        });
        bld.assert_zero(r[C + i].clone() - byte);
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

fn row_for(op: u32, a: u32, b: u32, counter: &mut ByteCounter) -> Vec<Val> {
    let sll = op == alu_op::SLL;
    let s = b & 31;
    let hb = (b & 0xff) >> 5;
    counter.range_bits(hb, 3);
    counter.range((b >> 8) & 0xff, (b >> 16) & 0xff);
    counter.range(b >> 24, 0);
    let abits: Vec<u32> = (0..32).map(|i| (a >> i) & 1).collect();
    let mut x: Vec<u32> = (0..32)
        .map(|i| if sll { abits[31 - i] } else { abits[i] })
        .collect();
    let fill = if op == alu_op::SRA { abits[31] } else { 0 };
    let mut stages = Vec::with_capacity(160);
    for j in 0..5 {
        let d = 1usize << j;
        let on = (s >> j) & 1 == 1;
        let next: Vec<u32> = (0..32)
            .map(|i| {
                if on {
                    if i + d < 32 {
                        x[i + d]
                    } else {
                        fill
                    }
                } else {
                    x[i]
                }
            })
            .collect();
        stages.extend(next.iter().copied());
        x = next;
    }
    let cv = result(op, a, b);
    let mut r = vec![
        Val::from_bool(sll),
        Val::from_bool(op == alu_op::SRL),
        Val::from_bool(op == alu_op::SRA),
    ];
    r.extend(bytes(a));
    r.extend(bytes(b));
    r.extend(bytes(cv));
    r.extend(abits.iter().map(|x| Val::from_u32(*x)));
    r.extend((0..5).map(|j| Val::from_u32((s >> j) & 1)));
    r.push(Val::from_u32(hb));
    r.extend(stages.iter().map(|x| Val::from_u32(*x)));
    r
}

pub fn trace(
    reqs: &[(u32, u32, u32)],
    counter: &mut ByteCounter,
    min: usize,
) -> RowMajorMatrix<Val> {
    let rows = reqs
        .iter()
        .map(|&(op, a, b)| row_for(op, a, b, counter))
        .collect();
    matrix(rows, WIDTH, min)
}
