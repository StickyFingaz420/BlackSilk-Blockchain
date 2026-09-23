//! `ALU_LT`: SLT, SLTU and EQ (zkvm.md §6.1). Result `c = [r, 0, 0, 0]`.
//!
//! The row computes `d = a − b mod 2^32` with a borrow chain, written as the
//! addition `b + d = a + 2^32·k3` byte by byte (as in `ALU_ADD`):
//! - unsigned `a < b` ⇔ the addition overflows ⇔ `k3 = 1`;
//! - signed: with sign bits `sa`, `sb` from `a3 = 128·sa + ra`, `b3 = 128·sb + rb`
//!   (`ra, rb < 128`), `a <s b` ⇔ `sa ∧ ¬sb` ∨ (`sa = sb` ∧ `k3`);
//! - equal ⇔ `d = 0` ⇔ `d0 + d1 + d2 + d3 = 0` (bytes are non-negative), via an
//!   inverse witness: `z = 1 − s·inv`, `s·z = 0`.

use super::byte::ByteCounter;
use super::util::{alu_op, bytes, c, matrix, range_bits, range_word, row, ALU};
use blacksilk_zk::config::Val;
use p3_air::AirBuilder;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

const SLT: usize = 0;
const SLTU: usize = 1;
const EQ: usize = 2;
const A: usize = 3;
const B: usize = 7;
const D: usize = 11;
const K: usize = 15;
const SA: usize = 19;
const RA: usize = 20;
const SB: usize = 21;
const RB: usize = 22;
const INV: usize = 23;
const R: usize = 24;
pub const WIDTH: usize = 25;

pub fn eval<AB: AirBuilder + InteractionBuilder>(bld: &mut AB) {
    let (r, _) = row(bld);
    let (slt, sltu, eq) = (r[SLT].clone(), r[SLTU].clone(), r[EQ].clone());
    for f in [&slt, &sltu, &eq] {
        bld.assert_bool(f.clone());
    }
    let real = slt.clone() + sltu.clone() + eq.clone();
    bld.assert_bool(real.clone());

    // b + d = a (mod 2^32), borrow k3.
    let mut carry = AB::Expr::ZERO;
    for i in 0..4 {
        let k = r[K + i].clone();
        bld.assert_bool(k.clone());
        bld.assert_zero(
            r[B + i].clone() + r[D + i].clone() + carry.clone()
                - r[A + i].clone()
                - k.clone() * c::<AB>(256),
        );
        carry = k;
    }
    let ltu = r[K + 3].clone();

    // Sign bits.
    let (sa, sb) = (r[SA].clone(), r[SB].clone());
    bld.assert_bool(sa.clone());
    bld.assert_bool(sb.clone());
    bld.assert_zero(r[A + 3].clone() - sa.clone() * c::<AB>(128) - r[RA].clone());
    bld.assert_zero(r[B + 3].clone() - sb.clone() * c::<AB>(128) - r[RB].clone());
    range_bits(bld, r[RA].clone(), 7, real.clone());
    range_bits(bld, r[RB].clone(), 7, real.clone());
    let same_sign = AB::Expr::ONE - sa.clone() - sb.clone() + sa.clone() * sb.clone() * c::<AB>(2);
    let lts = sa.clone() * (AB::Expr::ONE - sb) + same_sign * ltu.clone();

    // Zero test of d.
    let s = r[D].clone() + r[D + 1].clone() + r[D + 2].clone() + r[D + 3].clone();
    let z = AB::Expr::ONE - s.clone() * r[INV].clone();
    bld.assert_zero(s * z.clone());

    bld.assert_zero(r[R].clone() - slt.clone() * lts - sltu.clone() * ltu - eq.clone() * z);

    for base in [A, B, D] {
        range_word(bld, &r[base..base + 4], real.clone());
    }
    let op = slt * c::<AB>(alu_op::SLT) + sltu * c::<AB>(alu_op::SLTU) + eq * c::<AB>(alu_op::EQ);
    let mut msg = vec![op];
    msg.extend_from_slice(&r[A..A + 8]);
    msg.extend([r[R].clone(), AB::Expr::ZERO, AB::Expr::ZERO, AB::Expr::ZERO]);
    ALU.table_entry(bld, msg, real);
}

/// Reference result of an `ALU_LT` operation.
pub fn result(op: u32, a: u32, b: u32) -> u32 {
    match op {
        alu_op::SLT => ((a as i32) < (b as i32)) as u32,
        alu_op::SLTU => (a < b) as u32,
        alu_op::EQ => (a == b) as u32,
        _ => unreachable!("not an ALU_LT op"),
    }
}

fn row_for(op: u32, a: u32, b: u32, counter: &mut ByteCounter) -> Vec<Val> {
    let d = a.wrapping_sub(b);
    let (bb, db) = (b.to_le_bytes(), d.to_le_bytes());
    let mut k = [0u32; 4];
    let mut carry = 0u32;
    for i in 0..4 {
        let s = bb[i] as u32 + db[i] as u32 + carry;
        k[i] = s >> 8;
        carry = k[i];
    }
    let (a3, b3) = (a >> 24, b >> 24);
    let (sa, ra, sb, rb) = (a3 >> 7, a3 & 127, b3 >> 7, b3 & 127);
    let s: u32 = db.iter().map(|x| *x as u32).sum();
    let inv = Val::from_u32(s).try_inverse().unwrap_or(Val::ZERO);
    for w in [a, b, d] {
        counter.word(w);
    }
    counter.range_bits(ra, 7);
    counter.range_bits(rb, 7);
    let mut r = vec![
        Val::from_bool(op == alu_op::SLT),
        Val::from_bool(op == alu_op::SLTU),
        Val::from_bool(op == alu_op::EQ),
    ];
    r.extend(bytes(a));
    r.extend(bytes(b));
    r.extend(bytes(d));
    r.extend(k.map(Val::from_u32));
    r.extend([sa, ra, sb, rb].map(Val::from_u32));
    r.push(inv);
    r.push(Val::from_u32(result(op, a, b)));
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
