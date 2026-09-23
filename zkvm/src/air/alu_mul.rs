//! `ALU_MUL`: MUL, MULH, MULHSU, MULHU (Zmmul, zkvm.md §4, §6.1).
//!
//! The operands are extended to 8 bytes (sign-extended when the variant treats
//! them as signed: `a` for MULH/MULHSU, `b` for MULH) and the low 64 bits of
//! the product are computed byte by byte:
//!
//! ```text
//! Σ_{i+j=k} A_i·B_j + carry_{k−1} = P_k + 256·carry_k        k = 0..7
//! ```
//!
//! with `P_k` range-checked bytes and `carry_k = lo_k + 256·hi_k`, `hi_k < 16`.
//! The left side is < 8·255² + 2^12 < 2^20, so the carries fit in 12 bits and
//! every equation holds over the integers. The result is `P0..P3` for MUL and
//! `P4..P7` for the high variants (the low 64 bits of the sign-extended product
//! equal the true signed/unsigned product modulo 2^64).

use super::byte::ByteCounter;
use super::util::{alu_op, bytes, c, matrix, range_bits, range_pair, range_word, row, ALU};
use blacksilk_zk::config::Val;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

const MUL: usize = 0;
const MULH: usize = 1;
const MULHSU: usize = 2;
const MULHU: usize = 3;
const A: usize = 4;
const B: usize = 8;
const C: usize = 12;
const SA: usize = 16;
const RA: usize = 17;
const SB: usize = 18;
const RB: usize = 19;
const P: usize = 20;
const LO: usize = 28;
const HI: usize = 36;
pub const WIDTH: usize = 44;

pub fn eval<AB: AirBuilder + InteractionBuilder>(bld: &mut AB) {
    let (r, _) = row(bld);
    let flags = [
        r[MUL].clone(),
        r[MULH].clone(),
        r[MULHSU].clone(),
        r[MULHU].clone(),
    ];
    for f in &flags {
        bld.assert_bool(f.clone());
    }
    let real = flags.iter().fold(AB::Expr::ZERO, |a, f| a + f.clone());
    bld.assert_bool(real.clone());
    let a_signed = flags[1].clone() + flags[2].clone();
    let b_signed = flags[1].clone();

    let (sa, sb) = (r[SA].clone(), r[SB].clone());
    bld.assert_bool(sa.clone());
    bld.assert_bool(sb.clone());
    bld.assert_zero(r[A + 3].clone() - sa.clone() * c::<AB>(128) - r[RA].clone());
    bld.assert_zero(r[B + 3].clone() - sb.clone() * c::<AB>(128) - r[RB].clone());
    range_bits(bld, r[RA].clone(), 7, real.clone());
    range_bits(bld, r[RB].clone(), 7, real.clone());

    let ext_a = sa * a_signed * c::<AB>(255);
    let ext_b = sb * b_signed * c::<AB>(255);
    let av: Vec<AB::Expr> = (0..8)
        .map(|i| {
            if i < 4 {
                r[A + i].clone()
            } else {
                ext_a.clone()
            }
        })
        .collect();
    let bv: Vec<AB::Expr> = (0..8)
        .map(|i| {
            if i < 4 {
                r[B + i].clone()
            } else {
                ext_b.clone()
            }
        })
        .collect();

    let mut carry = AB::Expr::ZERO;
    for k in 0..8 {
        let mut sum = carry.clone();
        for i in 0..=k {
            sum += av[i].clone() * bv[k - i].clone();
        }
        let ck = r[LO + k].clone() + r[HI + k].clone() * c::<AB>(256);
        bld.assert_zero(sum - r[P + k].clone() - ck.clone() * c::<AB>(256));
        range_bits(bld, r[HI + k].clone(), 4, real.clone());
        carry = ck;
    }
    for k in (0..8).step_by(2) {
        range_pair(bld, r[P + k].clone(), r[P + k + 1].clone(), real.clone());
        range_pair(bld, r[LO + k].clone(), r[LO + k + 1].clone(), real.clone());
    }
    let mul = flags[0].clone();
    for i in 0..4 {
        bld.assert_zero(
            r[C + i].clone()
                - mul.clone() * r[P + i].clone()
                - (AB::Expr::ONE - mul.clone()) * r[P + 4 + i].clone(),
        );
    }
    range_word(bld, &r[A..A + 4], real.clone());
    range_word(bld, &r[B..B + 4], real.clone());
    let op = flags[0].clone() * c::<AB>(alu_op::MUL)
        + flags[1].clone() * c::<AB>(alu_op::MULH)
        + flags[2].clone() * c::<AB>(alu_op::MULHSU)
        + flags[3].clone() * c::<AB>(alu_op::MULHU);
    let mut msg = vec![op];
    msg.extend_from_slice(&r[A..A + 12]);
    ALU.table_entry(bld, msg, real);
}

pub fn result(op: u32, a: u32, b: u32) -> u32 {
    match op {
        alu_op::MUL => a.wrapping_mul(b),
        alu_op::MULH => ((a as i32 as i64 * b as i32 as i64) >> 32) as u32,
        alu_op::MULHSU => ((a as i32 as i64 * b as i64) >> 32) as u32,
        alu_op::MULHU => ((a as u64 * b as u64) >> 32) as u32,
        _ => unreachable!("not an ALU_MUL op"),
    }
}

fn row_for(op: u32, a: u32, b: u32, counter: &mut ByteCounter) -> Vec<Val> {
    let a_signed = op == alu_op::MULH || op == alu_op::MULHSU;
    let b_signed = op == alu_op::MULH;
    let ext = |x: u32, signed: bool| -> [u32; 8] {
        let e = if signed && (x >> 31) == 1 { 255 } else { 0 };
        let bb = x.to_le_bytes();
        [
            bb[0] as u32,
            bb[1] as u32,
            bb[2] as u32,
            bb[3] as u32,
            e,
            e,
            e,
            e,
        ]
    };
    let (av, bv) = (ext(a, a_signed), ext(b, b_signed));
    let mut p = [0u32; 8];
    let mut carries = [0u32; 8];
    let mut carry = 0u64;
    for k in 0..8 {
        let mut sum = carry;
        for i in 0..=k {
            sum += av[i] as u64 * bv[k - i] as u64;
        }
        p[k] = (sum & 0xff) as u32;
        carry = sum >> 8;
        carries[k] = carry as u32;
    }
    let (a3, b3) = (a >> 24, b >> 24);
    counter.range_bits(a3 & 127, 7);
    counter.range_bits(b3 & 127, 7);
    for carry in carries {
        counter.range_bits(carry >> 8, 4);
    }
    for k in (0..8).step_by(2) {
        counter.range(p[k], p[k + 1]);
        counter.range(carries[k] & 0xff, carries[k + 1] & 0xff);
    }
    counter.word(a);
    counter.word(b);
    let cv = result(op, a, b);
    let mut r: Vec<Val> = [alu_op::MUL, alu_op::MULH, alu_op::MULHSU, alu_op::MULHU]
        .iter()
        .map(|o| Val::from_bool(*o == op))
        .collect();
    r.extend(bytes(a));
    r.extend(bytes(b));
    r.extend(bytes(cv));
    r.extend([a3 >> 7, a3 & 127, b3 >> 7, b3 & 127].map(Val::from_u32));
    r.extend(p.map(Val::from_u32));
    r.extend(carries.map(|x| Val::from_u32(x & 0xff)));
    r.extend(carries.map(|x| Val::from_u32(x >> 8)));
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
