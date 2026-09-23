//! `ALU_BIT`: 32-bit AND, OR, XOR (zkvm.md §6.1).
//!
//! One row per request. Each byte `(a_i, b_i, c_i)` is looked up in the
//! `BYTE` table under the row's operation, which both computes `c_i` and
//! range-checks all three bytes. Provides `(op, a, b, c)` on the ALU bus once
//! per real row.

use super::byte::ByteCounter;
use super::util::{alu_op, byte_op, bytes, c, matrix, row, ALU, BYTE_OP};
use blacksilk_zk::config::Val;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

const XOR: usize = 0;
const OR: usize = 1;
const AND: usize = 2;
const A: usize = 3;
const B: usize = 7;
const C: usize = 11;
pub const WIDTH: usize = 15;

pub fn eval<AB: AirBuilder + InteractionBuilder>(bld: &mut AB) {
    let (r, _) = row(bld);
    let (xor, or, and) = (r[XOR].clone(), r[OR].clone(), r[AND].clone());
    for f in [&xor, &or, &and] {
        bld.assert_bool(f.clone());
    }
    let real = xor.clone() + or.clone() + and.clone();
    bld.assert_bool(real.clone());
    let byte_op_id = xor.clone() * c::<AB>(byte_op::XOR)
        + or.clone() * c::<AB>(byte_op::OR)
        + and.clone() * c::<AB>(byte_op::AND);
    for i in 0..4 {
        BYTE_OP.lookup_key(
            bld,
            [
                byte_op_id.clone(),
                r[A + i].clone(),
                r[B + i].clone(),
                r[C + i].clone(),
            ],
            Count::bounded(real.clone(), 1),
        );
    }
    let op = xor * c::<AB>(alu_op::XOR) + or * c::<AB>(alu_op::OR) + and * c::<AB>(alu_op::AND);
    let mut msg = vec![op];
    msg.extend_from_slice(&r[A..A + 12]);
    ALU.table_entry(bld, msg, real);
}

fn row_for(op: u32, a: u32, b: u32, counter: &mut ByteCounter) -> Vec<Val> {
    let (cv, bop) = match op {
        alu_op::XOR => (a ^ b, byte_op::XOR),
        alu_op::OR => (a | b, byte_op::OR),
        alu_op::AND => (a & b, byte_op::AND),
        _ => unreachable!("not an ALU_BIT op"),
    };
    let (ab, bb) = (a.to_le_bytes(), b.to_le_bytes());
    for i in 0..4 {
        counter.op(bop, ab[i] as u32, bb[i] as u32);
    }
    let mut r = vec![
        Val::from_bool(op == alu_op::XOR),
        Val::from_bool(op == alu_op::OR),
        Val::from_bool(op == alu_op::AND),
    ];
    r.extend(bytes(a));
    r.extend(bytes(b));
    r.extend(bytes(cv));
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
