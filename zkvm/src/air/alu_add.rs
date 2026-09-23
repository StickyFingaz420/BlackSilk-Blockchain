//! `ALU_ADD`: 32-bit addition and subtraction (zkvm.md §6.1).
//!
//! One row per request. With `(u, v, w) = (a, b, c)` for ADD and `(b, c, a)`
//! for SUB, the row proves `u + v ≡ w (mod 2^32)` byte by byte:
//!
//! ```text
//! u0 + v0      = w0 + 256·k0
//! u1 + v1 + k0 = w1 + 256·k1          k0..k3 ∈ {0, 1}
//! u2 + v2 + k1 = w2 + 256·k2
//! u3 + v3 + k2 = w3 + 256·k3          (k3 is the dropped carry)
//! ```
//!
//! All of `a`, `b`, `c` are range-checked bytes, so each equation holds over
//! the integers (both sides < 2^10, far below p) and the result is unique.
//! Provides `(op, a, b, c)` on the ALU bus once per real row.

use super::byte::ByteCounter;
use super::util::{alu_op, bytes, c, matrix, range_word, row, ALU};
use blacksilk_zk::config::Val;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

const ADD: usize = 0;
const SUB: usize = 1;
const A: usize = 2;
const B: usize = 6;
const C: usize = 10;
const K: usize = 14;
pub const WIDTH: usize = 18;

pub fn eval<AB: AirBuilder + InteractionBuilder>(bld: &mut AB) {
    let (r, _) = row(bld);
    let (add, sub) = (r[ADD].clone(), r[SUB].clone());
    let real = add.clone() + sub.clone();
    bld.assert_bool(add.clone());
    bld.assert_bool(sub.clone());
    bld.assert_zero(add.clone() * sub.clone());
    let sel = |x: usize, y: usize| -> Vec<AB::Expr> {
        (0..4)
            .map(|i| add.clone() * r[x + i].clone() + sub.clone() * r[y + i].clone())
            .collect()
    };
    let u = sel(A, B);
    let v = sel(B, C);
    let w = sel(C, A);
    let mut carry = AB::Expr::ZERO;
    for i in 0..4 {
        let k = r[K + i].clone();
        bld.assert_bool(k.clone());
        bld.assert_zero(
            u[i].clone() + v[i].clone() + carry.clone() - w[i].clone() - k.clone() * c::<AB>(256),
        );
        carry = k;
    }
    for base in [A, B, C] {
        range_word(bld, &r[base..base + 4], real.clone());
    }
    let op = add * c::<AB>(alu_op::ADD) + sub * c::<AB>(alu_op::SUB);
    let mut msg = vec![op];
    msg.extend_from_slice(&r[A..A + 12]);
    ALU.table_entry(bld, msg, real);
}

/// One ADD/SUB request: returns its row and records its byte lookups.
fn row_for(op: u32, a: u32, b: u32, counter: &mut ByteCounter) -> Vec<Val> {
    let c_val = match op {
        alu_op::ADD => a.wrapping_add(b),
        alu_op::SUB => a.wrapping_sub(b),
        _ => unreachable!("not an ALU_ADD op"),
    };
    let (u, v) = if op == alu_op::ADD {
        (a, b)
    } else {
        (b, c_val)
    };
    let (ub, vb) = (u.to_le_bytes(), v.to_le_bytes());
    let mut k = [0u32; 4];
    let mut carry = 0u32;
    for i in 0..4 {
        let s = ub[i] as u32 + vb[i] as u32 + carry;
        k[i] = s >> 8;
        carry = k[i];
    }
    for w in [a, b, c_val] {
        counter.word(w);
    }
    let mut r = vec![
        Val::from_bool(op == alu_op::ADD),
        Val::from_bool(op == alu_op::SUB),
    ];
    r.extend(bytes(a));
    r.extend(bytes(b));
    r.extend(bytes(c_val));
    r.extend(k.map(Val::from_u32));
    r
}

/// The trace for `(op, a, b)` requests, padded to a power of two ≥ `min`.
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
