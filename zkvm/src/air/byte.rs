//! `BYTE`: the preprocessed table of all byte pairs (zkvm.md §6.1).
//!
//! Row `256·a + b` holds `(a, b, a AND b, a OR b, a XOR b)` as preprocessed
//! (verifier-computed) columns. The main trace holds four multiplicities: how
//! often each pair is used as a range check and as each byte operation.
//!
//! Provides:
//! - `RANGE`: `(a, b)` — both are bytes;
//! - `BYTE_OP`: `(AND, a, b, a&b)`, `(OR, a, b, a|b)`, `(XOR, a, b, a^b)`.

use super::util::{byte_op, c, prep, row, BYTE_OP, RANGE};
use blacksilk_zk::config::Val;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

pub const HEIGHT: usize = 1 << 16;
pub const WIDTH: usize = 4;
pub const PREP_WIDTH: usize = 5;

const M_RANGE: usize = 0;
const M_AND: usize = 1;
const M_OR: usize = 2;
const M_XOR: usize = 3;

/// The table's public columns (computed once).
pub fn columns() -> &'static [Vec<Val>] {
    static C: std::sync::OnceLock<Vec<Vec<Val>>> = std::sync::OnceLock::new();
    C.get_or_init(|| super::columns(&preprocessed()))
}

pub fn preprocessed() -> RowMajorMatrix<Val> {
    let mut v = Vec::with_capacity(HEIGHT * PREP_WIDTH);
    for a in 0..256u32 {
        for bb in 0..256u32 {
            v.extend([a, bb, a & bb, a | bb, a ^ bb].map(Val::from_u32));
        }
    }
    RowMajorMatrix::new(v, PREP_WIDTH)
}

pub fn eval<AB: AirBuilder + InteractionBuilder>(b: &mut AB) {
    let (m, _) = row(b);
    let p = prep(b, WIDTH);
    let (x, y) = (p[0].clone(), p[1].clone());
    RANGE.table_entry(b, [x.clone(), y.clone()], m[M_RANGE].clone());
    for (op, col, res) in [
        (byte_op::AND, M_AND, 2usize),
        (byte_op::OR, M_OR, 3),
        (byte_op::XOR, M_XOR, 4),
    ] {
        BYTE_OP.table_entry(
            b,
            [c::<AB>(op), x.clone(), y.clone(), p[res].clone()],
            m[col].clone(),
        );
    }
}

/// Counts every byte lookup made by the other tables' traces.
pub struct ByteCounter {
    counts: Vec<[u32; 4]>,
}

impl Default for ByteCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl ByteCounter {
    pub fn new() -> Self {
        Self {
            counts: vec![[0; 4]; HEIGHT],
        }
    }

    /// A range lookup of `(x, y)`; both must be bytes.
    pub fn range(&mut self, x: u32, y: u32) {
        assert!(x < 256 && y < 256, "range lookup of a non-byte ({x}, {y})");
        self.counts[(x * 256 + y) as usize][M_RANGE] += 1;
    }

    /// Mirrors `util::range_bits`.
    pub fn range_bits(&mut self, x: u32, bits: u32) {
        self.range(x, x << (8 - bits));
    }

    pub fn word(&mut self, w: u32) {
        let b = w.to_le_bytes();
        self.range(b[0] as u32, b[1] as u32);
        self.range(b[2] as u32, b[3] as u32);
    }

    pub fn op(&mut self, op: u32, x: u32, y: u32) {
        let col = match op {
            byte_op::AND => M_AND,
            byte_op::OR => M_OR,
            byte_op::XOR => M_XOR,
            _ => unreachable!("unknown byte op"),
        };
        self.counts[(x * 256 + y) as usize][col] += 1;
    }

    pub fn trace(&self) -> RowMajorMatrix<Val> {
        let mut v = Vec::with_capacity(HEIGHT * WIDTH);
        for c in &self.counts {
            v.extend(c.map(Val::from_u32));
        }
        RowMajorMatrix::new(v, WIDTH)
    }
}
