//! BVM-1 constraint tables (docs/zkvm.md §6).
//!
//! [`Table`] is the single AIR type of a BVM-1 proof: the batch prover needs
//! one type for all tables, so each variant dispatches to its module. Every
//! table's constraints live in its module next to its trace generator, and are
//! checked against the reference interpreter by the oracle in [`check`].
//!
//! Tables holding public data (`Program`, `Image`, `Output`) build their
//! preprocessed columns from it; the verifier constructs them from the program
//! and the claimed outputs, never from the prover.

pub mod alu_add;
pub mod alu_bit;
pub mod alu_lt;
pub mod alu_mul;
pub mod alu_shift;
pub mod byte;
pub mod check;
pub mod cpu;
pub mod memory;
pub mod poseidon;
pub mod program;
pub mod trace;
pub mod util;

use crate::program::Program;
use blacksilk_zk::config::Val;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use std::borrow::Cow;
use std::sync::Arc;

/// Appends `table`'s public columns to its trace (the constrained copies read
/// by [`util::prep`]).
pub fn with_public_columns(table: &Table, trace: RowMajorMatrix<Val>) -> RowMajorMatrix<Val> {
    use p3_air::BaseAir;
    let cols = table.periodic_columns();
    if cols.is_empty() {
        return trace;
    }
    let (h, w, k) = (trace.height(), trace.width(), cols.len());
    let mut v = Vec::with_capacity(h * (w + k));
    for r in 0..h {
        v.extend_from_slice(&trace.values[r * w..(r + 1) * w]);
        v.extend(cols.iter().map(|c| c[r]));
    }
    RowMajorMatrix::new(v, w + k)
}

/// The columns of a row-major matrix.
pub fn columns(m: &RowMajorMatrix<Val>) -> Vec<Vec<Val>> {
    (0..m.width())
        .map(|c| {
            (0..m.height())
                .map(|r| m.values[r * m.width() + c])
                .collect()
        })
        .collect()
}

/// Minimum table height (the parameter set's minimum).
pub const MIN_HEIGHT: usize = 1 << blacksilk_zk::params::MIN_LOG_HEIGHT;

#[derive(Clone, Debug)]
pub enum Table {
    Byte,
    AluAdd,
    AluBit,
    AluLt,
    AluShift,
    AluMul,
    /// The committed program of execution `.1`.
    Program(Arc<Program>, u32),
    /// Image words and initial registers of execution `.1`, sorted by key.
    Image(Arc<Vec<(u32, u32)>>, u32),
    MemInit(u32),
    Cpu(u32),
    /// The claimed public output words of execution `.1`.
    Output(Arc<Vec<u32>>, u32),
    /// Shared by all executions.
    Poseidon2,
}

impl BaseAir<Val> for Table {
    fn width(&self) -> usize {
        match self {
            Table::Byte => byte::WIDTH + byte::PREP_WIDTH,
            Table::AluAdd => alu_add::WIDTH,
            Table::AluBit => alu_bit::WIDTH,
            Table::AluLt => alu_lt::WIDTH,
            Table::AluShift => alu_shift::WIDTH,
            Table::AluMul => alu_mul::WIDTH,
            Table::Program(..) => program::WIDTH + program::PREP_WIDTH,
            Table::Image(..) | Table::Output(..) => memory::DUMMY_WIDTH + memory::IMAGE_PREP_WIDTH,
            Table::MemInit(_) => memory::INIT_WIDTH,
            Table::Cpu(_) => cpu::WIDTH,
            Table::Poseidon2 => poseidon::WIDTH,
        }
    }

    fn num_public_values(&self) -> usize {
        match self {
            Table::Cpu(_) => cpu::pv::COUNT,
            _ => 0,
        }
    }

    fn num_periodic_columns(&self) -> usize {
        match self {
            Table::Byte => byte::PREP_WIDTH,
            Table::Program(..) => program::PREP_WIDTH,
            Table::Image(..) | Table::Output(..) => memory::IMAGE_PREP_WIDTH,
            _ => 0,
        }
    }

    /// Public tables (byte operations, program, image, outputs) are periodic
    /// columns whose period is the table height: the verifier evaluates them
    /// itself, so they are never committed (zkvm.md §6.1). They are bound to
    /// the Fiat–Shamir transcript through the statement digest
    /// (`prove::statement_digest`).
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        match self {
            Table::Byte => Cow::Borrowed(byte::columns()),
            Table::Program(p, _) => Cow::Owned(columns(&program::preprocessed(p, MIN_HEIGHT))),
            Table::Image(w, _) => Cow::Owned(columns(&memory::image_preprocessed(w, MIN_HEIGHT))),
            Table::Output(o, _) => Cow::Owned(columns(&memory::output_preprocessed(o, MIN_HEIGHT))),
            _ => Cow::Owned(Vec::new()),
        }
    }
}

impl<AB: AirBuilder<F = Val> + InteractionBuilder> Air<AB> for Table {
    fn eval(&self, b: &mut AB) {
        match self {
            Table::Byte => byte::eval(b),
            Table::AluAdd => alu_add::eval(b),
            Table::AluBit => alu_bit::eval(b),
            Table::AluLt => alu_lt::eval(b),
            Table::AluShift => alu_shift::eval(b),
            Table::AluMul => alu_mul::eval(b),
            Table::Program(_, e) => program::eval(b, *e),
            Table::Image(_, e) => memory::image_eval(b, *e),
            Table::MemInit(e) => memory::init_eval(b, *e),
            Table::Cpu(e) => cpu::eval(b, *e),
            Table::Output(_, e) => memory::output_eval(b, *e),
            Table::Poseidon2 => poseidon::eval(b),
        }
    }
}
