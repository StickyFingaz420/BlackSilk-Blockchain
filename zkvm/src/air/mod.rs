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
pub mod program;
pub mod trace;
pub mod util;

use crate::program::Program;
use blacksilk_zk::config::Val;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use std::sync::Arc;

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
    /// The committed program.
    Program(Arc<Program>),
    /// Image words and initial registers, sorted by key.
    Image(Arc<Vec<(u32, u32)>>),
    MemInit,
    Cpu,
    /// The claimed public output words.
    Output(Arc<Vec<u32>>),
}

impl BaseAir<Val> for Table {
    fn width(&self) -> usize {
        match self {
            Table::Byte => byte::WIDTH,
            Table::AluAdd => alu_add::WIDTH,
            Table::AluBit => alu_bit::WIDTH,
            Table::AluLt => alu_lt::WIDTH,
            Table::AluShift => alu_shift::WIDTH,
            Table::AluMul => alu_mul::WIDTH,
            Table::Program(_) => program::WIDTH,
            Table::Image(_) | Table::Output(_) => memory::DUMMY_WIDTH,
            Table::MemInit => memory::INIT_WIDTH,
            Table::Cpu => cpu::WIDTH,
        }
    }

    fn num_public_values(&self) -> usize {
        match self {
            Table::Cpu => cpu::pv::COUNT,
            _ => 0,
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        match self {
            Table::Byte => Some(byte::preprocessed()),
            Table::Program(p) => Some(program::preprocessed(p, MIN_HEIGHT)),
            Table::Image(w) => Some(memory::image_preprocessed(w, MIN_HEIGHT)),
            Table::Output(o) => Some(memory::output_preprocessed(o, MIN_HEIGHT)),
            _ => None,
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Table::Byte => byte::PREP_WIDTH,
            Table::Program(_) => program::PREP_WIDTH,
            Table::Image(_) | Table::Output(_) => memory::IMAGE_PREP_WIDTH,
            _ => 0,
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
            Table::Program(_) => program::eval(b),
            Table::Image(_) => memory::image_eval(b),
            Table::MemInit => memory::init_eval(b),
            Table::Cpu => cpu::eval(b),
            Table::Output(_) => memory::output_eval(b),
        }
    }
}
