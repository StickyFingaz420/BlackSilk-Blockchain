//! The deploy-time row caps of a registered function (record
//! `px-deploy-row-caps`, freeze gate B2, the "V12" caps): the single
//! definition of the cap values and of the two deploy rules built on them.
//!
//! Consensus applies them through `blacksilk-tx` (`params::PX_FN_LOG_*`,
//! `params::PX_LOG_*`, `px::budget_is_provable`, `px::program_is_provable`
//! are re-exports of the items here, record `v12-caps-single-definition`);
//! the prover's early stop ([`crate::prove::FN_RUN_LOG_CYCLES`]) and the B2
//! measurement example (`px/examples/freeze_b2_b3.rs`) use the same items.
//! The values are pinned once, numerically, by this module's tests
//! (`the_v12_caps_and_table_are_pinned`), and the node's consensus manifest
//! carries the ten log2 caps (`tx.PX_FN_LOG_CYCLES_KEYS_PROGRAM_IMAGE`,
//! `tx.PX_LOG_ADD_BIT_LT_SHIFT_MUL_POSEIDON`).

use crate::prove::{kernel_budget, PX_MAX_LOG_HEIGHT};
use blacksilk_px_core::call::MAX_FN;
use blacksilk_zkvm::air::trace::Budget;
use blacksilk_zkvm::Program;

/// A registered function's own tables, as log2 of a table height: its CPU
/// table (`Budget::cycles`), its memory-init table (`Budget::keys`), and its
/// program and image tables (`program::height`, the padded image length).
pub const PX_FN_LOG_CYCLES: u32 = 15;
pub const PX_FN_LOG_KEYS: u32 = 14;
pub const PX_FN_LOG_PROGRAM: u32 = 14;
pub const PX_FN_LOG_IMAGE: u32 = 14;
/// The tables shared with the kernel: `K.x + MAX_FN·b.x ≤ 2^cap` for the
/// kernel budget `K = kernel_budget(MAX_FN)`, so any pair of registered
/// functions fits together with the kernel.
pub const PX_LOG_ADD: u32 = 16;
pub const PX_LOG_BIT: u32 = 14;
pub const PX_LOG_LT: u32 = 16;
pub const PX_LOG_SHIFT: u32 = 14;
pub const PX_LOG_MUL: u32 = 14;
pub const PX_LOG_POSEIDON: u32 = 11;

// Every capped table stays at or below the tallest PX table,
// `PX_MAX_LOG_HEIGHT` (2^16, the byte table), which the PX5 shape check
// (`prove::check_shape_bits`) enforces.
const PX_MAX_LOG: u32 = PX_MAX_LOG_HEIGHT as u32;
const _: () = assert!(
    PX_FN_LOG_CYCLES <= PX_MAX_LOG
        && PX_FN_LOG_KEYS <= PX_MAX_LOG
        && PX_FN_LOG_PROGRAM <= PX_MAX_LOG
        && PX_FN_LOG_IMAGE <= PX_MAX_LOG
        && PX_LOG_ADD <= PX_MAX_LOG
        && PX_LOG_BIT <= PX_MAX_LOG
        && PX_LOG_LT <= PX_MAX_LOG
        && PX_LOG_SHIFT <= PX_MAX_LOG
        && PX_LOG_MUL <= PX_MAX_LOG
        && PX_LOG_POSEIDON <= PX_MAX_LOG
);
// The tallest PX table is the byte table, whose height is fixed.
const _: () = assert!(1usize << PX_MAX_LOG_HEIGHT == blacksilk_zkvm::air::byte::HEIGHT);

/// Whether a function with budget `b` is within the deploy-time row caps
/// (record `px-deploy-row-caps`, freeze gate B2; replaces R7-5's
/// "provable alone" rule):
/// - its own tables: `cycles ≤ 2^PX_FN_LOG_CYCLES`, `keys ≤ 2^PX_FN_LOG_KEYS`;
/// - the tables shared with the kernel (ALU and Poseidon2): with the kernel's
///   budget for the most functions, `K = kernel_budget(MAX_FN)`,
///   `K.x + MAX_FN·b.x ≤ 2^cap` in checked arithmetic.
///
/// So any `MAX_FN` registered functions fit together with the kernel, every
/// PX table stays at or below 2^16 rows, and the widest PX proof stays below
/// 3.8 MB (about 3.70 MB expected, 3.78 MB worst over the query positions,
/// by the B2 model). The function's program and image are capped separately
/// ([`program_is_provable`]).
pub fn budget_is_provable(b: &Budget) -> bool {
    let k = kernel_budget(MAX_FN);
    let within = |x: usize, kx: usize, log: u32| {
        x.checked_mul(MAX_FN)
            .and_then(|s| s.checked_add(kx))
            .is_some_and(|s| s <= 1usize << log)
    };
    b.cycles <= 1usize << PX_FN_LOG_CYCLES
        && b.keys <= 1usize << PX_FN_LOG_KEYS
        && within(b.add, k.add, PX_LOG_ADD)
        && within(b.bit, k.bit, PX_LOG_BIT)
        && within(b.lt, k.lt, PX_LOG_LT)
        && within(b.shift, k.shift, PX_LOG_SHIFT)
        && within(b.mul, k.mul, PX_LOG_MUL)
        && within(b.poseidon, k.poseidon, PX_LOG_POSEIDON)
}

/// Whether a registered program's own fixed tables are within the deploy
/// caps (record `px-deploy-row-caps`): its program table
/// (`program::height`) at most `2^PX_FN_LOG_PROGRAM` rows and its image
/// table (the initial image, code words, data and registers, padded to a
/// power of two) at most `2^PX_FN_LOG_IMAGE` rows. The image holds every
/// code word, so in practice the image bound is the tighter one.
pub fn program_is_provable(p: &Program) -> bool {
    use blacksilk_zkvm::air::{program, trace, MIN_HEIGHT};
    let image = trace::image(p).len().max(MIN_HEIGHT).next_power_of_two();
    program::height(p, MIN_HEIGHT) <= 1usize << PX_FN_LOG_PROGRAM
        && image <= 1usize << PX_FN_LOG_IMAGE
}

/// Every budget field at its largest value [`budget_is_provable`] allows
/// (the "V12 table" of the B2 research): `2^cap` for cycles and keys, and
/// `⌊(2^cap − K.x) / MAX_FN⌋` for the tables shared with the kernel.
/// Not a rule: the B2 measurements and the tests build on it.
pub fn largest_budget() -> Budget {
    let k = kernel_budget(MAX_FN);
    let shared = |kx: usize, log: u32| ((1usize << log) - kx) / MAX_FN;
    Budget {
        cycles: 1 << PX_FN_LOG_CYCLES,
        keys: 1 << PX_FN_LOG_KEYS,
        add: shared(k.add, PX_LOG_ADD),
        bit: shared(k.bit, PX_LOG_BIT),
        lt: shared(k.lt, PX_LOG_LT),
        shift: shared(k.shift, PX_LOG_SHIFT),
        mul: shared(k.mul, PX_LOG_MUL),
        poseidon: shared(k.poseidon, PX_LOG_POSEIDON),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blacksilk_zkvm::air::{program, trace, MIN_HEIGHT};
    use std::sync::Arc;

    fn fields(b: &Budget) -> [usize; 8] {
        [
            b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
        ]
    }

    fn field_mut(b: &mut Budget, i: usize) -> &mut usize {
        match i {
            0 => &mut b.cycles,
            1 => &mut b.keys,
            2 => &mut b.add,
            3 => &mut b.bit,
            4 => &mut b.lt,
            5 => &mut b.shift,
            6 => &mut b.mul,
            7 => &mut b.poseidon,
            _ => unreachable!(),
        }
    }

    /// The one numeric pin of the V12 caps and of the per-function maxima
    /// they give with the frozen kernel budget (record
    /// `v12-caps-single-definition`): every other user takes the values
    /// from this module, so a silent change of a cap fails here (and in the
    /// node's manifest pins).
    #[test]
    fn the_v12_caps_and_table_are_pinned() {
        assert_eq!(
            [
                PX_FN_LOG_CYCLES,
                PX_FN_LOG_KEYS,
                PX_FN_LOG_PROGRAM,
                PX_FN_LOG_IMAGE
            ],
            [15, 14, 14, 14]
        );
        assert_eq!(
            [
                PX_LOG_ADD,
                PX_LOG_BIT,
                PX_LOG_LT,
                PX_LOG_SHIFT,
                PX_LOG_MUL,
                PX_LOG_POSEIDON
            ],
            [16, 14, 16, 14, 14, 11]
        );
        assert_eq!(MAX_FN, 2);
        assert_eq!(
            fields(&largest_budget()),
            [32_768, 16_384, 20_168, 7_192, 22_493, 7_367, 7_367, 948]
        );
        assert_eq!(crate::prove::FN_RUN_LOG_CYCLES, PX_FN_LOG_CYCLES);
    }

    /// The budget rule at every field's boundary: the largest budget is
    /// allowed, one more on any field is refused, and an overflowing field
    /// is refused rather than wrapping.
    #[test]
    fn budget_rule_boundaries() {
        let top = largest_budget();
        assert!(budget_is_provable(&top));
        for i in 0..8 {
            let mut b = top;
            *field_mut(&mut b, i) += 1;
            assert!(!budget_is_provable(&b), "field {i} one above its cap");
            *field_mut(&mut b, i) = usize::MAX;
            assert!(!budget_is_provable(&b), "field {i} at usize::MAX");
            *field_mut(&mut b, i) = usize::MAX / MAX_FN + 1;
            assert!(!budget_is_provable(&b), "field {i}: product overflows");
        }
        assert!(budget_is_provable(&crate::vault::BUDGET));
        assert!(budget_is_provable(&Budget {
            cycles: 0,
            keys: 0,
            add: 0,
            bit: 0,
            lt: 0,
            shift: 0,
            mul: 0,
            poseidon: 0,
        }));
    }

    /// The vault with its code padded by `addi x0, x0, 0` to `code_len`
    /// words (never executed; the vault has no segment above its code).
    fn padded_vault(code_len: usize) -> Arc<Program> {
        let v = crate::vault::program();
        let mut code = v.code.clone();
        code.resize(code_len, 0x0000_0013);
        Arc::new(
            Program::new(v.entry, v.code_base, code, v.data.clone())
                .expect("the padded vault is a valid program"),
        )
    }

    /// The program rule at its boundaries: an image of exactly 2^14 words
    /// is allowed and one word more is refused; a program table of 2^15
    /// rows is refused.
    #[test]
    fn program_rule_boundaries() {
        let v = crate::vault::program();
        assert!(program_is_provable(&v));
        let extra = trace::image(&v).len() - v.code.len();
        let at_cap = (1 << PX_FN_LOG_IMAGE) - extra;
        let p = padded_vault(at_cap);
        assert_eq!(trace::image(&p).len(), 1 << PX_FN_LOG_IMAGE);
        assert!(program::height(&p, MIN_HEIGHT) <= 1 << PX_FN_LOG_PROGRAM);
        assert!(program_is_provable(&p), "image at the cap");
        let over = padded_vault(at_cap + 1);
        assert_eq!(trace::image(&over).len(), (1 << PX_FN_LOG_IMAGE) + 1);
        assert!(!program_is_provable(&over), "image one word above the cap");
        let tall = padded_vault((1 << PX_FN_LOG_PROGRAM) + 1);
        assert!(program::height(&tall, MIN_HEIGHT) > 1 << PX_FN_LOG_PROGRAM);
        assert!(!program_is_provable(&tall), "program table above the cap");
    }
}
