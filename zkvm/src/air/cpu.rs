//! `CPU`: one row per executed instruction (zkvm.md §6).
//!
//! **Control.**
//! - Real rows come first and start at `clk = 0`, `pc = entry` (public).
//! - Each real row is followed by a real row with `clk + 1`, `pc = next_pc`, or
//!   is the last real row, which must be `HALT`.
//! - Rows after `HALT` are padding and are **inert**: all their instruction
//!   fields and syscall flags are forced to zero, so they make no lookups and
//!   no memory accesses.
//!
//! **Decoding.** `(pc, fields…)` is looked up in `PROGRAM`, so every real row
//! executes an instruction of the committed program with its exact decoding.
//!
//! **Registers and memory.** Every row reads two registers (slots 0 and 1) and,
//! when it writes, writes one (slot 3). Loads and stores read the memory word
//! (slot 2); stores write it (slot 3). Each access consumes the key's previous
//! entry and produces the next, with `t − t_prev − 1 ∈ [0, 2^24)`.
//!
//! **Values.**
//! - The value `C` an instruction computes is always constrained (even for
//!   `rd = x0`); only the register write is gated by `rd ≠ 0`.
//! - ALU results come from the ALU tables.
//! - Computed addresses and jump targets are range-checked below 2^28 before
//!   they are used as field elements (zkvm.md §2).
//! - Columns an instruction does not use are forced to zero, so the witness
//!   is unique.

use super::program::{class, f};
use super::util::{
    alu_op, c, mem_consume, mem_produce, range_bits, range_pair, range_word, row, ALU, OUTPUT,
    PROGRAM, REG_BASE,
};
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, InteractionBuilder};

pub const IS_REAL: usize = 0;
pub const CLK: usize = 1;
pub const PC: usize = 2;
pub const NEXT_PC: usize = 3;
pub const INS: usize = 4;
pub const A: usize = INS + f::COUNT; // 30
pub const TA: usize = A + 4;
pub const DA: usize = TA + 1;
pub const B: usize = DA + 3;
pub const TB: usize = B + 4;
pub const DB: usize = TB + 1;
pub const C: usize = DB + 3;
pub const CP: usize = C + 4;
pub const TC: usize = CP + 4;
pub const DC: usize = TC + 1;
pub const S: usize = DC + 3;
pub const L0: usize = S + 4;
pub const L1: usize = L0 + 1;
pub const H: usize = L1 + 1;
pub const O: usize = H + 1;
pub const WK: usize = O + 4;
pub const M: usize = WK + 1;
pub const TM: usize = M + 4;
pub const DM: usize = TM + 1;
pub const N: usize = DM + 3;
pub const SGN: usize = N + 4;
pub const SR: usize = SGN + 1;
pub const COND: usize = SR + 1;
pub const PB: usize = COND + 1;
pub const SH: usize = PB + 4;
pub const SRD: usize = SH + 1;
pub const SWR: usize = SRD + 1;
pub const OUT: usize = SWR + 1;
pub const WIDTH: usize = OUT + 1;

/// Public values of the CPU table.
pub mod pv {
    pub const ENTRY: usize = 0;
    pub const CODE_END: usize = 1; // 4 bytes
    pub const EXIT: usize = 5; // 4 bytes
    pub const N_OUT: usize = 9;
    /// The 32-byte transaction binding as 16 little-endian 16-bit limbs;
    /// absorbed in the transcript, not otherwise constrained.
    pub const BINDING: usize = 10;
    pub const COUNT: usize = 26;
}

/// `x0 + 256·x1 + 65536·x2 + 2^24·x3`.
fn word<AB: AirBuilder>(x: &[AB::Expr]) -> AB::Expr {
    (0..4).fold(AB::Expr::ZERO, |a, i| {
        a + x[i].clone() * c::<AB>(1 << (8 * i))
    })
}

fn diff24<AB: AirBuilder>(d: &[AB::Expr]) -> AB::Expr {
    d[0].clone() + d[1].clone() * c::<AB>(256) + d[2].clone() * c::<AB>(65536)
}

/// Range-checks a 3-byte timestamp difference.
fn range_diff<AB: InteractionBuilder>(b: &mut AB, d: &[AB::Expr], count: AB::Expr) {
    range_pair(b, d[0].clone(), d[1].clone(), count.clone());
    range_pair(b, d[2].clone(), AB::Expr::ZERO, count);
}

pub fn eval<AB: AirBuilder + InteractionBuilder>(b: &mut AB) {
    let (r, n) = row(b);
    let pvs: Vec<AB::Expr> = b.public_values().iter().map(|v| (*v).into()).collect();
    let one = AB::Expr::ONE;
    let real = r[IS_REAL].clone();
    let fl = |k: usize| r[INS + f::FLAGS + k].clone();
    let fld = |k: usize| r[INS + k].clone();
    let (f_rr, f_ri, f_lui, f_auipc) = (
        fl(class::ALU_RR),
        fl(class::ALU_RI),
        fl(class::LUI),
        fl(class::AUIPC),
    );
    let (f_jal, f_jalr, f_br, f_ld) = (
        fl(class::JAL),
        fl(class::JALR),
        fl(class::BRANCH),
        fl(class::LOAD),
    );
    let (f_st, f_ecall) = (fl(class::STORE), fl(class::ECALL));
    let (kb, kh, kw, sg) = (fld(f::KB), fld(f::KH), fld(f::KW), fld(f::SIGNED));
    let (alu, br_neg, rdw, imm_f) = (
        fld(f::ALU_OP),
        fld(f::BR_NEG),
        fld(f::RD_WRITE),
        fld(f::IMM_F),
    );
    let imm: Vec<AB::Expr> = (0..4).map(|i| fld(f::IMM + i)).collect();
    let v = |base: usize| -> Vec<AB::Expr> { (0..4).map(|i| r[base + i].clone()).collect() };
    let (a, bb, cc, s, m, nn, pb) = (v(A), v(B), v(C), v(S), v(M), v(N), v(PB));
    let (sh, srd, swr) = (r[SH].clone(), r[SRD].clone(), r[SWR].clone());
    let mem = f_ld.clone() + f_st.clone();
    let addr_use = mem.clone() + f_jalr.clone();
    let write = rdw.clone() + f_ecall.clone() * srd.clone();
    let computes = f_rr.clone()
        + f_ri.clone()
        + f_lui.clone()
        + f_auipc.clone()
        + f_jal.clone()
        + f_jalr.clone()
        + f_ld.clone()
        + f_ecall.clone() * srd.clone();
    let clk1 = r[CLK].clone() + one.clone();
    let ts = |slot: u32| clk1.clone() * c::<AB>(4) + c::<AB>(slot);

    // ---- control ----
    b.assert_bool(real.clone());
    b.when_transition()
        .assert_zero((one.clone() - real.clone()) * n[IS_REAL].clone());
    b.when_first_row().assert_one(real.clone());
    b.when_first_row().assert_zero(r[CLK].clone());
    b.when_first_row()
        .assert_zero(r[PC].clone() - pvs[pv::ENTRY].clone());
    b.when_first_row().assert_zero(r[OUT].clone());
    {
        let nr = n[IS_REAL].clone();
        let mut t = b.when_transition();
        t.assert_zero(nr.clone() * (n[CLK].clone() - clk1.clone()));
        t.assert_zero(nr.clone() * (n[PC].clone() - r[NEXT_PC].clone()));
        t.assert_zero(nr.clone() * (n[OUT].clone() - r[OUT].clone() - swr.clone()));
        // The last real row halts, and nothing runs after a halt.
        t.assert_zero(real.clone() * (one.clone() - nr.clone()) * (one.clone() - sh.clone()));
        t.assert_zero(sh.clone() * nr);
    }
    b.when_last_row()
        .assert_zero(real.clone() * (one.clone() - sh.clone()));
    for i in 0..4 {
        b.assert_zero(sh.clone() * (bb[i].clone() - pvs[pv::EXIT + i].clone()));
    }
    b.assert_zero(sh.clone() * (r[OUT].clone() - pvs[pv::N_OUT].clone()));

    // Padding rows are inert.
    for k in 0..f::COUNT {
        b.assert_zero((one.clone() - real.clone()) * fld(k));
    }

    // ---- decode ----
    let mut fetch = vec![r[PC].clone()];
    fetch.extend((0..f::COUNT).map(fld));
    PROGRAM.lookup_key(b, fetch, Count::bounded(real.clone(), 1));

    // pc bytes (pc < 2^28), used as an ALU operand for AUIPC/JAL/JALR.
    b.assert_zero(r[PC].clone() - word::<AB>(&pb));
    range_word(b, &pb, real.clone());
    range_bits(b, pb[3].clone(), 4, real.clone());

    // ---- register reads (slots 0, 1) ----
    for (base, t_col, d_col, idx, slot) in [(A, TA, DA, f::RS1, 0u32), (B, TB, DB, f::RS2, 1)] {
        let key = c::<AB>(REG_BASE) + fld(idx);
        let val = v(base);
        let d: Vec<AB::Expr> = (0..3).map(|i| r[d_col + i].clone()).collect();
        mem_consume(b, key.clone(), &val, r[t_col].clone(), real.clone());
        mem_produce(b, key, &val, ts(slot), real.clone());
        b.assert_zero(
            real.clone() * (ts(slot) - r[t_col].clone() - one.clone() - diff24::<AB>(&d)),
        );
        range_diff(b, &d, real.clone());
    }

    // ---- register write (slot 3) ----
    {
        let key = c::<AB>(REG_BASE) + fld(f::RD);
        let d: Vec<AB::Expr> = (0..3).map(|i| r[DC + i].clone()).collect();
        mem_consume(b, key.clone(), &v(CP), r[TC].clone(), write.clone());
        mem_produce(b, key, &cc, ts(3), write.clone());
        b.assert_zero(write.clone() * (ts(3) - r[TC].clone() - one.clone() - diff24::<AB>(&d)));
        range_diff(b, &d, write.clone());
        let no_write = one.clone() - write.clone();
        for i in 0..4 {
            b.assert_zero(no_write.clone() * r[CP + i].clone());
        }
        b.assert_zero(no_write.clone() * r[TC].clone());
        for x in &d {
            b.assert_zero(no_write.clone() * x.clone());
        }
    }
    range_word(b, &cc, computes.clone());
    for x in &cc {
        b.assert_zero((one.clone() - computes.clone()) * x.clone());
    }

    // ---- computed values ----
    let alu_msg = |op: AB::Expr, x: &[AB::Expr], y: &[AB::Expr], z: &[AB::Expr]| -> Vec<AB::Expr> {
        let mut msg = vec![op];
        msg.extend_from_slice(x);
        msg.extend_from_slice(y);
        msg.extend_from_slice(z);
        msg
    };
    ALU.lookup_key(
        b,
        alu_msg(alu.clone(), &a, &bb, &cc),
        Count::bounded(f_rr, 1),
    );
    ALU.lookup_key(
        b,
        alu_msg(alu.clone(), &a, &imm, &cc),
        Count::bounded(f_ri, 1),
    );
    for i in 0..4 {
        b.assert_zero(f_lui.clone() * (cc[i].clone() - imm[i].clone()));
    }
    let add = c::<AB>(alu_op::ADD);
    ALU.lookup_key(
        b,
        alu_msg(add.clone(), &pb, &imm, &cc),
        Count::bounded(f_auipc, 1),
    );
    let four = [c::<AB>(4), AB::Expr::ZERO, AB::Expr::ZERO, AB::Expr::ZERO];
    ALU.lookup_key(
        b,
        alu_msg(add.clone(), &pb, &four, &cc),
        Count::bounded(f_jal.clone() + f_jalr.clone(), 1),
    );

    // ---- branches ----
    let cond = r[COND].clone();
    let zero3 = [AB::Expr::ZERO, AB::Expr::ZERO, AB::Expr::ZERO];
    let mut cmp_res = vec![cond.clone()];
    cmp_res.extend(zero3.iter().cloned());
    ALU.lookup_key(
        b,
        alu_msg(alu.clone(), &a, &bb, &cmp_res),
        Count::bounded(f_br.clone(), 1),
    );
    b.assert_zero((one.clone() - f_br.clone()) * cond.clone());
    let taken = cond.clone() + br_neg * (one.clone() - cond * c::<AB>(2));

    // ---- addresses (loads, stores, JALR) ----
    ALU.lookup_key(
        b,
        alu_msg(add, &a, &imm, &s),
        Count::bounded(addr_use.clone(), 1),
    );
    range_bits(b, s[3].clone(), 4, addr_use.clone());
    let (l0, l1, h) = (r[L0].clone(), r[L1].clone(), r[H].clone());
    b.assert_bool(l0.clone());
    b.assert_bool(l1.clone());
    b.assert_zero(
        addr_use.clone()
            * (s[0].clone() - l0.clone() - l1.clone() * c::<AB>(2) - h.clone() * c::<AB>(4)),
    );
    range_bits(b, h.clone(), 6, addr_use.clone());
    let not_addr = one.clone() - addr_use.clone();
    for x in s.iter().chain([&l0, &l1, &h]) {
        b.assert_zero(not_addr.clone() * x.clone());
    }
    let addr_f = word::<AB>(&s);
    let o: Vec<AB::Expr> = (0..4).map(|k| r[O + k].clone()).collect();
    let (nl0, nl1) = (one.clone() - l0.clone(), one.clone() - l1.clone());
    b.assert_zero(o[0].clone() - mem.clone() * nl0.clone() * nl1.clone());
    b.assert_zero(o[1].clone() - mem.clone() * l0.clone() * nl1.clone());
    b.assert_zero(o[2].clone() - mem.clone() * nl0 * l1.clone());
    b.assert_zero(o[3].clone() - mem.clone() * l0.clone() * l1.clone());
    b.assert_zero(kw.clone() * l0.clone());
    b.assert_zero(kw.clone() * l1.clone());
    b.assert_zero(kh.clone() * l0.clone());
    b.assert_zero(
        mem.clone()
            * (r[WK].clone() * c::<AB>(4) + l0.clone() + l1.clone() * c::<AB>(2) - addr_f.clone()),
    );
    b.assert_zero((one.clone() - mem.clone()) * r[WK].clone());
    // addr ≥ NULL_GUARD = 0x1000, and stores at or above the end of the code.
    let zero4 = [
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
    ];
    let guard = [
        AB::Expr::ZERO,
        c::<AB>(0x10),
        AB::Expr::ZERO,
        AB::Expr::ZERO,
    ];
    let sltu = c::<AB>(alu_op::SLTU);
    ALU.lookup_key(
        b,
        alu_msg(sltu.clone(), &s, &guard, &zero4),
        Count::bounded(mem.clone(), 1),
    );
    let code_end: Vec<AB::Expr> = (0..4).map(|i| pvs[pv::CODE_END + i].clone()).collect();
    ALU.lookup_key(
        b,
        alu_msg(sltu, &s, &code_end, &zero4),
        Count::bounded(f_st.clone(), 1),
    );

    // ---- next pc ----
    let jalr_target = addr_f - l0;
    let pc = r[PC].clone();
    let expected = pc.clone()
        + c::<AB>(4)
        + f_jal * (imm_f.clone() - c::<AB>(4))
        + f_br * taken * (imm_f - c::<AB>(4))
        + f_jalr * (jalr_target - pc - c::<AB>(4));
    b.assert_zero(real.clone() * (r[NEXT_PC].clone() - expected));

    // ---- memory word (slot 2 read, slot 3 write) ----
    {
        let key = r[WK].clone();
        let d: Vec<AB::Expr> = (0..3).map(|i| r[DM + i].clone()).collect();
        mem_consume(b, key.clone(), &m, r[TM].clone(), mem.clone());
        mem_produce(b, key.clone(), &m, ts(2), mem.clone());
        b.assert_zero(mem.clone() * (ts(2) - r[TM].clone() - one.clone() - diff24::<AB>(&d)));
        range_diff(b, &d, mem.clone());
        mem_consume(b, key.clone(), &m, ts(2), f_st.clone());
        mem_produce(b, key, &nn, ts(3), f_st.clone());
        range_word(b, &nn, f_st.clone());
        let no_mem = one.clone() - mem.clone();
        for x in m.iter().chain(d.iter()).chain([&r[TM]]) {
            b.assert_zero(no_mem.clone() * x.clone());
        }
        for x in &nn {
            b.assert_zero((one.clone() - f_st.clone()) * x.clone());
        }
    }

    // ---- load value ----
    let sel_b = (0..4).fold(AB::Expr::ZERO, |acc, k| acc + o[k].clone() * m[k].clone());
    let half_lo = o[0].clone() * m[0].clone() + o[2].clone() * m[2].clone();
    let half_hi = o[0].clone() * m[1].clone() + o[2].clone() * m[3].clone();
    let (sgn, sr) = (r[SGN].clone(), r[SR].clone());
    let signed_load = f_ld.clone() * sg;
    b.assert_bool(sgn.clone());
    b.assert_zero((one.clone() - signed_load.clone()) * sgn.clone());
    b.assert_zero((one.clone() - signed_load.clone()) * sr.clone());
    let sign_byte = kb.clone() * sel_b.clone() + kh.clone() * half_hi.clone();
    b.assert_zero(signed_load.clone() * (sign_byte - sgn.clone() * c::<AB>(128) - sr.clone()));
    range_bits(b, sr, 7, signed_load);
    let ext = sgn * c::<AB>(255);
    let lb = f_ld.clone() * kb.clone();
    b.assert_zero(lb.clone() * (cc[0].clone() - sel_b));
    for x in &cc[1..] {
        b.assert_zero(lb.clone() * (x.clone() - ext.clone()));
    }
    let lh = f_ld.clone() * kh.clone();
    b.assert_zero(lh.clone() * (cc[0].clone() - half_lo));
    b.assert_zero(lh.clone() * (cc[1].clone() - half_hi));
    for x in &cc[2..] {
        b.assert_zero(lh.clone() * (x.clone() - ext.clone()));
    }
    let lw = f_ld * kw.clone();
    for i in 0..4 {
        b.assert_zero(lw.clone() * (cc[i].clone() - m[i].clone()));
    }

    // ---- store value ----
    let sb = f_st.clone() * kb;
    for k in 0..4 {
        b.assert_zero(
            sb.clone()
                * (nn[k].clone()
                    - o[k].clone() * bb[0].clone()
                    - (one.clone() - o[k].clone()) * m[k].clone()),
        );
    }
    let shw = f_st.clone() * kh;
    for (k, off, src) in [(0usize, 0usize, 0usize), (1, 0, 1), (2, 2, 0), (3, 2, 1)] {
        b.assert_zero(
            shw.clone()
                * (nn[k].clone()
                    - o[off].clone() * bb[src].clone()
                    - (one.clone() - o[off].clone()) * m[k].clone()),
        );
    }
    let sw = f_st * kw;
    for k in 0..4 {
        b.assert_zero(sw.clone() * (nn[k].clone() - bb[k].clone()));
    }

    // ---- system calls ----
    for x in [&sh, &srd, &swr] {
        b.assert_bool(x.clone());
    }
    b.assert_zero(sh.clone() + srd.clone() + swr.clone() - f_ecall.clone());
    b.assert_zero(f_ecall.clone() * (a[0].clone() - srd - swr.clone() * c::<AB>(2)));
    for x in &a[1..] {
        b.assert_zero(f_ecall.clone() * x.clone());
    }
    let mut out = vec![r[OUT].clone()];
    out.extend(bb.iter().cloned());
    OUTPUT.table_entry(b, out, swr);
}
