//! `POSEIDON2`: the `POSEIDON2` syscall (zkvm.md §5, §6).
//!
//! One row per syscall. Columns `0..P2_COLS` are Plonky3's
//! `Poseidon2Air` layout (BabyBear, width 16, S-box degree 7 with one register,
//! 4 + 4 full rounds, 13 partial rounds, standard constants), evaluated through
//! `SubAirBuilder` unchanged. After them come:
//! - the buffer pointer (bytes; 4-aligned, `< 2^28`) and its word key;
//! - for each of the 16 words: input bytes, the previous timestamp and its
//!   difference, output bytes, and canonical-encoding flags.
//!
//! **Memory.** Each word is consumed with its previous timestamp (which must be
//! below `4·(clk + 1) + 2`) and produced with the output at `4·(clk + 1) + 3`,
//! in the same offline memory argument as the CPU. (Reading at slot 2 and
//! writing at slot 3 would add a produce/consume pair at slot 2 that cancels
//! within the row; it is omitted.)
//!
//! **Bytes.** Input bytes are not range-checked here: a consumed tuple equals
//! a produced one, and every producer (image, CPU writes, this table's
//! outputs) range-checks its bytes. The CPU's register and memory reads rely
//! on the same argument. Output bytes are range-checked.
//!
//! **Canonical words.** The permutation works on field elements; memory holds
//! 32-bit words. Every input and output word must be the canonical encoding of
//! its field element (`value < p`), else one element would have two byte
//! encodings. For bytes `x0..x3` this is: either `x3 < 120`, or `x3 = 120` and
//! `x0 = x1 = x2 = 0` (`p − 1 = 120·2^24`). With the flag `e = [x3 = 120]`,
//! `x3 + 136 − 120·e` is a byte in both cases and only then; two words share
//! one byte-pair lookup.
//!
//! **Syscall.** The CPU of execution `e` requests `(e, clk, ptr)` on the
//! syscall bus; the row's `EX` column must equal `e`, and tags its memory
//! accesses. The table is shared by all executions of a proof. It also checks
//! `ptr ≥ CODE_END` and `ptr < 2^28 − 63`, so the whole 64-byte buffer is
//! writable memory.

use super::byte::ByteCounter;
use super::util::{
    bytes, c, mem_consume, mem_produce, range_bits, range_pair, range_word, row, SYSCALL,
};
use blacksilk_zk::config::Val;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::{
    GenericPoseidon2LinearLayersBabyBear, BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL, BABYBEAR_POSEIDON2_RC_16_INTERNAL,
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::{generate_trace_rows, num_cols, Poseidon2Air, RoundConstants};
use p3_uni_stark::SubAirBuilder;

pub type P2Air = Poseidon2Air<Val, GenericPoseidon2LinearLayersBabyBear, 16, 7, 1, 4, 13>;

pub const P2_COLS: usize = num_cols::<16, 7, 1, 4, 13>();
/// The permutation output: the `post` state of the last full round, the last
/// 16 columns of the Poseidon2 layout.
pub const P2_OUT: usize = P2_COLS - 16;

const IS_REAL: usize = P2_COLS;
const CLK: usize = IS_REAL + 1;
const PTR: usize = CLK + 1;
const PH: usize = PTR + 4;
const KEY: usize = PH + 1;
/// The execution that made the call (bound by the syscall lookup).
const EX: usize = KEY + 1;
const WORDS: usize = EX + 1;
/// Per word: in(4) ts(1) diff(3) out(4) canonical flags in/out(2).
const PER_WORD: usize = 14;
pub const WIDTH: usize = WORDS + 16 * PER_WORD;

pub fn constants() -> RoundConstants<Val, 16, 4, 13> {
    RoundConstants::new(
        BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
        BABYBEAR_POSEIDON2_RC_16_INTERNAL,
        BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    )
}

pub fn air() -> P2Air {
    P2Air::new(constants())
}

/// Constrains the flag `e` of bytes `x` (see the module notes) and returns
/// the value that must be a byte for `x` to be canonical.
fn canonical<AB: InteractionBuilder>(b: &mut AB, x: &[AB::Expr], e: AB::Expr) -> AB::Expr {
    b.assert_bool(e.clone());
    b.assert_zero(e.clone() * (x[3].clone() - c::<AB>(120)));
    for xi in &x[..3] {
        b.assert_zero(e.clone() * xi.clone());
    }
    x[3].clone() + c::<AB>(136) - e * c::<AB>(120)
}

fn word<AB: AirBuilder>(x: &[AB::Expr]) -> AB::Expr {
    (0..4).fold(AB::Expr::ZERO, |a, i| {
        a + x[i].clone() * c::<AB>(1 << (8 * i))
    })
}

pub fn eval<AB: AirBuilder<F = Val> + InteractionBuilder>(b: &mut AB) {
    {
        let mut sub: SubAirBuilder<'_, AB, P2Air, AB::Var> = SubAirBuilder::new(b, 0..P2_COLS);
        air().eval(&mut sub);
    }
    let (r, _) = row(b);
    let real = r[IS_REAL].clone();
    b.assert_bool(real.clone());

    let ptr: Vec<AB::Expr> = (0..4).map(|i| r[PTR + i].clone()).collect();
    range_word(b, &ptr, real.clone());
    range_bits(b, ptr[3].clone(), 4, real.clone());
    b.assert_zero(ptr[0].clone() - r[PH].clone() * c::<AB>(4));
    range_bits(b, r[PH].clone(), 6, real.clone());
    b.assert_zero(r[KEY].clone() * c::<AB>(4) - word::<AB>(&ptr));

    let clk1 = r[CLK].clone() + AB::Expr::ONE;
    let ts2 = clk1.clone() * c::<AB>(4) + c::<AB>(2);
    let ts3 = clk1 * c::<AB>(4) + c::<AB>(3);
    // Values checked two words per lookup: canonical-input and -output
    // bytes, and the top timestamp-difference byte.
    let mut pending: Vec<[AB::Expr; 3]> = Vec::new();
    for k in 0..16 {
        let base = WORDS + k * PER_WORD;
        let inp: Vec<AB::Expr> = (0..4).map(|i| r[base + i].clone()).collect();
        let tp = r[base + 4].clone();
        let d: Vec<AB::Expr> = (0..3).map(|i| r[base + 5 + i].clone()).collect();
        let out: Vec<AB::Expr> = (0..4).map(|i| r[base + 8 + i].clone()).collect();
        let (ei, eo) = (r[base + 12].clone(), r[base + 13].clone());

        // The permutation's input and output are these words (on padding
        // rows the permutation runs on zeros and the words are unused).
        b.assert_zero(real.clone() * (r[k].clone() - word::<AB>(&inp)));
        b.assert_zero(real.clone() * (r[P2_OUT + k].clone() - word::<AB>(&out)));
        let ci = canonical(b, &inp, ei);
        let co = canonical(b, &out, eo);
        range_word(b, &out, real.clone());

        // Consume the previous value, produce the output at slot 3.
        let key = r[KEY].clone() + c::<AB>(k as u32);
        mem_consume(
            b,
            r[EX].clone(),
            key.clone(),
            &inp,
            tp.clone(),
            real.clone(),
        );
        let diff = d[0].clone() + d[1].clone() * c::<AB>(256) + d[2].clone() * c::<AB>(65536);
        b.assert_zero(real.clone() * (ts2.clone() - tp - AB::Expr::ONE - diff));
        range_pair(b, d[0].clone(), d[1].clone(), real.clone());
        mem_produce(b, r[EX].clone(), key, &out, ts3.clone(), real.clone());
        pending.push([ci, co, d[2].clone()]);
    }
    for pair in pending.chunks(2) {
        for (x, y) in pair[0].iter().zip(&pair[1]) {
            range_pair(b, x.clone(), y.clone(), real.clone());
        }
    }
    let mut msg = vec![r[EX].clone(), r[CLK].clone()];
    msg.extend(ptr);
    SYSCALL.table_entry(b, msg, real);
}

/// One `POSEIDON2` syscall of the execution.
pub struct Call {
    /// The calling execution's id.
    pub exec: u32,
    pub clk: u32,
    pub ptr: u32,
    pub input: [u32; 16],
    pub prev_ts: [u32; 16],
    pub output: [u32; 16],
}

/// The canonical flag of `v` and the byte the lookup checks.
fn canonical_flag(v: u32) -> (Val, u32) {
    assert!(v < Val::ORDER_U32, "non-canonical word");
    let x3 = v >> 24;
    if x3 == 120 {
        (Val::ONE, 136)
    } else {
        (Val::ZERO, x3 + 136)
    }
}

pub fn trace(calls: &[Call], counter: &mut ByteCounter, min: usize) -> RowMajorMatrix<Val> {
    let h = calls.len().max(min).next_power_of_two();
    let inputs: Vec<[Val; 16]> = (0..h)
        .map(|i| match calls.get(i) {
            Some(call) => call.input.map(Val::from_u32),
            None => [Val::ZERO; 16],
        })
        .collect();
    let p2 = generate_trace_rows::<Val, GenericPoseidon2LinearLayersBabyBear, 16, 7, 1, 4, 13>(
        inputs,
        &constants(),
        0,
    );
    let mut v = vec![Val::ZERO; h * WIDTH];
    for i in 0..h {
        v[i * WIDTH..i * WIDTH + P2_COLS]
            .copy_from_slice(&p2.values[i * P2_COLS..(i + 1) * P2_COLS]);
        let Some(call) = calls.get(i) else { continue };
        let r = &mut v[i * WIDTH..(i + 1) * WIDTH];
        r[IS_REAL] = Val::ONE;
        r[CLK] = Val::from_u32(call.clk);
        r[PTR..PTR + 4].copy_from_slice(&bytes(call.ptr));
        counter.word(call.ptr);
        counter.range_bits(call.ptr >> 24, 4);
        r[PH] = Val::from_u32((call.ptr & 0xff) >> 2);
        counter.range_bits((call.ptr & 0xff) >> 2, 6);
        r[KEY] = Val::from_u32(call.ptr / 4);
        r[EX] = Val::from_u32(call.exec);
        let ts2 = 4 * (call.clk + 1) + 2;
        let mut pending = Vec::new();
        for k in 0..16 {
            let base = WORDS + k * PER_WORD;
            r[base..base + 4].copy_from_slice(&bytes(call.input[k]));
            r[base + 4] = Val::from_u32(call.prev_ts[k]);
            let d = ts2 - call.prev_ts[k] - 1;
            assert!(d < 1 << 24);
            let db = d.to_le_bytes();
            counter.range(db[0] as u32, db[1] as u32);
            r[base + 5..base + 8]
                .copy_from_slice(&[db[0], db[1], db[2]].map(|x| Val::from_u32(x as u32)));
            r[base + 8..base + 12].copy_from_slice(&bytes(call.output[k]));
            counter.word(call.output[k]);
            let (ei, ci) = canonical_flag(call.input[k]);
            let (eo, co) = canonical_flag(call.output[k]);
            r[base + 12] = ei;
            r[base + 13] = eo;
            pending.push([ci, co, db[2] as u32]);
            // The AIR's output columns must equal the permutation computed by
            // the interpreter (the same permutation, standard constants).
            assert_eq!(
                r[P2_OUT + k],
                Val::from_u32(call.output[k]),
                "Poseidon2 AIR and interpreter disagree"
            );
        }
        for pair in pending.chunks(2) {
            for (&x, &y) in pair[0].iter().zip(&pair[1]) {
                counter.range(x, y);
            }
        }
    }
    RowMajorMatrix::new(v, WIDTH)
}

/// Satisfies `BaseAir` for the embedded sub-AIR (width only).
pub fn p2_width() -> usize {
    <P2Air as BaseAir<Val>>::width(&air())
}
