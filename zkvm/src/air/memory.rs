//! The endpoints of the offline memory argument (zkvm.md §6.3): `IMAGE`,
//! `MEM_INIT`, and the public `OUTPUT` table.
//!
//! **`IMAGE`** (preprocessed, verifier-computed) lists every word of the
//! initial image — code, data and the 32 registers — once, as
//! `(key, v0..v3)` on the image bus.
//!
//! **`MEM_INIT`** has one row per key used by the execution (plus every image
//! key). Each row produces the key's initial entry `(key, v_init, 0)` and
//! consumes its final entry `(key, v_final, t_final)` on the memory bus.
//! - Keys are range-checked (`< 2^27`) and strictly increasing, so every key
//!   appears exactly once.
//! - Image keys must be received from `IMAGE` with their image value
//!   (`in_image = 1`); since keys are unique, an image key cannot also appear
//!   with `in_image = 0`, and every non-image key starts at 0.
//!
//! With every access consuming the previous entry of its key and producing
//! the next, the memory bus balances exactly when every read returns the last
//! value written (Blum et al.).
//!
//! **`OUTPUT`** (preprocessed from the *claimed* public outputs) provides
//! `(index, v0..v3)` once per output word; the CPU consumes one per `WRITE`.

use super::byte::ByteCounter;
use super::util::{
    bytes, c, matrix, mem_consume, mem_produce, prep, range_bits, range_pair, row, IMAGE, OUTPUT,
    REG_BASE,
};
use blacksilk_zk::config::Val;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

/// Preprocessed `(key, v0..v3, is_real)` rows, sorted by key.
pub const IMAGE_PREP_WIDTH: usize = 6;
/// A single column that must be zero (the table's content is preprocessed).
pub const DUMMY_WIDTH: usize = 1;

pub fn image_preprocessed(words: &[(u32, u32)], min: usize) -> RowMajorMatrix<Val> {
    let rows = words
        .iter()
        .map(|&(k, v)| {
            let mut r = vec![Val::from_u32(k)];
            r.extend(bytes(v));
            r.push(Val::ONE);
            r
        })
        .collect();
    matrix(rows, IMAGE_PREP_WIDTH, min)
}

pub fn image_eval<AB: AirBuilder + InteractionBuilder>(b: &mut AB, exec: u32) {
    let (m, _) = row(b);
    let p = prep(b, DUMMY_WIDTH);
    b.assert_zero(m[0].clone());
    let mut msg = vec![c::<AB>(exec)];
    msg.extend_from_slice(&p[..5]);
    IMAGE.lookup_key(b, msg, Count::bounded(p[5].clone(), 1));
}

/// Preprocessed `(index, v0..v3, is_real)` rows of the claimed outputs.
pub fn output_preprocessed(output: &[u32], min: usize) -> RowMajorMatrix<Val> {
    let words: Vec<(u32, u32)> = output
        .iter()
        .enumerate()
        .map(|(i, v)| (i as u32, *v))
        .collect();
    image_preprocessed(&words, min)
}

pub fn output_eval<AB: AirBuilder + InteractionBuilder>(b: &mut AB, exec: u32) {
    let (m, _) = row(b);
    let p = prep(b, DUMMY_WIDTH);
    b.assert_zero(m[0].clone());
    let mut msg = vec![c::<AB>(exec)];
    msg.extend_from_slice(&p[..5]);
    OUTPUT.lookup_key(b, msg, Count::bounded(p[5].clone(), 1));
}

const IS_REAL: usize = 0;
const KEY: usize = 1;
const KB: usize = 2;
const VI: usize = 6;
const VF: usize = 10;
const TF: usize = 14;
const II: usize = 15;
const D: usize = 16;
pub const INIT_WIDTH: usize = 20;

pub fn init_eval<AB: AirBuilder + InteractionBuilder>(b: &mut AB, exec: u32) {
    let ex = c::<AB>(exec);
    let (r, n) = row(b);
    let real = r[IS_REAL].clone();
    b.assert_bool(real.clone());
    b.when_transition()
        .assert_zero((AB::Expr::ONE - real.clone()) * n[IS_REAL].clone());

    // The key and its range (< 2^27).
    let key_bytes = (0..4).fold(AB::Expr::ZERO, |a, i| {
        a + r[KB + i].clone() * c::<AB>(1 << (8 * i))
    });
    b.assert_zero(r[KEY].clone() - key_bytes);
    range_pair(b, r[KB].clone(), r[KB + 1].clone(), real.clone());
    range_pair(b, r[KB + 2].clone(), r[KB + 3].clone(), real.clone());
    range_bits(b, r[KB + 3].clone(), 3, real.clone());

    // Strictly increasing keys: next.key = key + 1 + next.D, with D < 2^27.
    for i in 0..4 {
        b.when_first_row().assert_zero(r[D + i].clone());
    }
    let next_d = (0..4).fold(AB::Expr::ZERO, |a, i| {
        a + n[D + i].clone() * c::<AB>(1 << (8 * i))
    });
    b.when_transition().assert_zero(
        n[IS_REAL].clone() * (n[KEY].clone() - r[KEY].clone() - AB::Expr::ONE - next_d),
    );
    range_pair(b, r[D].clone(), r[D + 1].clone(), real.clone());
    range_pair(b, r[D + 2].clone(), r[D + 3].clone(), real.clone());
    range_bits(b, r[D + 3].clone(), 3, real.clone());

    // Initial value: the image word, or 0.
    let ii = r[II].clone();
    b.assert_bool(ii.clone());
    b.assert_zero(ii.clone() * (AB::Expr::ONE - real.clone()));
    for i in 0..4 {
        b.assert_zero((AB::Expr::ONE - ii.clone()) * r[VI + i].clone());
    }
    let mut img = vec![ex.clone(), r[KEY].clone()];
    img.extend_from_slice(&r[VI..VI + 4]);
    IMAGE.table_entry(b, img, ii);

    // Endpoints of the key's history.
    mem_produce(
        b,
        ex.clone(),
        r[KEY].clone(),
        &r[VI..VI + 4],
        AB::Expr::ZERO,
        real.clone(),
    );
    mem_consume(
        b,
        ex.clone(),
        r[KEY].clone(),
        &r[VF..VF + 4],
        r[TF].clone(),
        real,
    );
}

/// One `MEM_INIT` row: `(key, init, final, final_ts, in_image)`.
pub struct InitRow {
    pub key: u32,
    pub init: u32,
    pub fin: u32,
    pub fin_ts: u32,
    pub in_image: bool,
}

/// The `MEM_INIT` trace; `rows` must be sorted by key with unique keys.
pub fn init_trace(rows: &[InitRow], counter: &mut ByteCounter, min: usize) -> RowMajorMatrix<Val> {
    let mut prev: Option<u32> = None;
    let out = rows
        .iter()
        .map(|x| {
            assert!(x.key < 1 << 27, "key out of range");
            let d = match prev {
                Some(p) => x
                    .key
                    .checked_sub(p + 1)
                    .expect("keys must be strictly increasing"),
                None => 0,
            };
            prev = Some(x.key);
            let kb = x.key.to_le_bytes();
            let db = d.to_le_bytes();
            counter.range(kb[0] as u32, kb[1] as u32);
            counter.range(kb[2] as u32, kb[3] as u32);
            counter.range_bits(kb[3] as u32, 3);
            counter.range(db[0] as u32, db[1] as u32);
            counter.range(db[2] as u32, db[3] as u32);
            counter.range_bits(db[3] as u32, 3);
            let mut r = vec![Val::ONE, Val::from_u32(x.key)];
            r.extend(bytes(x.key));
            r.extend(bytes(x.init));
            r.extend(bytes(x.fin));
            r.push(Val::from_u32(x.fin_ts));
            r.push(Val::from_bool(x.in_image));
            r.extend(bytes(d));
            r
        })
        .collect();
    matrix(out, INIT_WIDTH, min)
}

/// Registers in the image: all zero except the stack pointer.
pub fn register_image() -> Vec<(u32, u32)> {
    (0..32)
        .map(|r| (REG_BASE + r, if r == 2 { crate::STACK_TOP } else { 0 }))
        .collect()
}
