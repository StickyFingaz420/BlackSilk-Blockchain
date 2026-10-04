//! Structure-aware proof mutation (T-1 d).
//!
//! `proofs.rs::byte_mutations_never_verify_and_never_panic_the_caller` flips
//! evenly spaced bytes, which mostly hits the middle of field elements and
//! rarely a whole element. This test locates **every field element** of a
//! small proof's encoding (Plonky3 serializes each BabyBear element as a fixed
//! 4-byte array; extension elements are 8 of them) with a layout-recording
//! serde serializer that reproduces postcard's format byte for byte, then
//! replaces elements one at a time with another canonical field element
//! (`v + 1 mod p`, and `−v` on a sample). Every such proof must be refused:
//! by the strict decoder, or by verification.
//!
//! The proof is the two-table toy statement of `proofs.rs` (256 rows), not a
//! zkVM/PX proof: it is cheap to produce. The proof has 59 395 field elements
//! (242 228 bytes); every element cannot be verified in reasonable time, so a
//! stride is used. Measured 2026-09-27, release build without LTO: ~6 000
//! elements (stride 10) plus ~750 negations in 136 s. Debug builds use a
//! target of ~300 elements (426 mutations in 147 s, same day). The proof
//! size varied between the two runs (242 228 / 240 468 bytes) with the same
//! seed. `BLACKSILK_ZK_FIELD_STRIDE` overrides the stride
//! (1 = every element); the first and last 64 elements are always included.

use blacksilk_zk::config::{ProverConfig, Val, VerifierConfig};
use blacksilk_zk::{decode_proof, encode_proof, prove, verify, ZkError};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_lookup::{InteractionBuilder, LookupBus};
use p3_matrix::dense::RowMajorMatrix;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::ser::{self, Serialize};

// ------------------------------------------------ the toy statement (proofs.rs)

const RANGE: LookupBus<'static> = LookupBus::new("test/range");
const BINDING: usize = 4;

#[derive(Clone, Copy, Debug)]
enum Toy {
    Counter,
    Range,
}

impl<F> BaseAir<F> for Toy {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        match self {
            Toy::Counter => 2 + BINDING,
            Toy::Range => 0,
        }
    }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for Toy {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let local: Vec<AB::Expr> = main.current_slice().iter().map(|v| (*v).into()).collect();
        let next: Vec<AB::Expr> = main.next_slice().iter().map(|v| (*v).into()).collect();
        match self {
            Toy::Counter => {
                let pis: Vec<AB::Expr> = b.public_values().iter().map(|v| (*v).into()).collect();
                let (x, sq) = (local[0].clone(), local[1].clone());
                b.assert_zero(sq.clone() - x.clone() * x.clone());
                b.when_first_row().assert_zero(x.clone() - pis[0].clone());
                b.when_transition()
                    .assert_zero(next[0].clone() - x.clone() - AB::Expr::ONE);
                b.when_last_row().assert_zero(sq - pis[1].clone());
                RANGE.lookup_key(b, [x], 1);
            }
            Toy::Range => {
                let (v, mult) = (local[0].clone(), local[1].clone());
                b.when_first_row().assert_zero(v.clone());
                b.when_transition()
                    .assert_zero(next[0].clone() - v.clone() - AB::Expr::ONE);
                RANGE.table_entry(b, [v], mult);
            }
        }
    }
}

const AIRS: [Toy; 2] = [Toy::Counter, Toy::Range];
const LIMITS: [usize; 2] = [16, 16];

fn statement() -> (Vec<RowMajorMatrix<Val>>, Vec<Vec<Val>>) {
    let (start, n, range) = (3u32, 256usize, 512usize);
    let mut counter = Vec::with_capacity(2 * n);
    let mut mult = vec![0u32; range];
    for i in 0..n as u32 {
        let x = start + i;
        counter.push(Val::from_u32(x));
        counter.push(Val::from_u32(x) * Val::from_u32(x));
        mult[x as usize] += 1;
    }
    let mut table = Vec::with_capacity(2 * range);
    for (v, m) in mult.iter().enumerate() {
        table.push(Val::from_u32(v as u32));
        table.push(Val::from_u32(*m));
    }
    let last = start + n as u32 - 1;
    let mut pv = vec![
        Val::from_u32(start),
        Val::from_u32(last) * Val::from_u32(last),
    ];
    pv.extend((0..BINDING as u32).map(|i| Val::from_u32(16 + i)));
    (
        vec![
            RowMajorMatrix::new(counter, 2),
            RowMajorMatrix::new(table, 2),
        ],
        vec![pv, vec![]],
    )
}

// ------------------------------------- a postcard-layout recording serializer

#[derive(Debug)]
struct LayoutError(String);
impl std::fmt::Display for LayoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for LayoutError {}
impl ser::Error for LayoutError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        LayoutError(msg.to_string())
    }
}

/// Writes postcard's wire format and records the offset of every 4-byte
/// tuple made of four `u8`s (a serialized field element).
#[derive(Default)]
struct Layout {
    out: Vec<u8>,
    u8_calls: usize,
    other_calls: usize,
    tuples: Vec<(usize, usize, usize, usize)>, // (len, start, u8 calls, other calls)
    fields: Vec<usize>,
}

impl Layout {
    fn varint(&mut self, mut v: u128) {
        self.other_calls += 1;
        while v >= 0x80 {
            self.out.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        self.out.push(v as u8);
    }
    fn raw(&mut self, b: &[u8]) {
        self.other_calls += 1;
        self.out.extend_from_slice(b);
    }
}

type R = Result<(), LayoutError>;

impl ser::Serializer for &mut Layout {
    type Ok = ();
    type Error = LayoutError;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn is_human_readable(&self) -> bool {
        false
    }
    fn serialize_bool(self, v: bool) -> R {
        self.raw(&[v as u8]);
        Ok(())
    }
    fn serialize_i8(self, v: i8) -> R {
        self.raw(&[v as u8]);
        Ok(())
    }
    fn serialize_i16(self, v: i16) -> R {
        self.varint(((v << 1) ^ (v >> 15)) as u16 as u128);
        Ok(())
    }
    fn serialize_i32(self, v: i32) -> R {
        self.varint(((v << 1) ^ (v >> 31)) as u32 as u128);
        Ok(())
    }
    fn serialize_i64(self, v: i64) -> R {
        self.varint(((v << 1) ^ (v >> 63)) as u64 as u128);
        Ok(())
    }
    fn serialize_u8(self, v: u8) -> R {
        self.u8_calls += 1;
        self.out.push(v);
        Ok(())
    }
    fn serialize_u16(self, v: u16) -> R {
        self.varint(v as u128);
        Ok(())
    }
    fn serialize_u32(self, v: u32) -> R {
        self.varint(v as u128);
        Ok(())
    }
    fn serialize_u64(self, v: u64) -> R {
        self.varint(v as u128);
        Ok(())
    }
    fn serialize_u128(self, v: u128) -> R {
        self.varint(v);
        Ok(())
    }
    fn serialize_f32(self, v: f32) -> R {
        self.raw(&v.to_bits().to_le_bytes());
        Ok(())
    }
    fn serialize_f64(self, v: f64) -> R {
        self.raw(&v.to_bits().to_le_bytes());
        Ok(())
    }
    fn serialize_char(self, v: char) -> R {
        let mut b = [0u8; 4];
        self.serialize_str(v.encode_utf8(&mut b))
    }
    fn serialize_str(self, v: &str) -> R {
        self.varint(v.len() as u128);
        self.raw(v.as_bytes());
        Ok(())
    }
    fn serialize_bytes(self, v: &[u8]) -> R {
        self.varint(v.len() as u128);
        self.raw(v);
        Ok(())
    }
    fn serialize_none(self) -> R {
        self.raw(&[0]);
        Ok(())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> R {
        self.raw(&[1]);
        value.serialize(self)
    }
    fn serialize_unit(self) -> R {
        Ok(())
    }
    fn serialize_unit_struct(self, _: &'static str) -> R {
        Ok(())
    }
    fn serialize_unit_variant(self, _: &'static str, i: u32, _: &'static str) -> R {
        self.varint(i as u128);
        Ok(())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(self, _: &'static str, v: &T) -> R {
        v.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        i: u32,
        _: &'static str,
        v: &T,
    ) -> R {
        self.varint(i as u128);
        v.serialize(self)
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Self, LayoutError> {
        let len = len.ok_or_else(|| LayoutError("unknown length".into()))?;
        self.varint(len as u128);
        Ok(self)
    }
    fn serialize_tuple(self, len: usize) -> Result<Self, LayoutError> {
        self.tuples
            .push((len, self.out.len(), self.u8_calls, self.other_calls));
        Ok(self)
    }
    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self, LayoutError> {
        self.tuples.push((0, 0, 0, 0));
        Ok(self)
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        i: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self, LayoutError> {
        self.varint(i as u128);
        self.tuples.push((0, 0, 0, 0));
        Ok(self)
    }
    fn serialize_map(self, len: Option<usize>) -> Result<Self, LayoutError> {
        let len = len.ok_or_else(|| LayoutError("unknown length".into()))?;
        self.varint(len as u128);
        Ok(self)
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self, LayoutError> {
        Ok(self)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        i: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self, LayoutError> {
        self.varint(i as u128);
        Ok(self)
    }
}

impl Layout {
    fn end_tuple(&mut self) {
        let (len, start, u8s, others) = self.tuples.pop().expect("tuple stack");
        if len == 4
            && self.out.len() - start == 4
            && self.u8_calls - u8s == 4
            && self.other_calls == others
        {
            self.fields.push(start);
        }
    }
}

macro_rules! compound {
    ($trait:ident, $method:ident $(, $key:ident)?) => {
        impl ser::$trait for &mut Layout {
            type Ok = ();
            type Error = LayoutError;
            fn $method<T: ?Sized + Serialize>(&mut self, $($key: &'static str,)? v: &T) -> R {
                v.serialize(&mut **self)
            }
            fn end(self) -> R {
                compound!(@end self, $trait);
                Ok(())
            }
        }
    };
    (@end $s:ident, SerializeTuple) => { $s.end_tuple() };
    (@end $s:ident, SerializeTupleStruct) => { $s.end_tuple() };
    (@end $s:ident, SerializeTupleVariant) => { $s.end_tuple() };
    (@end $s:ident, $other:ident) => { let _ = $s; };
}
compound!(SerializeSeq, serialize_element);
compound!(SerializeTuple, serialize_element);
compound!(SerializeTupleStruct, serialize_field);
compound!(SerializeTupleVariant, serialize_field);
compound!(SerializeStruct, serialize_field, _k);
compound!(SerializeStructVariant, serialize_field, _k);

impl ser::SerializeMap for &mut Layout {
    type Ok = ();
    type Error = LayoutError;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, k: &T) -> R {
        k.serialize(&mut **self)
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, v: &T) -> R {
        v.serialize(&mut **self)
    }
    fn end(self) -> R {
        Ok(())
    }
}

// ------------------------------------------------------------------ the test

const P: u32 = Val::ORDER_U32;

#[test]
fn every_field_element_mutation_is_refused() {
    let (traces, pv) = statement();
    let cfg = ProverConfig::new(&[42; 32], &mut ChaCha20Rng::seed_from_u64(42));
    let proof = prove(&cfg, &AIRS, &traces, &pv, &LIMITS).expect("honest proof");
    let v = VerifierConfig::new();
    assert_eq!(verify(&v, &AIRS, &proof, &pv, &LIMITS), Ok(()));
    let bytes = encode_proof(&proof);

    // The layout serializer reproduces the encoding exactly.
    let mut layout = Layout::default();
    proof.serialize(&mut layout).unwrap();
    assert_eq!(layout.out.as_slice(), &bytes[1..], "postcard layout");
    let fields: Vec<usize> = layout.fields.iter().map(|o| o + 1).collect(); // + version byte
    assert!(!fields.is_empty());
    for &o in &fields {
        let x = u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        assert!(x < P, "offset {o} holds a field element");
    }

    let target = if cfg!(debug_assertions) {
        300
    } else {
        6_000usize
    };
    let stride = std::env::var("BLACKSILK_ZK_FIELD_STRIDE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| fields.len().div_ceil(target).max(1));
    let chosen: Vec<usize> = (0..fields.len())
        .filter(|&i| i % stride == 0 || i < 64 || i + 64 >= fields.len())
        .collect();
    println!(
        "proof: {} bytes, {} field elements; mutating {} (stride {stride})",
        bytes.len(),
        fields.len(),
        chosen.len()
    );

    let mut outcomes = [0usize; 4]; // decode error, invalid, shape/height, verifier panic
    let mut run = |idx: usize, new: u32, what: &str| {
        let o = fields[idx];
        let mut b = bytes.clone();
        b[o..o + 4].copy_from_slice(&new.to_le_bytes());
        match decode_proof(&b) {
            Err(ZkError::Encoding(_)) => outcomes[0] += 1,
            Err(e) => panic!("unexpected decode error {e:?}"),
            Ok(p) => match verify(&v, &AIRS, &p, &pv, &LIMITS) {
                Ok(()) => panic!("field element {idx} (byte {o}, {what}) mutated and verified"),
                Err(ZkError::Invalid(_)) => outcomes[1] += 1,
                Err(ZkError::Shape(_)) | Err(ZkError::Height { .. }) => outcomes[2] += 1,
                Err(ZkError::VerifierPanicked) => outcomes[3] += 1,
                Err(e) => panic!("unexpected {e:?}"),
            },
        }
    };
    for (k, &idx) in chosen.iter().enumerate() {
        let o = fields[idx];
        let x = u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        run(idx, (x + 1) % P, "+1");
        if k % 8 == 0 && x != 0 {
            run(idx, P - x, "negated");
        }
    }
    println!(
        "outcomes: {} refused by decoding, {} invalid, {} shape/height, {} verifier panics caught",
        outcomes[0], outcomes[1], outcomes[2], outcomes[3]
    );
    assert!(outcomes.iter().sum::<usize>() >= chosen.len());
}

/// A field element encoded as a value at or above the BabyBear modulus `p`
/// (a non-canonical representative) is refused by the strict decoder, never
/// reduced: `p` itself (the second encoding of 0), `x + p` where it fits in
/// 32 bits (the second encoding of `x`), and `u32::MAX`. Checked at the first,
/// middle and last field element of the proof.
#[test]
fn a_field_element_at_or_above_p_is_refused_by_decoding() {
    let (traces, pv) = statement();
    let cfg = ProverConfig::new(&[42; 32], &mut ChaCha20Rng::seed_from_u64(42));
    let proof = prove(&cfg, &AIRS, &traces, &pv, &LIMITS).expect("honest proof");
    let bytes = encode_proof(&proof);
    assert!(decode_proof(&bytes).is_ok());

    let mut layout = Layout::default();
    proof.serialize(&mut layout).unwrap();
    assert_eq!(layout.out.as_slice(), &bytes[1..], "postcard layout");
    let fields: Vec<usize> = layout.fields.iter().map(|o| o + 1).collect();
    assert!(fields.len() > 2);

    let mut checked = 0;
    for idx in [0, fields.len() / 2, fields.len() - 1] {
        let o = fields[idx];
        let x = u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        assert!(x < P);
        let mut values = vec![P, u32::MAX];
        if let Some(y) = x.checked_add(P) {
            values.push(y);
        }
        for new in values {
            let mut b = bytes.clone();
            b[o..o + 4].copy_from_slice(&new.to_le_bytes());
            match decode_proof(&b) {
                Err(ZkError::Encoding(_)) => checked += 1,
                Err(e) => panic!("element {idx} (byte {o}) = {new:#x}: {e:?}"),
                Ok(_) => panic!("element {idx} (byte {o}) = {new:#x} decoded"),
            }
        }
    }
    assert!(checked >= 6);
}
