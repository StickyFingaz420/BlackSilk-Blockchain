//! Structure-aware tamper sweep over the golden PX fixture's proof
//! (`src/px_fixture.bin`, `blacksilk_node::fingerprint::PxFixture`): verify
//! only, no proving.
//!
//! **Layout map.** The fixture's proof is decoded once (the consensus decoder,
//! `decode_px_proof`) and re-encoded field by field, in encoding order, by a
//! minimal postcard writer ([`wire`]: serde with postcard's rules, so no new
//! dependency). Every byte is assigned to one region: the version byte, a
//! vector length or `Option` tag (structure), or one value (a base field
//! element, an extension element, a digest, a FRI arity byte, a degree-bits
//! varint). The test asserts that the regions concatenate to the fixture's
//! exact proof bytes, which proves the map is the real layout and partitions
//! `[0, len)`, and that every field the proof carries has at least one value
//! region (the map is not vacuous).
//!
//! **Cases.** Each case flips one bit (XOR 1) of one byte of the proof at the
//! wire level, then decodes and verifies through the node's path for PX5:
//! `decode_px_proof` (`decode_proof_with` under `PROOF_LIMITS`), then
//! `blacksilk_px::prove::verify` with the arguments `check_px_proof_decoded`
//! passes for a transaction without functions (its statement, an empty call
//! list, its window and `h_tx = binding(domain)`); the smoke test also runs
//! `check_px_proof` itself on every case. Statement-side cases flip one byte
//! of `h_tx` or one word of the kernel's public statement and verify the
//! unmodified proof. No case may verify, and each must be refused with the
//! class its field implies (derived from the code, see [`expected`]):
//!
//! - `Decode`: the version byte, every length and tag (the prescan's exact
//!   counts, `postcard`, the trailing-bytes and re-encoding checks), a
//!   commit-phase grinding witness (canonical zero, `check_canonical_form`),
//!   and any value whose flipped 4-byte limb is not a canonical BabyBear
//!   element (`MontyField31` deserialization);
//! - `Shape`: a degree-bits entry (`check_shape_bits`), the public `n_fn`
//!   word (the statement's call count);
//! - `Invalid`: every other value (commitments, opened values, hidden
//!   openings, FRI commitments, openings, salts, sibling digests, the final
//!   polynomial, the query grinding witness, lookup terminals), a FRI arity
//!   (`check_fri_schedule`), `h_tx` and every other public word; and an
//!   input-opening row width whose flip re-parses into another well-formed
//!   proof (one value moves between two adjacent rows, [`row_width_resyncs`]
//!   derives exactly when): it decodes and verification refuses it.
//!
//! A verifier panic (`VerifierPanicked`) is contained and refused by the node,
//! but it is counted separately and fails the sweep: no field's expected
//! refusal is a panic. A panic outside the verifier's containment fails it too.
//!
//! **Known non-binding cases** (asserted to verify, [`known_non_binding`]):
//! for a transaction without functions the window enters the statement only
//! through function prefixes, so `verify` with another window and the same
//! `h_tx` is `Ok` (the transaction's window is bound through `h_tx`, which
//! covers it); and the range proof and the signatures are outside `h_tx`
//! (the prunable part), so changing them leaves `check_px_proof` `Ok` (the
//! CLSAGs sign them, and the proof bytes, instead).
//!
//! **Limits.** Each case flips bit 0 of one byte, so a verifier that lost a
//! higher bit of a value (say a limb masked to 15 bits) would not show; the
//! large vectors are sampled, not exhaustive; and a verifier that accepted
//! any query grinding witness would not show either, since the witness is
//! still observed and a changed one moves the query positions (a throwaway
//! mutant confirmed it). Throwaway mutants that drop bit 0 of an `h_tx` byte,
//! skip one FRI input batch's or one commit-phase round's Merkle check, or
//! drop the canonical-zero rule of the commit-phase grinding witnesses each
//! make the full sweep report a verifying case (docs/STATUS.md).
//!
//! The smoke subset (the first and last value and the first length or tag of
//! every field) runs with the suite; the full sweep is ignored by default
//! (several minutes in release) and runs in CI's `px-tamper` job:
//!
//! ```text
//! cargo test --release -p blacksilk-node --test px_tamper -- --ignored --nocapture full_px_proof_tamper_sweep
//! ```
//!
//! Scope: the transfer fixture only (no functions); the two-function fixture
//! is not built yet (docs/STATUS.md).

use blacksilk_node::fingerprint::{fixture_rules, px_fixture_verdict, PxFixture};
use blacksilk_px::core::kernel::Public;
use blacksilk_px::prove::VerifyError;
use blacksilk_tx::px::{PxTx, Window};
use blacksilk_tx::state::MemoryChain;
use blacksilk_tx::validate::{check_px_proof, decode_px_proof, PxProof};
use blacksilk_tx::TxError;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

/// The proof encoding's version byte (`blacksilk_zk::PROOF_VERSION`).
const PROOF_VERSION: u8 = 1;
/// The BabyBear modulus: a 4-byte limb at or above it does not decode.
const BABYBEAR_P: u32 = 0x7800_0001;
/// The seed of the sampled positions.
const SWEEP_SEED: u64 = 0x0B5F_7A3B;

/// A minimal postcard writer (postcard 1.x wire rules: unsigned integers
/// above 8 bits as LEB128 varints, signed ones zigzagged, `u8` raw, an
/// `Option` as a 0/1 tag, a sequence as its varint length then its elements,
/// structs and tuples as their fields in order, unit and `PhantomData` as
/// nothing). Not human-readable, as postcard, so field elements take their
/// fixed 4-byte form. The layout test checks its output against the
/// fixture's bytes.
mod wire {
    use serde::ser::{self, Serialize};
    use std::fmt;

    #[derive(Debug)]
    pub struct Error(String);

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for Error {}

    impl ser::Error for Error {
        fn custom<T: fmt::Display>(msg: T) -> Self {
            Error(msg.to_string())
        }
    }

    pub fn varint(out: &mut Vec<u8>, mut v: u128) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    fn zigzag(v: i128) -> u128 {
        ((v << 1) ^ (v >> 127)) as u128
    }

    pub fn encode<T: Serialize + ?Sized>(v: &T) -> Vec<u8> {
        let mut w = Writer(Vec::new());
        v.serialize(&mut w).expect("the proof serializes");
        w.0
    }

    pub struct Writer(Vec<u8>);

    type R = Result<(), Error>;

    impl ser::Serializer for &mut Writer {
        type Ok = ();
        type Error = Error;
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
            self.0.push(u8::from(v));
            Ok(())
        }
        fn serialize_i8(self, v: i8) -> R {
            self.0.push(v as u8);
            Ok(())
        }
        fn serialize_i16(self, v: i16) -> R {
            varint(&mut self.0, zigzag(v.into()));
            Ok(())
        }
        fn serialize_i32(self, v: i32) -> R {
            varint(&mut self.0, zigzag(v.into()));
            Ok(())
        }
        fn serialize_i64(self, v: i64) -> R {
            varint(&mut self.0, zigzag(v.into()));
            Ok(())
        }
        fn serialize_i128(self, v: i128) -> R {
            varint(&mut self.0, zigzag(v));
            Ok(())
        }
        fn serialize_u8(self, v: u8) -> R {
            self.0.push(v);
            Ok(())
        }
        fn serialize_u16(self, v: u16) -> R {
            varint(&mut self.0, v.into());
            Ok(())
        }
        fn serialize_u32(self, v: u32) -> R {
            varint(&mut self.0, v.into());
            Ok(())
        }
        fn serialize_u64(self, v: u64) -> R {
            varint(&mut self.0, v.into());
            Ok(())
        }
        fn serialize_u128(self, v: u128) -> R {
            varint(&mut self.0, v);
            Ok(())
        }
        fn serialize_f32(self, v: f32) -> R {
            self.0.extend(v.to_le_bytes());
            Ok(())
        }
        fn serialize_f64(self, v: f64) -> R {
            self.0.extend(v.to_le_bytes());
            Ok(())
        }
        fn serialize_char(self, v: char) -> R {
            self.serialize_str(v.encode_utf8(&mut [0; 4]))
        }
        fn serialize_str(self, v: &str) -> R {
            self.serialize_bytes(v.as_bytes())
        }
        fn serialize_bytes(self, v: &[u8]) -> R {
            varint(&mut self.0, v.len() as u128);
            self.0.extend(v);
            Ok(())
        }
        fn serialize_none(self) -> R {
            self.0.push(0);
            Ok(())
        }
        fn serialize_some<T: ?Sized + Serialize>(self, v: &T) -> R {
            self.0.push(1);
            v.serialize(self)
        }
        fn serialize_unit(self) -> R {
            Ok(())
        }
        fn serialize_unit_struct(self, _: &'static str) -> R {
            Ok(())
        }
        fn serialize_unit_variant(self, _: &'static str, i: u32, _: &'static str) -> R {
            varint(&mut self.0, i.into());
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
            varint(&mut self.0, i.into());
            v.serialize(self)
        }
        fn serialize_seq(self, len: Option<usize>) -> Result<Self, Error> {
            let len = len.ok_or_else(|| Error("a sequence without a length".into()))?;
            varint(&mut self.0, len as u128);
            Ok(self)
        }
        fn serialize_tuple(self, _: usize) -> Result<Self, Error> {
            Ok(self)
        }
        fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self, Error> {
            Ok(self)
        }
        fn serialize_tuple_variant(
            self,
            _: &'static str,
            i: u32,
            _: &'static str,
            _: usize,
        ) -> Result<Self, Error> {
            varint(&mut self.0, i.into());
            Ok(self)
        }
        fn serialize_map(self, len: Option<usize>) -> Result<Self, Error> {
            let len = len.ok_or_else(|| Error("a map without a length".into()))?;
            varint(&mut self.0, len as u128);
            Ok(self)
        }
        fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self, Error> {
            Ok(self)
        }
        fn serialize_struct_variant(
            self,
            _: &'static str,
            i: u32,
            _: &'static str,
            _: usize,
        ) -> Result<Self, Error> {
            varint(&mut self.0, i.into());
            Ok(self)
        }
    }

    macro_rules! compound {
        ($($t:ident :: $m:ident),*) => {$(
            impl ser::$t for &mut Writer {
                type Ok = ();
                type Error = Error;
                fn $m<T: ?Sized + Serialize>(&mut self, v: &T) -> R {
                    v.serialize(&mut **self)
                }
                fn end(self) -> R {
                    Ok(())
                }
            }
        )*};
    }
    compound!(
        SerializeSeq::serialize_element,
        SerializeTuple::serialize_element,
        SerializeTupleStruct::serialize_field,
        SerializeTupleVariant::serialize_field
    );

    impl ser::SerializeMap for &mut Writer {
        type Ok = ();
        type Error = Error;
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

    impl ser::SerializeStruct for &mut Writer {
        type Ok = ();
        type Error = Error;
        fn serialize_field<T: ?Sized + Serialize>(&mut self, _: &'static str, v: &T) -> R {
            v.serialize(&mut **self)
        }
        fn end(self) -> R {
            Ok(())
        }
    }

    impl ser::SerializeStructVariant for &mut Writer {
        type Ok = ();
        type Error = Error;
        fn serialize_field<T: ?Sized + Serialize>(&mut self, _: &'static str, v: &T) -> R {
            v.serialize(&mut **self)
        }
        fn end(self) -> R {
            Ok(())
        }
    }
}

/// The proof's fields, in encoding order (p3-batch-stark 0.7.0 `BatchProof`;
/// the hiding PCS proof is `(hidden openings, FriProof)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Field {
    Version,
    /// `commitments.main` (a Merkle cap: its root count, then its roots).
    CapMain,
    /// `commitments.permutation` (tag, cap).
    CapPermutation,
    CapQuotient,
    /// `commitments.random` (tag, cap).
    CapRandom,
    /// `opened_values.instances` (the instance count).
    Instances,
    TraceLocal,
    TraceNext,
    PreprocessedLocal,
    PreprocessedNext,
    QuotientChunks,
    RandomOpening,
    PermutationLocal,
    PermutationNext,
    /// The hidden random-codeword openings: round, matrix, point, values.
    Hidden,
    CommitPhaseCommits,
    CommitPowWitnesses,
    /// `input_openings` (the batch count).
    InputBatches,
    /// `input_openings[b].opened_values[q][m]`: the opened rows.
    InputValues,
    /// `input_openings[b].opening_proof.0[q][m]`: the Merkle salts.
    InputSalts,
    /// `input_openings[b].opening_proof.1.sibling_hashes`.
    InputSiblings,
    /// `commit_phase_openings` (the round count).
    CommitPhaseOpenings,
    LogArity,
    SiblingValues,
    CommitPhaseSalts,
    CommitPhaseSiblings,
    FinalPoly,
    QueryPowWitness,
    LookupTerminals,
    DegreeBits,
}

/// What a region holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Kind {
    Version,
    /// A vector length (varint).
    Length,
    /// An `Option` tag.
    Tag,
    /// One value.
    Value,
}

/// A byte range of the encoded proof. `at` locates it: per field, up to four
/// indices (instance or round or batch, then query or matrix, and so on; the
/// last one is the element index within its vector).
#[derive(Clone, Copy, Debug)]
struct Region {
    start: usize,
    end: usize,
    field: Field,
    kind: Kind,
    at: [usize; 4],
}

impl Region {
    /// A value made of 4-byte BabyBear limbs (every value except a FRI arity
    /// byte and a degree-bits varint).
    fn limbs(&self) -> bool {
        self.kind == Kind::Value && !matches!(self.field, Field::LogArity | Field::DegreeBits)
    }
}

/// The layout map: the re-encoded proof and its regions.
struct Layout {
    bytes: Vec<u8>,
    regions: Vec<Region>,
}

const Z: [usize; 4] = [0; 4];

fn at(a: usize, b: usize, c: usize) -> [usize; 4] {
    [a, b, c, 0]
}

impl Layout {
    fn push(&mut self, field: Field, kind: Kind, at: [usize; 4], bytes: &[u8]) {
        let start = self.bytes.len();
        self.bytes.extend(bytes);
        self.regions.push(Region {
            start,
            end: self.bytes.len(),
            field,
            kind,
            at,
        });
    }
    fn len(&mut self, field: Field, n: usize, at: [usize; 4]) {
        let mut b = Vec::new();
        wire::varint(&mut b, n as u128);
        self.push(field, Kind::Length, at, &b);
    }
    fn tag(&mut self, field: Field, some: bool, at: [usize; 4]) {
        self.push(field, Kind::Tag, at, &[u8::from(some)]);
    }
    fn value<T: Serialize + ?Sized>(&mut self, field: Field, at: [usize; 4], v: &T) {
        self.push(field, Kind::Value, at, &wire::encode(v));
    }
    /// A vector: its length, then each element (index in `at[3]`).
    fn values<T: Serialize>(&mut self, field: Field, at: [usize; 4], v: &[T]) {
        self.len(field, v.len(), at);
        for (i, x) in v.iter().enumerate() {
            let mut a = at;
            a[3] = i;
            self.value(field, a, x);
        }
    }
    fn opt_values<T: Serialize>(&mut self, field: Field, at: [usize; 4], v: Option<&[T]>) {
        self.tag(field, v.is_some(), at);
        if let Some(v) = v {
            self.values(field, at, v);
        }
    }
}

/// A Merkle cap: its root count, then each root.
macro_rules! cap {
    ($l:expr, $field:expr, $cap:expr, $i:expr) => {{
        let roots = $cap.roots();
        $l.len($field, roots.len(), at($i, 0, 0));
        for (k, r) in roots.iter().enumerate() {
            $l.value($field, [$i, 0, 0, k], r);
        }
    }};
}

/// Builds the layout map of `p`, field by field in encoding order.
fn layout(p: &PxProof) -> Layout {
    let mut l = Layout {
        bytes: Vec::new(),
        regions: Vec::new(),
    };
    l.push(Field::Version, Kind::Version, Z, &[PROOF_VERSION]);

    let c = &p.commitments;
    cap!(l, Field::CapMain, c.main, 0);
    l.tag(Field::CapPermutation, c.permutation.is_some(), Z);
    if let Some(cap) = &c.permutation {
        cap!(l, Field::CapPermutation, cap, 0);
    }
    cap!(l, Field::CapQuotient, c.quotient_chunks, 0);
    l.tag(Field::CapRandom, c.random.is_some(), Z);
    if let Some(cap) = &c.random {
        cap!(l, Field::CapRandom, cap, 0);
    }

    let instances = &p.opened_values.instances;
    l.len(Field::Instances, instances.len(), Z);
    for (i, o) in instances.iter().enumerate() {
        let b = &o.base_opened_values;
        l.values(Field::TraceLocal, at(i, 0, 0), &b.trace_local);
        l.opt_values(Field::TraceNext, at(i, 0, 0), b.trace_next.as_deref());
        l.opt_values(
            Field::PreprocessedLocal,
            at(i, 0, 0),
            b.preprocessed_local.as_deref(),
        );
        l.opt_values(
            Field::PreprocessedNext,
            at(i, 0, 0),
            b.preprocessed_next.as_deref(),
        );
        l.len(Field::QuotientChunks, b.quotient_chunks.len(), at(i, 0, 0));
        for (k, chunk) in b.quotient_chunks.iter().enumerate() {
            l.values(Field::QuotientChunks, at(i, k, 0), chunk);
        }
        l.opt_values(Field::RandomOpening, at(i, 0, 0), b.random.as_deref());
        l.values(Field::PermutationLocal, at(i, 0, 0), &o.permutation_local);
        l.values(Field::PermutationNext, at(i, 0, 0), &o.permutation_next);
    }

    let hidden = &p.opening_proof.0;
    l.len(Field::Hidden, hidden.len(), Z);
    for (r, round) in hidden.iter().enumerate() {
        l.len(Field::Hidden, round.len(), at(r, 0, 0));
        for (m, matrix) in round.iter().enumerate() {
            l.len(Field::Hidden, matrix.len(), at(r, m, 0));
            for (q, point) in matrix.iter().enumerate() {
                l.values(Field::Hidden, at(r, m, q), point);
            }
        }
    }

    let fri = &p.opening_proof.1;
    l.len(Field::CommitPhaseCommits, fri.commit_phase_commits.len(), Z);
    for (k, cap) in fri.commit_phase_commits.iter().enumerate() {
        cap!(l, Field::CommitPhaseCommits, cap, k);
    }
    l.values(Field::CommitPowWitnesses, Z, &fri.commit_pow_witnesses);
    l.len(Field::InputBatches, fri.input_openings.len(), Z);
    for (b, batch) in fri.input_openings.iter().enumerate() {
        l.len(Field::InputValues, batch.opened_values.len(), at(b, 0, 0));
        for (q, rows) in batch.opened_values.iter().enumerate() {
            l.len(Field::InputValues, rows.len(), at(b, q, 0));
            for (m, row) in rows.iter().enumerate() {
                l.values(Field::InputValues, at(b, q, m), row);
            }
        }
        let (salts, paths) = &batch.opening_proof;
        l.len(Field::InputSalts, salts.len(), at(b, 0, 0));
        for (q, s) in salts.iter().enumerate() {
            l.len(Field::InputSalts, s.len(), at(b, q, 0));
            for (m, salt) in s.iter().enumerate() {
                l.values(Field::InputSalts, at(b, q, m), salt);
            }
        }
        l.values(Field::InputSiblings, at(b, 0, 0), &paths.sibling_hashes);
    }
    l.len(
        Field::CommitPhaseOpenings,
        fri.commit_phase_openings.len(),
        Z,
    );
    for (r, o) in fri.commit_phase_openings.iter().enumerate() {
        l.value(Field::LogArity, at(r, 0, 0), &o.log_arity);
        l.len(Field::SiblingValues, o.sibling_values.len(), at(r, 0, 0));
        for (q, s) in o.sibling_values.iter().enumerate() {
            l.values(Field::SiblingValues, at(r, q, 0), s);
        }
        let (salts, paths) = &o.opening_proof;
        l.len(Field::CommitPhaseSalts, salts.len(), at(r, 0, 0));
        for (q, s) in salts.iter().enumerate() {
            l.len(Field::CommitPhaseSalts, s.len(), at(r, q, 0));
            for (m, salt) in s.iter().enumerate() {
                l.values(Field::CommitPhaseSalts, at(r, q, m), salt);
            }
        }
        l.values(
            Field::CommitPhaseSiblings,
            at(r, 0, 0),
            &paths.sibling_hashes,
        );
    }
    l.values(Field::FinalPoly, Z, &fri.final_poly);
    l.value(Field::QueryPowWitness, Z, &fri.query_pow_witness);

    l.len(Field::LookupTerminals, p.lookup_terminals.len(), Z);
    for (i, t) in p.lookup_terminals.iter().enumerate() {
        l.tag(Field::LookupTerminals, t.is_some(), at(i, 0, 0));
        if let Some(t) = t {
            l.value(Field::LookupTerminals, at(i, 0, 0), t);
        }
    }
    l.values(Field::DegreeBits, Z, &p.degree_bits);
    l
}

/// Fields that must carry at least one value in the fixture's proof (the
/// map's non-vacuity). The optional preprocessed openings, the lookup
/// terminals and the per-instance values are checked separately.
const VALUE_FIELDS: [Field; 21] = [
    Field::CapMain,
    Field::CapPermutation,
    Field::CapQuotient,
    Field::CapRandom,
    Field::TraceLocal,
    Field::TraceNext,
    Field::QuotientChunks,
    Field::RandomOpening,
    Field::PermutationLocal,
    Field::PermutationNext,
    Field::Hidden,
    Field::CommitPhaseCommits,
    Field::CommitPowWitnesses,
    Field::InputValues,
    Field::InputSalts,
    Field::InputSiblings,
    Field::LogArity,
    Field::SiblingValues,
    Field::CommitPhaseSalts,
    Field::CommitPhaseSiblings,
    Field::FinalPoly,
];

/// The refusal class of a case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Verdict {
    /// Verified: never expected.
    Ok,
    /// Refused by `decode_px_proof` (every decode refusal is
    /// `ZkError::Encoding`).
    Decode,
    /// `VerifyError::Shape` or `ZkError::Shape`.
    Shape,
    Height,
    /// `ZkError::Encoding` after decoding (the verifier's canonical-form
    /// re-check).
    Encoding,
    Invalid,
    /// `ZkError::VerifierPanicked`: contained by the verifier.
    Panicked,
    Unregistered,
    /// A panic the verifier did not contain.
    Uncontained,
}

/// Classifies a `ZkError` by its variant (the test cannot name the type
/// without a new dependency; its derived `Debug` starts with the variant).
fn zk_class(e: &impl std::fmt::Debug) -> Verdict {
    let s = format!("{e:?}");
    for (prefix, v) in [
        ("Shape(", Verdict::Shape),
        ("Height", Verdict::Height),
        ("Encoding(", Verdict::Encoding),
        ("Invalid(", Verdict::Invalid),
        ("VerifierPanicked", Verdict::Panicked),
    ] {
        if s.starts_with(prefix) {
            return v;
        }
    }
    panic!("unknown ZkError {s}");
}

/// The verification context of the fixture transaction.
struct Ctx {
    tx: PxTx,
    public: Public,
    h_tx: [u8; 32],
}

impl Ctx {
    fn new() -> Self {
        let tx = PxFixture::get().px.clone();
        assert!(
            tx.functions.is_empty(),
            "the transfer fixture has no functions"
        );
        let public = tx.public();
        let h_tx = tx.binding(fixture_rules().domain());
        Ctx { tx, public, h_tx }
    }

    /// PX5 on `self.tx.proof`, for `public`, `window` and `h_tx`, as
    /// `check_px_proof` runs it for a transaction without functions.
    fn verdict_with(&self, public: &Public, window: &Window, h_tx: [u8; 32]) -> Verdict {
        let run = catch_unwind(AssertUnwindSafe(|| {
            let proof = match decode_px_proof(&self.tx) {
                Ok(p) => p,
                Err(TxError::PxProof) => return Verdict::Decode,
                Err(e) => panic!("decode_px_proof returned {e:?}"),
            };
            match blacksilk_px::prove::verify(public, &[], window, h_tx, &proof, |_, _| None) {
                Ok(()) => Verdict::Ok,
                Err(VerifyError::Shape) => Verdict::Shape,
                Err(VerifyError::Unregistered(_)) => Verdict::Unregistered,
                Err(VerifyError::Proof(e)) => zk_class(&e),
            }
        }));
        run.unwrap_or(Verdict::Uncontained)
    }

    fn verdict(&self) -> Verdict {
        self.verdict_with(&self.public, &self.tx.window, self.h_tx)
    }

    /// The node's single-call PX5 (`check_px_proof`) on `self.tx`. A
    /// transaction without functions reads nothing from the chain.
    fn node_verdict(&self) -> Result<(), TxError> {
        check_px_proof(&self.tx, &MemoryChain::new(), &fixture_rules())
    }
}

/// A tamper case.
#[derive(Clone, Debug)]
enum Target {
    /// Flip bit 0 of this byte of the encoded proof.
    Proof { offset: usize, region: usize },
    /// Flip bit 0 of this byte of `h_tx`.
    HTx(usize),
    /// Flip bit 0 of this public word (see [`PUBLIC_WORDS`], [`flip_public`]).
    Public(usize),
}

/// The public words a test can change through `Public`, in
/// `Public::write`'s order after the constant `VERSION` word: the anchor,
/// the nullifiers, the commitments, `bridge_in` and `bridge_out` (low then
/// high half) and `n_fn`. (`VERSION` is a constant of the kernel, written by
/// `Public::write` itself; the function slots are empty for `n_fn = 0`.)
const PUBLIC_WORDS: usize = 8 + 16 + 16 + 4 + 1;

fn flip_public(p: &Public, w: usize) -> (Public, &'static str) {
    let mut p = *p;
    let name = match w {
        0..=7 => {
            p.anchor[w] ^= 1;
            "anchor"
        }
        8..=23 => {
            p.nullifiers[(w - 8) / 8][(w - 8) % 8] ^= 1;
            "nullifiers"
        }
        24..=39 => {
            p.commitments[(w - 24) / 8][(w - 24) % 8] ^= 1;
            "commitments"
        }
        40 => {
            p.bridge_in ^= 1;
            "bridge_in.lo"
        }
        41 => {
            p.bridge_in ^= 1 << 32;
            "bridge_in.hi"
        }
        42 => {
            p.bridge_out ^= 1;
            "bridge_out.lo"
        }
        43 => {
            p.bridge_out ^= 1 << 32;
            "bridge_out.hi"
        }
        44 => {
            p.n_fn ^= 1;
            "n_fn"
        }
        _ => unreachable!(),
    };
    (p, name)
}

/// The class a case must be refused with (module docs).
fn expected(target: &Target, l: &Layout) -> Verdict {
    match *target {
        Target::HTx(_) => Verdict::Invalid,
        Target::Public(w) => {
            if w == 44 {
                Verdict::Shape
            } else {
                Verdict::Invalid
            }
        }
        Target::Proof { offset, region } => {
            let r = &l.regions[region];
            match r.kind {
                Kind::Length if row_width_resyncs(l, region) => Verdict::Invalid,
                Kind::Version | Kind::Length | Kind::Tag => Verdict::Decode,
                Kind::Value => {
                    if r.limbs() {
                        let limb = r.start + (offset - r.start) / 4 * 4;
                        let mut b: [u8; 4] = l.bytes[limb..limb + 4].try_into().unwrap();
                        b[offset - limb] ^= 1;
                        if u32::from_le_bytes(b) >= BABYBEAR_P {
                            return Verdict::Decode;
                        }
                    }
                    match r.field {
                        Field::CommitPowWitnesses => Verdict::Decode,
                        Field::DegreeBits => Verdict::Shape,
                        _ => Verdict::Invalid,
                    }
                }
            }
        }
    }
}

/// Whether flipping bit 0 of the input-opening row width at `region` gives
/// bytes that still decode: a well-formed proof whose rows of this query
/// have other widths (values move between adjacent rows). The query's rows
/// are re-parsed from the tampered bytes exactly as the decoder reads them
/// (each row a LEB128 width at most the prescan's row cap, then that many
/// 4-byte limbs, each below `p`); the bytes decode iff the parse of the
/// query's row count ends exactly where the rows end, since every byte after
/// is unchanged. For example a width `w` read as `w + 1` absorbs the limb
/// `[wn, V0[0], V0[1], V0[2]]` of the next row and reads `V0[3]` as that
/// row's width: aligned again if `V0[3] = wn − 1`.
///
/// The re-encoding check passes too (the bytes are a canonical encoding of
/// the other proof), so such a proof is refused by verification (`Invalid`),
/// not by decoding. The full sweep found 37 such widths among the 13,288 row
/// widths of the fixture; no other vector of the proof showed one.
fn row_width_resyncs(l: &Layout, region: usize) -> bool {
    let rs = &l.regions;
    let r = &rs[region];
    let is_width = |k: usize| {
        rs[k].field == Field::InputValues
            && rs[k].kind == Kind::Length
            && rs
                .get(k + 1)
                .is_some_and(|v| v.field == Field::InputValues && v.kind == Kind::Value)
    };
    if r.field != Field::InputValues || !is_width(region) {
        return false;
    }
    // The query's row count precedes its first row's width; both are
    // lengths located at (batch, query, 0).
    let head = [r.at[0], r.at[1], 0];
    let is_head = |k: usize| rs[k].kind == Kind::Length && rs[k].at[..3] == head;
    let mut first = region;
    while !(is_head(first) && is_head(first - 1)) {
        first -= 1;
    }
    let count = &rs[first - 1];
    let rows = l.bytes[count.start] as usize;
    // The end of the query's rows: the last value region of this (batch,
    // query).
    let mut last = region;
    while rs[last + 1].field == Field::InputValues && rs[last + 1].at[..2] == r.at[..2] {
        last += 1;
    }
    let end = rs[last].end;
    let row_cap = widest_opened(l) + 8;
    let mut bytes = l.bytes[rs[first].start..end].to_vec();
    bytes[r.start - rs[first].start] ^= 1;
    let mut pos = 0usize;
    for _ in 0..rows {
        let mut w = 0usize;
        let mut shift = 0;
        loop {
            let Some(&b) = bytes.get(pos) else {
                return false;
            };
            pos += 1;
            w |= ((b & 0x7f) as usize) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
            if shift > 28 {
                return false;
            }
        }
        if w > row_cap {
            return false;
        }
        for _ in 0..w {
            let Some(limb) = bytes.get(pos..pos + 4) else {
                return false;
            };
            if u32::from_le_bytes(limb.try_into().unwrap()) >= BABYBEAR_P {
                return false;
            }
            pos += 4;
        }
    }
    pos == bytes.len()
}

/// The widest opened vector of any instance (the prescan's `widest`, in
/// extension elements).
fn widest_opened(l: &Layout) -> usize {
    let mut n: BTreeMap<(Field, [usize; 3]), usize> = BTreeMap::new();
    for r in &l.regions {
        if r.kind == Kind::Value
            && matches!(
                r.field,
                Field::TraceLocal
                    | Field::TraceNext
                    | Field::PreprocessedLocal
                    | Field::PreprocessedNext
                    | Field::QuotientChunks
                    | Field::RandomOpening
                    | Field::PermutationLocal
                    | Field::PermutationNext
            )
        {
            *n.entry((r.field, [r.at[0], r.at[1], r.at[2]])).or_default() += 1;
        }
    }
    n.values().copied().max().unwrap_or(0)
}

/// The fixture context and its layout map, checked: the regions concatenate
/// to the fixture's proof bytes, in order, without gaps.
fn fixture_layout(ctx: &Ctx) -> Layout {
    let proof = decode_px_proof(&ctx.tx).expect("the fixture's proof decodes");
    let l = layout(&proof);
    assert_eq!(l.bytes.len(), ctx.tx.proof.len(), "layout length");
    assert!(
        l.bytes == ctx.tx.proof,
        "the layout map does not re-encode the fixture's proof"
    );
    let mut pos = 0;
    for r in &l.regions {
        assert_eq!(r.start, pos, "gap or overlap at {r:?}");
        assert!(r.end > r.start, "empty region {r:?}");
        if r.limbs() {
            assert_eq!((r.end - r.start) % 4, 0, "{r:?}");
        }
        pos = r.end;
    }
    assert_eq!(pos, ctx.tx.proof.len());
    l
}

/// Per field and kind: region count and byte count.
fn summary(l: &Layout) -> BTreeMap<(Field, Kind), (usize, usize)> {
    let mut s = BTreeMap::new();
    for r in &l.regions {
        let e = s.entry((r.field, r.kind)).or_insert((0, 0));
        e.0 += 1;
        e.1 += r.end - r.start;
    }
    s
}

#[test]
fn the_layout_map_partitions_the_fixture_proof() {
    let ctx = Ctx::new();
    let l = fixture_layout(&ctx);
    let s = summary(&l);
    for f in VALUE_FIELDS {
        assert!(
            s.get(&(f, Kind::Value)).is_some_and(|&(n, _)| n > 0),
            "{f:?} has no value in the fixture's proof"
        );
    }
    // The lookup terminals and degree bits: one per instance.
    let instances = l
        .regions
        .iter()
        .filter(|r| r.field == Field::DegreeBits && r.kind == Kind::Value)
        .count();
    assert!(instances > 0);
    assert_eq!(
        l.regions
            .iter()
            .filter(|r| r.field == Field::LookupTerminals && r.kind == Kind::Tag)
            .count(),
        instances
    );
    assert!(s.contains_key(&(Field::LookupTerminals, Kind::Value)));
    assert!(s.contains_key(&(Field::QueryPowWitness, Kind::Value)));
    println!("proof bytes {}", l.bytes.len());
    for ((f, k), (n, b)) in &s {
        println!("{f:?}\t{k:?}\t{n}\t{b}");
    }
}

/// One tamper run: the verdict, the expected class, the time.
struct Outcome {
    label: String,
    field: Option<Field>,
    kind: Option<Kind>,
    verdict: Verdict,
    expected: Verdict,
    time: Duration,
}

fn run_case(ctx: &mut Ctx, l: &Layout, target: &Target, with_node: bool) -> Outcome {
    let expected = expected(target, l);
    let start = Instant::now();
    let (label, field, kind, verdict) = match *target {
        Target::Proof { offset, region } => {
            let r = l.regions[region];
            ctx.tx.proof[offset] ^= 1;
            let v = ctx.verdict();
            if with_node {
                // The node's own single call agrees: refused as `PxProof`.
                let node = ctx.node_verdict();
                assert_eq!(
                    node.is_ok(),
                    v == Verdict::Ok,
                    "check_px_proof disagrees at byte {offset}: {node:?} vs {v:?}"
                );
                if node.is_err() {
                    assert_eq!(node, Err(TxError::PxProof));
                }
            }
            ctx.tx.proof[offset] ^= 1;
            (
                format!(
                    "byte {offset} ({:?} {:?} at {:?}, +{})",
                    r.field,
                    r.kind,
                    r.at,
                    offset - r.start
                ),
                Some(r.field),
                Some(r.kind),
                v,
            )
        }
        Target::HTx(i) => {
            let mut h = ctx.h_tx;
            h[i] ^= 1;
            let v = ctx.verdict_with(&ctx.public, &ctx.tx.window, h);
            (format!("h_tx byte {i}"), None, None, v)
        }
        Target::Public(w) => {
            let (p, name) = flip_public(&ctx.public, w);
            let v = ctx.verdict_with(&p, &ctx.tx.window, ctx.h_tx);
            (format!("public word {w} ({name})"), None, None, v)
        }
    };
    Outcome {
        label,
        field,
        kind,
        verdict,
        expected,
        time: start.elapsed(),
    }
}

/// Runs `targets`, reports per class and asserts: no case verifies, every
/// case gets its expected class.
fn sweep(ctx: &mut Ctx, l: &Layout, targets: &[Target], with_node: bool) {
    // The unmodified fixture verifies, in the same process (the control).
    assert_eq!(
        ctx.verdict(),
        Verdict::Ok,
        "the control: the fixture verifies"
    );
    assert_eq!(ctx.node_verdict(), Ok(()));
    let start = Instant::now();
    let mut outcomes = Vec::with_capacity(targets.len());
    for t in targets {
        let o = run_case(ctx, l, t, with_node);
        // Stop at once on a case that verifies: a proof byte (or statement
        // value) verification does not bind.
        assert_ne!(
            o.verdict,
            Verdict::Ok,
            "POTENTIAL CONSENSUS FINDING: {} verifies",
            o.label
        );
        outcomes.push(o);
    }
    let total = start.elapsed();
    // Control again: the in-place flips were all undone.
    assert_eq!(ctx.verdict(), Verdict::Ok);

    let mut by_class: BTreeMap<(String, Verdict), (usize, Duration, Duration)> = BTreeMap::new();
    for o in &outcomes {
        let key = match (o.field, o.kind) {
            (Some(f), Some(k)) => format!("{f:?}/{k:?}"),
            _ => o.label.split(' ').next().unwrap_or("").to_string() + "(statement)",
        };
        let e = by_class
            .entry((key, o.verdict))
            .or_insert((0, Duration::ZERO, Duration::ZERO));
        e.0 += 1;
        e.1 += o.time;
        e.2 = e.2.max(o.time);
    }
    println!("field/kind\tverdict\tcases\tmean ms\tmax ms");
    for ((k, v), (n, sum, max)) in &by_class {
        println!(
            "{k}\t{v:?}\t{n}\t{:.1}\t{:.1}",
            sum.as_secs_f64() * 1e3 / *n as f64,
            max.as_secs_f64() * 1e3
        );
    }
    let mut totals: BTreeMap<Verdict, usize> = BTreeMap::new();
    for o in &outcomes {
        *totals.entry(o.verdict).or_default() += 1;
    }
    println!(
        "cases {} in {:.1} s; by verdict {totals:?}",
        outcomes.len(),
        total.as_secs_f64()
    );
    let wrong: Vec<String> = outcomes
        .iter()
        .filter(|o| o.verdict != o.expected)
        .map(|o| format!("{}: {:?}, expected {:?}", o.label, o.verdict, o.expected))
        .collect();
    assert!(
        wrong.is_empty(),
        "{} cases refused with another class:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The statement-side cases: every byte of `h_tx`, every public word.
fn statement_targets() -> Vec<Target> {
    (0..32)
        .map(Target::HTx)
        .chain((0..PUBLIC_WORDS).map(Target::Public))
        .collect()
}

/// The smoke subset: the version byte, the first and the last value and the
/// first length or tag of every field, the first and last byte of `h_tx`,
/// the first anchor word and `n_fn`.
fn smoke_targets(l: &Layout) -> Vec<Target> {
    let mut seen = BTreeSet::new();
    let mut last: BTreeMap<Field, usize> = BTreeMap::new();
    let mut t = Vec::new();
    for (i, r) in l.regions.iter().enumerate() {
        let class = if r.kind == Kind::Value { 0 } else { 1 };
        if seen.insert((r.field, class)) {
            t.push(Target::Proof {
                offset: r.start,
                region: i,
            });
        }
        if r.kind == Kind::Value {
            last.insert(r.field, i);
        }
    }
    for &i in last.values() {
        if !t
            .iter()
            .any(|x| matches!(x, Target::Proof { region, .. } if *region == i))
        {
            t.push(Target::Proof {
                offset: l.regions[i].start,
                region: i,
            });
        }
    }
    t.extend([
        Target::HTx(0),
        Target::HTx(31),
        Target::Public(0),
        Target::Public(44),
    ]);
    t
}

/// The full sweep's targets (module docs; sampled with [`SWEEP_SEED`]):
///
/// - every byte of every version, length and tag region;
/// - every element of the small fields (the four commitments and the FRI
///   commit-phase commitments: every 4-byte limb of each root; the grinding
///   witnesses, the query grinding witness (all four bytes), the FRI arities,
///   the final polynomial, the lookup terminals, the degree bits);
/// - per vector of the opened values: the first, the last and one random
///   element; per hidden-opening matrix: the first, the last and one random
///   value;
/// - the input openings: one random value of one random matrix at every
///   query, and one random value of every matrix at the first and the last
///   query; per batch, the first, last and three random salts and sibling
///   digests;
/// - the commit-phase openings: one random sibling value at every query of
///   every round; per round, the first, last and three random salts and
///   sibling digests;
/// - the statement side: every `h_tx` byte and every public word.
///
/// Within a value, the flipped byte is random (seeded), except for the
/// limbs of the commitments (byte 0 of each).
fn full_targets(l: &Layout) -> Vec<Target> {
    let mut rng = ChaCha20Rng::seed_from_u64(SWEEP_SEED);
    let mut pick = |n: usize| (rng.next_u64() % n as u64) as usize;
    let mut offsets: BTreeMap<usize, usize> = BTreeMap::new();
    // Value regions grouped by field and their location without the element
    // index.
    let mut groups: BTreeMap<(Field, [usize; 3]), Vec<usize>> = BTreeMap::new();
    for (i, r) in l.regions.iter().enumerate() {
        match r.kind {
            Kind::Version | Kind::Length | Kind::Tag => {
                for o in r.start..r.end {
                    offsets.insert(o, i);
                }
            }
            Kind::Value => {
                let key = match r.field {
                    // Per (round, matrix): all points together.
                    Field::Hidden => [r.at[0], r.at[1], 0],
                    // Per batch (or round) and query: the rows of every matrix.
                    Field::InputValues => [r.at[0], r.at[1], 0],
                    // Per batch (or round): every query's salts.
                    Field::InputSalts | Field::CommitPhaseSalts => [r.at[0], 0, 0],
                    // Per round and query.
                    Field::SiblingValues => [r.at[0], r.at[1], 0],
                    _ => [r.at[0], r.at[1], r.at[2]],
                };
                groups.entry((r.field, key)).or_default().push(i);
            }
        }
    }
    let mut add = |offsets: &mut BTreeMap<usize, usize>, i: usize, byte: Option<usize>| {
        let r = &l.regions[i];
        let o = r.start + byte.unwrap_or_else(|| pick(r.end - r.start));
        offsets.insert(o, i);
    };
    let mut rng2 = ChaCha20Rng::seed_from_u64(SWEEP_SEED ^ 1);
    let mut pick2 = |n: usize| (rng2.next_u64() % n as u64) as usize;
    for ((field, _), v) in &groups {
        match field {
            Field::CapMain
            | Field::CapPermutation
            | Field::CapQuotient
            | Field::CapRandom
            | Field::CommitPhaseCommits => {
                for &i in v {
                    let r = &l.regions[i];
                    for limb in (0..r.end - r.start).step_by(4) {
                        add(&mut offsets, i, Some(limb));
                    }
                }
            }
            Field::QueryPowWitness => {
                for &i in v {
                    for b in 0..4 {
                        add(&mut offsets, i, Some(b));
                    }
                }
            }
            Field::CommitPowWitnesses
            | Field::LogArity
            | Field::FinalPoly
            | Field::LookupTerminals
            | Field::DegreeBits => {
                for &i in v {
                    add(&mut offsets, i, None);
                }
            }
            // `v` is every value of one (batch, query), or of one (round,
            // query): one random value.
            Field::InputValues | Field::SiblingValues => {
                add(&mut offsets, v[pick2(v.len())], None);
            }
            Field::InputSiblings
            | Field::CommitPhaseSiblings
            | Field::InputSalts
            | Field::CommitPhaseSalts => {
                let mut s = vec![v[0], v[v.len() - 1]];
                for _ in 0..3 {
                    s.push(v[pick2(v.len())]);
                }
                for i in s {
                    add(&mut offsets, i, None);
                }
            }
            _ => {
                for i in [v[0], v[v.len() - 1], v[pick2(v.len())]] {
                    add(&mut offsets, i, None);
                }
            }
        }
    }
    // The input openings: every matrix at the first and the last query.
    let last_query = l
        .regions
        .iter()
        .filter(|r| r.field == Field::InputValues && r.kind == Kind::Value)
        .map(|r| r.at[1])
        .max()
        .expect("input openings");
    let mut per_matrix: BTreeMap<[usize; 3], Vec<usize>> = BTreeMap::new();
    for (i, r) in l.regions.iter().enumerate() {
        if r.field == Field::InputValues
            && r.kind == Kind::Value
            && (r.at[1] == 0 || r.at[1] == last_query)
        {
            per_matrix
                .entry([r.at[0], r.at[1], r.at[2]])
                .or_default()
                .push(i);
        }
    }
    for v in per_matrix.values() {
        add(&mut offsets, v[pick2(v.len())], None);
    }
    offsets
        .into_iter()
        .map(|(offset, region)| Target::Proof { offset, region })
        .chain(statement_targets())
        .collect()
}

/// The smoke subset (every field once), through both the verifier call and
/// the node's `check_px_proof`.
#[test]
fn tamper_smoke_every_proof_field_is_refused() {
    let mut ctx = Ctx::new();
    let l = fixture_layout(&ctx);
    let targets = smoke_targets(&l);
    assert!(targets.len() >= 40, "{} smoke cases", targets.len());
    sweep(&mut ctx, &l, &targets, true);
}

/// The full structure-aware sweep (module docs, [`full_targets`]).
#[test]
#[ignore = "the full tamper sweep: several minutes in release (CI job px-tamper)"]
fn full_px_proof_tamper_sweep() {
    let mut ctx = Ctx::new();
    let l = fixture_layout(&ctx);
    let targets = full_targets(&l);
    println!("full sweep: {} cases", targets.len());
    sweep(&mut ctx, &l, &targets, false);
}

/// The known non-binding cases, asserted to verify (module docs).
#[test]
fn known_non_binding() {
    let ctx = Ctx::new();
    let rules = fixture_rules();
    let chain = MemoryChain::new();
    // Another window with the same h_tx: the statement of a transaction
    // without functions does not contain the window.
    for w in [
        Window {
            not_before: 1,
            not_after: 2,
        },
        Window {
            not_before: 7,
            not_after: 0,
        },
    ] {
        assert_ne!(w, ctx.tx.window);
        assert_eq!(ctx.verdict_with(&ctx.public, &w, ctx.h_tx), Verdict::Ok);
        // The transaction's own window is bound, through h_tx.
        let mut v = ctx.tx.clone();
        v.window = w;
        assert_ne!(v.binding(rules.domain()), ctx.h_tx);
        assert_eq!(check_px_proof(&v, &chain, &rules), Err(TxError::PxProof));
    }
    // The range proof and the signatures are outside h_tx: PX5 still holds,
    // and full validation refuses the transaction before PX5.
    let mut v = ctx.tx.clone();
    assert!(v.range_proof.is_some());
    v.range_proof = None;
    assert_eq!(v.binding(rules.domain()), ctx.h_tx);
    assert_eq!(check_px_proof(&v, &chain, &rules), Ok(()));
    assert!(px_fixture_verdict(&v, true).is_err());
    let mut v = ctx.tx.clone();
    assert!(!v.signatures.is_empty());
    v.signatures.clear();
    assert_eq!(v.binding(rules.domain()), ctx.h_tx);
    assert_eq!(check_px_proof(&v, &chain, &rules), Ok(()));
    assert!(px_fixture_verdict(&v, true).is_err());
}
