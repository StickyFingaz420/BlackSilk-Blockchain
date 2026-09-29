//! Allocation bounds of the proof decoder (red team RT-FUZZ-1).
//!
//! `postcard` decodes a vector of any length the bytes announce. An empty
//! inner vector costs one byte on the wire and 24 bytes of heap (its header),
//! so a proof padded with empty vectors under [`crate::params::MAX_PROOF_BYTES`]
//! decoded to 34 times its size (143 MB for 4 MiB) before any rule saw it.
//!
//! [`prescan`] walks the encoded proof **before** it is decoded, without
//! allocating, and refuses it as soon as a length exceeds its cap. Every cap
//! is one the verifier implies, so no valid proof is refused: see
//! [`DecodeLimits`] for the caps that depend on the statement, and the
//! comments of [`prescan`] for the others, each with the check that implies
//! it. Where the verifier requires an exact count and the count is cheap to
//! know here (the query counts, the matrices of each opening round, the salt
//! length), it is required exactly: those are the vectors a proof holds by
//! the ten thousand, so each must carry its data.
//!
//! The walk mirrors the `postcard` encoding of [`crate::Proof`] field by
//! field (structs and tuples in order, vectors as a varint length, options as
//! a 0/1 byte, field elements as 4 raw bytes, extension elements and digests
//! as 32). A walk that disagreed with the real layout would refuse honest
//! proofs (the tests decode real proofs) or reject at a different field, never
//! let `postcard` allocate beyond the caps: `postcard` reads the same length
//! prefixes, and the caller decodes only bytes the walk consumed exactly.

use crate::params::{
    EXTENSION_DEGREE, LOG_BLOWUP, LOG_FINAL_POLY_LEN, MAX_COMMITTED_COLUMNS, MAX_LOG_ARITY,
    MAX_LOG_HEIGHT, MERKLE_SALT_ELEMS, NUM_QUERIES, NUM_RANDOM_CODEWORDS, OPENING_POINTS,
};
use crate::ZkError;

/// The caps of the proof decoder that depend on the statement: its number of
/// tables and their shapes. The decoder does not know the statement, so these
/// are maxima over every statement the caller verifies; a proof beyond one of
/// them cannot verify for any of those statements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Most tables (proof instances). `verify` requires exactly one instance
    /// per AIR of the statement, and as many degree bits and lookup terminals.
    pub max_instances: usize,
    /// Most extension elements in any one opened vector of an instance (trace,
    /// next row, preprocessed, permutation). Each is the width of a committed
    /// matrix, which an honest shape keeps within `MAX_COMMITTED_COLUMNS` in
    /// total.
    pub max_opened_width: usize,
    /// Most quotient chunks of one instance. `verify_batch` requires exactly
    /// `2^(log2_ceil(d) + 1)` chunks for an AIR of constraint degree `d ≥ 1`
    /// (`get_log_num_quotient_chunks`: zero knowledge adds one to the degree
    /// and doubles the count); a degree at most `MAX_CONSTRAINT_DEGREE =
    /// 2^LOG_BLOWUP` gives at most `2^(LOG_BLOWUP + 1)`.
    pub max_quotient_chunks: usize,
}

impl DecodeLimits {
    /// The widest statement of any BlackSilk verifier: BVM-1 with its maximum
    /// of five executions (33 tables; `blacksilk_zkvm` asserts at compile time
    /// that its table count fits, and tests that every table's verifier-derived
    /// quotient chunk count fits), columns within the committed-column
    /// envelope. [`crate::decode_proof`] uses it; a caller that knows a
    /// narrower family of statements (PX) passes its own to
    /// [`crate::decode_proof_with`].
    pub const ENVELOPE: DecodeLimits = DecodeLimits {
        max_instances: 33,
        max_opened_width: MAX_COMMITTED_COLUMNS,
        max_quotient_chunks: 2 << LOG_BLOWUP,
    };
}

/// Most FRI commit-phase rounds: the arities (each at least 1) sum to the
/// fold from the largest input height, at most `MAX_LOG_HEIGHT + 1 +
/// LOG_BLOWUP` (the degree bits `verify` accepts, plus the blow-up), down to
/// `LOG_BLOWUP + LOG_FINAL_POLY_LEN`.
pub const MAX_FRI_ROUNDS: usize = MAX_LOG_HEIGHT + 1 - LOG_FINAL_POLY_LEN;

/// Deepest Merkle tree of a proof: binary trees (one root, cap height 0) over
/// at most `2^(MAX_LOG_HEIGHT + 1 + LOG_BLOWUP)` leaves.
pub const MAX_MERKLE_DEPTH: usize = MAX_LOG_HEIGHT + 1 + LOG_BLOWUP;

/// Most sibling digests of one pruned multiproof: each of the `NUM_QUERIES`
/// queried leaves contributes at most one sibling per level
/// (`restore_paths` requires the exact count the queries need).
pub const MAX_PRUNED_SIBLINGS: usize = NUM_QUERIES * MAX_MERKLE_DEPTH;

/// Encoded sizes (postcard): a base field element is 4 raw bytes, an
/// extension element or a digest 8 of them.
const VAL: usize = 4;
const EXT: usize = VAL * EXTENSION_DEGREE;
const DIGEST: usize = 32;

/// Byte reader over the proof body. Every read is bounds-checked.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

fn exhausted() -> ZkError {
    ZkError::Encoding("proof bytes end early".into())
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, ZkError> {
        let b = *self.bytes.get(self.pos).ok_or_else(exhausted)?;
        self.pos += 1;
        Ok(b)
    }

    /// Skips `count` items of `size` bytes each.
    fn skip(&mut self, count: usize, size: usize) -> Result<(), ZkError> {
        let n = count.checked_mul(size).ok_or_else(exhausted)?;
        let end = self.pos.checked_add(n).ok_or_else(exhausted)?;
        if end > self.bytes.len() {
            return Err(exhausted());
        }
        self.pos = end;
        Ok(())
    }

    /// A `usize` varint exactly as `postcard` reads it on a 64-bit target
    /// (LEB128, at most 10 bytes, the last one at most 1).
    fn varint(&mut self) -> Result<u64, ZkError> {
        let mut out = 0u64;
        for i in 0..10 {
            let b = self.byte()?;
            out |= u64::from(b & 0x7f) << (7 * i);
            if b & 0x80 == 0 {
                if i == 9 && b > 1 {
                    break;
                }
                return Ok(out);
            }
        }
        Err(ZkError::Encoding("bad varint".into()))
    }

    /// A vector length, at most `cap`.
    fn len(&mut self, what: &str, cap: usize) -> Result<usize, ZkError> {
        let n = self.varint()?;
        match usize::try_from(n) {
            Ok(n) if n <= cap => Ok(n),
            _ => Err(ZkError::Encoding(format!(
                "decode bound: {what} has {n} entries, more than {cap}"
            ))),
        }
    }

    /// A vector length, exactly `expected`.
    fn exact(&mut self, what: &str, expected: usize) -> Result<(), ZkError> {
        let n = self.varint()?;
        if usize::try_from(n) == Ok(expected) {
            Ok(())
        } else {
            Err(ZkError::Encoding(format!(
                "decode bound: {what} has {n} entries, not {expected}"
            )))
        }
    }

    /// An `Option` tag.
    fn option(&mut self) -> Result<bool, ZkError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ZkError::Encoding("bad option tag".into())),
        }
    }

    /// A vector of extension elements of at most `cap`; returns its length.
    fn ext_vec(&mut self, what: &str, cap: usize) -> Result<usize, ZkError> {
        let n = self.len(what, cap)?;
        self.skip(n, EXT)?;
        Ok(n)
    }

    /// A Merkle cap: exactly one root (the canonical-form rule, F24-2).
    fn merkle_cap(&mut self, index: usize) -> Result<(), ZkError> {
        let n = self.varint()?;
        if n != 1 {
            return Err(ZkError::Encoding(format!(
                "commitment {index} has {n} Merkle cap roots, not 1"
            )));
        }
        self.skip(1, DIGEST)
    }

    /// The hiding MMCS multiproof (`MerkleTreeHidingMmcs::MultiProof`):
    /// `NUM_QUERIES × matrices` salts of `MERKLE_SALT_ELEMS` elements, then
    /// the pruned sibling digests. `verify_multi_batch` zips the salts with
    /// the opened rows (one per query, one per matrix, `zip_eq`), and pins
    /// each salted row to its width plus `MERKLE_SALT_ELEMS`
    /// (duplicate queries must equal their representative), so all three
    /// counts are exact in a valid proof.
    fn multiproof(&mut self, what: &str, matrices: usize) -> Result<(), ZkError> {
        self.exact(what, NUM_QUERIES)?;
        for _ in 0..NUM_QUERIES {
            self.exact(what, matrices)?;
            for _ in 0..matrices {
                self.exact(what, MERKLE_SALT_ELEMS)?;
                self.skip(MERKLE_SALT_ELEMS, VAL)?;
            }
        }
        let siblings = self.len(what, MAX_PRUNED_SIBLINGS)?;
        self.skip(siblings, DIGEST)
    }
}

/// Walks the encoded proof `body` (without the version byte) and refuses it
/// if any vector exceeds its cap, before anything is allocated for it. `Ok`
/// only if the walk consumed `body` exactly.
///
/// The caps, in encoding order (`verify` is `crate::verify`; the p3 names are
/// Plonky3 0.7.0's `verify_batch`, the hiding PCS's `verify` and the FRI
/// `verify_fri` / `open_inputs`):
/// - **instances** at most `max_instances`; per instance: every opened vector
///   at most `max_opened_width`; the quotient chunks at most
///   `max_quotient_chunks`, each at most `EXTENSION_DEGREE` long (exactly
///   that in a valid proof, `QuotientChunkDimensionMismatch`); the random
///   opening at most `EXTENSION_DEGREE` (`RandomizationError`).
/// - **hidden openings**: exactly the proof's opening rounds (the
///   canonical-form rule of `check_hidden_openings`, applied early); per round
///   at most one matrix per instance, or one per quotient chunk in the
///   quotient round (the hiding verifier requires exactly the opening
///   argument's matrices); at most `OPENING_POINTS` points per matrix (ζ and
///   gζ); at most `NUM_RANDOM_CODEWORDS` values per point (canonical form).
/// - **FRI**: at most `MAX_FRI_ROUNDS` commit-phase commitments, and no more
///   grinding witnesses or round openings than commitments (both exact in
///   `verify_fri`); at most one input batch per opening round
///   (`InputProofBatchCountMismatch`), each with exactly `NUM_QUERIES` opened
///   row sets (`InputOpeningsQueryCountMismatch`) of exactly the round's
///   matrices (`BatchOpenedValuesCountMismatch`, and the hidden openings
///   already fix that count), each row at most the widest opened vector plus
///   `NUM_RANDOM_CODEWORDS` (`check_widths` pins a row to its claimed
///   evaluations: public plus hidden); every round opening with exactly
///   `NUM_QUERIES` sibling sets (`CommitPhaseQueryCountMismatch`) of at most
///   `2^MAX_LOG_ARITY − 1` values (`SiblingValuesLengthMismatch`, arity at
///   most `MAX_LOG_ARITY`), and a one-matrix multiproof; the final polynomial
///   at most `2^LOG_FINAL_POLY_LEN` (`FinalPolyLengthMismatch`).
/// - **lookup terminals** and **degree bits**: at most one per instance
///   (`verify`'s instance count checks).
pub(crate) fn prescan(body: &[u8], limits: &DecodeLimits) -> Result<(), ZkError> {
    let mut r = Reader {
        bytes: body,
        pos: 0,
    };
    // Commitments: main, permutation?, quotient chunks, random?.
    r.merkle_cap(0)?;
    let permutation = r.option()?;
    if permutation {
        r.merkle_cap(1)?;
    }
    let mut cap_index = 1 + usize::from(permutation);
    r.merkle_cap(cap_index)?;
    cap_index += 1;
    let random = r.option()?;
    if random {
        r.merkle_cap(cap_index)?;
        cap_index += 1;
    }

    // Opened values, one entry per instance.
    let w = limits.max_opened_width;
    let n = r.len("instances", limits.max_instances)?;
    let mut chunks_total = 0usize;
    let mut widest = 0usize;
    let mut preprocessed = false;
    for _ in 0..n {
        widest = widest.max(r.ext_vec("trace_local", w)?);
        if r.option()? {
            widest = widest.max(r.ext_vec("trace_next", w)?);
        }
        if r.option()? {
            preprocessed = true;
            widest = widest.max(r.ext_vec("preprocessed_local", w)?);
        }
        if r.option()? {
            widest = widest.max(r.ext_vec("preprocessed_next", w)?);
        }
        let chunks = r.len("quotient_chunks", limits.max_quotient_chunks)?;
        chunks_total += chunks;
        for _ in 0..chunks {
            widest = widest.max(r.ext_vec("quotient chunk", EXTENSION_DEGREE)?);
        }
        if r.option()? {
            widest = widest.max(r.ext_vec("random opening", EXTENSION_DEGREE)?);
        }
        widest = widest.max(r.ext_vec("permutation_local", w)?);
        widest = widest.max(r.ext_vec("permutation_next", w)?);
    }

    // Hidden random-codeword openings: round, matrix, point, value.
    let rounds = usize::from(random) + 2 + usize::from(preprocessed) + usize::from(permutation);
    let got = r.varint()?;
    if got != rounds as u64 {
        return Err(ZkError::Encoding(format!(
            "{got} hidden opening rounds, the proof has {rounds}"
        )));
    }
    let quotient_round = usize::from(random) + 1;
    // At most five rounds (R, main, quotient, preprocessed, permutation).
    let mut matrices = [0usize; 5];
    for (round, m) in matrices.iter_mut().enumerate().take(rounds) {
        let cap = if round == quotient_round {
            chunks_total
        } else {
            n
        };
        *m = r.len("hidden opening matrices", cap)?;
        for _ in 0..*m {
            let points = r.len("hidden opening points", OPENING_POINTS)?;
            for _ in 0..points {
                r.ext_vec("hidden opening values", NUM_RANDOM_CODEWORDS)?;
            }
        }
    }

    // The FRI proof.
    let fri_rounds = r.len("FRI commit-phase commitments", MAX_FRI_ROUNDS)?;
    for _ in 0..fri_rounds {
        r.merkle_cap(cap_index)?;
        cap_index += 1;
    }
    let witnesses = r.len("commit-phase grinding witnesses", fri_rounds)?;
    r.skip(witnesses, VAL)?;
    let batches = r.len("FRI input batches", rounds)?;
    let row_cap = widest + NUM_RANDOM_CODEWORDS;
    for &m in &matrices[..batches] {
        r.exact("input opening queries", NUM_QUERIES)?;
        for _ in 0..NUM_QUERIES {
            r.exact("input opening matrices", m)?;
            for _ in 0..m {
                let width = r.len("input opening row", row_cap)?;
                r.skip(width, VAL)?;
            }
        }
        r.multiproof("input opening multiproof", m)?;
    }
    let openings = r.len("commit-phase openings", fri_rounds)?;
    for _ in 0..openings {
        r.byte()?; // log_arity
        r.exact("commit-phase queries", NUM_QUERIES)?;
        for _ in 0..NUM_QUERIES {
            r.ext_vec("commit-phase sibling values", (1 << MAX_LOG_ARITY) - 1)?;
        }
        r.multiproof("commit-phase multiproof", 1)?;
    }
    r.ext_vec("final polynomial", 1 << LOG_FINAL_POLY_LEN)?;
    r.skip(1, VAL)?; // query_pow_witness

    // Lookup terminals and degree bits, one per instance.
    let terminals = r.len("lookup terminals", n)?;
    for _ in 0..terminals {
        if r.option()? {
            r.skip(1, EXT)?;
        }
    }
    let degree_bits = r.len("degree bits", n)?;
    for _ in 0..degree_bits {
        r.varint()?;
    }
    if r.pos != body.len() {
        return Err(ZkError::Encoding("trailing bytes".into()));
    }
    Ok(())
}
