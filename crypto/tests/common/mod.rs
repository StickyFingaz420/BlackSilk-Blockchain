//! Shared helpers for the pinned vector suites (`clsag_vectors`, `bpp_vectors`,
//! `stealth_vectors`).
//!
//! Two parts:
//! - [`spec`]: the hash functions of `docs/transactions.md` §1.2, written again
//!   from the text with raw `blake2` and dalek calls. They deliberately do not
//!   call `blacksilk_crypto::hash`, so the vector suites re-derive values
//!   independently of the implementation's helpers.
//! - [`Pins`]: the pinned values in `tests/vectors/*.txt`, one `name = hex` line
//!   each. Every suite checks a section (a name prefix) and fails if a pin is
//!   wrong, missing or never checked. Set `BLACKSILK_PRINT_VECTORS=1` and run with
//!   `--nocapture` to print the current values in the file format (review the
//!   diff before committing a regenerated file: a changed pin is a changed
//!   protocol).

// Each integration test binary compiles this module separately and uses only
// part of it.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub mod spec {
    use blake2::digest::consts::U32;
    use blake2::digest::Digest;
    use blake2::{Blake2b, Blake2b512};
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;

    /// `tag(t) = u8(len(t)) ‖ t` with `t = "BlackSilk/v1/" ‖ name`.
    pub fn tag(name: &str) -> Vec<u8> {
        let t = format!("BlackSilk/v1/{name}");
        let mut out = vec![u8::try_from(t.len()).expect("tag length")];
        out.extend_from_slice(t.as_bytes());
        out
    }

    /// `H32(t, x) = Blake2b-256(tag(t) ‖ x)`.
    pub fn h32(name: &str, x: &[u8]) -> [u8; 32] {
        let mut d = Blake2b::<U32>::new();
        d.update(tag(name));
        d.update(x);
        d.finalize().into()
    }

    /// `H64(t, x) = Blake2b-512(tag(t) ‖ x)`.
    pub fn h64(name: &str, x: &[u8]) -> [u8; 64] {
        let mut d = Blake2b512::new();
        d.update(tag(name));
        d.update(x);
        d.finalize().into()
    }

    /// `Hs(t, x)`: `H64` as a 512-bit little-endian integer, reduced mod ℓ.
    pub fn hs(name: &str, x: &[u8]) -> Scalar {
        Scalar::from_bytes_mod_order_wide(&h64(name, x))
    }

    /// `Hp(t, x)`: RFC 9496 element derivation of `H64(t, x)`.
    pub fn hp(name: &str, x: &[u8]) -> RistrettoPoint {
        RistrettoPoint::from_uniform_bytes(&h64(name, x))
    }

    /// Untagged Blake2b-256, used only for the generator digest.
    pub fn blake2b256(x: &[u8]) -> [u8; 32] {
        Blake2b::<U32>::digest(x).into()
    }

    /// `G`: the Ristretto255 base point.
    pub fn g() -> RistrettoPoint {
        curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT
    }

    /// `H = Hp("generator/H", "")`.
    pub fn h() -> RistrettoPoint {
        hp("generator/H", &[])
    }

    /// `Com(a, y) = y·G + a·H`.
    pub fn com(amount: u64, mask: &Scalar) -> RistrettoPoint {
        mask * g() + Scalar::from(amount) * h()
    }

    /// Concatenation helper for hash inputs.
    pub fn cat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    pub fn enc(p: &RistrettoPoint) -> [u8; 32] {
        p.compress().to_bytes()
    }
}

/// `Scalar::from_bytes_mod_order_wide([b; 64])`: the fixed test scalars.
pub fn wide(b: u8) -> curve25519_dalek::scalar::Scalar {
    curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&[b; 64])
}

/// A constant RNG (all zeros), for regression pins of the hedged signers:
/// with it the output is a function of the statement and secrets only.
pub struct ZeroRng;

impl rand_core::RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        dest.fill(0);
        Ok(())
    }
}
impl rand_core::CryptoRng for ZeroRng {}

/// One section of a pinned vector file.
pub struct Pins {
    file: &'static str,
    prefix: String,
    pins: BTreeMap<String, String>,
    checked: BTreeSet<String>,
    errors: Vec<String>,
    printed: Vec<String>,
}

fn print_mode() -> bool {
    std::env::var_os("BLACKSILK_PRINT_VECTORS").is_some()
}

impl Pins {
    /// `contents` is the vector file (`include_str!`); `prefix` selects the
    /// section this test owns (every pin whose name starts with it).
    pub fn new(file: &'static str, contents: &str, prefix: &str) -> Self {
        let mut pins = BTreeMap::new();
        for (n, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, value) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("{file}:{}: expected `name = value`", n + 1));
            let (name, value) = (name.trim().to_string(), value.trim().to_string());
            if name.starts_with(prefix) {
                assert!(
                    pins.insert(name.clone(), value).is_none(),
                    "{file}: duplicate pin {name}"
                );
            }
        }
        Self {
            file,
            prefix: prefix.to_string(),
            pins,
            checked: BTreeSet::new(),
            errors: Vec::new(),
            printed: Vec::new(),
        }
    }

    /// Compares `actual` with the pin `prefix + name`.
    pub fn check(&mut self, name: &str, actual: impl AsRef<[u8]>) {
        self.check_str(name, &hex::encode(actual));
    }

    /// Like [`Pins::check`] for a value that is already text (decimal, hex).
    pub fn check_str(&mut self, name: &str, actual: &str) {
        let full = format!("{}{}", self.prefix, name);
        assert!(
            self.checked.insert(full.clone()),
            "pin {full} checked twice"
        );
        self.printed.push(format!("{full} = {actual}"));
        match self.pins.get(&full) {
            Some(v) if v == actual => {}
            Some(v) => self
                .errors
                .push(format!("{full}:\n  pinned {v}\n  actual {actual}")),
            None => self.errors.push(format!("{full}: no pin in {}", self.file)),
        }
    }

    /// The pinned hex value `prefix + name`, decoded (for accept vectors that
    /// are read from the file rather than recomputed).
    pub fn bytes(&self, name: &str) -> Vec<u8> {
        let full = format!("{}{}", self.prefix, name);
        let v = self
            .pins
            .get(&full)
            .unwrap_or_else(|| panic!("{}: no pin {full}", self.file));
        hex::decode(v).unwrap_or_else(|e| panic!("{full}: {e}"))
    }

    /// Fails on any mismatch, missing pin, or pin in the section never checked.
    pub fn finish(self) {
        if print_mode() {
            println!("{}", self.printed.join("\n"));
            return;
        }
        let mut errors = self.errors;
        for name in self.pins.keys() {
            if !self.checked.contains(name) {
                errors.push(format!("{name}: pinned in {} but never checked", self.file));
            }
        }
        assert!(
            errors.is_empty(),
            "{} pinned-vector failure(s) in {}:\n{}",
            errors.len(),
            self.file,
            errors.join("\n")
        );
    }
}
