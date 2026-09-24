//! `Hk`: the arithmetization-friendly hash of PX (zk.md §9.6).
//!
//! A sponge over Poseidon2 (BabyBear, width 16):
//! - rate 8 (state words 0..8), capacity 8 (words 8..16);
//! - the capacity starts as `[domain, length, 0, …]`, so each use and each
//!   input length is a distinct function (no padding ambiguity: the length is
//!   fixed before absorbing);
//! - input elements are added into the rate, 8 per permutation;
//! - the digest is the rate after the last permutation: 8 elements, 248 bits.
//!
//! Generic security: 124-bit collision and preimage resistance from the
//! 8-element (248-bit) capacity and output, assuming the Poseidon2
//! permutation behaves ideally (docs/px.md §8 lists this assumption).
//!
//! **Tree nodes** use the 2-to-1 compression `node(l, r) = P(l ‖ r)[0..8]`
//! (one permutation; the construction of Plonky3's own Merkle trees,
//! `TruncatedPermutation`), with 124-bit collision resistance in the same
//! model. It is separated from the sponge because every sponge call has a
//! nonzero domain constant in word 8, while a node input has there the first
//! element of a right child: equality needs a digest whose last seven
//! elements equal `[domain, len, 0, 0, 0, 0, 0]`, a 2^−186 event.
//! Depth is fixed at 32, so a leaf can never be read as a node.

use crate::{add, canonical};

/// A digest: 8 canonical BabyBear elements.
pub type Digest = [u32; 8];

pub const ZERO_DIGEST: Digest = [0; 8];

/// A width-16 Poseidon2 permutation over canonical BabyBear words.
///
/// Implementations: the Plonky3 permutation on the host (crate `blacksilk-px`),
/// the `POSEIDON2` syscall in the guest. Both use the standard BabyBear
/// constants; `blacksilk-px` tests that they agree.
pub trait Permutation {
    fn permute(&mut self, state: &mut [u32; 16]);
}

/// Domain constants of `Hk`. Each is a distinct canonical element.
pub mod domain {
    const BASE: u32 = 0x0050_5800; // "PX" in the upper bytes, < p
    pub const SK: u32 = BASE + 1;
    pub const NK: u32 = BASE + 2;
    pub const AK: u32 = BASE + 3;
    pub const OWNER: u32 = BASE + 4;
    pub const DIVERSIFIER: u32 = BASE + 5;
    pub const RECORD: u32 = BASE + 6;
    pub const NULLIFIER: u32 = BASE + 7;
    pub const RHO: u32 = BASE + 8;
    pub const IO: u32 = BASE + 9;
    pub const NULLIFIER_CONTRACT: u32 = BASE + 10;
}

/// An incremental `Hk` computation with a declared input length.
pub struct Sponge {
    state: [u32; 16],
    pos: usize,
    remaining: u32,
    permuted: bool,
}

impl Sponge {
    pub fn new(domain: u32, len: u32) -> Self {
        let mut state = [0u32; 16];
        state[8] = domain;
        state[9] = len;
        Sponge {
            state,
            pos: 0,
            remaining: len,
            permuted: false,
        }
    }

    /// Absorbs one canonical element.
    ///
    /// # Panics
    /// If more elements are absorbed than declared, or `x` is not canonical.
    pub fn absorb<P: Permutation>(&mut self, perm: &mut P, x: u32) {
        assert!(self.remaining > 0, "Hk: input longer than declared");
        assert!(canonical(x), "Hk: non-canonical input");
        self.remaining -= 1;
        self.state[self.pos] = add(self.state[self.pos], x);
        self.pos += 1;
        if self.pos == 8 {
            perm.permute(&mut self.state);
            self.pos = 0;
            self.permuted = true;
        }
    }

    pub fn absorb_all<P: Permutation>(&mut self, perm: &mut P, xs: &[u32]) {
        for &x in xs {
            self.absorb(perm, x);
        }
    }

    /// # Panics
    /// If fewer elements were absorbed than declared.
    pub fn finish<P: Permutation>(mut self, perm: &mut P) -> Digest {
        assert_eq!(self.remaining, 0, "Hk: input shorter than declared");
        if self.pos > 0 || !self.permuted {
            perm.permute(&mut self.state);
        }
        let mut d = [0u32; 8];
        d.copy_from_slice(&self.state[..8]);
        d
    }
}

/// `Hk(domain, parts…)` over the concatenation of `parts`: the same function
/// as [`Sponge`], without its per-element bookkeeping (a test checks they
/// agree).
///
/// # Panics
/// If an input element is not canonical.
pub fn hash<P: Permutation>(perm: &mut P, domain: u32, parts: &[&[u32]]) -> Digest {
    let len: usize = parts.iter().map(|p| p.len()).sum();
    let mut s = [0u32; 16];
    s[8] = domain;
    s[9] = len as u32;
    let mut pos = 0usize;
    for part in parts {
        for &x in part.iter() {
            assert!(canonical(x), "Hk: non-canonical input");
            s[pos] = add(s[pos], x);
            pos += 1;
            if pos == 8 {
                perm.permute(&mut s);
                pos = 0;
            }
        }
    }
    if pos > 0 || len == 0 {
        perm.permute(&mut s);
    }
    let mut d = [0u32; 8];
    d.copy_from_slice(&s[..8]);
    d
}

/// A commitment-tree node: `P(left ‖ right)[0..8]`.
pub fn node<P: Permutation>(perm: &mut P, left: &Digest, right: &Digest) -> Digest {
    let mut s = [0u32; 16];
    s[..8].copy_from_slice(left);
    s[8..].copy_from_slice(right);
    perm.permute(&mut s);
    let mut d = [0u32; 8];
    d.copy_from_slice(&s[..8]);
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::P;

    /// A toy mixing permutation (bijective on canonical states), enough to
    /// check the sponge bookkeeping. The real permutation is tested in
    /// `blacksilk-px`.
    struct Toy;
    impl Permutation for Toy {
        fn permute(&mut self, s: &mut [u32; 16]) {
            for r in 0..4 {
                for i in 0..16 {
                    let j = (i + 1 + r) % 16;
                    s[i] = add(s[i], ((s[j] as u64 * 7 + 3) % P as u64) as u32);
                }
                s.rotate_left(3);
            }
        }
    }

    #[test]
    fn hash_equals_the_reference_sponge_for_every_length() {
        let input: [u32; 40] = core::array::from_fn(|i| (i as u32 * 0x0123_4567) % P);
        for len in 0..=40 {
            let mut sp = Sponge::new(domain::RECORD, len as u32);
            sp.absorb_all(&mut Toy, &input[..len]);
            let reference = sp.finish(&mut Toy);
            // Split into parts at arbitrary points.
            let (a, b) = input[..len].split_at(len / 3);
            assert_eq!(
                hash(&mut Toy, domain::RECORD, &[a, b]),
                reference,
                "len {len}"
            );
        }
    }

    #[test]
    fn domain_and_length_separate_outputs() {
        let x = [5u32; 8];
        let h = |d: u32, xs: &[u32]| hash(&mut Toy, d, &[xs]);
        assert_ne!(h(domain::NK, &x), h(domain::AK, &x));
        // Trailing zeros are not padding: lengths differ, digests differ.
        assert_ne!(
            h(domain::NK, &x[..7]),
            h(domain::NK, &[5, 5, 5, 5, 5, 5, 5, 0])
        );
        assert_ne!(h(domain::NK, &[]), h(domain::NK, &[0]));
    }

    #[test]
    #[should_panic(expected = "non-canonical")]
    fn non_canonical_input_panics() {
        hash(&mut Toy, domain::NK, &[&[P]]);
    }

    #[test]
    fn domains_are_distinct_and_canonical() {
        let all = [
            domain::SK,
            domain::NK,
            domain::AK,
            domain::OWNER,
            domain::DIVERSIFIER,
            domain::RECORD,
            domain::NULLIFIER,
            domain::RHO,
            domain::IO,
            domain::NULLIFIER_CONTRACT,
        ];
        for (i, a) in all.iter().enumerate() {
            assert!(*a < P && *a != 0);
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
