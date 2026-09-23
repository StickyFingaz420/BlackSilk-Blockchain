//! Domain-separated hashing (spec §1.2).
//!
//! Every hash input starts with `u8(len(tag)) ‖ tag`, where `tag` is
//! `"BlackSilk/v1/" ‖ name`. The length prefix makes the (tag, data) split
//! unambiguous, so hashes for different purposes can never collide by
//! construction. All names are listed in [`tags`]; a test checks they are distinct.

use blake2::digest::consts::U32;
use blake2::digest::Digest;
use blake2::{Blake2b, Blake2b512};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

/// Prefix of every domain tag.
pub const DOMAIN_PREFIX: &str = "BlackSilk/v1/";

/// Tag names (without [`DOMAIN_PREFIX`]).
pub mod tags {
    pub const GENERATOR_H: &str = "generator/H";
    pub const GENERATOR_BP_G: &str = "generator/bp+/G";
    pub const GENERATOR_BP_H: &str = "generator/bp+/H";
    pub const WALLET_SPEND_KEY: &str = "wallet/spend-key";
    pub const WALLET_VIEW_KEY: &str = "wallet/view-key";
    pub const SUBADDRESS: &str = "subaddress";
    pub const INPUT_CONTEXT: &str = "input-context";
    pub const INPUT_CONTEXT_COINBASE: &str = "input-context/coinbase";
    pub const EPHEMERAL: &str = "ephemeral";
    pub const OUTPUT_KEY: &str = "output-key";
    pub const VIEW_TAG: &str = "view-tag";
    pub const AMOUNT: &str = "amount";
    pub const MASK: &str = "mask";
    pub const ANCHOR: &str = "anchor";
    pub const KEY_IMAGE: &str = "key-image";
    pub const CLSAG_AGG_P: &str = "clsag/agg-P";
    pub const CLSAG_AGG_C: &str = "clsag/agg-C";
    pub const CLSAG_ROUND: &str = "clsag/round";
    pub const BPP_INIT: &str = "bp+/init";
    pub const BPP_Y: &str = "bp+/y";
    pub const BPP_Z: &str = "bp+/z";
    pub const BPP_ROUND: &str = "bp+/round";
    pub const BPP_FINAL: &str = "bp+/final";
    pub const TX_PREFIX: &str = "tx/prefix";
    pub const TX_BASE: &str = "tx/base";
    pub const TX_PRUNABLE: &str = "tx/prunable";
    pub const TX_BP: &str = "tx/bp";
    pub const TX_HASH: &str = "tx/hash";
    pub const TX_SIG_MESSAGE: &str = "tx/sig-message";
    pub const NONCE: &str = "nonce";
    pub const NONCE_STREAM: &str = "nonce/stream";
    pub const ADDRESS_CHECKSUM: &str = "address/checksum";

    /// Every tag, for the distinctness test.
    pub const ALL: &[&str] = &[
        GENERATOR_H,
        GENERATOR_BP_G,
        GENERATOR_BP_H,
        WALLET_SPEND_KEY,
        WALLET_VIEW_KEY,
        SUBADDRESS,
        INPUT_CONTEXT,
        INPUT_CONTEXT_COINBASE,
        EPHEMERAL,
        OUTPUT_KEY,
        VIEW_TAG,
        AMOUNT,
        MASK,
        ANCHOR,
        KEY_IMAGE,
        CLSAG_AGG_P,
        CLSAG_AGG_C,
        CLSAG_ROUND,
        BPP_INIT,
        BPP_Y,
        BPP_Z,
        BPP_ROUND,
        BPP_FINAL,
        TX_PREFIX,
        TX_BASE,
        TX_PRUNABLE,
        TX_BP,
        TX_HASH,
        TX_SIG_MESSAGE,
        NONCE,
        NONCE_STREAM,
        ADDRESS_CHECKSUM,
    ];
}

fn absorb_tag<D: Digest>(digest: &mut D, name: &str) {
    let len = DOMAIN_PREFIX.len() + name.len();
    assert!(len <= u8::MAX as usize, "domain tag too long");
    digest.update([len as u8]);
    digest.update(DOMAIN_PREFIX.as_bytes());
    digest.update(name.as_bytes());
}

/// Incremental 512-bit domain-separated hash (`H64`, and the base of `Hs`/`Hp`).
/// Cloning snapshots the state, so a common prefix is hashed only once.
#[derive(Clone)]
pub struct Hasher64(Blake2b512);

impl Hasher64 {
    pub fn new(name: &str) -> Self {
        let mut inner = Blake2b512::new();
        absorb_tag(&mut inner, name);
        Self(inner)
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data);
        self
    }

    pub fn chain(mut self, data: &[u8]) -> Self {
        self.0.update(data);
        self
    }

    pub fn finalize(self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out.copy_from_slice(&self.0.finalize());
        out
    }

    /// `Hs`: the 512-bit digest reduced mod ℓ (bias < 2^-259).
    pub fn to_scalar(self) -> Scalar {
        Scalar::from_bytes_mod_order_wide(&self.finalize())
    }

    /// `Hp`: RFC 9496 element derivation from the 512-bit digest.
    pub fn to_point(self) -> RistrettoPoint {
        RistrettoPoint::from_uniform_bytes(&self.finalize())
    }
}

/// `H32(name, parts…)`: Blake2b-256 over the tag and the concatenated parts.
pub fn h32(name: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Blake2b::<U32>::new();
    absorb_tag(&mut digest, name);
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

/// `H64(name, parts…)`.
pub fn h64(name: &str, parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Hasher64::new(name);
    for part in parts {
        h.update(part);
    }
    h.finalize()
}

/// `Hs(name, parts…)`.
pub fn hash_to_scalar(name: &str, parts: &[&[u8]]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&h64(name, parts))
}

/// `Hp(name, parts…)`.
pub fn hash_to_point(name: &str, parts: &[&[u8]]) -> RistrettoPoint {
    RistrettoPoint::from_uniform_bytes(&h64(name, parts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn tags_are_distinct_and_short() {
        let set: HashSet<_> = tags::ALL.iter().collect();
        assert_eq!(set.len(), tags::ALL.len(), "duplicate tag name");
        for t in tags::ALL {
            assert!(DOMAIN_PREFIX.len() + t.len() <= 255);
        }
    }

    #[test]
    fn domain_separation() {
        // Same data under different tags gives unrelated outputs.
        let a = h32(tags::MASK, &[b"x"]);
        let b = h32(tags::AMOUNT, &[b"x"]);
        assert_ne!(a, b);
        // The length prefix prevents moving bytes between tag and data:
        // tag "mask" + data "x" differs from the raw concatenation without a prefix.
        let mut raw = Blake2b::<U32>::new();
        raw.update(format!("{DOMAIN_PREFIX}maskx").as_bytes());
        let raw: [u8; 32] = raw.finalize().into();
        assert_ne!(a, raw);
    }

    #[test]
    fn parts_are_concatenated() {
        assert_eq!(h32(tags::MASK, &[b"ab", b"c"]), h32(tags::MASK, &[b"abc"]));
        assert_eq!(
            h64(tags::MASK, &[b"ab", b"c"]),
            h64(tags::MASK, &[b"a", b"bc"])
        );
        let h = Hasher64::new(tags::MASK)
            .chain(b"a")
            .chain(b"bc")
            .finalize();
        assert_eq!(h, h64(tags::MASK, &[b"abc"]));
    }

    /// The helpers match a direct Blake2b computation of the spec's definition.
    #[test]
    fn kat_matches_definition() {
        let mut d = Blake2b512::new();
        let tag = b"BlackSilk/v1/mask";
        d.update([tag.len() as u8]);
        d.update(tag);
        d.update(b"data");
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&d.finalize());
        assert_eq!(h64(tags::MASK, &[b"data"]), wide);
        assert_eq!(
            hash_to_scalar(tags::MASK, &[b"data"]),
            Scalar::from_bytes_mod_order_wide(&wide)
        );
        assert_eq!(
            hash_to_point(tags::MASK, &[b"data"]),
            RistrettoPoint::from_uniform_bytes(&wide)
        );
    }
}
