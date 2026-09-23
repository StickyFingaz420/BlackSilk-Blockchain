//! Hedged randomness (spec §10).
//!
//! Every secret random value (Janus anchors, pseudo-output masks, CLSAG nonces,
//! Bulletproofs+ blinding values) comes from a [`HedgedRng`]:
//!
//! ```text
//! seed    = H64("nonce", LE64(#secrets) ‖ (LE64(len) ‖ secret)… ‖
//!                        LE64(#context) ‖ (LE64(len) ‖ context)… ‖ 32 fresh CSPRNG bytes)
//! value_i = H64("nonce/stream", seed ‖ LE64(i))
//! ```
//!
//! - With a working CSPRNG the values are uniformly random.
//! - With a broken or even constant CSPRNG they remain unpredictable to anyone
//!   who does not know the secrets. They also differ whenever the context (the
//!   signed message, ring, outputs…) differs. So a nonce is never reused for two
//!   different challenges, which is what leaks the key in Schnorr-type schemes.

use crate::hash::{tags, Hasher64};
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

pub struct HedgedRng {
    seed: [u8; 64],
    counter: u64,
}

impl HedgedRng {
    pub fn new<R: RngCore + CryptoRng>(secrets: &[&[u8]], context: &[&[u8]], rng: &mut R) -> Self {
        let mut fresh = [0u8; 32];
        rng.fill_bytes(&mut fresh);
        let mut h = Hasher64::new(tags::NONCE);
        for list in [secrets, context] {
            h.update(&(list.len() as u64).to_le_bytes());
            for item in list {
                h.update(&(item.len() as u64).to_le_bytes());
                h.update(item);
            }
        }
        h.update(&fresh);
        fresh.zeroize();
        Self {
            seed: h.finalize(),
            counter: 0,
        }
    }

    fn next_block(&mut self) -> [u8; 64] {
        let out = Hasher64::new(tags::NONCE_STREAM)
            .chain(&self.seed)
            .chain(&self.counter.to_le_bytes())
            .finalize();
        self.counter += 1;
        out
    }

    /// A uniformly distributed non-zero scalar.
    pub fn scalar(&mut self) -> Scalar {
        loop {
            let mut block = self.next_block();
            let s = Scalar::from_bytes_mod_order_wide(&block);
            block.zeroize();
            if s != Scalar::ZERO {
                return s;
            }
        }
    }

    pub fn bytes16(&mut self) -> [u8; 16] {
        let mut block = self.next_block();
        let mut out = [0u8; 16];
        out.copy_from_slice(&block[..16]);
        block.zeroize();
        out
    }
}

impl Drop for HedgedRng {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

#[cfg(test)]
pub(crate) mod test_rng {
    use rand_chacha::rand_core::SeedableRng;
    pub use rand_chacha::ChaCha20Rng;

    pub fn seeded(seed: u64) -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(seed)
    }

    /// A "CSPRNG" that always outputs zeros: models a completely broken RNG.
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
}

#[cfg(test)]
mod tests {
    use super::test_rng::*;
    use super::*;

    #[test]
    fn stream_values_differ() {
        let mut h = HedgedRng::new(&[b"secret"], &[b"ctx"], &mut seeded(1));
        let a = h.scalar();
        let b = h.scalar();
        assert_ne!(a, b);
        assert_ne!(h.bytes16(), h.bytes16());
    }

    #[test]
    fn broken_rng_still_separates_contexts_and_secrets() {
        let x = HedgedRng::new(&[b"k"], &[b"m1"], &mut ZeroRng).scalar();
        let y = HedgedRng::new(&[b"k"], &[b"m2"], &mut ZeroRng).scalar();
        let z = HedgedRng::new(&[b"k2"], &[b"m1"], &mut ZeroRng).scalar();
        assert_ne!(x, y, "different messages must give different nonces");
        assert_ne!(x, z, "different secrets must give different nonces");
        // Deterministic when everything is equal (RFC 6979-like), which is safe.
        assert_eq!(x, HedgedRng::new(&[b"k"], &[b"m1"], &mut ZeroRng).scalar());
    }

    #[test]
    fn fresh_randomness_is_used() {
        let a = HedgedRng::new(&[b"k"], &[b"m"], &mut seeded(1)).scalar();
        let b = HedgedRng::new(&[b"k"], &[b"m"], &mut seeded(2)).scalar();
        assert_ne!(a, b);
    }

    #[test]
    fn list_boundaries_are_unambiguous() {
        let a = HedgedRng::new(&[b"ab", b"c"], &[], &mut ZeroRng).scalar();
        let b = HedgedRng::new(&[b"a", b"bc"], &[], &mut ZeroRng).scalar();
        let c = HedgedRng::new(&[b"ab"], &[b"c"], &mut ZeroRng).scalar();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
