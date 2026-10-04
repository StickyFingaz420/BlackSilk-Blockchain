//! Blake2b-256, the consensus hash `H` (spec: conventions).

use blake2::digest::consts::U32;
use blake2::digest::Digest;
use blake2::Blake2b;

pub type Hash = [u8; 32];

/// Incremental Blake2b-256.
pub struct H(Blake2b<U32>);

/// The domain prefix of tagged hashes, as `blacksilk_crypto::hash::DOMAIN_PREFIX`
/// (`blacksilk-tx` checks that they are equal).
pub const DOMAIN_PREFIX: &str = "BlackSilk/v1/";

impl H {
    pub fn new() -> Self {
        Self(Blake2b::new())
    }

    /// Blake2b-256 started with the domain tag `u8(len) ‖ "BlackSilk/v1/" ‖
    /// name`, the convention of `blacksilk_crypto::hash` (`H32`).
    pub fn tagged(name: &str) -> Self {
        let len = DOMAIN_PREFIX.len() + name.len();
        assert!(len <= u8::MAX as usize, "domain tag too long");
        Self::new()
            .chain(&[len as u8])
            .chain(DOMAIN_PREFIX.as_bytes())
            .chain(name.as_bytes())
    }

    pub fn chain(mut self, data: &[u8]) -> Self {
        self.0.update(data);
        self
    }

    pub fn finish(self) -> Hash {
        self.0.finalize().into()
    }
}

impl Default for H {
    fn default() -> Self {
        Self::new()
    }
}
