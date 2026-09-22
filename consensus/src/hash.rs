//! Blake2b-256, the consensus hash `H` (spec: conventions).

use blake2::digest::consts::U32;
use blake2::digest::Digest;
use blake2::Blake2b;

pub type Hash = [u8; 32];

/// Incremental Blake2b-256.
pub struct H(Blake2b<U32>);

impl H {
    pub fn new() -> Self {
        Self(Blake2b::new())
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
