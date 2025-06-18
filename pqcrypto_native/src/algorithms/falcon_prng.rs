//! SHAKE256-based PRNG for Falcon
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use alloc::vec;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::string::ToString;

pub struct FalconPrng {
    reader: Box<dyn XofReader>,
}

impl FalconPrng {
    /// Initialize PRNG with a seed (typically 48 bytes for Falcon-512)
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(seed);
        let reader = Box::new(hasher.finalize_xof());
        FalconPrng { reader }
    }
    /// Fill a buffer with random bytes
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        self.reader.read(out);
    }
    /// Get a random u64
    pub fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
}
