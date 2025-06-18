#![no_std]

use alloc::vec;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::string::ToString;
use sha2::{Sha384, Digest as Sha2Digest};
use sha3::{Sha3_256, Digest as Sha3Digest};

pub fn sha384(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

pub fn sha3_256(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}
