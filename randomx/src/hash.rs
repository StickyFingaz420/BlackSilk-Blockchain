//! Blake2b helpers used throughout RandomX (`Hash512`, `Hash256`, Argon2's `H'`).

use blake2::digest::{Digest, Update, VariableOutput};
use blake2::{Blake2b512, Blake2bVar};

pub(crate) fn blake2b_512(data: &[u8]) -> [u8; 64] {
    Blake2b512::digest(data).into()
}

pub(crate) fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    blake2b_var(&mut out, &[data]);
    out
}

/// Blake2b with an output length of `out.len()` (1..=64) over the concatenation of `parts`.
pub(crate) fn blake2b_var(out: &mut [u8], parts: &[&[u8]]) {
    let mut h = Blake2bVar::new(out.len()).expect("blake2b output length must be 1..=64");
    for p in parts {
        h.update(p);
    }
    h.finalize_variable(out)
        .expect("output buffer length matches");
}

/// Argon2's variable-length hash `H'` (RFC 9106, section 3.3).
pub(crate) fn blake2b_long(out: &mut [u8], input: &[u8]) {
    let outlen = out.len() as u32;
    let len_prefix = outlen.to_le_bytes();
    if out.len() <= 64 {
        blake2b_var(out, &[&len_prefix, input]);
        return;
    }
    let mut v = [0u8; 64];
    blake2b_var(&mut v, &[&len_prefix, input]);
    out[..32].copy_from_slice(&v[..32]);
    let mut pos = 32;
    let mut remaining = out.len() - 32;
    while remaining > 64 {
        v = blake2b_512(&v);
        out[pos..pos + 32].copy_from_slice(&v[..32]);
        pos += 32;
        remaining -= 32;
    }
    blake2b_var(&mut out[pos..], &[&v]);
}
