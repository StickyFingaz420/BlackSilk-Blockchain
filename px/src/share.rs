//! Sharing a record's opening off chain (docs/px.md §13.3).
//!
//! On chain, each output's ciphertext reaches one address. When more parties
//! need a record (for example a contract record that both the creator and a
//! counterparty act on), its holder can **share** it: the opening sealed to
//! the other party's PX address with the same hybrid encryption as on-chain
//! delivery (§6), sent over any channel.
//!
//! ```text
//! share = SHARE_VERSION ‖ cm (32) ‖ rho (32) ‖ delivery ciphertext
//! ```
//!
//! The recipient opens it with [`open_share`], which applies the on-chain
//! acceptance rule: the decrypted record must recompute `cm`. The wallet then
//! also requires `cm` to be in the chain's commitment tree, so a share can
//! only ever describe a real, existing record. A share reveals nothing to
//! anyone but the addressee, and it is bound to its `cm` (the AEAD's
//! associated data).

use crate::delivery::{self, Address, DeliveryKeys, SealError, CIPHERTEXT_BYTES};
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{Digest, P};
use rand_core::{CryptoRng, RngCore};

pub const SHARE_VERSION: u8 = 1;
pub const SHARE_BYTES: usize = 1 + 32 + 32 + CIPHERTEXT_BYTES;

fn put(out: &mut Vec<u8>, d: &Digest) {
    for x in d {
        out.extend_from_slice(&x.to_le_bytes());
    }
}

fn get(b: &[u8]) -> Option<Digest> {
    let mut d = [0u32; 8];
    for (i, x) in d.iter_mut().enumerate() {
        *x = u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().ok()?);
        if *x >= P {
            return None;
        }
    }
    Some(d)
}

/// Seals `record`, committed as `cm`, to `to`.
pub fn seal_share<R: RngCore + CryptoRng>(
    rng: &mut R,
    to: &Address,
    record: &Record,
    cm: &Digest,
) -> Result<Vec<u8>, SealError> {
    let ct = delivery::seal(rng, to, record, cm)?;
    let mut out = Vec::with_capacity(SHARE_BYTES);
    out.push(SHARE_VERSION);
    put(&mut out, cm);
    put(&mut out, &record.rho);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Opens a share as the address with `keys` and owner tag `owner`: the record
/// and its commitment, if the share is well formed, addressed to this address
/// and consistent with its commitment.
pub fn open_share(keys: &DeliveryKeys, owner: &Digest, share: &[u8]) -> Option<(Record, Digest)> {
    if share.len() != SHARE_BYTES || share[0] != SHARE_VERSION {
        return None;
    }
    let cm = get(&share[1..33])?;
    let rho = get(&share[33..65])?;
    let record = delivery::open(keys, owner, &share[65..], &cm, &rho)?;
    Some((record, cm))
}
