//! Keys, records, commitments and nullifiers (zk.md §4.2–§4.4).
//!
//! ```text
//! nk      = Hk("px/nk", sk)                 nullifier key
//! ak      = Hk("px/ak", sk)                 authorization key
//! d_i     = Hk("px/diversifier", sk ‖ i)    per-address diversifier (wallet-side)
//! owner   = Hk("px/owner", ak ‖ nk ‖ d)     per-address owner tag
//! cm      = Hk("px/record", owner ‖ contract ‖ asset ‖ value₁₆[4] ‖ data ‖ rho ‖ rcm)
//! nf      = Hk("px/nf", nk ‖ rho ‖ cm)
//! rho_j   = Hk("px/rho", nf_0 ‖ j)          for output j of a transaction
//! ```
//!
//! Spending proves knowledge of `sk` (hash-based ownership: no discrete
//! logarithms, zk.md §4.2).

use crate::hash::{domain, hash, Digest, Permutation, ZERO_DIGEST};

/// The two keys derived from a spend secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keys {
    pub nk: Digest,
    pub ak: Digest,
}

impl Keys {
    pub fn derive<P: Permutation>(perm: &mut P, sk: &Digest) -> Keys {
        Keys {
            nk: hash(perm, domain::NK, &[sk]),
            ak: hash(perm, domain::AK, &[sk]),
        }
    }

    /// The owner tag of the address with diversifier `d`.
    pub fn owner<P: Permutation>(&self, perm: &mut P, d: &Digest) -> Digest {
        hash(perm, domain::OWNER, &[&self.ak, &self.nk, d])
    }
}

/// The diversifier of address `index` of spend secret `sk`.
pub fn diversifier<P: Permutation>(perm: &mut P, sk: &Digest, index: u32) -> Digest {
    // `index` is a u32 and may exceed p: split into 16-bit halves.
    hash(
        perm,
        domain::DIVERSIFIER,
        &[sk, &[index & 0xffff, index >> 16]],
    )
}

/// A PX record (zk.md §4.3). In v2.0 `contract` and `asset` must be zero
/// (plain BLK records); the kernel enforces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub owner: Digest,
    pub contract: Digest,
    pub asset: Digest,
    pub value: u64,
    pub data: [u32; 8],
    pub rho: Digest,
    pub rcm: Digest,
}

/// The four 16-bit limbs of a value, least significant first.
pub fn limbs(value: u64) -> [u32; 4] {
    [0, 1, 2, 3].map(|i| ((value >> (16 * i)) & 0xffff) as u32)
}

impl Record {
    /// A plain BLK record.
    pub fn plain(owner: Digest, value: u64, data: [u32; 8], rho: Digest, rcm: Digest) -> Record {
        Record {
            owner,
            contract: ZERO_DIGEST,
            asset: ZERO_DIGEST,
            value,
            data,
            rho,
            rcm,
        }
    }

    pub fn commit<P: Permutation>(&self, perm: &mut P) -> Digest {
        hash(
            perm,
            domain::RECORD,
            &[
                &self.owner,
                &self.contract,
                &self.asset,
                &limbs(self.value),
                &self.data,
                &self.rho,
                &self.rcm,
            ],
        )
    }
}

pub fn nullifier<P: Permutation>(perm: &mut P, nk: &Digest, rho: &Digest, cm: &Digest) -> Digest {
    hash(perm, domain::NULLIFIER, &[nk, rho, cm])
}

/// The nullifier of a contract record: `Hk(NULLIFIER_CONTRACT, contract ‖ rcm
/// ‖ cm)`, as the kernel computes it (`kernel.rs`). It depends only on the
/// opening, so every holder of the opening sees when the record is consumed.
pub fn contract_nullifier<P: Permutation>(
    perm: &mut P,
    contract: &Digest,
    rcm: &Digest,
    cm: &Digest,
) -> Digest {
    hash(perm, domain::NULLIFIER_CONTRACT, &[contract, rcm, cm])
}

/// `rho` of output `j`, derived from the transaction's first nullifier.
pub fn output_rho<P: Permutation>(perm: &mut P, nf0: &Digest, j: u32) -> Digest {
    hash(perm, domain::RHO, &[nf0, &[j]])
}
