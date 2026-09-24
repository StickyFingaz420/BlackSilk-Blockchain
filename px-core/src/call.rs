//! Contract function calls (zk.md §7; docs/px.md §7): the transcript a
//! private function commits to, shared by the function program and the
//! kernel.
//!
//! A function of contract `C` decides, from private data only it sees:
//! - which kernel inputs it **approves** for consumption (records of `C`),
//!   identified by their exact commitments;
//! - which kernel outputs it **specifies**: records of `C` (new contract
//!   state) or payouts to users, as `(owner, contract, value, data)`; the
//!   kernel adds `rho` and the caller's `rcm`.
//!
//! Both sides compute
//!
//! ```text
//! io_hash = Hk(IO, C ‖ per input i: [a_i, a_i·cm_i] ‖ per output j: [s_j, s_j·(owner ‖ contract ‖ value₁₆[4] ‖ data)] ‖ blind)
//! ```
//!
//! The function writes `io_hash ‖ C` as the first 16 words of its public
//! output, the kernel writes the same pair for each function, and the
//! verifier builds both from one public value. The `blind` (8 random
//! elements) makes `io_hash` a hiding commitment: it reveals nothing about
//! the records or amounts involved.

use crate::hash::{domain, Digest, Permutation, Sponge};
use crate::kernel::{N_IN, N_OUT};
use crate::record::limbs;
use crate::ZERO_DIGEST;

/// Most functions per transaction.
pub const MAX_FN: usize = 2;

/// An output a function specifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutSpec {
    pub owner: Digest,
    pub contract: Digest,
    pub value: u64,
    pub data: [u32; 8],
}

/// A function's transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Call {
    pub contract: Digest,
    /// Approved input commitments, by kernel input slot.
    pub approve: [Option<Digest>; N_IN],
    /// Specified outputs, by kernel output slot.
    pub spec: [Option<OutSpec>; N_OUT],
    pub blind: Digest,
}

/// Elements of the `io_hash` input.
const IO_LEN: u32 = (8 + N_IN * 9 + N_OUT * (1 + 8 + 8 + 4 + 8) + 8) as u32;

impl Call {
    pub fn io_hash<P: Permutation>(&self, perm: &mut P) -> Digest {
        let mut s = Sponge::new(domain::IO, IO_LEN);
        s.absorb_all(perm, &self.contract);
        for a in &self.approve {
            s.absorb(perm, a.is_some() as u32);
            s.absorb_all(perm, &a.unwrap_or(ZERO_DIGEST));
        }
        let none = OutSpec {
            owner: ZERO_DIGEST,
            contract: ZERO_DIGEST,
            value: 0,
            data: [0; 8],
        };
        for o in &self.spec {
            s.absorb(perm, o.is_some() as u32);
            let o = o.unwrap_or(none);
            s.absorb_all(perm, &o.owner);
            s.absorb_all(perm, &o.contract);
            s.absorb_all(perm, &limbs(o.value));
            s.absorb_all(perm, &o.data);
        }
        s.absorb_all(perm, &self.blind);
        s.finish(perm)
    }
}

/// The first 16 public output words of a function: `io_hash ‖ contract`.
pub fn function_prefix(io_hash: &Digest, contract: &Digest) -> [u32; 16] {
    let mut w = [0u32; 16];
    w[..8].copy_from_slice(io_hash);
    w[8..].copy_from_slice(contract);
    w
}
