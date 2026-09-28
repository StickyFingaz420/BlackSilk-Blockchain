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
//! The kernel writes `(C, io_hash)` for each function. The function writes
//! the **function prefix** ([`function_prefix`], call ABI [`ABI_VERSION`])
//! as the first [`PREFIX_WORDS`] words of its public output:
//!
//! ```text
//! abi ‖ io_hash ‖ C ‖ not_before (2 words, LE) ‖ not_after (2 words, LE)
//! ```
//!
//! The verifier builds the kernel's pair and every prefix from public values:
//! `abi` from the program's registration, `io_hash` and `C` from the
//! transaction's function list, and the validity window from the
//! transaction ([`Window`], PX6). So a function can rely on the window: a
//! proof of it exists only for a transaction carrying exactly that window,
//! and consensus includes the transaction only at a height inside it. The
//! `blind` (8 random elements) makes `io_hash` a hiding commitment: it
//! reveals nothing about the records or amounts involved.
//!
//! **ABI versioning** (F-28-1). `abi` is the first prefix word, and every
//! registered program records the ABI it was built for. A later kernel
//! generation that changes the call format ([`Call`], [`OutSpec`], `N_IN`,
//! `N_OUT`, the prefix) gets a new ABI version, so that the verifier can
//! tell old-ABI programs from new ones (docs/contracts.md §4).

use crate::hash::{domain, Digest, Permutation, Sponge};
use crate::kernel::{N_IN, N_OUT};
use crate::record::limbs;
use crate::ZERO_DIGEST;

/// Most functions per transaction.
pub const MAX_FN: usize = 2;

/// The call ABI of this kernel generation: the first word of every function
/// prefix and the only ABI a deploy may register (F-28-1).
pub const ABI_VERSION: u32 = 1;

/// Words of the function prefix ([`function_prefix`]).
pub const PREFIX_WORDS: usize = 1 + 8 + 8 + 2 + 2;

/// A transaction's validity window (PX6): it may be included only in a block
/// at a height `h` with `not_before ≤ h` and, if `not_after ≠ 0`,
/// `h ≤ not_after`. `(0, 0)`, the default, is unbounded, and every
/// transaction without a reason for a window carries it, so the window does
/// not fingerprint wallets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Window {
    pub not_before: u64,
    pub not_after: u64,
}

impl Window {
    /// The unbounded window `(0, 0)`.
    pub const UNBOUNDED: Window = Window {
        not_before: 0,
        not_after: 0,
    };

    /// Whether the window is well formed: unbounded above, or not inverted.
    pub fn is_well_formed(&self) -> bool {
        self.not_after == 0 || self.not_before <= self.not_after
    }

    /// Whether a block at `height` may include the transaction.
    pub fn contains(&self, height: u64) -> bool {
        self.not_before <= height && (self.not_after == 0 || height <= self.not_after)
    }

    /// The window as four words: `not_before` then `not_after`, each low word
    /// first.
    pub fn words(&self) -> [u32; 4] {
        [
            self.not_before as u32,
            (self.not_before >> 32) as u32,
            self.not_after as u32,
            (self.not_after >> 32) as u32,
        ]
    }
}

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

/// The first [`PREFIX_WORDS`] public output words of a function:
/// `abi ‖ io_hash ‖ contract ‖ window` (module docs).
pub fn function_prefix(
    abi: u32,
    io_hash: &Digest,
    contract: &Digest,
    window: &Window,
) -> [u32; PREFIX_WORDS] {
    let mut w = [0u32; PREFIX_WORDS];
    w[0] = abi;
    w[1..9].copy_from_slice(io_hash);
    w[9..17].copy_from_slice(contract);
    w[17..].copy_from_slice(&window.words());
    w
}
