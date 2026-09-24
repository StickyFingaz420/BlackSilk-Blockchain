//! The PX kernel (zk.md §6; docs/px.md §4, §7).
//!
//! [`transfer`] reads a witness and either returns the public statement or an
//! error. The kernel guest program runs it inside the zkVM and writes
//! [`Public::write`] as its output. A proof of that program with exit code 0
//! therefore shows that a witness exists for which every check below passed.
//!
//! **Shape.** Always two inputs and two outputs; unused slots are dummies
//! (inputs) or zero-value records (outputs). A transaction may also call up
//! to [`MAX_FN`] contract functions, proven in the same batch proof
//! (docs/px.md §7); their number is public.
//!
//! **Checks**, for each input `i`:
//! 1. **User record** (`contract = 0`): `nk, ak` derive from the witness `sk`,
//!    and `owner = Hk(ak ‖ nk ‖ d)`. Only the holder of `sk` can spend a record
//!    paid to one of its addresses.
//!    **Contract record** (`contract ≠ 0`): `owner = 0`, and some called
//!    function of that contract approves exactly this commitment.
//! 2. `cm_i = Commit(record_i)` (`asset = 0`).
//! 3. Real input: the Merkle path from `cm_i` at `position_i` reaches `anchor`.
//!    Dummy input: a user record of value 0 (its path is still hashed).
//! 4. Nullifier: `Hk(NULLIFIER, nk ‖ rho ‖ cm)` for user records,
//!    `Hk(NULLIFIER_CONTRACT, contract ‖ rcm ‖ cm)` for contract records;
//!    `nf_0 ≠ nf_1`.
//!
//! For each output `j`: `rho'_j = Hk(RHO, nf_0 ‖ j)`, `cm'_j = Commit(record'_j)`.
//! If a function specifies slot `j`, the output has exactly the specified
//! contents; a contract output must be specified by a function of its
//! contract; a function may specify only its own contract's records or user
//! payouts; at most one function specifies a slot.
//!
//! For each function `k`: `contract_k ≠ 0`; it approves only records of its
//! own contract; the kernel outputs `(contract_k, io_hash_k)` computed from
//! the actual commitments and outputs (`call::Call::io_hash`).
//!
//! Balance, over the integers: `Σ value_i + bridge_in = Σ value'_j + bridge_out`.
//!
//! **Constant work.** For a given number of functions, successful executions
//! run the same instruction sequence up to a handful of branch-dependent
//! instructions: both nullifier forms and the owner tag are computed for
//! every input, paths are hashed for dummies, and comparisons do not exit
//! early. So the (public) table heights do not reveal dummies, record kinds,
//! positions or values. `blacksilk-px` tests this.

use crate::call::{Call, OutSpec, MAX_FN};
use crate::hash::{domain, hash, node, Digest, Permutation};
use crate::record::{nullifier, output_rho, Keys, Record};
use crate::{canonical, ZERO_DIGEST};

/// Kernel format version: the first witness word and the first output word.
pub const VERSION: u32 = 2;
pub const TREE_DEPTH: usize = 32;
pub const N_IN: usize = 2;
pub const N_OUT: usize = 2;

/// Most public output words (`Public::write`).
pub const MAX_PUBLIC_WORDS: usize = 1 + 8 + 8 * N_IN + 8 * N_OUT + 2 + 2 + 1 + 16 * MAX_FN;

/// Why a witness was rejected. The guest halts with `exit_code()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Version,
    NonCanonical,
    NotBoolean,
    DummyWithValue,
    NotInTree,
    DuplicateNullifier,
    Unbalanced,
    /// More than [`MAX_FN`] functions.
    TooManyFunctions,
    /// A function with contract 0.
    ZeroContract,
    /// A contract input no function of its contract approved, or a contract
    /// output no function of its contract specified.
    Unauthorized,
    /// A function approved an input that is not a record of its contract.
    ApprovalMismatch,
    /// An output differs from the function's specification.
    SpecMismatch,
    /// A function specified a record of another contract.
    SpecForeignContract,
    /// Two functions specified the same output.
    SpecConflict,
    /// A dummy input with a contract.
    DummyContract,
}

impl Error {
    /// Exit code of the kernel guest (0 is success, 1 is a panic).
    pub fn exit_code(self) -> u32 {
        2 + self as u32
    }
}

/// A source of witness words (the `READ` syscall in the guest).
pub trait Source {
    fn next(&mut self) -> u32;
}

/// A source over a slice (host side). Reading past the end yields an error
/// word (`u32::MAX`, never canonical), as the guest would trap.
pub struct SliceSource<'a> {
    words: &'a [u32],
    pos: usize,
}

impl<'a> SliceSource<'a> {
    pub fn new(words: &'a [u32]) -> Self {
        SliceSource { words, pos: 0 }
    }
}

impl Source for SliceSource<'_> {
    fn next(&mut self) -> u32 {
        let w = self.words.get(self.pos).copied().unwrap_or(u32::MAX);
        self.pos += 1;
        w
    }
}

/// The public statement of a PX transaction's kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Public {
    pub anchor: Digest,
    pub nullifiers: [Digest; N_IN],
    pub commitments: [Digest; N_OUT],
    pub bridge_in: u64,
    pub bridge_out: u64,
    /// Number of called functions.
    pub n_fn: usize,
    /// `(contract, io_hash)` of each called function (first `n_fn`).
    pub functions: [(Digest, Digest); MAX_FN],
}

impl Public {
    /// Writes the public output words.
    pub fn write(&self, mut out: impl FnMut(u32)) {
        out(VERSION);
        self.anchor.iter().for_each(|&x| out(x));
        for d in self.nullifiers.iter().chain(self.commitments.iter()) {
            d.iter().for_each(|&x| out(x));
        }
        for v in [self.bridge_in, self.bridge_out] {
            out(v as u32);
            out((v >> 32) as u32);
        }
        out(self.n_fn as u32);
        for (c, h) in &self.functions[..self.n_fn] {
            c.iter().chain(h.iter()).for_each(|&x| out(x));
        }
    }
}

fn elem<S: Source>(src: &mut S) -> Result<u32, Error> {
    let x = src.next();
    if canonical(x) {
        Ok(x)
    } else {
        Err(Error::NonCanonical)
    }
}

fn digest<S: Source>(src: &mut S) -> Result<Digest, Error> {
    let mut d = [0u32; 8];
    for x in d.iter_mut() {
        *x = elem(src)?;
    }
    Ok(d)
}

fn u64_word<S: Source>(src: &mut S) -> u64 {
    let lo = src.next() as u64;
    let hi = src.next() as u64;
    lo | (hi << 32)
}

fn boolean<S: Source>(src: &mut S) -> Result<bool, Error> {
    match src.next() {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::NotBoolean),
    }
}

/// Digest equality without an early exit.
fn digest_eq(a: &Digest, b: &Digest) -> bool {
    a.iter().zip(b).fold(0u32, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn is_zero(a: &Digest) -> bool {
    digest_eq(a, &ZERO_DIGEST)
}

/// Selects `a` if `c`, else `b`, with masks.
fn select(c: bool, a: &Digest, b: &Digest) -> Digest {
    let m = (c as u32).wrapping_neg();
    let mut r = [0u32; 8];
    for i in 0..8 {
        r[i] = (a[i] & m) | (b[i] & !m);
    }
    r
}

fn read_spec<S: Source>(src: &mut S) -> Result<Option<OutSpec>, Error> {
    let present = boolean(src)?;
    let spec = OutSpec {
        owner: digest(src)?,
        contract: digest(src)?,
        value: u64_word(src),
        data: digest(src)?,
    };
    Ok(present.then_some(spec))
}

/// Runs the kernel over a witness (layout: docs/px.md §4.2).
pub fn transfer<P: Permutation, S: Source>(perm: &mut P, src: &mut S) -> Result<Public, Error> {
    if src.next() != VERSION {
        return Err(Error::Version);
    }
    let anchor = digest(src)?;
    let bridge_in = u64_word(src);
    let bridge_out = u64_word(src);

    // Function transcripts (the commitments of approved inputs are filled in
    // from the actual inputs below).
    let n_fn = src.next() as usize;
    if n_fn > MAX_FN {
        return Err(Error::TooManyFunctions);
    }
    let empty = Call {
        contract: ZERO_DIGEST,
        approve: [None; N_IN],
        spec: [None; N_OUT],
        blind: ZERO_DIGEST,
    };
    let mut calls = [empty; MAX_FN];
    for call in calls.iter_mut().take(n_fn) {
        call.contract = digest(src)?;
        call.blind = digest(src)?;
        if is_zero(&call.contract) {
            return Err(Error::ZeroContract);
        }
        for a in call.approve.iter_mut() {
            // Placeholder: replaced by the input's actual commitment.
            *a = boolean(src)?.then_some(ZERO_DIGEST);
        }
        for s in call.spec.iter_mut() {
            *s = read_spec(src)?;
            if let Some(o) = s {
                if !is_zero(&o.contract) && !digest_eq(&o.contract, &call.contract) {
                    return Err(Error::SpecForeignContract);
                }
            }
        }
    }

    let mut total_in = bridge_in as u128;
    let mut nullifiers = [ZERO_DIGEST; N_IN];
    // Membership is accumulated and decided after both inputs, so a
    // successful execution does the same work whatever the dummy flags are.
    let mut ok = true;
    for (i, nf) in nullifiers.iter_mut().enumerate() {
        let dummy = boolean(src)?;
        let contract = digest(src)?;
        let sk = digest(src)?;
        let d = digest(src)?;
        let value = u64_word(src);
        let data = digest(src)?;
        let rho = digest(src)?;
        let rcm = digest(src)?;
        let is_contract = !is_zero(&contract);
        // Both owner and nullifier forms are computed (constant work).
        let keys = Keys::derive(perm, &sk);
        let user_owner = keys.owner(perm, &d);
        let owner = select(is_contract, &ZERO_DIGEST, &user_owner);
        let record = Record {
            owner,
            contract,
            asset: ZERO_DIGEST,
            value,
            data,
            rho,
            rcm,
        };
        let cm = record.commit(perm);

        let position = src.next();
        let mut cur = cm;
        for level in 0..TREE_DEPTH {
            let sibling = digest(src)?;
            let right = (position >> level) & 1 == 1;
            let l = select(right, &sibling, &cur);
            let r = select(right, &cur, &sibling);
            cur = node(perm, &l, &r);
        }
        let member = digest_eq(&cur, &anchor);
        if dummy {
            if value != 0 {
                return Err(Error::DummyWithValue);
            }
            if is_contract {
                return Err(Error::DummyContract);
            }
        } else {
            ok &= member;
        }

        // Authorization of contract records; approvals must match.
        let mut approved = false;
        for call in calls.iter_mut().take(n_fn) {
            if let Some(a) = call.approve[i].as_mut() {
                if dummy || !is_contract || !digest_eq(&call.contract, &contract) {
                    return Err(Error::ApprovalMismatch);
                }
                *a = cm;
                approved = true;
            }
        }
        if is_contract && !approved {
            return Err(Error::Unauthorized);
        }

        let user_nf = nullifier(perm, &keys.nk, &rho, &cm);
        let contract_nf = hash(perm, domain::NULLIFIER_CONTRACT, &[&contract, &rcm, &cm]);
        *nf = select(is_contract, &contract_nf, &user_nf);
        total_in += value as u128;
    }
    if !ok {
        return Err(Error::NotInTree);
    }
    if digest_eq(&nullifiers[0], &nullifiers[1]) {
        return Err(Error::DuplicateNullifier);
    }

    let mut total_out = bridge_out as u128;
    let mut commitments = [ZERO_DIGEST; N_OUT];
    for (j, cm) in commitments.iter_mut().enumerate() {
        let owner = digest(src)?;
        let contract = digest(src)?;
        let value = u64_word(src);
        let data = digest(src)?;
        let rcm = digest(src)?;
        let rho = output_rho(perm, &nullifiers[0], j as u32);
        *cm = Record {
            owner,
            contract,
            asset: ZERO_DIGEST,
            value,
            data,
            rho,
            rcm,
        }
        .commit(perm);
        total_out += value as u128;

        let mut specs = 0;
        let mut by_own_contract = false;
        for call in calls.iter().take(n_fn) {
            if let Some(o) = &call.spec[j] {
                specs += 1;
                let same = digest_eq(&o.owner, &owner)
                    & digest_eq(&o.contract, &contract)
                    & (o.value == value)
                    & digest_eq(&o.data, &data);
                if !same {
                    return Err(Error::SpecMismatch);
                }
                by_own_contract |= digest_eq(&call.contract, &contract);
            }
        }
        if specs > 1 {
            return Err(Error::SpecConflict);
        }
        if !is_zero(&contract) && !by_own_contract {
            return Err(Error::Unauthorized);
        }
    }
    if total_in != total_out {
        return Err(Error::Unbalanced);
    }

    let mut functions = [(ZERO_DIGEST, ZERO_DIGEST); MAX_FN];
    for (f, call) in functions.iter_mut().zip(calls.iter()).take(n_fn) {
        *f = (call.contract, call.io_hash(perm));
    }
    Ok(Public {
        anchor,
        nullifiers,
        commitments,
        bridge_in,
        bridge_out,
        n_fn,
        functions,
    })
}

/// An input witness, built on the host. `contract = 0` is a user record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputWitness {
    pub dummy: bool,
    pub contract: Digest,
    pub sk: Digest,
    pub d: Digest,
    pub value: u64,
    pub data: [u32; 8],
    pub rho: Digest,
    pub rcm: Digest,
    pub position: u32,
    pub path: [Digest; TREE_DEPTH],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputWitness {
    pub owner: Digest,
    pub contract: Digest,
    pub value: u64,
    pub data: [u32; 8],
    pub rcm: Digest,
}

/// A function's part of the kernel witness: its contract, blind, approval
/// flags and output specifications (the transcript without commitments).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FunctionWitness {
    pub contract: Digest,
    pub blind: Digest,
    pub approve: [bool; N_IN],
    pub spec: [Option<OutSpec>; N_OUT],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pub anchor: Digest,
    pub bridge_in: u64,
    pub bridge_out: u64,
    pub n_fn: usize,
    pub functions: [Option<FunctionWitness>; MAX_FN],
    pub inputs: [InputWitness; N_IN],
    pub outputs: [OutputWitness; N_OUT],
}

fn u64w(out: &mut impl FnMut(u32), v: u64) {
    out(v as u32);
    out((v >> 32) as u32);
}

fn dw(out: &mut impl FnMut(u32), d: &Digest) {
    d.iter().for_each(|&x| out(x));
}

impl Witness {
    /// Serializes the witness, word by word, in the order [`transfer`] reads.
    pub fn write(&self, mut out: impl FnMut(u32)) {
        out(VERSION);
        dw(&mut out, &self.anchor);
        u64w(&mut out, self.bridge_in);
        u64w(&mut out, self.bridge_out);
        out(self.n_fn as u32);
        for f in self.functions.iter().take(self.n_fn) {
            let f = f.as_ref().expect("n_fn functions present");
            dw(&mut out, &f.contract);
            dw(&mut out, &f.blind);
            for a in f.approve {
                out(a as u32);
            }
            for s in &f.spec {
                out(s.is_some() as u32);
                let o = s.unwrap_or(OutSpec {
                    owner: ZERO_DIGEST,
                    contract: ZERO_DIGEST,
                    value: 0,
                    data: [0; 8],
                });
                dw(&mut out, &o.owner);
                dw(&mut out, &o.contract);
                u64w(&mut out, o.value);
                dw(&mut out, &o.data);
            }
        }
        for i in &self.inputs {
            out(i.dummy as u32);
            for d in [&i.contract, &i.sk, &i.d] {
                dw(&mut out, d);
            }
            u64w(&mut out, i.value);
            for d in [&i.data, &i.rho, &i.rcm] {
                dw(&mut out, d);
            }
            out(i.position);
            for s in &i.path {
                dw(&mut out, s);
            }
        }
        for o in &self.outputs {
            dw(&mut out, &o.owner);
            dw(&mut out, &o.contract);
            u64w(&mut out, o.value);
            for d in [&o.data, &o.rcm] {
                dw(&mut out, d);
            }
        }
    }
}
