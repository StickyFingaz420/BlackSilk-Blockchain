//! Private-execution (PX) transactions (docs/px.md §11): the PX transaction
//! (kind 2) and the private-contract deploy (kind 3). Formats, hashing and
//! the stateless rules; contextual and block rules are in [`crate::validate`].
//!
//! **PX transaction.** One transaction carries
//! - the PX statement: anchor, two nullifiers, two commitments with their
//!   record ciphertexts, the public bridge amounts, and the called functions
//!   (contract, program id, public output words);
//! - an optional v1 part: ring inputs (to bridge value in), hidden change
//!   outputs (only with inputs), and clear-amount **payouts** (bridge-out
//!   stealth outputs whose amounts are public anyway, like coinbase outputs);
//! - the public fee;
//! - the validity window `[not_before, not_after]` (PX6; `(0, 0)` is
//!   unbounded), which every called function receives in its prefix;
//! - the PX proof, bound to `h_tx`, which covers everything but the prunable
//!   part.
//!
//! **Balance** (v1 side): with `v = fee + bridge_in + Σ payouts − bridge_out`,
//! `Σ pseudo_outs − Σ hidden outputs = v·H`. Without v1 inputs there are no
//! hidden outputs and `v = 0` exactly. The PX side (`Σ inputs + bridge_in =
//! Σ outputs + bridge_out`) is proven by the kernel; the pool keeps the
//! bridge contained (px/src/state.rs).
//!
//! **Deploy.** A v1 transfer (paying the fee) plus a salt and up to 16
//! function programs (RISC-V binaries, stored on chain because verifiers
//! need them), each with its row budget, call ABI and number of public
//! output words. The contract id is derived from the first key image, the
//! salt and the whole payload (programs, budgets, ABIs and output words), so
//! it is unique and fixes every registration.

use crate::codec::{DecodeError, Reader, Writer};
use crate::params::*;
use crate::types::*;
use crate::validate::TxError;
use blacksilk_crypto::bulletproofs_plus::{self as bpp, BppProof};
use blacksilk_crypto::clsag::Clsag;
use blacksilk_crypto::generators::h;
use blacksilk_crypto::hash::{h32, h64, tags};
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_px::delivery::CIPHERTEXT_BYTES;
use blacksilk_px_core::call::MAX_FN;
pub use blacksilk_px_core::call::{Window, ABI_VERSION};
use blacksilk_px_core::kernel::Public;
use blacksilk_px_core::{Digest, P};
use blacksilk_zkvm::air::trace::Budget;
use blacksilk_zkvm::Program;
use std::sync::Arc;

/// A function called by a PX transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PxFunction {
    pub contract: Digest,
    pub program_id: [u8; 32],
    /// The function's transcript commitment (docs/px.md §7.2).
    pub io_hash: Digest,
    /// The function's public output words after `io_hash ‖ contract`.
    pub outputs: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PxTx {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub payouts: Vec<CoinbaseOutput>,
    pub fee: u64,
    pub bridge_in: u64,
    pub bridge_out: u64,
    /// The validity window (PX6): the heights at which a block may include
    /// the transaction. Covered by `h_tx` and placed in every function's
    /// prefix. `Window::UNBOUNDED` for every transaction that needs none.
    pub window: Window,
    pub anchor: Digest,
    pub nullifiers: [Digest; 2],
    pub commitments: [Digest; 2],
    pub ciphertexts: [Vec<u8>; 2],
    pub functions: Vec<PxFunction>,
    pub pseudo_outs: Vec<Point>,
    pub range_proof: Option<BppProof>,
    pub signatures: Vec<Clsag>,
    pub proof: Vec<u8>,
}

/// A function program registered by a deploy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub elf: Vec<u8>,
    pub budget: Budget,
    /// The call ABI the program was built for (the first word of its
    /// function prefix). A deploy must register [`ABI_VERSION`] (F-28-1).
    pub abi: u32,
    /// The exact number of public output words the program writes after its
    /// prefix; every call must publish exactly this many (F-28-5).
    pub out_words: u32,
}

impl Registration {
    /// A registration of `elf` for the current call ABI ([`ABI_VERSION`]).
    pub fn new(elf: Vec<u8>, budget: Budget, out_words: u32) -> Self {
        Registration {
            elf,
            budget,
            abi: ABI_VERSION,
            out_words,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PxDeploy {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub fee: u64,
    pub salt: [u8; 32],
    pub programs: Vec<Registration>,
    pub pseudo_outs: Vec<Point>,
    pub range_proof: BppProof,
    pub signatures: Vec<Clsag>,
}

// ---- field encodings ----

/// A digest as 32 bytes (8 little-endian words).
pub fn digest_bytes(d: &Digest) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, x) in d.iter().enumerate() {
        b[4 * i..4 * i + 4].copy_from_slice(&x.to_le_bytes());
    }
    b
}

pub(crate) fn write_digest(w: &mut Writer, d: &Digest) {
    for x in d {
        w.bytes(&x.to_le_bytes());
    }
}

pub(crate) fn read_digest(r: &mut Reader<'_>) -> Result<Digest, DecodeError> {
    let mut d = [0u32; 8];
    for x in d.iter_mut() {
        *x = u32::from_le_bytes(r.array()?);
        if *x >= P {
            return Err(DecodeError::NonCanonicalField);
        }
    }
    Ok(d)
}

fn write_budget(w: &mut Writer, b: &Budget) {
    for v in [
        b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
    ] {
        w.varint(v as u64);
    }
}

fn read_budget(r: &mut Reader<'_>) -> Result<Budget, DecodeError> {
    // Every budget field is bounded by the largest table (2^22 rows).
    let mut v = [0usize; 8];
    for x in v.iter_mut() {
        *x = r.count("budget", 0, 1 << blacksilk_zk::params::MAX_LOG_HEIGHT)?;
    }
    Ok(Budget {
        cycles: v[0],
        keys: v[1],
        add: v[2],
        bit: v[3],
        lt: v[4],
        shift: v[5],
        mul: v[6],
        poseidon: v[7],
    })
}

fn write_inputs(w: &mut Writer, inputs: &[Input]) {
    w.varint(inputs.len() as u64);
    for input in inputs {
        w.point(&input.key_image);
        crate::types::write_ring_pub(w, &input.ring);
    }
}

fn read_inputs(r: &mut Reader<'_>, min: u64) -> Result<Vec<Input>, DecodeError> {
    let n = r.count("inputs", min, MAX_INPUTS as u64)?;
    let mut inputs = Vec::with_capacity(n);
    for _ in 0..n {
        let key_image = r.point()?;
        let ring = crate::types::read_ring_pub(r)?;
        inputs.push(Input { key_image, ring });
    }
    Ok(inputs)
}

fn write_outputs(w: &mut Writer, outputs: &[Output]) {
    w.varint(outputs.len() as u64);
    for o in outputs {
        w.point(&o.one_time_key);
        w.point(&o.ephemeral);
        w.u8(o.view_tag);
        w.point(&o.commitment);
        w.bytes(&o.enc_amount);
        w.bytes(&o.enc_anchor);
    }
}

fn read_outputs(r: &mut Reader<'_>, min: u64) -> Result<Vec<Output>, DecodeError> {
    let k = r.count("outputs", min, MAX_OUTPUTS as u64)?;
    let mut outputs = Vec::with_capacity(k);
    for _ in 0..k {
        outputs.push(Output {
            one_time_key: r.point()?,
            ephemeral: r.point()?,
            view_tag: r.u8()?,
            commitment: r.point()?,
            enc_amount: r.array()?,
            enc_anchor: r.array()?,
        });
    }
    Ok(outputs)
}

fn write_sigs(w: &mut Writer, sigs: &[Clsag]) {
    for s in sigs {
        w.scalar(&s.c0);
        for x in &s.s {
            w.scalar(x);
        }
        w.point(&s.d);
    }
}

fn read_sigs(r: &mut Reader<'_>, n: usize) -> Result<Vec<Clsag>, DecodeError> {
    (0..n)
        .map(|_| {
            let c0 = r.scalar()?;
            let mut s = [Scalar::ZERO; RING_SIZE];
            for x in &mut s {
                *x = r.scalar()?;
            }
            let d = r.point()?;
            Ok(Clsag { c0, s, d })
        })
        .collect()
}

fn read_bytes(r: &mut Reader<'_>, what: &'static str, max: usize) -> Result<Vec<u8>, DecodeError> {
    let len = r.count(what, 0, max as u64)?;
    let start = r.position();
    r.skip(len)?;
    Ok(r.slice(start, start + len).to_vec())
}

// ---- PX transaction ----

impl PxTx {
    pub fn prefix_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.varint(TX_VERSION);
        w.u8(KIND_PX);
        write_inputs(&mut w, &self.inputs);
        write_outputs(&mut w, &self.outputs);
        w.varint(self.payouts.len() as u64);
        for o in &self.payouts {
            w.point(&o.one_time_key);
            w.point(&o.ephemeral);
            w.u8(o.view_tag);
            w.varint(o.amount);
            w.bytes(&o.enc_anchor);
        }
        w.varint(self.fee);
        w.varint(self.bridge_in);
        w.varint(self.bridge_out);
        w.varint(self.window.not_before);
        w.varint(self.window.not_after);
        write_digest(&mut w, &self.anchor);
        for d in self.nullifiers.iter().chain(&self.commitments) {
            write_digest(&mut w, d);
        }
        for c in &self.ciphertexts {
            w.bytes(c);
        }
        w.varint(self.functions.len() as u64);
        for f in &self.functions {
            write_digest(&mut w, &f.contract);
            w.bytes(&f.program_id);
            write_digest(&mut w, &f.io_hash);
            w.varint(f.outputs.len() as u64);
            for x in &f.outputs {
                w.bytes(&x.to_le_bytes());
            }
        }
        w.into_bytes()
    }

    pub fn base_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        for p in &self.pseudo_outs {
            w.point(p);
        }
        w.into_bytes()
    }

    fn range_proof_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        if let Some(p) = &self.range_proof {
            crate::types::write_bpp(&mut w, p);
        }
        w.into_bytes()
    }

    pub fn prunable_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.range_proof_bytes());
        write_sigs(&mut w, &self.signatures);
        w.varint(self.proof.len() as u64);
        w.bytes(&self.proof);
        w.into_bytes()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.prefix_bytes();
        out.extend(self.base_bytes());
        out.extend(self.prunable_bytes());
        out
    }

    pub fn encoded_len(&self) -> usize {
        self.encode().len()
    }

    pub(crate) fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let inputs = read_inputs(r, 0)?;
        let outputs = read_outputs(r, 0)?;
        let m = r.count("payouts", 0, MAX_PAYOUTS as u64)?;
        let mut payouts = Vec::with_capacity(m);
        for _ in 0..m {
            payouts.push(CoinbaseOutput {
                one_time_key: r.point()?,
                ephemeral: r.point()?,
                view_tag: r.u8()?,
                amount: r.varint()?,
                enc_anchor: r.array()?,
            });
        }
        let fee = r.varint()?;
        let bridge_in = r.varint()?;
        let bridge_out = r.varint()?;
        let window = Window {
            not_before: r.varint()?,
            not_after: r.varint()?,
        };
        let anchor = read_digest(r)?;
        let nullifiers = [read_digest(r)?, read_digest(r)?];
        let commitments = [read_digest(r)?, read_digest(r)?];
        let ciphertexts = [
            r.array::<CIPHERTEXT_BYTES>()?.to_vec(),
            r.array::<CIPHERTEXT_BYTES>()?.to_vec(),
        ];
        let nf = r.count("functions", 0, MAX_FN as u64)?;
        let mut functions = Vec::with_capacity(nf);
        for _ in 0..nf {
            let contract = read_digest(r)?;
            let program_id = r.array()?;
            let io_hash = read_digest(r)?;
            let n_out = r.count("function outputs", 0, MAX_FN_OUTPUT_WORDS as u64)?;
            let mut outs = Vec::with_capacity(n_out);
            for _ in 0..n_out {
                outs.push(u32::from_le_bytes(r.array()?));
            }
            functions.push(PxFunction {
                contract,
                program_id,
                io_hash,
                outputs: outs,
            });
        }
        let n = inputs.len();
        let pseudo_outs = (0..n).map(|_| r.point()).collect::<Result<_, _>>()?;
        let range_proof = if outputs.is_empty() {
            None
        } else {
            Some(crate::types::read_bpp_pub(r, outputs.len())?)
        };
        let signatures = read_sigs(r, n)?;
        let proof = read_bytes(r, "px proof", blacksilk_zk::params::MAX_PROOF_BYTES)?;
        Ok(Self {
            inputs,
            outputs,
            payouts,
            fee,
            bridge_in,
            bridge_out,
            window,
            anchor,
            nullifiers,
            commitments,
            ciphertexts,
            functions,
            pseudo_outs,
            range_proof,
            signatures,
            proof,
        })
    }

    pub fn prefix_hash(&self) -> Hash {
        h32(tags::TX_PREFIX, &[&self.prefix_bytes()])
    }

    pub fn base_hash(&self) -> Hash {
        h32(tags::TX_BASE, &[&self.base_bytes()])
    }

    pub fn prunable_hash(&self) -> Hash {
        h32(tags::TX_PRUNABLE, &[&self.prunable_bytes()])
    }

    /// `h_tx`: the binding of the PX proof (zk.md §5.2). It covers the whole
    /// transaction except the prunable part (range proof, signatures, the
    /// proof itself; so the validity window too), and the signature domain (network, branch and genesis
    /// ids, RT-14), so a proof is valid for exactly one transaction on one
    /// chain in one epoch. It is a public input of the proof, so the domain
    /// does not change the kernel.
    pub fn binding(&self, domain: SigDomain) -> Hash {
        h32(
            tags::PX_TX_BINDING,
            &[&domain.bytes(), &self.prefix_hash(), &self.base_hash()],
        )
    }

    /// The message the v1 inputs' CLSAGs sign: everything except the
    /// signatures, including the range proof and the PX proof.
    pub fn signature_message(&self, domain: SigDomain) -> Hash {
        h32(
            tags::PX_SIG_MESSAGE,
            &[
                &domain.bytes(),
                &self.prefix_hash(),
                &self.base_hash(),
                &h32(tags::TX_BP, &[&self.range_proof_bytes()]),
                &h32(tags::PX_PROOF, &[&self.proof]),
            ],
        )
    }

    /// The kernel's public statement.
    pub fn public(&self) -> Public {
        let mut functions = [([0u32; 8], [0u32; 8]); MAX_FN];
        for (slot, f) in functions.iter_mut().zip(&self.functions) {
            *slot = (f.contract, f.io_hash);
        }
        Public {
            anchor: self.anchor,
            nullifiers: self.nullifiers,
            commitments: self.commitments,
            bridge_in: self.bridge_in,
            bridge_out: self.bridge_out,
            n_fn: self.functions.len(),
            functions,
        }
    }

    /// Output keys added to the global output set: hidden outputs, then
    /// payouts (commitment `G + a·H`, as coinbase outputs).
    pub fn output_keys(&self) -> Vec<OutputKey> {
        self.outputs
            .iter()
            .map(|o| OutputKey {
                one_time_key: o.one_time_key,
                commitment: o.commitment,
            })
            .chain(self.payouts.iter().map(|o| OutputKey {
                one_time_key: o.one_time_key,
                commitment: o.commitment(),
            }))
            .collect()
    }

    /// The stealth-output context of the transaction's v1 outputs.
    pub fn output_context(&self) -> [u8; 32] {
        let nfs: Vec<[u8; 32]> = self.nullifiers.iter().map(digest_bytes).collect();
        let images: Vec<Point> = self.inputs.iter().map(|i| i.key_image).collect();
        blacksilk_crypto::stealth::px_context(&nfs, &images)
    }
}

// ---- deploy ----

/// The deploy payload: salt, program count, and each program's length, ELF
/// bytes, budget, call ABI and output-word count. The contract id hashes it
/// ([`PxDeploy::contract_id`]), so the ABI and the output words of every
/// program are part of the contract's identity.
pub(crate) fn deploy_payload_bytes(salt: &[u8; 32], programs: &[Registration]) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(salt);
    w.varint(programs.len() as u64);
    for p in programs {
        w.varint(p.elf.len() as u64);
        w.bytes(&p.elf);
        write_budget(&mut w, &p.budget);
        w.varint(p.abi as u64);
        w.varint(p.out_words as u64);
    }
    w.into_bytes()
}

/// The exact fee of a deploy with `inputs` v1 inputs and `outputs` outputs
/// registering `programs` (R5-1, R6 TX-4; docs/px.md §11.3):
///
/// `rules.standard_fee(inputs, outputs) + DEPLOY_FEE_PER_BYTE × payload length`,
/// where `rules.standard_fee(n, k) = FEE_PER_WEIGHT × max_weight(n, k)`.
///
/// The transfer part pays exactly the standard fee of a transfer of the same
/// shape (the exact v1 fee, T8, through the same `TxRules` function); the
/// payload pays per byte. Neither term depends on the fee itself, and every
/// input is public, so the fee reveals nothing about the wallet.
pub fn deploy_fee(
    inputs: usize,
    outputs: usize,
    programs: &[Registration],
    rules: &TxRules,
) -> u64 {
    let payload = deploy_payload_bytes(&[0; 32], programs).len() as u64;
    rules
        .standard_fee(inputs, outputs)
        .unwrap_or(u64::MAX)
        .saturating_add(DEPLOY_FEE_PER_BYTE.saturating_mul(payload))
}

impl PxDeploy {
    fn payload_bytes(&self) -> Vec<u8> {
        deploy_payload_bytes(&self.salt, &self.programs)
    }

    pub fn prefix_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.varint(TX_VERSION);
        w.u8(KIND_PX_DEPLOY);
        write_inputs(&mut w, &self.inputs);
        write_outputs(&mut w, &self.outputs);
        w.varint(self.fee);
        w.bytes(&self.payload_bytes());
        w.into_bytes()
    }

    pub fn base_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        for p in &self.pseudo_outs {
            w.point(p);
        }
        w.into_bytes()
    }

    pub fn prunable_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        crate::types::write_bpp(&mut w, &self.range_proof);
        write_sigs(&mut w, &self.signatures);
        w.into_bytes()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.prefix_bytes();
        out.extend(self.base_bytes());
        out.extend(self.prunable_bytes());
        out
    }

    pub fn encoded_len(&self) -> usize {
        self.encode().len()
    }

    pub(crate) fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let inputs = read_inputs(r, 1)?;
        let outputs = read_outputs(r, MIN_OUTPUTS as u64)?;
        let fee = r.varint()?;
        let salt = r.array()?;
        let np = r.count("programs", 1, MAX_DEPLOY_PROGRAMS as u64)?;
        let mut programs = Vec::with_capacity(np);
        for _ in 0..np {
            let elf = read_bytes(r, "program", MAX_PROGRAM_BYTES)?;
            let budget = read_budget(r)?;
            // Any u32 decodes; `check_deploy_structure` refuses an ABI other
            // than ABI_VERSION with its own error.
            let abi = r.count("program abi", 0, u32::MAX as u64)? as u32;
            let out_words = r.count("program output words", 0, MAX_FN_OUTPUT_WORDS as u64)? as u32;
            programs.push(Registration {
                elf,
                budget,
                abi,
                out_words,
            });
        }
        let n = inputs.len();
        let pseudo_outs = (0..n).map(|_| r.point()).collect::<Result<_, _>>()?;
        let range_proof = crate::types::read_bpp_pub(r, outputs.len())?;
        let signatures = read_sigs(r, n)?;
        Ok(Self {
            inputs,
            outputs,
            fee,
            salt,
            programs,
            pseudo_outs,
            range_proof,
            signatures,
        })
    }

    pub fn prefix_hash(&self) -> Hash {
        h32(tags::TX_PREFIX, &[&self.prefix_bytes()])
    }

    /// The v1 transfer part, for the transfer rules (structure, balance,
    /// range proof). Its own signature message is not used: deploys sign
    /// [`Self::signature_message`], which also covers the payload.
    pub fn as_transfer(&self) -> Transfer {
        Transfer {
            inputs: self.inputs.clone(),
            outputs: self.outputs.clone(),
            fee: self.fee,
            pseudo_outs: self.pseudo_outs.clone(),
            range_proof: self.range_proof.clone(),
            signatures: self.signatures.clone(),
        }
    }

    pub fn signature_message(&self, domain: SigDomain) -> Hash {
        let t = self.as_transfer();
        h32(
            tags::TX_SIG_MESSAGE,
            &[
                &domain.bytes(),
                &self.prefix_hash(),
                &t.base_hash(),
                &h32(tags::TX_BP, &[&t.range_proof_bytes()]),
            ],
        )
    }

    /// The contract id: 8 canonical field elements from
    /// `H64("px/contract-id", first key image ‖ salt ‖ payload hash)`. Key
    /// images never repeat, so neither do contract ids. The payload hash
    /// covers every program's ELF, budget, ABI and output words, so a
    /// contract id fixes its registrations.
    ///
    /// Total: a deploy without inputs (which `decode` never produces, and
    /// which is invalid by T3) takes the identity encoding (32 zero bytes) in
    /// place of the first key image instead of panicking. T4 forbids an
    /// identity key image, so no valid deploy hashes the same preimage, and
    /// the id of every deploy with inputs is unchanged. Callers such as
    /// mempool conflict keys may run before validation.
    pub fn contract_id(&self) -> Digest {
        const NO_INPUT: [u8; 32] = [0; 32];
        let payload = h32(tags::PX_DEPLOY_PAYLOAD, &[&self.payload_bytes()]);
        let first_image = self
            .inputs
            .first()
            .map_or(&NO_INPUT, |i| i.key_image.bytes());
        let wide = h64(tags::PX_CONTRACT_ID, &[first_image, &self.salt, &payload]);
        let mut d = [0u32; 8];
        for (i, x) in d.iter_mut().enumerate() {
            let v = u64::from_le_bytes(wide[8 * i..8 * i + 8].try_into().expect("8 bytes"));
            *x = (v % P as u64) as u32;
        }
        d
    }

    /// The registered programs, loaded (a program that does not load makes
    /// the deploy invalid).
    pub fn load_programs(&self) -> Result<Vec<(Arc<Program>, Budget)>, TxError> {
        self.programs
            .iter()
            .map(|p| {
                Program::from_elf(&p.elf)
                    .map(|prog| (Arc::new(prog), p.budget))
                    .map_err(|_| TxError::PxInvalidProgram)
            })
            .collect()
    }

    /// The fee this deploy must pay under `rules`, exactly ([`deploy_fee`]).
    pub fn required_fee(&self, rules: &TxRules) -> u64 {
        deploy_fee(self.inputs.len(), self.outputs.len(), &self.programs, rules)
    }
}

// ---- stateless rules ----

fn strictly_increasing<T: Ord>(items: impl IntoIterator<Item = T>) -> bool {
    let mut prev: Option<T> = None;
    for item in items {
        if let Some(p) = &prev {
            if *p >= item {
                return false;
            }
        }
        prev = Some(item);
    }
    true
}

/// The PX ciphertext `R` rule (docs/reviews/v3-consensus-changes.md
/// `px-ciphertext-r`; docs/px.md §6, §11.3): every record ciphertext is
/// exactly [`CIPHERTEXT_BYTES`] long, and its first 32 bytes, the ephemeral
/// key `R`, are a canonical ristretto255 encoding (RFC 9496 decoding, the
/// same `Point::decode` as every v1 point) of a point other than the
/// identity. The ristretto255 group has prime order, so a canonical decoding
/// is a complete group-membership check. Nothing else in the ciphertext is
/// checkable (the view tag is a hash byte, every ML-KEM-768 ciphertext of the
/// right length is well formed, and the AEAD body is pseudorandom).
///
/// A wrong length cannot come from `decode` (which reads exactly
/// `CIPHERTEXT_BYTES`); it is refused here, as non-canonical, for
/// transactions built in memory. The non-canonical check comes first, so a
/// non-canonical encoding of the identity is reported as non-canonical.
pub fn check_ciphertext_r(ciphertexts: &[Vec<u8>; 2]) -> Result<(), TxError> {
    for (ciphertext, c) in ciphertexts.iter().enumerate() {
        let r: Option<&[u8; 32]> = (c.len() == CIPHERTEXT_BYTES)
            .then(|| c.get(..32).and_then(|r| r.try_into().ok()))
            .flatten();
        let point = r
            .and_then(Point::decode)
            .ok_or(TxError::PxCiphertextRNonCanonical { ciphertext })?;
        if point.is_identity() {
            return Err(TxError::PxCiphertextRIdentity { ciphertext });
        }
    }
    Ok(())
}

/// Structure of a PX transaction (the PX counterpart of T1, T3–T8, T10, T11),
/// and the ciphertext `R` rule ([`check_ciphertext_r`]).
pub fn check_px_structure(tx: &PxTx) -> Result<(), TxError> {
    let n = tx.inputs.len();
    let k = tx.outputs.len();
    if n > MAX_INPUTS {
        return Err(TxError::InputCount(n));
    }
    if k > MAX_OUTPUTS || (k > 0 && n == 0) {
        // Hidden outputs need input masks to balance (module docs).
        return Err(TxError::OutputCount(k));
    }
    for (i, input) in tx.inputs.iter().enumerate() {
        if input.key_image.is_identity() {
            return Err(TxError::KeyImageIdentity { input: i });
        }
        if !strictly_increasing(input.ring.iter()) {
            return Err(TxError::RingNotIncreasing { input: i });
        }
    }
    if !strictly_increasing(tx.inputs.iter().map(|i| i.key_image)) {
        return Err(TxError::KeyImagesNotSorted);
    }
    let keys: Vec<(Point, Point)> = tx
        .outputs
        .iter()
        .map(|o| (o.one_time_key, o.ephemeral))
        .chain(tx.payouts.iter().map(|o| (o.one_time_key, o.ephemeral)))
        .collect();
    for (j, (otk, eph)) in keys.iter().enumerate() {
        if otk.is_identity() {
            return Err(TxError::OutputKeyIdentity { output: j });
        }
        if eph.is_identity() {
            return Err(TxError::EphemeralIdentity { output: j });
        }
    }
    if !strictly_increasing(tx.outputs.iter().map(|o| o.one_time_key))
        || !strictly_increasing(tx.payouts.iter().map(|o| o.one_time_key))
    {
        return Err(TxError::OutputsNotSorted);
    }
    // Hidden outputs and payouts are sorted separately, so a key shared by
    // the two lists is not caught above. This check is the only rule that
    // rejects it: one-time keys are distinct within a transaction, never
    // required unique across transactions (D8 option B,
    // docs/reviews/v3-consensus-changes.md §1). It must never be dropped: it
    // is what the wallet-side burning-bug argument rests on
    // (docs/transactions.md §3.1). `output` indexes `output_keys()` (hidden
    // outputs, then payouts).
    let mut seen = std::collections::HashSet::with_capacity(keys.len());
    for (j, (otk, _)) in keys.iter().enumerate() {
        if !seen.insert(*otk.bytes()) {
            return Err(TxError::PxDuplicateOutputKey { output: j });
        }
    }
    // The same for the two nullifiers, which PX2 rejects on every chain when
    // they are equal.
    if tx.nullifiers[0] == tx.nullifiers[1] {
        return Err(TxError::PxNullifierRepeated);
    }
    check_ciphertext_r(&tx.ciphertexts)?;
    if tx.pseudo_outs.len() != n {
        return Err(TxError::PseudoOutCount);
    }
    if tx.signatures.len() != n {
        return Err(TxError::SignatureCount);
    }
    crate::validate::check_aux_images(&tx.signatures)?;
    match (&tx.range_proof, k) {
        (None, 0) => {}
        (Some(p), k) if k > 0 => {
            let rounds = bpp::rounds(k).ok_or(TxError::RangeProofShape)?;
            if p.l.len() != rounds || p.r.len() != rounds {
                return Err(TxError::RangeProofShape);
            }
        }
        _ => return Err(TxError::RangeProofShape),
    }
    if tx.functions.len() > MAX_FN {
        return Err(TxError::PxShape);
    }
    // PX6, its stateless part: an inverted window admits no height.
    if !tx.window.is_well_formed() {
        return Err(TxError::PxWindowInverted);
    }
    let size = tx.encoded_len();
    if size > MAX_PX_TX_SIZE {
        return Err(TxError::TooLarge { size });
    }
    // One fee for every PX transaction. It covers the per-byte fee of any
    // PX transaction, since none exceeds MAX_PX_TX_SIZE.
    if tx.fee != PX_STANDARD_FEE {
        return Err(TxError::PxFeeNotStandard { fee: tx.fee });
    }
    Ok(())
}

/// The v1-side balance of a PX transaction (module docs).
pub fn check_px_balance(tx: &PxTx) -> Result<(), TxError> {
    let payouts: u128 = tx.payouts.iter().map(|o| o.amount as u128).sum();
    let v: i128 = tx.fee as i128 + tx.bridge_in as i128 + payouts as i128 - tx.bridge_out as i128;
    if tx.inputs.is_empty() {
        return if tx.outputs.is_empty() && v == 0 {
            Ok(())
        } else {
            Err(TxError::Unbalanced)
        };
    }
    let scalar = if v >= 0 {
        Scalar::from(v as u128)
    } else {
        -Scalar::from((-v) as u128)
    };
    let inputs: RistrettoPoint = tx.pseudo_outs.iter().map(|p| p.point()).sum();
    let outputs: RistrettoPoint = tx.outputs.iter().map(|o| o.commitment.point()).sum();
    if Point::from_point(inputs - outputs - scalar * h()).is_identity() {
        Ok(())
    } else {
        Err(TxError::Unbalanced)
    }
}

/// Whether a function with budget `b` can be proven, alone, with the kernel
/// (R7-5): every table of the one-function statement stays within its height
/// limit (`blacksilk_zkvm::prove::limits`).
/// - The function's CPU table: at most `MAX_CYCLES` rows.
/// - Its memory-init table (`keys`): at most `2^MAX_LOG_HEIGHT` rows.
/// - The ALU and Poseidon2 tables are shared with the kernel, whose budget
///   for one function is `kernel_budget(1)`: their sum is at most
///   `2^MAX_LOG_HEIGHT` rows.
///
/// A call of two large functions can still exceed a shared table; such a
/// combination cannot be proven, and the verifier refuses the heights.
pub fn budget_is_provable(b: &Budget) -> bool {
    let max = 1usize << blacksilk_zk::params::MAX_LOG_HEIGHT;
    let k = blacksilk_px::prove::kernel_budget(1);
    let shared = [
        (b.add, k.add),
        (b.bit, k.bit),
        (b.lt, k.lt),
        (b.shift, k.shift),
        (b.mul, k.mul),
        (b.poseidon, k.poseidon),
    ];
    b.cycles <= blacksilk_zkvm::MAX_CYCLES as usize
        && b.keys <= max
        && shared
            .iter()
            .all(|&(x, kx)| x.checked_add(kx).is_some_and(|s| s <= max))
}

/// Structure of a deploy: the transfer rules on its v1 part, the exact fee
/// ([`deploy_fee`]), supported ABIs, provable budgets, and loadable, distinct
/// programs.
pub fn check_deploy_structure(tx: &PxDeploy, rules: &TxRules) -> Result<(), TxError> {
    // The v1 part must be a valid transfer shape; the fee rule is the
    // deploy's own exact fee below (the transfer's exact fee plus the payload).
    crate::validate::check_shape(&tx.as_transfer())?;
    let size = tx.encoded_len();
    if size > MAX_DEPLOY_TX_SIZE {
        return Err(TxError::TooLarge { size });
    }
    // One fee per shape and payload (R6 §3.3): any other amount would
    // fingerprint the wallet.
    let required = tx.required_fee(rules);
    if tx.fee != required {
        return Err(TxError::DeployFeeNotExact {
            fee: tx.fee,
            required,
        });
    }
    for (i, p) in tx.programs.iter().enumerate() {
        // F-28-1: this kernel generation verifies exactly one call ABI.
        if p.abi != ABI_VERSION {
            return Err(TxError::PxUnsupportedAbi { program: i });
        }
        // The decoding bound, for deploys not produced by `decode`.
        if p.out_words as usize > MAX_FN_OUTPUT_WORDS {
            return Err(TxError::PxShape);
        }
        if !budget_is_provable(&p.budget) {
            return Err(TxError::PxBudgetTooLarge { program: i });
        }
    }
    let programs = tx.load_programs()?;
    // R5-7: the registry answers `(contract, program id)` with the first
    // match, so a repeated program would be unreachable. Ids of the loaded
    // programs are compared: different ELF files can load to one program.
    let mut ids = std::collections::HashSet::with_capacity(programs.len());
    for (i, (program, _)) in programs.iter().enumerate() {
        if !ids.insert(program.id()) {
            return Err(TxError::PxDuplicateProgram { program: i });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The ciphertext `R` rule (`check_ciphertext_r`; record
    //! `px-ciphertext-r`), case by case.

    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64);
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
        }
        b
    }

    /// The base point's encoding: a valid, non-identity `R`.
    fn base() -> [u8; 32] {
        blacksilk_crypto::generators::G.compress().to_bytes()
    }

    /// A ciphertext of the fixed length whose `R` is `r`.
    fn ct(r: [u8; 32]) -> Vec<u8> {
        let mut c = vec![0x5a; CIPHERTEXT_BYTES];
        c[..32].copy_from_slice(&r);
        c
    }

    fn check(c0: Vec<u8>, c1: Vec<u8>) -> Result<(), TxError> {
        check_ciphertext_r(&[c0, c1])
    }

    const NON_CANONICAL_0: Result<(), TxError> =
        Err(TxError::PxCiphertextRNonCanonical { ciphertext: 0 });
    const NON_CANONICAL_1: Result<(), TxError> =
        Err(TxError::PxCiphertextRNonCanonical { ciphertext: 1 });

    /// RFC 9496 Appendix A.2, "Invalid Encodings": encodings that MUST be
    /// rejected (Section 4.3.1). Copied from the RFC text
    /// (rfc-editor.org/rfc/rfc9496.txt), in the RFC's groups and order.
    const RFC9496_INVALID: [&str; 29] = [
        // Non-canonical field encodings.
        "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        // Negative field elements.
        "0100000000000000000000000000000000000000000000000000000000000000",
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20",
        "c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562",
        "c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78",
        "47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24",
        "f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72",
        "87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309",
        // Non-square x^2.
        "26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371",
        "4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f",
        "de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b",
        "bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042",
        "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
        "f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22",
        "8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731",
        "2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b",
        // Negative x * y value.
        "3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e",
        "a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220",
        "d483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e",
        "8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32",
        "32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b",
        "227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165",
        "5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e",
        "445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b",
        // s = -1, which causes y = 0.
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];

    #[test]
    fn valid_r_in_both_ciphertexts_passes() {
        assert_eq!(check(ct(base()), ct(base())), Ok(()));
        // Another valid point: 2·G.
        let g = blacksilk_crypto::generators::G;
        let two_g = (g + g).compress().to_bytes();
        assert_eq!(check(ct(two_g), ct(base())), Ok(()));
    }

    #[test]
    fn identity_r_is_refused_with_its_index() {
        assert_eq!(
            check(ct([0; 32]), ct(base())),
            Err(TxError::PxCiphertextRIdentity { ciphertext: 0 })
        );
        assert_eq!(
            check(ct(base()), ct([0; 32])),
            Err(TxError::PxCiphertextRIdentity { ciphertext: 1 })
        );
        // The first failing ciphertext is reported.
        assert_eq!(
            check(ct([0; 32]), ct([0; 32])),
            Err(TxError::PxCiphertextRIdentity { ciphertext: 0 })
        );
    }

    /// `p = 2^255 − 19` encodes zero non-canonically: refused as
    /// non-canonical, never as the identity (decoding comes first).
    #[test]
    fn p_a_non_canonical_identity_is_non_canonical() {
        let p = hex32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        assert_eq!(check(ct(p), ct(base())), NON_CANONICAL_0);
        assert_eq!(check(ct(base()), ct(p)), NON_CANONICAL_1);
        // Zero with the top bit (ignored by field decoding) set.
        let mut z = [0u8; 32];
        z[31] = 0x80;
        assert_eq!(check(ct(z), ct(base())), NON_CANONICAL_0);
    }

    /// A valid encoding with bit 255 set encodes the same field element a
    /// second way: refused.
    #[test]
    fn the_high_bit_is_refused() {
        let mut r = base();
        r[31] |= 0x80;
        assert_eq!(check(ct(r), ct(base())), NON_CANONICAL_0);
        assert_eq!(check(ct(base()), ct(r)), NON_CANONICAL_1);
    }

    /// `s = 1` is a negative field element (odd).
    #[test]
    fn a_negative_s_is_refused() {
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(check(ct(one), ct(base())), NON_CANONICAL_0);
    }

    /// The Edwards constant `d` (its canonical encoding, computed as
    /// −121665/121666 mod p) is negative: curve25519-dalek 4.1.3's own test
    /// `decompress_negative_s_fails` (src/ristretto.rs) asserts that it does
    /// not decode.
    #[test]
    fn the_edwards_d_constant_is_refused() {
        let d = hex32("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352");
        assert_eq!(check(ct(d), ct(base())), NON_CANONICAL_0);
    }

    /// Every RFC 9496 invalid encoding (non-canonical field encodings,
    /// negative field elements, non-square `x²`, negative `xy`, `s = −1`) is
    /// refused, in either ciphertext.
    #[test]
    fn every_rfc9496_invalid_encoding_is_refused() {
        for h in RFC9496_INVALID {
            let r = hex32(h);
            assert_eq!(check(ct(r), ct(base())), NON_CANONICAL_0, "{h}");
            assert_eq!(check(ct(base()), ct(r)), NON_CANONICAL_1, "{h}");
        }
    }

    /// Lengths other than `CIPHERTEXT_BYTES` (not produced by `decode`, only
    /// by a local builder) are refused, without a panic.
    #[test]
    fn a_wrong_length_is_refused() {
        for len in [0, 1, 31, 32, CIPHERTEXT_BYTES - 1, CIPHERTEXT_BYTES + 1] {
            let mut c = vec![0u8; len];
            let n = len.min(32);
            c[..n].copy_from_slice(&base()[..n]);
            assert_eq!(check(c.clone(), ct(base())), NON_CANONICAL_0, "{len}");
            assert_eq!(check(ct(base()), c), NON_CANONICAL_1, "{len}");
        }
    }

    /// Only `R` is checked: the rest of the ciphertext may be any bytes.
    #[test]
    fn the_rest_of_the_ciphertext_is_not_checked() {
        let mut c = ct(base());
        c[32..].fill(0xff);
        assert_eq!(check(c, ct(base())), Ok(()));
    }

    /// A PX transaction that `check_px_structure` accepts, with every
    /// ciphertext `R` valid.
    fn px_ok() -> PxTx {
        PxTx {
            inputs: vec![],
            outputs: vec![],
            payouts: vec![],
            fee: PX_STANDARD_FEE,
            bridge_in: 0,
            bridge_out: PX_STANDARD_FEE,
            window: Window::UNBOUNDED,
            anchor: [0; 8],
            nullifiers: [[1; 8], [2; 8]],
            commitments: [[3; 8], [4; 8]],
            ciphertexts: [ct(base()), ct(base())],
            functions: vec![],
            pseudo_outs: vec![],
            range_proof: None,
            signatures: vec![],
            proof: vec![],
        }
    }

    /// The rule is part of `check_px_structure` (every path: mempool, P2P
    /// admission, blocks, the builder's self-check), with stateless errors.
    #[test]
    fn check_px_structure_applies_the_rule() {
        assert_eq!(check_px_structure(&px_ok()), Ok(()));
        let mut t = px_ok();
        t.ciphertexts[1] = ct([0; 32]);
        let e = check_px_structure(&t).unwrap_err();
        assert_eq!(e, TxError::PxCiphertextRIdentity { ciphertext: 1 });
        assert!(e.is_stateless());
        let mut t = px_ok();
        t.ciphertexts[0][31] |= 0x80;
        let e = check_px_structure(&t).unwrap_err();
        assert_eq!(e, TxError::PxCiphertextRNonCanonical { ciphertext: 0 });
        assert!(e.is_stateless());
    }

    /// A decoded transaction gets the rule's verdict: the identity `R`
    /// survives encoding and decoding (the codec reads ciphertexts as bytes)
    /// and is refused by the structure check.
    #[test]
    fn a_decoded_transaction_with_an_identity_r_is_refused() {
        let mut t = px_ok();
        t.ciphertexts[0] = ct([0; 32]);
        let bytes = Transaction::Px(Box::new(t)).encode();
        let Ok(Transaction::Px(d)) = Transaction::decode(&bytes) else {
            panic!("decodes as a PX transaction");
        };
        assert_eq!(
            check_px_structure(&d),
            Err(TxError::PxCiphertextRIdentity { ciphertext: 0 })
        );
    }
}
