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
//! need them) with their row budgets. The contract id is derived from the
//! first key image, the salt and the programs, so it is unique.

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
    /// proof itself), and the network, so a proof is valid for exactly one
    /// transaction on one network.
    pub fn binding(&self, network_id: u32) -> Hash {
        h32(
            tags::PX_TX_BINDING,
            &[
                &network_id.to_le_bytes(),
                &self.prefix_hash(),
                &self.base_hash(),
            ],
        )
    }

    /// The message the v1 inputs' CLSAGs sign: everything except the
    /// signatures, including the range proof and the PX proof.
    pub fn signature_message(&self, network_id: u32) -> Hash {
        h32(
            tags::PX_SIG_MESSAGE,
            &[
                &network_id.to_le_bytes(),
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

    /// The minimum fee: [`PX_FEE_PER_BYTE`] per encoded byte.
    pub fn min_fee(&self) -> u64 {
        (self.encoded_len() as u64).saturating_mul(PX_FEE_PER_BYTE)
    }
}

// ---- deploy ----

impl PxDeploy {
    fn payload_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.salt);
        w.varint(self.programs.len() as u64);
        for p in &self.programs {
            w.varint(p.elf.len() as u64);
            w.bytes(&p.elf);
            write_budget(&mut w, &p.budget);
        }
        w.into_bytes()
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
            programs.push(Registration { elf, budget });
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

    pub fn signature_message(&self, network_id: u32) -> Hash {
        let t = self.as_transfer();
        h32(
            tags::TX_SIG_MESSAGE,
            &[
                &network_id.to_le_bytes(),
                &self.prefix_hash(),
                &t.base_hash(),
                &h32(tags::TX_BP, &[&t.range_proof_bytes()]),
            ],
        )
    }

    /// The contract id: 8 canonical field elements from
    /// `H64("px/contract-id", first key image ‖ salt ‖ payload hash)`. Key
    /// images never repeat, so neither do contract ids.
    pub fn contract_id(&self) -> Digest {
        let payload = h32(tags::PX_DEPLOY_PAYLOAD, &[&self.payload_bytes()]);
        let wide = h64(
            tags::PX_CONTRACT_ID,
            &[self.inputs[0].key_image.bytes(), &self.salt, &payload],
        );
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

    pub fn min_fee(&self) -> u64 {
        (self.encoded_len() as u64).saturating_mul(PX_FEE_PER_BYTE)
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

/// Structure of a PX transaction (the PX counterpart of T1, T3–T8, T10, T11).
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
    if tx.pseudo_outs.len() != n {
        return Err(TxError::PseudoOutCount);
    }
    if tx.signatures.len() != n {
        return Err(TxError::SignatureCount);
    }
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
    let size = tx.encoded_len();
    if size > MAX_PX_TX_SIZE {
        return Err(TxError::TooLarge { size });
    }
    let required = tx.min_fee();
    if tx.fee < required {
        return Err(TxError::FeeTooLow {
            fee: tx.fee,
            required,
        });
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

/// Structure of a deploy: the transfer rules on its v1 part, a fee covering
/// its size, and loadable programs within their limits.
pub fn check_deploy_structure(tx: &PxDeploy, rules: &TxRules) -> Result<(), TxError> {
    // The v1 part must be a valid transfer shape, except the fee rule, which
    // is per byte for deploys.
    let relaxed = TxRules {
        fee_per_weight: 0,
        ..*rules
    };
    crate::validate::check_structure(&tx.as_transfer(), &relaxed)?;
    let size = tx.encoded_len();
    if size > MAX_DEPLOY_TX_SIZE {
        return Err(TxError::TooLarge { size });
    }
    let required = tx.min_fee();
    if tx.fee < required {
        return Err(TxError::FeeTooLow {
            fee: tx.fee,
            required,
        });
    }
    tx.load_programs()?;
    Ok(())
}
