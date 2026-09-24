//! Transaction format, serialization, hashing and weight (spec §4, §8.4).

use crate::codec::{DecodeError, Reader, Writer};
use crate::params::*;
use blacksilk_crypto::bulletproofs_plus::{self as bpp, BppProof};
use blacksilk_crypto::clsag::Clsag;
use blacksilk_crypto::commitment::coinbase_commitment;
use blacksilk_crypto::hash::{h32, tags};
use blacksilk_crypto::janus::ANCHOR_BYTES;
use blacksilk_crypto::stealth::{OutputAmount, OutputFields};
use blacksilk_crypto::Point;

pub type Hash = [u8; 32];

/// A transfer input: its key image and 16 ring members by global output index
/// (strictly increasing).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub key_image: Point,
    pub ring: [u64; RING_SIZE],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub one_time_key: Point,
    pub ephemeral: Point,
    pub view_tag: u8,
    pub commitment: Point,
    pub enc_amount: [u8; 8],
    pub enc_anchor: [u8; ANCHOR_BYTES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseOutput {
    pub one_time_key: Point,
    pub ephemeral: Point,
    pub view_tag: u8,
    pub amount: u64,
    pub enc_anchor: [u8; ANCHOR_BYTES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub fee: u64,
    pub pseudo_outs: Vec<Point>,
    pub range_proof: BppProof,
    pub signatures: Vec<Clsag>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coinbase {
    pub height: u64,
    pub outputs: Vec<CoinbaseOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transaction {
    Coinbase(Coinbase),
    /// Boxed: a transfer is ~25x larger than a coinbase.
    Transfer(Box<Transfer>),
    /// A private-execution transaction (docs/px.md §11).
    Px(Box<crate::px::PxTx>),
    /// A private-contract deploy (docs/px.md §11).
    PxDeploy(Box<crate::px::PxDeploy>),
}

impl From<Transfer> for Transaction {
    fn from(t: Transfer) -> Self {
        Transaction::Transfer(Box::new(t))
    }
}

impl From<Coinbase> for Transaction {
    fn from(c: Coinbase) -> Self {
        Transaction::Coinbase(c)
    }
}

/// An output as stored in the chain's global output set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputKey {
    pub one_time_key: Point,
    pub commitment: Point,
}

impl Output {
    pub fn fields(&self) -> OutputFields<'_> {
        OutputFields {
            one_time_key: &self.one_time_key,
            ephemeral: &self.ephemeral,
            view_tag: self.view_tag,
            amount: OutputAmount::Hidden {
                commitment: &self.commitment,
                enc_amount: &self.enc_amount,
            },
            enc_anchor: &self.enc_anchor,
        }
    }
}

impl CoinbaseOutput {
    pub fn fields(&self) -> OutputFields<'_> {
        OutputFields {
            one_time_key: &self.one_time_key,
            ephemeral: &self.ephemeral,
            view_tag: self.view_tag,
            amount: OutputAmount::Clear(self.amount),
            enc_anchor: &self.enc_anchor,
        }
    }

    /// The implicit commitment `G + a·H`.
    pub fn commitment(&self) -> Point {
        Point::from_point(coinbase_commitment(self.amount))
    }
}

// ---- encoding ----

pub(crate) fn write_ring_pub(w: &mut Writer, ring: &[u64; RING_SIZE]) {
    write_ring(w, ring)
}

pub(crate) fn read_ring_pub(r: &mut Reader<'_>) -> Result<[u64; RING_SIZE], DecodeError> {
    read_ring(r)
}

pub(crate) fn read_bpp_pub(r: &mut Reader<'_>, outputs: usize) -> Result<BppProof, DecodeError> {
    read_bpp(r, outputs)
}

fn write_ring(w: &mut Writer, ring: &[u64; RING_SIZE]) {
    w.varint(ring[0]);
    for pair in ring.windows(2) {
        // Callers only encode validated (strictly increasing) rings; an invalid
        // in-memory ring encodes to bytes that do not decode.
        w.varint(pair[1].wrapping_sub(pair[0]));
    }
}

fn read_ring(r: &mut Reader<'_>) -> Result<[u64; RING_SIZE], DecodeError> {
    let mut ring = [0u64; RING_SIZE];
    ring[0] = r.varint()?;
    for i in 1..RING_SIZE {
        let delta = r.varint()?;
        if delta == 0 {
            return Err(DecodeError::InvalidRingOffsets);
        }
        ring[i] = ring[i - 1]
            .checked_add(delta)
            .ok_or(DecodeError::InvalidRingOffsets)?;
    }
    Ok(ring)
}

pub(crate) fn write_bpp(w: &mut Writer, p: &BppProof) {
    w.point(&p.a);
    w.point(&p.a1);
    w.point(&p.b);
    w.scalar(&p.r1);
    w.scalar(&p.s1);
    w.scalar(&p.d1);
    for l in &p.l {
        w.point(l);
    }
    for r in &p.r {
        w.point(r);
    }
}

fn read_bpp(r: &mut Reader<'_>, outputs: usize) -> Result<BppProof, DecodeError> {
    let rounds = bpp::rounds(outputs).ok_or(DecodeError::CountOutOfRange {
        what: "range proof outputs",
        count: outputs as u64,
    })?;
    let a = r.point()?;
    let a1 = r.point()?;
    let b = r.point()?;
    let r1 = r.scalar()?;
    let s1 = r.scalar()?;
    let d1 = r.scalar()?;
    let l = (0..rounds).map(|_| r.point()).collect::<Result<_, _>>()?;
    let rr = (0..rounds).map(|_| r.point()).collect::<Result<_, _>>()?;
    Ok(BppProof {
        a,
        a1,
        b,
        r1,
        s1,
        d1,
        l,
        r: rr,
    })
}

fn write_clsag(w: &mut Writer, s: &Clsag) {
    w.scalar(&s.c0);
    for x in &s.s {
        w.scalar(x);
    }
    w.point(&s.d);
}

fn read_clsag(r: &mut Reader<'_>) -> Result<Clsag, DecodeError> {
    let c0 = r.scalar()?;
    let mut s = [blacksilk_crypto::Scalar::ZERO; RING_SIZE];
    for x in &mut s {
        *x = r.scalar()?;
    }
    let d = r.point()?;
    Ok(Clsag { c0, s, d })
}

impl Transfer {
    pub fn prefix_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.varint(TX_VERSION);
        w.u8(KIND_TRANSFER);
        w.varint(self.inputs.len() as u64);
        for input in &self.inputs {
            w.point(&input.key_image);
            write_ring(&mut w, &input.ring);
        }
        w.varint(self.outputs.len() as u64);
        for o in &self.outputs {
            w.point(&o.one_time_key);
            w.point(&o.ephemeral);
            w.u8(o.view_tag);
            w.point(&o.commitment);
            w.bytes(&o.enc_amount);
            w.bytes(&o.enc_anchor);
        }
        w.varint(self.fee);
        w.into_bytes()
    }

    pub fn base_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        for p in &self.pseudo_outs {
            w.point(p);
        }
        w.into_bytes()
    }

    pub fn range_proof_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        write_bpp(&mut w, &self.range_proof);
        w.into_bytes()
    }

    pub fn prunable_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        write_bpp(&mut w, &self.range_proof);
        for s in &self.signatures {
            write_clsag(&mut w, s);
        }
        w.into_bytes()
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

    /// The message every CLSAG signs (spec §4.4): everything except the CLSAGs,
    /// plus the network id.
    pub fn signature_message(&self, network_id: u32) -> Hash {
        let bp_hash = h32(tags::TX_BP, &[&self.range_proof_bytes()]);
        h32(
            tags::TX_SIG_MESSAGE,
            &[
                &network_id.to_le_bytes(),
                &self.prefix_hash(),
                &self.base_hash(),
                &bp_hash,
            ],
        )
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.count("inputs", 1, MAX_INPUTS as u64)?;
        let mut inputs = Vec::with_capacity(n);
        for _ in 0..n {
            let key_image = r.point()?;
            let ring = read_ring(r)?;
            inputs.push(Input { key_image, ring });
        }
        let k = r.count("outputs", MIN_OUTPUTS as u64, MAX_OUTPUTS as u64)?;
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
        let fee = r.varint()?;
        let pseudo_outs = (0..n).map(|_| r.point()).collect::<Result<_, _>>()?;
        let range_proof = read_bpp(r, k)?;
        let signatures = (0..n).map(|_| read_clsag(r)).collect::<Result<_, _>>()?;
        Ok(Self {
            inputs,
            outputs,
            fee,
            pseudo_outs,
            range_proof,
            signatures,
        })
    }

    /// Weight (spec §8.4): size plus the Bulletproofs+ clawback.
    pub fn weight(&self) -> u64 {
        let size = self.encoded_len() as u64;
        let m = self.outputs.len().next_power_of_two() as u64;
        if m <= 2 {
            return size;
        }
        let bp_size = self.range_proof.encoded_len() as u64;
        size + (320 * m).saturating_sub(bp_size) * 4 / 5
    }

    pub fn encoded_len(&self) -> usize {
        self.prefix_bytes().len() + self.base_bytes().len() + self.prunable_bytes().len()
    }
}

impl Coinbase {
    pub fn prefix_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.varint(TX_VERSION);
        w.u8(KIND_COINBASE);
        w.varint(self.height);
        w.varint(self.outputs.len() as u64);
        for o in &self.outputs {
            w.point(&o.one_time_key);
            w.point(&o.ephemeral);
            w.u8(o.view_tag);
            w.varint(o.amount);
            w.bytes(&o.enc_anchor);
        }
        w.into_bytes()
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let height = r.varint()?;
        let k = r.count(
            "coinbase outputs",
            MIN_COINBASE_OUTPUTS as u64,
            MAX_COINBASE_OUTPUTS as u64,
        )?;
        let mut outputs = Vec::with_capacity(k);
        for _ in 0..k {
            outputs.push(CoinbaseOutput {
                one_time_key: r.point()?,
                ephemeral: r.point()?,
                view_tag: r.u8()?,
                amount: r.varint()?,
                enc_anchor: r.array()?,
            });
        }
        Ok(Self { height, outputs })
    }

    /// Sum of the output amounts (u128: cannot overflow).
    pub fn total(&self) -> u128 {
        self.outputs.iter().map(|o| o.amount as u128).sum()
    }
}

impl Transaction {
    /// Strict decoding (rule T1): size limit, version, kind, bounded counts,
    /// canonical points/scalars/varints, well-formed rings, no trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_PX_TX_SIZE.max(MAX_DEPLOY_TX_SIZE) {
            return Err(DecodeError::TooLarge);
        }
        let mut r = Reader::new(bytes);
        let version = r.varint()?;
        if version != TX_VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }
        let kind = r.u8()?;
        // PX transactions have their own, larger size caps (params).
        let cap = match kind {
            KIND_PX => MAX_PX_TX_SIZE,
            KIND_PX_DEPLOY => MAX_DEPLOY_TX_SIZE,
            _ => MAX_TX_SIZE,
        };
        if bytes.len() > cap {
            return Err(DecodeError::TooLarge);
        }
        let tx = match kind {
            KIND_COINBASE => Transaction::Coinbase(Coinbase::decode_body(&mut r)?),
            KIND_TRANSFER => Transaction::from(Transfer::decode_body(&mut r)?),
            KIND_PX => Transaction::Px(Box::new(crate::px::PxTx::decode_body(&mut r)?)),
            KIND_PX_DEPLOY => {
                Transaction::PxDeploy(Box::new(crate::px::PxDeploy::decode_body(&mut r)?))
            }
            k => return Err(DecodeError::UnknownKind(k)),
        };
        r.finish()?;
        Ok(tx)
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Transaction::Coinbase(c) => c.prefix_bytes(),
            Transaction::Transfer(t) => {
                let mut out = t.prefix_bytes();
                out.extend(t.base_bytes());
                out.extend(t.prunable_bytes());
                out
            }
            Transaction::Px(t) => t.encode(),
            Transaction::PxDeploy(t) => t.encode(),
        }
    }

    /// `tx_hash = H32("tx/hash", prefix_hash ‖ base_hash ‖ prunable_hash)` (spec §4.4).
    pub fn hash(&self) -> Hash {
        let (prefix, base, prunable) = match self {
            Transaction::Coinbase(c) => (
                h32(tags::TX_PREFIX, &[&c.prefix_bytes()]),
                h32(tags::TX_BASE, &[]),
                h32(tags::TX_PRUNABLE, &[]),
            ),
            Transaction::Transfer(t) => (t.prefix_hash(), t.base_hash(), t.prunable_hash()),
            Transaction::Px(t) => (t.prefix_hash(), t.base_hash(), t.prunable_hash()),
            Transaction::PxDeploy(t) => (
                t.prefix_hash(),
                h32(tags::TX_BASE, &[&t.base_bytes()]),
                h32(tags::TX_PRUNABLE, &[&t.prunable_bytes()]),
            ),
        };
        h32(tags::TX_HASH, &[&prefix, &base, &prunable])
    }

    /// Weight against the v1 block weight limit. PX and deploy transactions
    /// count against the separate PX byte budget instead ([`Self::px_bytes`]).
    pub fn weight(&self) -> u64 {
        match self {
            Transaction::Coinbase(c) => c.prefix_bytes().len() as u64,
            Transaction::Transfer(t) => t.weight(),
            Transaction::Px(_) | Transaction::PxDeploy(_) => 0,
        }
    }

    /// Bytes counted against the block's PX budget (`MAX_PX_BLOCK_BYTES`).
    pub fn px_bytes(&self) -> u64 {
        match self {
            Transaction::Px(t) => t.encoded_len() as u64,
            Transaction::PxDeploy(t) => t.encoded_len() as u64,
            _ => 0,
        }
    }

    /// The public fee (zero for a coinbase).
    pub fn fee(&self) -> u64 {
        match self {
            Transaction::Coinbase(_) => 0,
            Transaction::Transfer(t) => t.fee,
            Transaction::Px(t) => t.fee,
            Transaction::PxDeploy(t) => t.fee,
        }
    }

    /// Key images spent by the transaction's v1 inputs.
    pub fn key_images(&self) -> Vec<Point> {
        let inputs: &[Input] = match self {
            Transaction::Coinbase(_) => &[],
            Transaction::Transfer(t) => &t.inputs,
            Transaction::Px(t) => &t.inputs,
            Transaction::PxDeploy(t) => &t.inputs,
        };
        inputs.iter().map(|i| i.key_image).collect()
    }

    /// The outputs this transaction adds to the global output set, in order.
    pub fn output_keys(&self) -> Vec<OutputKey> {
        match self {
            Transaction::Coinbase(c) => c
                .outputs
                .iter()
                .map(|o| OutputKey {
                    one_time_key: o.one_time_key,
                    commitment: o.commitment(),
                })
                .collect(),
            Transaction::Transfer(t) => t
                .outputs
                .iter()
                .map(|o| OutputKey {
                    one_time_key: o.one_time_key,
                    commitment: o.commitment,
                })
                .collect(),
            Transaction::Px(t) => t.output_keys(),
            Transaction::PxDeploy(t) => t
                .outputs
                .iter()
                .map(|o| OutputKey {
                    one_time_key: o.one_time_key,
                    commitment: o.commitment,
                })
                .collect(),
        }
    }

    pub fn is_coinbase(&self) -> bool {
        matches!(self, Transaction::Coinbase(_))
    }
}
