//! Wallet-side construction of transfers and coinbases (spec §3.2, §5, §6).
//!
//! The builder derives every secret random value (Janus anchors, pseudo-output
//! masks, signature and proof nonces) from a [`HedgedRng`] keyed with the wallet's
//! spend secret (spec §10). The anchor and pseudo-output-mask stream is bound to
//! the whole transfer being built ([`HedgeContext`]): network, key images, every
//! ring (global indices and keys), fee, every payment (address, amount), the
//! change address and amount, and any caller payload. It then re-validates its
//! own result before returning.

use crate::params::*;
use crate::types::*;
use crate::validate::{check_balance, check_range_proof, check_structure, TxError};
use blacksilk_crypto::bulletproofs_plus::{self as bpp, BppError};
use blacksilk_crypto::clsag::{self, ClsagError, RingMember};
use blacksilk_crypto::commitment::commit;
use blacksilk_crypto::janus::Anchor;
use blacksilk_crypto::keys::{Address, SubaddressIndex, WalletKeys};
use blacksilk_crypto::nonce::HedgedRng;
use blacksilk_crypto::stealth::{
    coinbase_context, create_output, transfer_context, CreatedOutput, OutputKind,
};
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// An owned output the wallet wants to spend. Its `Debug` output redacts the
/// output-key offset and the mask.
#[derive(Clone)]
pub struct SpendableOutput {
    pub global_index: u64,
    pub key: OutputKey,
    pub subaddress: SubaddressIndex,
    pub output_key_offset: Scalar,
    pub amount: u64,
    pub mask: Scalar,
}

impl core::fmt::Debug for SpendableOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpendableOutput")
            .field("global_index", &self.global_index)
            .field("key", &self.key)
            .field("subaddress", &self.subaddress)
            .field("output_key_offset", &"<redacted>")
            .field("amount", &self.amount)
            .field("mask", &"<redacted>")
            .finish()
    }
}

impl Drop for SpendableOutput {
    fn drop(&mut self) {
        self.output_key_offset.zeroize();
        self.mask.zeroize();
    }
}

impl From<&crate::scan::OwnedOutput> for SpendableOutput {
    fn from(o: &crate::scan::OwnedOutput) -> Self {
        Self {
            global_index: o.global_index,
            key: o.key,
            subaddress: o.received.subaddress,
            output_key_offset: o.received.output_key_offset,
            amount: o.received.amount,
            mask: o.received.mask,
        }
    }
}

/// A ring member chosen as a decoy: its global index and on-chain keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoy {
    pub global_index: u64,
    pub key: OutputKey,
}

/// One input: the real output plus exactly 15 decoys.
#[derive(Clone, Debug)]
pub struct InputPlan {
    pub real: SpendableOutput,
    pub decoys: Vec<Decoy>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Payment {
    pub address: Address,
    pub amount: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    InputCount(usize),
    /// Payments plus the change output must fit in 2..=16 outputs.
    PaymentCount(usize),
    DecoyCount {
        input: usize,
        count: usize,
    },
    DuplicateRingMember {
        input: usize,
    },
    /// The wallet keys do not open the output it claims to own.
    NotOwned {
        input: usize,
    },
    InsufficientFunds {
        available: u128,
        required: u128,
    },
    ChangeTooLarge,
    Signing(ClsagError),
    RangeProof(BppError),
    /// Self-check failed: indicates a bug; the transaction is not returned.
    SelfCheck(TxError),
}

/// Upper bound on the weight of a transfer with this shape (all varints at their
/// maximum length). Used for the standard fee.
pub fn max_weight(inputs: usize, outputs: usize) -> u64 {
    let varint_max = 10u64;
    let n = inputs as u64;
    let k = outputs as u64;
    let prefix = varint_max
        + 1
        + varint_max
        + n * (32 + RING_SIZE as u64 * varint_max)
        + varint_max
        + k * (32 + 32 + 1 + 32 + 8 + 16)
        + varint_max;
    let bp = bpp::proof_len(outputs).unwrap_or(0) as u64;
    let size = prefix + 32 * n + bp + n * clsag::CLSAG_BYTES as u64;
    let m = outputs.next_power_of_two() as u64;
    if m <= 2 {
        size
    } else {
        size + (320 * m).saturating_sub(bp) * 4 / 5
    }
}

/// The standard fee for a shape: `min_fee(max_weight)`. All wallets using it pay
/// identical fees for identical shapes, which removes fee fingerprinting (spec §11.3).
pub fn standard_fee(inputs: usize, outputs: usize, rules: &TxRules) -> u64 {
    rules
        .min_fee(max_weight(inputs, outputs))
        .expect("bounded shapes cannot overflow")
}

/// The context of a wallet hedge stream (spec §10): a purpose label followed
/// by every input of the statement being built. Each item is length-prefixed
/// by [`HedgedRng`]; variable-length lists are preceded by their count, so the
/// encoding is unambiguous.
pub(crate) struct HedgeContext {
    items: Vec<Vec<u8>>,
}

impl HedgeContext {
    pub(crate) fn new(label: &[u8]) -> Self {
        Self {
            items: vec![label.to_vec()],
        }
    }

    pub(crate) fn push(&mut self, item: &[u8]) -> &mut Self {
        self.items.push(item.to_vec());
        self
    }

    pub(crate) fn push_u64(&mut self, v: u64) -> &mut Self {
        self.push(&v.to_le_bytes())
    }

    /// The rings of `inputs`, in order: each ring's members sorted by global
    /// index, as `LE64(global index) ‖ one-time key ‖ commitment`.
    pub(crate) fn rings<'a>(
        &mut self,
        inputs: impl ExactSizeIterator<Item = &'a InputPlan>,
    ) -> &mut Self {
        self.push_u64(inputs.len() as u64);
        for plan in inputs {
            let mut members: Vec<Decoy> = plan.decoys.clone();
            members.push(Decoy {
                global_index: plan.real.global_index,
                key: plan.real.key,
            });
            members.sort_by_key(|m| m.global_index);
            let mut ring = Vec::with_capacity(members.len() * 72);
            for m in &members {
                ring.extend_from_slice(&m.global_index.to_le_bytes());
                ring.extend_from_slice(m.key.one_time_key.bytes());
                ring.extend_from_slice(m.key.commitment.bytes());
            }
            self.items.push(ring);
        }
        self
    }

    /// `payments`, in order, as `address ‖ LE64(amount)`.
    pub(crate) fn payments(&mut self, payments: &[Payment]) -> &mut Self {
        self.push_u64(payments.len() as u64);
        for p in payments {
            self.output(&p.address, p.amount);
        }
        self
    }

    /// One output: `address ‖ LE64(amount)`.
    pub(crate) fn output(&mut self, address: &Address, amount: u64) -> &mut Self {
        let mut item = address.to_bytes().to_vec();
        item.extend_from_slice(&amount.to_le_bytes());
        self.items.push(item);
        self
    }

    /// The hedge stream keyed with `secrets` over this context.
    pub(crate) fn stream<R: RngCore + CryptoRng>(
        &self,
        secrets: &[&[u8]],
        rng: &mut R,
    ) -> HedgedRng {
        let items: Vec<&[u8]> = self.items.iter().map(Vec::as_slice).collect();
        HedgedRng::new(secrets, &items, rng)
    }
}

/// Creates one output with a hedged anchor, retrying in the negligible `r = 0` case.
fn make_output(
    hedge: &mut HedgedRng,
    address: &Address,
    amount: u64,
    ctx: &[u8; 32],
    kind: OutputKind,
) -> CreatedOutput {
    loop {
        let anchor = Anchor(hedge.bytes16());
        if let Some(o) = create_output(address, amount, ctx, &anchor, kind) {
            return o;
        }
    }
}

/// Builds a signed transfer paying `payments`, with the remainder to `change`.
///
/// A change output is always created, even with amount 0, so every transfer has
/// at least 2 outputs (spec §8.1 T3). The fee must be at least the minimum for
/// the resulting weight; [`standard_fee`] always is.
pub fn build_transfer<R: RngCore + CryptoRng>(
    keys: &WalletKeys,
    inputs: Vec<InputPlan>,
    payments: &[Payment],
    change: &Address,
    fee: u64,
    rules: &TxRules,
    rng: &mut R,
) -> Result<Transfer, BuildError> {
    let net = rules.network_id;
    build_transfer_signing(keys, inputs, payments, change, fee, rules, rng, &[], &|t| {
        t.signature_message(net)
    })
}

/// As [`build_transfer`], signing `message(tx)` instead of the transfer's
/// own signature message (for transactions that extend a transfer, such as
/// deploys, whose signatures must also cover their payload). `payload` is
/// that extension's content (or a digest of it): it is bound into the hedge
/// context, so two different payloads never share anchors or masks.
#[allow(clippy::too_many_arguments)]
pub fn build_transfer_signing<R: RngCore + CryptoRng>(
    keys: &WalletKeys,
    inputs: Vec<InputPlan>,
    payments: &[Payment],
    change: &Address,
    fee: u64,
    rules: &TxRules,
    rng: &mut R,
    payload: &[u8],
    message: &dyn Fn(&Transfer) -> Hash,
) -> Result<Transfer, BuildError> {
    let n = inputs.len();
    if n == 0 || n > MAX_INPUTS {
        return Err(BuildError::InputCount(n));
    }
    if payments.is_empty() || payments.len() + 1 > MAX_OUTPUTS {
        return Err(BuildError::PaymentCount(payments.len()));
    }

    // Amounts.
    let available: u128 = inputs.iter().map(|i| i.real.amount as u128).sum();
    let required: u128 = payments.iter().map(|p| p.amount as u128).sum::<u128>() + fee as u128;
    if available < required {
        return Err(BuildError::InsufficientFunds {
            available,
            required,
        });
    }
    let change_amount =
        u64::try_from(available - required).map_err(|_| BuildError::ChangeTooLarge)?;

    // Secrets and key images; inputs sorted by key image (spec §5.2).
    struct Prepared {
        plan: InputPlan,
        p: Scalar,
        key_image: Point,
    }
    let mut prepared = Vec::with_capacity(n);
    for (i, plan) in inputs.into_iter().enumerate() {
        if plan.decoys.len() != RING_SIZE - 1 {
            return Err(BuildError::DecoyCount {
                input: i,
                count: plan.decoys.len(),
            });
        }
        let p = keys.one_time_secret(plan.real.subaddress, &plan.real.output_key_offset);
        if Point::from_point(RistrettoPoint::mul_base(&p)) != plan.real.key.one_time_key {
            return Err(BuildError::NotOwned { input: i });
        }
        let key_image = clsag::key_image(&p, &plan.real.key.one_time_key);
        prepared.push(Prepared { plan, p, key_image });
    }
    prepared.sort_by_key(|x| x.key_image);
    let key_images: Vec<Point> = prepared.iter().map(|x| x.key_image).collect();
    let ctx = transfer_context(&key_images);

    // The hedge binds the whole statement being built (spec §10), so a
    // rebuild over the same inputs with any other payment, amount, fee, ring
    // or change never reuses an anchor or pseudo-output mask, even with a
    // broken RNG.
    let mut secret = keys.hedge_secret();
    let mut hedge = HedgeContext::new(b"transfer/v2")
        .push(&rules.network_id.to_le_bytes())
        .push(&ctx)
        .push_u64(fee)
        .rings(prepared.iter().map(|x| &x.plan))
        .payments(payments)
        .output(change, change_amount)
        .push(payload)
        .stream(&[&secret], rng);
    secret.zeroize();

    // Outputs, sorted by one-time key (spec §5.2).
    let mut created: Vec<CreatedOutput> = payments
        .iter()
        .map(|p| (p.address, p.amount))
        .chain(std::iter::once((*change, change_amount)))
        .map(|(a, v)| make_output(&mut hedge, &a, v, &ctx, OutputKind::Transfer))
        .collect();
    created.sort_by_key(|o| o.one_time_key);

    // Range proof over the outputs, in order.
    let amounts: Vec<u64> = created.iter().map(|o| o.amount).collect();
    // Output masks and their sums are wiped on drop (best effort).
    let masks: zeroize::Zeroizing<Vec<Scalar>> =
        zeroize::Zeroizing::new(created.iter().map(|o| o.mask).collect());
    let (range_proof, commitments) =
        bpp::prove(&amounts, &masks, rng).map_err(BuildError::RangeProof)?;
    debug_assert!(commitments
        .iter()
        .zip(&created)
        .all(|(c, o)| *c == o.commitment));

    // Pseudo-outputs: Σ z_k = Σ y_j (spec §6).
    let mask_sum = zeroize::Zeroizing::new(masks.iter().sum::<Scalar>());
    let mut pseudo_masks: Vec<Scalar> = (0..n - 1).map(|_| hedge.scalar()).collect();
    let partial = zeroize::Zeroizing::new(pseudo_masks.iter().sum::<Scalar>());
    pseudo_masks.push(*mask_sum - *partial);
    let pseudo_outs: Vec<Point> = prepared
        .iter()
        .zip(&pseudo_masks)
        .map(|(x, z)| Point::from_point(commit(x.plan.real.amount, z)))
        .collect();

    // Rings.
    let mut rings = Vec::with_capacity(n);
    let mut real_positions = Vec::with_capacity(n);
    let mut tx_inputs = Vec::with_capacity(n);
    for (i, x) in prepared.iter().enumerate() {
        let mut members: Vec<Decoy> = x.plan.decoys.clone();
        members.push(Decoy {
            global_index: x.plan.real.global_index,
            key: x.plan.real.key,
        });
        members.sort_by_key(|m| m.global_index);
        if members
            .windows(2)
            .any(|w| w[0].global_index == w[1].global_index)
        {
            return Err(BuildError::DuplicateRingMember { input: i });
        }
        let pos = members
            .iter()
            .position(|m| m.global_index == x.plan.real.global_index)
            .expect("real member is in the ring");
        let ring: [RingMember; RING_SIZE] = std::array::from_fn(|j| RingMember {
            one_time_key: members[j].key.one_time_key,
            commitment: members[j].key.commitment,
        });
        tx_inputs.push(Input {
            key_image: x.key_image,
            ring: std::array::from_fn(|j| members[j].global_index),
        });
        rings.push(ring);
        real_positions.push(pos);
    }

    let mut tx = Transfer {
        inputs: tx_inputs,
        outputs: created
            .iter()
            .map(|o| Output {
                one_time_key: o.one_time_key,
                ephemeral: o.ephemeral,
                view_tag: o.view_tag,
                commitment: o.commitment,
                enc_amount: o.enc_amount,
                enc_anchor: o.enc_anchor,
            })
            .collect(),
        fee,
        pseudo_outs,
        range_proof,
        signatures: Vec::new(),
    };

    // Sign everything except the signatures (spec §4.4).
    let message = message(&tx);
    for (k, x) in prepared.iter().enumerate() {
        let z = x.plan.real.mask - pseudo_masks[k];
        let (sig, ki) = clsag::sign(
            &message,
            &rings[k],
            &tx.pseudo_outs[k],
            real_positions[k],
            &x.p,
            &z,
            rng,
        )
        .map_err(BuildError::Signing)?;
        debug_assert_eq!(ki, x.key_image);
        tx.signatures.push(sig);
    }
    for x in &mut prepared {
        x.p.zeroize();
    }
    for z in &mut pseudo_masks {
        z.zeroize();
    }
    for o in &mut created {
        o.mask.zeroize();
    }

    // Self-check (defence in depth against builder bugs).
    check_structure(&tx, rules).map_err(BuildError::SelfCheck)?;
    check_balance(&tx).map_err(BuildError::SelfCheck)?;
    crate::validate::check_ring_signatures(
        &tx.inputs,
        &tx.pseudo_outs,
        &tx.signatures,
        &rings,
        &message,
    )
    .map_err(BuildError::SelfCheck)?;
    check_range_proof(&tx).map_err(BuildError::SelfCheck)?;
    Ok(tx)
}

/// Builds the coinbase for a block at `height`, paying `payouts` (1..=16).
/// `hedge_secret` should be secret to the miner (e.g. its wallet's
/// [`WalletKeys::hedge_secret`]); it only hardens anchor generation.
pub fn build_coinbase<R: RngCore + CryptoRng>(
    height: u64,
    payouts: &[Payment],
    hedge_secret: &[u8],
    rng: &mut R,
) -> Result<Coinbase, BuildError> {
    if payouts.is_empty() || payouts.len() > MAX_COINBASE_OUTPUTS {
        return Err(BuildError::PaymentCount(payouts.len()));
    }
    let ctx = coinbase_context(height);
    let mut hedge = HedgeContext::new(b"coinbase/v2")
        .push(&ctx)
        .payments(payouts)
        .stream(&[hedge_secret], rng);
    let mut outputs: Vec<CoinbaseOutput> = payouts
        .iter()
        .map(|p| {
            let o = make_output(&mut hedge, &p.address, p.amount, &ctx, OutputKind::Coinbase);
            CoinbaseOutput {
                one_time_key: o.one_time_key,
                ephemeral: o.ephemeral,
                view_tag: o.view_tag,
                amount: p.amount,
                enc_anchor: o.enc_anchor,
            }
        })
        .collect();
    outputs.sort_by_key(|o| o.one_time_key);
    Ok(Coinbase { height, outputs })
}
