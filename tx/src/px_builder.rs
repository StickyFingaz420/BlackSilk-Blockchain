//! Wallet-side construction of PX transactions (docs/px.md §11.3).
//!
//! Order of construction (the proof is bound to everything but the prunable
//! part, and the v1 signatures cover the proof):
//! 1. run the kernel natively (statement: nullifiers, commitments, io_hashes)
//!    and every function in the interpreter (its public outputs);
//! 2. encrypt each output record to its recipient; an empty slot gets a real
//!    ciphertext to a throwaway address, indistinguishable from a payment;
//! 3. build the v1 part (payouts, hidden change, pseudo-outputs, range
//!    proof) with the stealth context of the transaction's nullifiers;
//! 4. compute `h_tx`, prove, attach the proof;
//! 5. sign the v1 inputs over the message that includes the proof;
//! 6. self-check the result.
//!
//! **Fee.** Every PX transaction pays exactly [`PX_STANDARD_FEE`], a
//! consensus rule: the fee reveals nothing about the transaction's shape or
//! the wallet that built it.

use crate::builder::{BuildError, Decoy, InputPlan, Payment};
use crate::params::*;
use crate::px::{check_px_balance, check_px_structure, PxFunction, PxTx};
use crate::types::*;
use crate::validate::check_ring_signatures;
use blacksilk_crypto::bulletproofs_plus as bpp;
use blacksilk_crypto::clsag::{self, RingMember};
use blacksilk_crypto::commitment::commit;
use blacksilk_crypto::janus::Anchor;
use blacksilk_crypto::keys::{Address, WalletKeys};
use blacksilk_crypto::nonce::HedgedRng;
use blacksilk_crypto::stealth::{create_output, CreatedOutput, OutputKind};
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_px::delivery::{self, DeliveryKeys};
use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{self as pxprove, witness_words, TransferError};
use blacksilk_px_core::kernel::{self, SliceSource, Witness};
use blacksilk_px_core::record::{output_rho, Record};
use blacksilk_zkvm::air::trace::Budget;
use blacksilk_zkvm::Program;
use rand_core::{CryptoRng, RngCore};
use std::sync::Arc;
use zeroize::Zeroize;

/// The fee every PX transaction pays ([`PX_STANDARD_FEE`], a consensus rule).
pub fn px_standard_fee() -> u64 {
    PX_STANDARD_FEE
}

/// A function call to prove with the kernel.
#[derive(Clone)]
pub struct FunctionRun {
    pub program: Arc<Program>,
    /// The function's private input.
    pub input: Vec<u32>,
    /// The program's registered budget.
    pub budget: Budget,
}

/// Everything needed to build a PX transaction.
pub struct PxPlan<'a> {
    /// Needed when there are v1 inputs.
    pub keys: Option<&'a WalletKeys>,
    /// v1 inputs (to bridge value in or pay the fee from v1 funds).
    pub inputs: Vec<InputPlan>,
    /// Receives the v1 change when there are inputs.
    pub change: Option<Address>,
    /// Clear-amount bridge-out outputs.
    pub payouts: Vec<Payment>,
    /// The kernel witness. Its `bridge_in`/`bridge_out` must balance the v1
    /// side with the fee (module docs of `crate::px`).
    pub witness: Witness,
    /// The PX delivery address of each output slot: the owner's address for a
    /// user record, the party that will act on it for a contract record;
    /// `None` for an empty slot.
    pub recipients: [Option<delivery::Address>; 2],
    pub functions: Vec<FunctionRun>,
    pub fee: u64,
}

#[derive(Debug)]
pub enum PxBuildError {
    V1(BuildError),
    Kernel(TransferError),
    /// A recipient address does not decode or does not match its output.
    Recipient(usize),
    /// A function run fails or disagrees with the kernel.
    Function(usize),
    /// The v1 side does not balance with the witness's bridge amounts.
    Unbalanced,
    SelfCheck(crate::validate::TxError),
}

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

/// Builds and proves a PX transaction.
pub fn build_px<R: RngCore + CryptoRng>(
    plan: PxPlan<'_>,
    rules: &TxRules,
    rng: &mut R,
) -> Result<PxTx, PxBuildError> {
    let n = plan.inputs.len();
    if n > MAX_INPUTS {
        return Err(PxBuildError::V1(BuildError::InputCount(n)));
    }
    if plan.payouts.len() > MAX_PAYOUTS {
        return Err(PxBuildError::V1(BuildError::PaymentCount(
            plan.payouts.len(),
        )));
    }
    // 1. The statement, natively.
    let words = witness_words(&plan.witness);
    let public = kernel::transfer(&mut HostPerm::new(), &mut SliceSource::new(&words))
        .map_err(|e| PxBuildError::Kernel(TransferError::Rejected(e)))?;
    let mut functions = Vec::with_capacity(plan.functions.len());
    for (k, f) in plan.functions.iter().enumerate() {
        let exec = blacksilk_zkvm::run(&f.program, &f.input, blacksilk_zkvm::MAX_CYCLES)
            .map_err(|_| PxBuildError::Function(k))?;
        let (contract, io_hash) = public.functions[k];
        if exec.exit_code != 0
            || exec.output.len() < 16
            || exec.output[..16] != blacksilk_px_core::call::function_prefix(&io_hash, &contract)
        {
            return Err(PxBuildError::Function(k));
        }
        functions.push(PxFunction {
            contract,
            program_id: f.program.id(),
            io_hash,
            outputs: exec.output[16..].to_vec(),
        });
    }

    // 2. Record delivery.
    let mut ciphertexts: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
    let mut perm = HostPerm::new();
    for (j, ct) in ciphertexts.iter_mut().enumerate() {
        let out = &plan.witness.outputs[j];
        let rho = output_rho(&mut perm, &public.nullifiers[0], j as u32);
        let record = Record {
            owner: out.owner,
            contract: out.contract,
            asset: [0; 8],
            value: out.value,
            data: out.data,
            rho,
            rcm: out.rcm,
        };
        let address = match &plan.recipients[j] {
            Some(a) => {
                // A user record goes to its owner's address. A contract
                // record (owner 0) goes to the party that will act on it
                // (docs/px.md §13).
                if out.contract == blacksilk_px_core::ZERO_DIGEST && a.owner != out.owner {
                    return Err(PxBuildError::Recipient(j));
                }
                a.clone()
            }
            None => {
                // A throwaway address: the ciphertext is real, the recipient
                // is nobody.
                let mut sk = [0u32; 8];
                for x in sk.iter_mut() {
                    *x = rng.next_u32() % blacksilk_px_core::P;
                }
                DeliveryKeys::derive(&sk, 0).address(out.owner)
            }
        };
        *ct = delivery::seal(rng, &address, &record, &public.commitments[j])
            .map_err(|_| PxBuildError::Recipient(j))?;
    }

    // 3. The v1 part.
    struct Prepared {
        plan: InputPlan,
        p: Scalar,
        key_image: Point,
    }
    let mut prepared = Vec::with_capacity(n);
    for (i, ip) in plan.inputs.into_iter().enumerate() {
        let keys = plan
            .keys
            .ok_or(PxBuildError::V1(BuildError::NotOwned { input: i }))?;
        if ip.decoys.len() != RING_SIZE - 1 {
            return Err(PxBuildError::V1(BuildError::DecoyCount {
                input: i,
                count: ip.decoys.len(),
            }));
        }
        let p = keys.one_time_secret(ip.real.subaddress, &ip.real.output_key_offset);
        if Point::from_point(RistrettoPoint::mul_base(&p)) != ip.real.key.one_time_key {
            return Err(PxBuildError::V1(BuildError::NotOwned { input: i }));
        }
        let key_image = clsag::key_image(&p, &ip.real.key.one_time_key);
        prepared.push(Prepared {
            plan: ip,
            p,
            key_image,
        });
    }
    prepared.sort_by_key(|x| x.key_image);

    let mut tx = PxTx {
        inputs: Vec::new(),
        outputs: Vec::new(),
        payouts: Vec::new(),
        fee: plan.fee,
        bridge_in: public.bridge_in,
        bridge_out: public.bridge_out,
        anchor: public.anchor,
        nullifiers: public.nullifiers,
        commitments: public.commitments,
        ciphertexts,
        functions,
        pseudo_outs: Vec::new(),
        range_proof: None,
        signatures: Vec::new(),
        proof: Vec::new(),
    };
    tx.inputs = prepared
        .iter()
        .map(|x| Input {
            key_image: x.key_image,
            ring: [0; RING_SIZE],
        })
        .collect();
    let ctx = tx.output_context();
    let mut secret = plan.keys.map(|k| k.hedge_secret()).unwrap_or_default();
    let mut hedge = HedgedRng::new(&[&secret], &[b"px", &ctx], rng);
    secret.zeroize();

    let payouts_total: u128 = plan.payouts.iter().map(|p| p.amount as u128).sum();
    let mut payouts: Vec<CoinbaseOutput> = plan
        .payouts
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
    payouts.sort_by_key(|o| o.one_time_key);
    tx.payouts = payouts;

    // v1 value: inputs = change + fee + bridge_in + payouts − bridge_out.
    let available: u128 = prepared.iter().map(|x| x.plan.real.amount as u128).sum();
    let required: i128 = plan.fee as i128 + public.bridge_in as i128 + payouts_total as i128
        - public.bridge_out as i128;
    let mut rings = Vec::with_capacity(n);
    let mut real_positions = Vec::with_capacity(n);
    let mut pseudo_masks: Vec<Scalar> = Vec::new();
    if n == 0 {
        if required != 0 {
            return Err(PxBuildError::Unbalanced);
        }
    } else {
        let change_amount =
            u64::try_from(available as i128 - required).map_err(|_| PxBuildError::Unbalanced)?;
        let change = plan.change.ok_or(PxBuildError::Unbalanced)?;
        let created = make_output(
            &mut hedge,
            &change,
            change_amount,
            &ctx,
            OutputKind::Transfer,
        );
        let (range_proof, commitments) = bpp::prove(&[created.amount], &[created.mask], rng)
            .map_err(|e| PxBuildError::V1(BuildError::RangeProof(e)))?;
        debug_assert_eq!(commitments[0], created.commitment);
        let mask_sum = created.mask;
        tx.outputs = vec![Output {
            one_time_key: created.one_time_key,
            ephemeral: created.ephemeral,
            view_tag: created.view_tag,
            commitment: created.commitment,
            enc_amount: created.enc_amount,
            enc_anchor: created.enc_anchor,
        }];
        tx.range_proof = Some(range_proof);
        // Pseudo-output masks sum to the change mask (spec §6).
        pseudo_masks = (0..n - 1).map(|_| hedge.scalar()).collect();
        let partial: Scalar = pseudo_masks.iter().sum();
        pseudo_masks.push(mask_sum - partial);
        tx.pseudo_outs = prepared
            .iter()
            .zip(&pseudo_masks)
            .map(|(x, z)| Point::from_point(commit(x.plan.real.amount, z)))
            .collect();
        tx.inputs.clear();
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
                return Err(PxBuildError::V1(BuildError::DuplicateRingMember {
                    input: i,
                }));
            }
            real_positions.push(
                members
                    .iter()
                    .position(|m| m.global_index == x.plan.real.global_index)
                    .expect("real member is in the ring"),
            );
            rings.push(std::array::from_fn::<RingMember, RING_SIZE, _>(|j| {
                RingMember {
                    one_time_key: members[j].key.one_time_key,
                    commitment: members[j].key.commitment,
                }
            }));
            tx.inputs.push(Input {
                key_image: x.key_image,
                ring: std::array::from_fn(|j| members[j].global_index),
            });
        }
    }

    // 4. The proof, bound to h_tx.
    let runs: Vec<(Arc<Program>, Vec<u32>, Budget)> = plan
        .functions
        .iter()
        .map(|f| (f.program.clone(), f.input.clone(), f.budget))
        .collect();
    let (proven, _, proof) =
        pxprove::prove(&plan.witness, &runs, tx.binding(rules.network_id), rng)
            .map_err(PxBuildError::Kernel)?;
    if proven != public {
        return Err(PxBuildError::Kernel(TransferError::Shape));
    }
    tx.proof = blacksilk_zk::encode_proof(&proof);

    // 5. Signatures over everything but themselves, including the proof.
    let message = tx.signature_message(rules.network_id);
    for (k, x) in prepared.iter().enumerate() {
        let z = x.plan.real.mask - pseudo_masks[k];
        let (sig, _) = clsag::sign(
            &message,
            &rings[k],
            &tx.pseudo_outs[k],
            real_positions[k],
            &x.p,
            &z,
            rng,
        )
        .map_err(|e| PxBuildError::V1(BuildError::Signing(e)))?;
        tx.signatures.push(sig);
    }
    for x in &mut prepared {
        x.p.zeroize();
    }
    for z in &mut pseudo_masks {
        z.zeroize();
    }

    // 6. Self-check.
    check_px_structure(&tx).map_err(PxBuildError::SelfCheck)?;
    check_px_balance(&tx).map_err(PxBuildError::SelfCheck)?;
    check_ring_signatures(
        &tx.inputs,
        &tx.pseudo_outs,
        &tx.signatures,
        &rings,
        &message,
    )
    .map_err(PxBuildError::SelfCheck)?;
    Ok(tx)
}

/// The fee of a deploy with `inputs` v1 inputs and `outputs` outputs that
/// registers `programs`: the per-byte fee of an upper bound of its encoded
/// size.
pub fn deploy_fee(inputs: usize, outputs: usize, programs: &[crate::px::Registration]) -> u64 {
    let payload: usize = 32
        + 10
        + programs
            .iter()
            .map(|p| p.elf.len() + 10 + 80)
            .sum::<usize>();
    PX_FEE_PER_BYTE * (crate::builder::max_weight(inputs, outputs) + payload as u64 + 64)
}

/// Builds a signed deploy registering `programs` (binary, budget), paid from
/// `inputs` with `payments` and change like a transfer. The fee is
/// [`deploy_fee`].
#[allow(clippy::too_many_arguments)]
pub fn build_deploy<R: RngCore + CryptoRng>(
    keys: &WalletKeys,
    inputs: Vec<InputPlan>,
    payments: &[Payment],
    change: &Address,
    salt: [u8; 32],
    programs: Vec<crate::px::Registration>,
    rules: &TxRules,
    rng: &mut R,
) -> Result<crate::px::PxDeploy, BuildError> {
    let fee = deploy_fee(inputs.len(), payments.len() + 1, &programs);
    let view = |t: &Transfer| crate::px::PxDeploy {
        inputs: t.inputs.clone(),
        outputs: t.outputs.clone(),
        fee: t.fee,
        salt,
        programs: programs.clone(),
        pseudo_outs: t.pseudo_outs.clone(),
        range_proof: t.range_proof.clone(),
        signatures: Vec::new(),
    };
    let net = rules.network_id;
    // The v1 part pays the per-byte fee, not the weight fee.
    let relaxed = TxRules {
        fee_per_weight: 0,
        ..*rules
    };
    let t = crate::builder::build_transfer_signing(
        keys,
        inputs,
        payments,
        change,
        fee,
        &relaxed,
        rng,
        &|t| view(t).signature_message(net),
    )?;
    let mut deploy = view(&t);
    deploy.signatures = t.signatures;
    crate::px::check_deploy_structure(&deploy, rules).map_err(BuildError::SelfCheck)?;
    Ok(deploy)
}
