//! Target body: the admission of a relayed PX transaction (RT-FUZZ design
//! 2; decisions "W4-FUZZ and RT-FUZZ"). Shared by
//! fuzz_targets/px_admission.rs and p2p/tests/fuzz_px_admission.rs, which
//! include `chain_fixture.rs`, `px_tx_struct.rs` and `proof_struct.rs` next
//! to it.
//!
//! The chain is a fixed regtest chain (`chain`): 75 blocks, then a block
//! deploying the vault contract, so the PX registry holds one contract. The
//! base transaction is a real PX deposit on it (a v1 input, a real proof),
//! which passes every check. The input is an edit script on the DECODED
//! transaction, 4 bytes per step `site, a, b, c` (at most 64):
//! - sites below 240: `px_tx_struct`'s edits (inputs, outputs, payouts,
//!   amounts, the window, the statement, ciphertexts, functions,
//!   pseudo-outputs, the range proof, signatures, raw proof bytes);
//! - 240 to 247: add a call of the registered vault function (its contract
//!   and program id, so the registry lookup succeeds and the proof's shape
//!   is checked against it);
//! - 248 to 255: `proof_struct`'s edits of the decoded proof (`a, b, c` as
//!   its site and operands), re-encoded into the transaction.
//!
//! The edited transaction is encoded and goes through the node's admission
//! steps (`net::fuzzing::admission`, feature `test-hooks`): decoding, the
//! pool lookups, the stateless PX checks the node runs off the chain actor
//! (structure, balance, the strict proof decoding), the cheap checks
//! (expiry policy, contextual rules, the proof's shape against its
//! registered functions), then the verification and its scoring.
//!
//! Invariants, beyond "no panic" (a contained Plonky3 panic is a panic
//! here: libFuzzer's hook aborts on any panic, and the stable twin counts
//! panics through its own hook):
//! - the verdict is stable: a second run of the stateless and cheap checks
//!   gives the same results, and a decoded proof's degree bits are the same
//!   (decoding is deterministic, and so is the shape check after it);
//! - an early refusal agrees with full validation: whatever the cheap
//!   checks refuse (except the expiry policy), `check_tx` refuses too, and
//!   what they score (a stateless rule) is stateless for `check_tx` too, so
//!   a relayer is never penalized for a transaction full validation would
//!   accept, nor scored on a contextual failure;
//! - a transaction that passes verification is the base transaction itself:
//!   no edit of a valid PX transaction yields another valid one
//!   (non-malleability, as far as the edits reach);
//! - bounded work: the decoded proof has at most `MAX_TABLES` degree bits,
//!   and the stateless and cheap checks take at most a fixed time plus a
//!   per-byte time (no superlinear decoding or checking); memory is bounded
//!   by the campaign's `-malloc_limit_mb` and `-rss_limit_mb`.
//!
//! What it shows: robustness and non-malleability over the edits reached,
//! not soundness. An edit that changes the statement fails Fiat-Shamir's
//! query proof of work before the FRI checks (F41-8); verifier grinding is
//! NOT disabled in these builds.

use crate::chain_fixture::{self, Miner};
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::mempool::MempoolError;
use blacksilk_crypto::keys::SubaddressIndex;
use blacksilk_p2p::net::fuzzing::{admission, Admission};
use blacksilk_px::prove::PROOF_LIMITS;
use blacksilk_px::wallet::{self as pxw, Account};
use blacksilk_px_core::Digest;
use blacksilk_tx::builder::Payment;
use blacksilk_tx::px::{PxFunction, PxTx, Registration};
use blacksilk_tx::px_builder::{build_deploy, build_px, px_standard_fee, PxPlan};
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::ChainView;
use blacksilk_tx::TxError;
use blacksilk_zk::{decode_proof_with, encode_proof};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MAX_EDITS: usize = 64;
/// Degree bits a decoded PX proof may carry at most (one per table; far
/// above any shape the kernel and its functions produce).
const MAX_TABLES: usize = 64;

/// The fixed chain, and the registered vault contract's id.
pub fn chain() -> (ChainManager, Miner, Digest) {
    let mut m = chain_fixture::open();
    let mut miner = Miner::new(8);
    for _ in 0..75 {
        miner.mine(&mut m);
    }
    let rules = *m.rules();
    let primary = miner.keys.address(SubaddressIndex::PRIMARY);
    let plan = chain_fixture::plan_nth(&m, &miner.keys, 1, &mut miner.rng);
    let deploy = build_deploy(
        &miner.keys,
        vec![plan],
        &[Payment {
            address: primary,
            amount: 0,
        }],
        &primary,
        [4; 32],
        vec![Registration {
            elf: blacksilk_px::vault::VAULT_ELF.to_vec(),
            budget: blacksilk_px::vault::BUDGET,
            abi: blacksilk_tx::px::ABI_VERSION,
            out_words: blacksilk_px::vault::OUT_WORDS,
        }],
        &rules,
        &mut miner.rng,
    )
    .expect("a deploy");
    let contract = deploy.contract_id();
    m.submit_tx(Transaction::PxDeploy(Box::new(deploy)))
        .expect("the deploy is valid");
    miner.mine(&mut m);
    assert!(m.state().px_contract_exists(&contract));
    (m, miner, contract)
}

/// The base transaction: a PX deposit of 5,000,000 from the miner's first
/// spendable output, with a real proof (about a minute, 4 to 6 GB).
pub fn deposit(m: &ChainManager, miner: &mut Miner) -> PxTx {
    let rules = *m.rules();
    let amount = 5_000_000;
    let plan = chain_fixture::plan_nth(m, &miner.keys, 0, &mut miner.rng);
    let acct = Account::from_seed(&[3; 32]);
    let rng = &mut miner.rng;
    let witness = pxw::witness(
        m.state().px().root(),
        amount,
        0,
        [pxw::dummy_input(rng), pxw::dummy_input(rng)],
        [
            pxw::output(rng, acct.owner(0), amount),
            pxw::empty_output(rng),
        ],
    );
    build_px(
        PxPlan {
            keys: Some(&miner.keys),
            inputs: vec![plan],
            change: Some(miner.keys.address(SubaddressIndex::PRIMARY)),
            payouts: vec![],
            witness,
            recipients: [Some(acct.address(0)), None],
            functions: vec![],
            fee: px_standard_fee(),
            window: Default::default(),
            hedge_secret: [0x5e; 32],
        },
        &rules,
        &mut miner.rng,
    )
    .expect("a PX deposit")
}

/// What one input runs against.
pub struct Base {
    pub chain: ChainManager,
    pub contract: Digest,
    pub tx: PxTx,
    id: [u8; 32],
}

impl Base {
    /// The base transaction's encoding.
    pub fn encoded(&self) -> Vec<u8> {
        Transaction::Px(Box::new(self.tx.clone())).encode()
    }

    /// `tx` must pass every admission step on `chain` (it was built for it).
    pub fn new(chain: ChainManager, contract: Digest, tx: PxTx) -> Self {
        // The activation grace of docs/p2p.md §10 (near an activation a
        // failing proof or signature is not scored) never applies with one
        // rule epoch; `spec_scored` leaves it out.
        assert_eq!(
            chain.params().schedule.epochs().len(),
            1,
            "spec_scored needs the activation grace for a chain with several epochs"
        );
        let bytes = Transaction::Px(Box::new(tx.clone())).encode();
        let a = admission(&chain, &bytes, true);
        assert!(
            matches!(a.verified, Some((Ok(_), false))),
            "the base transaction passes admission on the fixed chain: {a:?}"
        );
        let id = a.id.expect("an id");
        Base {
            chain,
            contract,
            tx,
            id,
        }
    }
}

pub fn run(base: &Base, data: &[u8]) {
    let mut tx = base.tx.clone();
    let mut proof_edits = Vec::new();
    for step in data.chunks(4).take(MAX_EDITS) {
        let [site, a, b, c] = [0, 1, 2, 3].map(|i| step.get(i).copied().unwrap_or(0));
        match site {
            0..=239 => crate::px_tx_struct::edit(&mut tx, site, a as usize, b as usize, c),
            240..=247 => tx.functions.push(PxFunction {
                contract: base.contract,
                program_id: blacksilk_px::vault::program().id(),
                io_hash: [a as u32; 8],
                outputs: vec![b as u32; (c as usize % 3).max(1)],
            }),
            _ => proof_edits.push([a, b, c, b ^ c]),
        }
    }
    if !proof_edits.is_empty() {
        if let Ok(mut p) = decode_proof_with(&tx.proof, &PROOF_LIMITS) {
            for [site, a, b, c] in proof_edits {
                crate::proof_struct::edit(&mut p, site, a as usize, b as usize, c);
            }
            tx.proof = encode_proof(&p);
        }
    }
    let bytes = Transaction::Px(Box::new(tx)).encode();

    let started = Instant::now();
    let first = admission(&base.chain, &bytes, false);
    let cheap_time = started.elapsed();
    let second = admission(&base.chain, &bytes, false);
    assert_eq!(
        first, second,
        "the stateless and cheap checks are deterministic"
    );
    // Bounded work before the verification: a fixed time plus a per-byte
    // time, far above the cost on any build (decoding a 2.4 MB proof takes
    // about 12 ms optimized), so only superlinear work trips it.
    let bound = Duration::from_secs(2) + Duration::from_micros(2) * bytes.len() as u32;
    assert!(
        cheap_time <= bound,
        "the cheap checks of {} bytes took {cheap_time:?} (bound {bound:?})",
        bytes.len()
    );
    if let Some(Ok(bits)) = &first.pre {
        assert!(bits.len() <= MAX_TABLES, "{} degree bits", bits.len());
    }
    let Admission { decoded, cheap, .. } = &first;
    if !decoded {
        tally(0);
        record(data, &first, None);
        return;
    }
    let tx = Transaction::decode(&bytes).expect("it decoded for the node");
    let mut verified = None;
    match cheap {
        // Passed: the verification (on the transaction lane) decides.
        Some(Ok(true)) => {
            let full = admission(&base.chain, &bytes, true);
            verified = full.verified;
            match verified {
                Some((Ok(id), proven)) => {
                    tally(5);
                    assert!(!proven);
                    assert_eq!(
                        id, base.id,
                        "an edited PX transaction passes verification (malleable)"
                    );
                }
                Some((Err(e), proven)) => {
                    tally(4);
                    assert_eq!(
                        proven,
                        spec_scored(&base.chain, &tx, &e),
                        "verification failure {e:?}: scored as the node did, not as \
                         docs/p2p.md §10 says ({:?})",
                        error_class(&e)
                    );
                }
                None => panic!("the cheap checks passed but nothing was verified"),
            }
        }
        // Refused early: scored exactly when the rule is stateless by the
        // specification, and full validation refuses too, stateless if the
        // early refusal was.
        Some(Err((e, scored))) => {
            tally(if *scored { 2 } else { 3 });
            let class = spec_class(e);
            assert_eq!(
                *scored,
                matches!(class, Class::Stateless(_)),
                "the cheap checks scored {e:?} as {}, the specification says {class:?}",
                if *scored { "stateless" } else { "contextual" }
            );
            let full = base.chain.check_tx(&tx);
            match full {
                Ok(_) => panic!("the cheap checks refuse ({e:?}) what full validation accepts"),
                Err(MempoolError::Invalid(f)) => {
                    if *scored {
                        assert!(
                            matches!(spec_class(&f), Class::Stateless(_)),
                            "stateless early ({e:?}), {:?} in full ({f:?})",
                            spec_class(&f)
                        );
                    }
                }
                Err(other) => panic!("full validation: {other:?} after an early {e:?}"),
            }
        }
        // The expiry policy, or dropped as a pooled or conflicting one.
        Some(Ok(false)) | None => tally(1),
    }
    record(data, &first, verified);
}

/// A rule's class by the specification: a failure of a stateless rule
/// proves the relayer broke a rule (scored 20, docs/p2p.md §10); a
/// contextual one is never scored, except an invalid signature over ring
/// members all at least 60 blocks deep. Each variant is mapped to the rule
/// it reports (named in the spec), and the rule's class is the spec's:
/// - T1–T11 stateless (docs/transactions.md §8.1), C1–C3 contextual (§8.2);
/// - the PX structure and deploy rules, the inverted window, the repeated
///   key between outputs and payouts and the repeated nullifier stateless
///   (docs/px.md §11.3 "Structure", "C1–C3", "PX6", "Deploy"; transactions.md
///   §8.5);
/// - PX1, PX2, PX3, PX4 contextual (transactions.md §8.5: "contextual rule
///   (C1–C3, PX1–PX4)"), except PX3's output-word count, stateless for
///   scoring (px.md §11.3 PX3);
/// - PX5 (the proof) misbehaviour (px.md §11.5 "Invalid proof"; p2p.md §10
///   step 4: "penalized as `PxProof`");
/// - PX6 (the window) contextual and never penalized (px.md §11.3 PX6);
/// - B8 (tree capacity) contextual for a mempool transaction (px.md §11.3).
///
/// Ambiguity: a deploy whose contract id exists (`DuplicateContract`) has no
/// class in the specification (px.md §11.3 "Deploy": "the contract id is new
/// in the chain and the block"); it depends on the chain, so it is taken as
/// contextual. A PX transaction never reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Stateless(&'static str),
    Contextual(&'static str),
}

fn spec_class(e: &TxError) -> Class {
    use Class::{Contextual, Stateless};
    use TxError::*;
    match e {
        TooLarge { .. } => Stateless("T1"),
        CoinbaseNotAllowed => Stateless("T2"),
        InputCount(_) | OutputCount(_) => Stateless("T3"),
        KeyImageIdentity { .. } | KeyImagesNotSorted => Stateless("T4"),
        RingNotIncreasing { .. } => Stateless("T5"),
        OutputKeyIdentity { .. } | EphemeralIdentity { .. } | OutputsNotSorted => Stateless("T6"),
        PseudoOutCount => Stateless("T7"),
        FeeNotExact { .. } | WeightOverflow => Stateless("T8"),
        Unbalanced => Stateless("T9"),
        RangeProofShape | RangeProofInvalid => Stateless("T10"),
        SignatureCount | AuxKeyImageIdentity { .. } => Stateless("T11"),
        UnknownRingMember { .. } | RingMemberTooYoung { .. } => Contextual("C1"),
        KeyImageSpent { .. } => Contextual("C2"),
        InvalidSignature { .. } => Contextual("C3"),
        PxShape | PxFeeNotStandard { .. } => Stateless("PX structure"),
        PxInvalidProgram
        | PxBudgetTooLarge { .. }
        | PxProgramTooLarge { .. }
        | DeployFeeNotExact { .. }
        | PxUnsupportedAbi { .. }
        | PxDuplicateProgram { .. } => Stateless("deploy structure"),
        PxWindowInverted => Stateless("PX6 (inverted)"),
        PxDuplicateOutputKey { .. } | PxNullifierRepeated => Stateless("PX repeat"),
        PxCiphertextRNonCanonical { .. } | PxCiphertextRIdentity { .. } => {
            Stateless("PX ciphertext R")
        }
        PxUnknownAnchor => Contextual("PX1"),
        PxNullifierSpent { .. } => Contextual("PX2"),
        PxUnregistered { .. } => Contextual("PX3"),
        PxOutputWords { .. } => Stateless("PX3 (output words)"),
        PxPoolUnderflow => Contextual("PX4"),
        PxProof => Stateless("PX5"),
        PxWindow => Contextual("PX6"),
        PxTreeFull => Contextual("B8"),
        DuplicateContract => Contextual("deploy contract id (unclassified)"),
    }
}

fn error_class(e: &MempoolError) -> Option<Class> {
    match e {
        MempoolError::Invalid(t) => Some(spec_class(t)),
        _ => None,
    }
}

/// Signature failures over ring members this deep are scored (docs/p2p.md
/// §10: "ring members all ≥ 60 blocks deep").
const SIGNATURE_BURIAL: u64 = 60;

/// Whether docs/p2p.md §10 scores a verification failure `e` of `tx` on
/// `c`: a stateless rule, or a signature over buried ring members. Outside
/// any activation's grace window (`Base::new` checks the chain has a single
/// rule epoch, so none applies).
fn spec_scored(c: &ChainManager, tx: &Transaction, e: &MempoolError) -> bool {
    let MempoolError::Invalid(t) = e else {
        return false;
    };
    match (spec_class(t), t) {
        (Class::Stateless(_), _) => true,
        (_, TxError::InvalidSignature { input }) => {
            let Transaction::Px(p) = tx else {
                return false;
            };
            let tip = c.height();
            p.inputs.get(*input).is_some_and(|i| {
                i.ring.iter().all(|&g| {
                    c.state()
                        .output(g)
                        .is_some_and(|o| o.height + SIGNATURE_BURIAL <= tip)
                })
            })
        }
        _ => false,
    }
}

/// The twin's per-input verdicts, in order (not in fuzz builds): for a
/// digest that two runs compare.
#[cfg(not(fuzzing))]
pub static VERDICTS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

type Verified = Option<(Result<[u8; 32], MempoolError>, bool)>;

fn record(data: &[u8], first: &Admission, verified: Verified) {
    #[cfg(not(fuzzing))]
    {
        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
        let line = format!(
            "{hex} decoded={} pre={:?} cheap={:?} verified={verified:?}",
            first.decoded,
            first.pre.as_ref().map(|r| r.as_ref().map(|b| b.len())),
            first.cheap
        );
        VERDICTS.lock().expect("the verdicts").push(line);
    }
    #[cfg(fuzzing)]
    let _ = (data, first, verified);
}

/// Seed inputs (named): the unedited transaction, and one per kind of edit.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("none", vec![]),
        ("fee", vec![6, 2, 0, 0]),
        ("window_expired", vec![9, 3, 0, 1]),
        ("anchor", vec![10, 0, 3, 0]),
        // A canonical anchor that is no recent root: PX1, contextual.
        ("anchor_unknown", vec![10, 0, 1, 0]),
        ("same_nullifiers", vec![13, 0, 0, 0]),
        ("nullifier_word", vec![11, 1, 1, 0]),
        ("ciphertext", vec![14, 100, 0, 0]),
        ("ring_member", vec![1, 0, 3, 2]),
        ("key_image", vec![1, 0, 0, 1]),
        ("drop_signature", vec![20, 0, 0, 1]),
        ("range_proof", vec![19, 0, 0, 0]),
        ("unregistered_function", vec![16, 0, 1, 2]),
        ("registered_function", vec![240, 0, 0, 0]),
        ("registered_function_two", vec![240, 1, 2, 1, 241, 3, 4, 2]),
        ("proof_degree_bits", vec![248, 0, 0, 0]),
        ("proof_vector", vec![248, 1, 0, 1]),
        ("proof_byte", vec![23, 7, 7, 3]),
        ("proof_empty", vec![22, 0, 0, 5]),
    ]
}

/// How far the inputs went (the stable twin prints it): not decoded,
/// dropped before the cheap checks or expiring, refused early and scored,
/// refused early as contextual, failed verification, passed verification.
pub static REACHED: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];

pub fn reached() -> String {
    let [u, e, s, c, f, v] = REACHED.each_ref().map(|c| c.load(Ordering::Relaxed));
    format!("not decoded {u}, dropped or expiring {e}, refused early: scored {s}, contextual {c}; failed verification {f}, passed {v}")
}

fn tally(i: usize) {
    REACHED[i].fetch_add(1, Ordering::Relaxed);
}
