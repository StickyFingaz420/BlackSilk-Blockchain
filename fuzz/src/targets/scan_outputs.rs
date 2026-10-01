//! Target body: wallet-side output scanning (`tx::scan`, spec §3.3;
//! decisions "W4-FUZZ and RT-FUZZ", design 3). Shared by
//! fuzz_targets/scan_outputs.rs and tx/tests/fuzz_scan.rs.
//!
//! Two wallets with fixed keys and subaddress tables: `A`, which the base
//! transactions pay (the seed generator's wallet, so the PX seeds pay it
//! too), and `B`, a stranger. Input, by its first byte:
//! - even: the rest is a transaction's encoding (anything that decodes:
//!   coinbases, transfers, deploys, PX transactions);
//! - odd: one of the base transactions (byte 1), then 4-byte edit steps
//!   `op, a, b, c` (at most 32) on its outputs: splice in an output of
//!   another transaction (a real output of `A`'s, under another
//!   transaction's context), flip the view tag, replace the one-time key
//!   (another output's, or shifted by `G`), the ephemeral key, the
//!   commitment or the encrypted amount, flip an anchor bit, duplicate,
//!   drop or swap outputs, or change the input context (a key image).
//!
//! Both wallets scan the result (`scan_transaction`, and `scan_block` over
//! two copies). Each output's outcome is derived independently with the
//! wallet's secret keys, without the scanner's shared-secret type, table
//! lookup or anchor check: the shared secret `k_v·R`; the view tag, the
//! output-key offset `x`, the mask, the amount pad and the anchor pad from
//! their hashes; the subaddress whose spend key `D` makes the one-time key
//! `x·G + D` (trying every one); the anchor's `r = Hs("ephemeral", anchor ‖
//! ctx ‖ D ‖ C)` with `r·D = R`; and the commitment. Invariants, beyond "no
//! panic":
//! - every output's outcome is exactly the derived one: not owned (a wrong
//!   view tag, or a key paying none of the wallet's subaddresses, so a
//!   matching view tag with a wrong key is never owned), refused for its
//!   anchor (a real output under another transaction's context, a Janus
//!   probe), refused for its commitment, or owned by exactly that
//!   subaddress (a wallet never misses an output paying its keys);
//! - an owned output's offset, mask and amount are the derived ones, its
//!   one-time secret opens its key (`(x + d)·G = O`), and its amount and
//!   mask open its commitment (hidden), or it is the clear amount with the
//!   implicit commitment (coinbase);
//! - global indices follow output positions, and `scan_block` over two
//!   copies of the transaction reports each owned output twice, the second
//!   time shifted by the output count;
//! - the scan's time is bounded per output (linear in the outputs).

use blacksilk_crypto::commitment::{coinbase_commitment, commit};
use blacksilk_crypto::hash::{h32, h64, hash_to_scalar, tags};
use blacksilk_crypto::keys::{SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_crypto::stealth::{
    coinbase_context, transfer_context, OutputAmount, OutputFields, ScanRejection,
};
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_tx::builder::{
    build_coinbase, build_transfer, standard_fee, Decoy, InputPlan, Payment, SpendableOutput,
};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::scan::{scan_block, scan_transaction};
use blacksilk_tx::types::{CoinbaseOutput, Output, Transaction};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// The tables' size: accounts and subaddresses per account.
const ACCOUNTS: u32 = 2;
const PER_ACCOUNT: u32 = 16;
const MAX_EDITS: usize = 32;

/// A wallet with its subaddress table and every subaddress spend key.
pub struct Wallet {
    pub keys: WalletKeys,
    table: SubaddressTable,
    subs: Vec<Sub>,
}

/// One subaddress: its index, spend key `D` and view key `C`.
struct Sub {
    index: SubaddressIndex,
    spend: RistrettoPoint,
    spend_bytes: [u8; 32],
    view_bytes: [u8; 32],
}

impl Wallet {
    fn new(keys: WalletKeys) -> Self {
        let table = SubaddressTable::new(keys.view_keys(), ACCOUNTS, PER_ACCOUNT);
        let subs = (0..ACCOUNTS)
            .flat_map(|a| (0..PER_ACCOUNT).map(move |i| SubaddressIndex::new(a, i)))
            .map(|index| {
                let a = keys.address(index);
                Sub {
                    index,
                    spend: *a.spend().point(),
                    spend_bytes: *a.spend().bytes(),
                    view_bytes: *a.view().bytes(),
                }
            })
            .collect();
        Self { keys, table, subs }
    }
}

pub struct Base {
    /// The seed generator's wallet (`ChaCha20Rng` seed 1, first keys).
    pub a: Wallet,
    pub b: Wallet,
    pub txs: Vec<Transaction>,
    /// Every output of the base transactions: splice donors.
    hidden: Vec<Output>,
    clear: Vec<CoinbaseOutput>,
}

fn keys(seed: u64) -> WalletKeys {
    WalletKeys::generate(&mut ChaCha20Rng::seed_from_u64(seed)).0
}

/// The base transactions: a 16-output coinbase paying `A`'s subaddresses, a
/// coinbase paying both wallets, and a transfer from `A` (spending the
/// first, with its siblings as decoys) paying `A`, `B` and `A`'s change.
pub fn base() -> &'static Base {
    static B: OnceLock<Base> = OnceLock::new();
    B.get_or_init(|| {
        let a = Wallet::new(keys(1));
        let b = Wallet::new(keys(99));
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let rules = TxRules::for_chain(&blacksilk_consensus::ChainParams::regtest());
        let pay = |w: &Wallet, acct: u32, i: u32, amount: u64| Payment {
            address: w.keys.address(SubaddressIndex::new(acct, i)),
            amount,
        };
        let funds: Vec<Payment> = (0..16)
            .map(|i| pay(&a, 0, i, 1_000_000 + i as u64))
            .collect();
        let funding = Transaction::Coinbase(
            build_coinbase(2, &funds, &[2; 32], &mut rng).expect("a coinbase"),
        );
        let mixed = Transaction::Coinbase(
            build_coinbase(
                3,
                &[pay(&a, 1, 2, 7), pay(&b, 0, 0, 8), pay(&a, 0, 15, 9)],
                &[3; 32],
                &mut rng,
            )
            .expect("a coinbase"),
        );
        let owned = scan_transaction(a.keys.view_keys(), &a.table, &funding, 2, 0).owned;
        assert_eq!(owned.len(), 16, "the wallet owns every funding output");
        let plan = InputPlan {
            real: SpendableOutput::from(&owned[0]),
            decoys: owned[1..]
                .iter()
                .map(|o| Decoy {
                    global_index: o.global_index,
                    key: o.key,
                })
                .collect(),
        };
        let transfer = build_transfer(
            &a.keys,
            vec![plan],
            &[pay(&a, 1, 1, 1_000), pay(&b, 0, 3, 2_000)],
            &a.keys.address(SubaddressIndex::PRIMARY),
            standard_fee(1, 3, &rules),
            &rules,
            &mut rng,
        )
        .expect("a transfer");
        let txs = vec![funding, mixed, Transaction::from(transfer)];
        let (hidden, clear) = donors(&txs);
        Base {
            a,
            b,
            txs,
            hidden,
            clear,
        }
    })
}

pub fn run(data: &[u8]) {
    let base = base();
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let tx = if mode & 1 == 0 {
        match Transaction::decode(rest) {
            Ok(tx) => tx,
            Err(_) => return,
        }
    } else {
        let Some((&which, steps)) = rest.split_first() else {
            return;
        };
        let mut tx = base.txs[which as usize % base.txs.len()].clone();
        for step in steps.chunks(4).take(MAX_EDITS) {
            let [op, a, b, c] = [0, 1, 2, 3].map(|i| step.get(i).copied().unwrap_or(0));
            edit(&mut tx, base, op, a as usize, b as usize, c);
        }
        tx
    };
    for w in [&base.a, &base.b] {
        check(w, &tx);
    }
}

// ------------------------------------------------------------- the oracle

/// The outputs' scanned fields, in `scan_transaction`'s order.
fn fields(tx: &Transaction) -> Vec<OutputFields<'_>> {
    match tx {
        Transaction::Coinbase(c) => c.outputs.iter().map(CoinbaseOutput::fields).collect(),
        Transaction::Transfer(t) => t.outputs.iter().map(Output::fields).collect(),
        Transaction::Px(t) => t
            .outputs
            .iter()
            .map(Output::fields)
            .chain(t.payouts.iter().map(CoinbaseOutput::fields))
            .collect(),
        Transaction::PxDeploy(t) => t.outputs.iter().map(Output::fields).collect(),
    }
}

/// The input context `ctx` the anchors bind (spec §3.1, docs/px.md §11).
fn context(tx: &Transaction) -> [u8; 32] {
    let images = |inputs: &[blacksilk_tx::types::Input]| -> Vec<Point> {
        inputs.iter().map(|i| i.key_image).collect()
    };
    match tx {
        Transaction::Coinbase(c) => coinbase_context(c.height),
        Transaction::Transfer(t) => transfer_context(&images(&t.inputs)),
        Transaction::Px(t) => t.output_context(),
        Transaction::PxDeploy(t) => transfer_context(&images(&t.inputs)),
    }
}

/// What scanning must report for one output: derived with the wallet's
/// secret keys, independently of the scanner (no shared-secret type, no
/// table lookup, no `janus::verify`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expected {
    NotOwned,
    Owned(SubaddressIndex),
    Refused(SubaddressIndex, ScanRejection),
}

/// The derivation's values an owned output must carry.
struct Derived {
    x: Scalar,
    mask: Scalar,
    /// The amount the encrypted field decrypts to (hidden amounts).
    amount: u64,
}

fn derive(w: &Wallet, ctx: &[u8; 32], f: &OutputFields<'_>) -> (Expected, Derived) {
    let s = (w.keys.view_keys().view_secret() * f.ephemeral.point())
        .compress()
        .to_bytes();
    let x = hash_to_scalar(tags::OUTPUT_KEY, &[&s]);
    let mask = hash_to_scalar(tags::MASK, &[&s]);
    let pad = h64(tags::AMOUNT, &[&s]);
    let amount = match f.amount {
        OutputAmount::Hidden { enc_amount, .. } => {
            let mut a = *enc_amount;
            for (b, p) in a.iter_mut().zip(&pad[..8]) {
                *b ^= p;
            }
            u64::from_le_bytes(a)
        }
        OutputAmount::Clear(a) => a,
    };
    let d = Derived { x, mask, amount };
    if h32(tags::VIEW_TAG, &[&s])[0] != f.view_tag {
        return (Expected::NotOwned, d);
    }
    let xg = RistrettoPoint::mul_base(&x);
    let Some(sub) = w
        .subs
        .iter()
        .find(|s| xg + s.spend == *f.one_time_key.point())
    else {
        return (Expected::NotOwned, d);
    };
    // The anchor: `r = Hs("ephemeral", anchor ‖ ctx ‖ D ‖ C)`, `r·D = R`.
    let anchor_pad = h64(tags::ANCHOR, &[&s]);
    let mut anchor = *f.enc_anchor;
    for (a, p) in anchor.iter_mut().zip(&anchor_pad[..16]) {
        *a ^= p;
    }
    let r = hash_to_scalar(
        tags::EPHEMERAL,
        &[&anchor, ctx, &sub.spend_bytes, &sub.view_bytes],
    );
    let big_r = r * sub.spend;
    let anchored = big_r != RistrettoPoint::default() && big_r == *f.ephemeral.point();
    let expected = if !anchored {
        Expected::Refused(sub.index, ScanRejection::JanusAnchorMismatch)
    } else {
        match f.amount {
            OutputAmount::Hidden { commitment, .. }
                if commit(amount, &mask) != *commitment.point() =>
            {
                Expected::Refused(sub.index, ScanRejection::CommitmentMismatch)
            }
            _ => Expected::Owned(sub.index),
        }
    };
    (expected, d)
}

fn check(w: &Wallet, tx: &Transaction) {
    let view = w.keys.view_keys();
    let all = fields(tx);
    let n = all.len();
    let started = Instant::now();
    let report = scan_transaction(view, &w.table, tx, 5, 1000);
    let elapsed = started.elapsed();
    // Linear in the outputs: a generous per-output bound (two scalar
    // multiplications, a few hashes and at most one commitment each), far
    // above the cost on any build, so only a superlinear scan trips it.
    let bound = Duration::from_millis(250) + Duration::from_millis(20) * n as u32;
    assert!(
        elapsed <= bound,
        "scanning {n} outputs took {elapsed:?} (bound {bound:?})"
    );
    let keys = tx.output_keys();
    assert_eq!(keys.len(), n, "output_keys and the scanned fields agree");
    let ctx = context(tx);

    let mut owned = report.owned.iter().peekable();
    let mut refused = report.rejected.iter().peekable();
    for (i, f) in all.iter().enumerate() {
        let (expected, d) = derive(w, &ctx, f);
        let got = match (
            owned.next_if(|o| o.index_in_tx == i),
            refused.next_if(|(j, _)| *j == i),
        ) {
            (None, None) => Expected::NotOwned,
            (Some(o), None) => {
                let r = &o.received;
                assert_eq!(r.output_key_offset, d.x, "output {i}: offset");
                assert_eq!(o.global_index, 1000 + i as u64);
                assert_eq!(o.key, keys[i]);
                // What the wallet derives spendability from (RT-STATEFUL: unchecked
                // before): the coinbase maturity applies to coinbase outputs only.
                assert_eq!(
                    o.coinbase,
                    matches!(tx, Transaction::Coinbase(_)),
                    "output {i}: coinbase flag"
                );
                assert_eq!(
                    (o.height, o.tx_hash, o.index_in_tx),
                    (5, tx.hash(), i),
                    "output {i}: position"
                );
                let p = w.keys.one_time_secret(r.subaddress, &r.output_key_offset);
                assert_eq!(
                    RistrettoPoint::mul_base(&p),
                    *f.one_time_key.point(),
                    "output {i}: the one-time secret does not open the key"
                );
                match f.amount {
                    OutputAmount::Hidden { commitment, .. } => {
                        assert_eq!((r.amount, r.mask), (d.amount, d.mask), "output {i}");
                        assert_eq!(
                            commit(r.amount, &r.mask),
                            *commitment.point(),
                            "output {i}: the amount does not open the commitment"
                        );
                    }
                    OutputAmount::Clear(a) => {
                        assert_eq!((r.amount, r.mask), (a, Scalar::ONE), "output {i}");
                        assert_eq!(coinbase_commitment(a), *keys[i].commitment.point());
                    }
                }
                Expected::Owned(r.subaddress)
            }
            // `ScanReport` drops the refused output's subaddress (local
            // diagnostics only); the reason is compared.
            (None, Some((_, reason))) => match expected {
                Expected::Refused(sub, _) => Expected::Refused(sub, *reason),
                _ => Expected::Refused(SubaddressIndex::PRIMARY, *reason),
            },
            (Some(_), Some(_)) => panic!("output {i} both owned and refused"),
        };
        assert_eq!(got, expected, "output {i}");
        let k = match got {
            Expected::NotOwned => 0,
            Expected::Owned(_) => 1,
            Expected::Refused(_, ScanRejection::JanusAnchorMismatch) => 2,
            Expected::Refused(_, ScanRejection::CommitmentMismatch) => 3,
        };
        REACHED[k].fetch_add(1, Ordering::Relaxed);
    }
    assert!(
        owned.next().is_none() && refused.next().is_none(),
        "reports out of order"
    );

    // The same through `scan_block`, over two copies of the transaction.
    let two = [tx.clone(), tx.clone()];
    let block = scan_block(view, &w.table, &two, 5, 1000);
    assert_eq!(block.owned.len(), 2 * report.owned.len());
    assert_eq!(block.rejected.len(), 2 * report.rejected.len());
    let k = report.owned.len();
    for (j, o) in report.owned.iter().enumerate() {
        assert_eq!(block.owned[j].global_index, o.global_index);
        assert_eq!(block.owned[k + j].global_index, o.global_index + n as u64);
    }
}

// ------------------------------------------------------------- the edits

/// The transaction's hidden and clear output lists (a PX transaction has
/// both: change outputs, then payouts).
fn lists(tx: &mut Transaction) -> (Option<&mut Vec<Output>>, Option<&mut Vec<CoinbaseOutput>>) {
    match tx {
        Transaction::Coinbase(c) => (None, Some(&mut c.outputs)),
        Transaction::Transfer(t) => (Some(&mut t.outputs), None),
        Transaction::Px(t) => (Some(&mut t.outputs), Some(&mut t.payouts)),
        Transaction::PxDeploy(t) => (Some(&mut t.outputs), None),
    }
}

fn donors(txs: &[Transaction]) -> (Vec<Output>, Vec<CoinbaseOutput>) {
    let (mut hidden, mut clear) = (Vec::new(), Vec::new());
    for tx in txs {
        let mut tx = tx.clone();
        let (h, c) = lists(&mut tx);
        hidden.extend(h.map(|v| v.clone()).unwrap_or_default());
        clear.extend(c.map(|v| v.clone()).unwrap_or_default());
    }
    (hidden, clear)
}

fn shifted(p: &Point) -> Point {
    Point::from_point(p.point() + RistrettoPoint::mul_base(&Scalar::ONE))
}

/// One edit of an output (`a`: which; the clear list when `c` is odd and
/// the transaction has both), or of the input context.
fn edit(tx: &mut Transaction, base: &Base, op: u8, a: usize, b: usize, c: u8) {
    let (hidden_donors, clear_donors) = (&base.hidden, &base.clear);
    if op % 10 == 9 {
        // The input context: a key image (transfers, deploys, PX) or the
        // coinbase height.
        match tx {
            Transaction::Coinbase(cb) => cb.height = cb.height.wrapping_add(1 + b as u64),
            Transaction::Transfer(t) => {
                if let Some(i) = t.inputs.first_mut() {
                    i.key_image = hidden_donors[b % hidden_donors.len()].one_time_key;
                }
            }
            Transaction::Px(t) => {
                if let Some(i) = t.inputs.first_mut() {
                    i.key_image = hidden_donors[b % hidden_donors.len()].one_time_key;
                } else {
                    t.nullifiers[0][a % 8] ^= 1 + c as u32;
                }
            }
            Transaction::PxDeploy(t) => {
                if let Some(i) = t.inputs.first_mut() {
                    i.key_image = hidden_donors[b % hidden_donors.len()].one_time_key;
                }
            }
        }
        return;
    }
    let (hidden, clear) = lists(tx);
    let use_clear = match (&hidden, &clear) {
        (Some(_), Some(_)) => c & 1 == 1,
        (None, _) => true,
        _ => false,
    };
    if use_clear {
        let Some(v) = clear else { return };
        let donor = &clear_donors[b % clear_donors.len()];
        edit_list(v, op, a, b, c, donor, |o, op, b, c| match op {
            1 => o.view_tag ^= 1 << (b % 8),
            2 => {
                o.one_time_key = match c % 3 {
                    0 => shifted(&o.one_time_key),
                    1 => o.ephemeral,
                    _ => clear_donors[b % clear_donors.len()].one_time_key,
                }
            }
            3 => o.ephemeral = clear_donors[b % clear_donors.len()].ephemeral,
            4 => o.amount ^= 1 << (b % 64),
            5 => o.amount = [0, 1, u64::MAX, 1 << 63][b % 4],
            _ => o.enc_anchor[b % 16] ^= 1 << (c % 8),
        });
    } else {
        let Some(v) = hidden else { return };
        let donor = &hidden_donors[b % hidden_donors.len()];
        edit_list(v, op, a, b, c, donor, |o, op, b, c| match op {
            1 => o.view_tag ^= 1 << (b % 8),
            2 => {
                o.one_time_key = match c % 3 {
                    0 => shifted(&o.one_time_key),
                    1 => o.commitment,
                    _ => hidden_donors[b % hidden_donors.len()].one_time_key,
                }
            }
            3 => o.ephemeral = hidden_donors[b % hidden_donors.len()].ephemeral,
            4 => o.enc_amount[b % 8] ^= 1 << (c % 8),
            5 => {
                o.commitment = match c % 2 {
                    0 => shifted(&o.commitment),
                    _ => hidden_donors[b % hidden_donors.len()].commitment,
                }
            }
            _ => o.enc_anchor[b % 16] ^= 1 << (c % 8),
        });
    }
}

/// `op` 0: splice in `donor` at `a`; 1 to 6: `field` edits of output `a`;
/// 7: duplicate it; 8: drop or swap outputs.
fn edit_list<T: Clone>(
    v: &mut Vec<T>,
    op: u8,
    a: usize,
    b: usize,
    c: u8,
    donor: &T,
    field: impl Fn(&mut T, u8, usize, u8),
) {
    let n = v.len();
    match op % 10 {
        0 => {
            if n == 0 || c & 2 != 0 {
                v.push(donor.clone());
            } else {
                v[a % n] = donor.clone();
            }
        }
        7 if n > 0 => {
            let x = v[a % n].clone();
            v.insert(b % (n + 1), x);
        }
        8 if n > 0 => {
            if c & 1 == 0 {
                v.remove(a % n);
            } else {
                v.swap(a % n, b % n);
            }
        }
        op @ 1..=6 if n > 0 => field(&mut v[a % n], op, b, c),
        _ => {}
    }
}

/// Seed inputs (named): each base transaction unedited (both modes), and
/// one per kind of edit.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let base = base();
    let mut out: Vec<(&'static str, Vec<u8>)> = vec![
        ("funding", [&[0u8][..], &base.txs[0].encode()].concat()),
        ("mixed", [&[0u8][..], &base.txs[1].encode()].concat()),
        ("transfer", [&[0u8][..], &base.txs[2].encode()].concat()),
    ];
    out.extend([
        ("edit_none_funding", vec![1, 0]),
        ("edit_none_transfer", vec![1, 2]),
        ("splice_owned_into_transfer", vec![1, 2, 0, 0, 0, 0]),
        ("splice_owned_into_coinbase", vec![1, 1, 0, 1, 5, 0]),
        ("view_tag", vec![1, 2, 1, 0, 3, 0]),
        ("key_shifted", vec![1, 2, 2, 0, 0, 0]),
        ("key_other", vec![1, 0, 2, 3, 5, 2]),
        ("ephemeral", vec![1, 2, 3, 0, 4, 0]),
        ("amount", vec![1, 2, 4, 0, 1, 2]),
        ("commitment", vec![1, 2, 5, 1, 0, 0]),
        ("clear_amount", vec![1, 1, 4, 0, 7, 0]),
        ("anchor", vec![1, 2, 6, 2, 3, 1]),
        ("duplicate", vec![1, 0, 7, 3, 0, 0]),
        ("drop_swap", vec![1, 2, 8, 0, 1, 1, 8, 0, 0, 0]),
        ("context", vec![1, 2, 9, 0, 0, 0]),
        ("coinbase_height", vec![1, 1, 9, 0, 0, 0]),
    ]);
    out
}

/// What the outputs scanned were (the stable twin prints it): not owned,
/// owned, refused for the anchor, refused for the commitment.
pub static REACHED: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

pub fn reached() -> String {
    let [n, o, a, c] = REACHED.each_ref().map(|c| c.load(Ordering::Relaxed));
    format!("outputs scanned: not owned {n}, owned {o}, refused for the anchor {a}, for the commitment {c}")
}
