//! Pinned v1 derivation vectors for keys, subaddresses, input contexts, outputs,
//! view tags and Janus anchors (spec §2, §3, §12; dossier 17, item 1 / F17-1).
//!
//! Every value is **independently derived**: the test recomputes it from the
//! formulas in `docs/transactions.md` §2.1, §2.2, §3.1–3.4 and §12.3 (and
//! `docs/px.md` §11 for the PX context) with raw Blake2b and dalek
//! (`common::spec`), checks that the implementation produces the same value,
//! and checks it against its pin in `tests/vectors/stealth.txt`. A refactor that
//! reorders a hash input, swaps `h32` and `h64`, or changes a tag then fails
//! here even though every round-trip test still passes.
//!
//! These are the v1 (seed version 1) derivations. They are wallet
//! interoperability constants, not consensus rules: a change strands existing
//! wallets' funds and addresses.

mod common;

use blacksilk_crypto::clsag;
use blacksilk_crypto::janus::{self, Anchor};
use blacksilk_crypto::keys::{Address, SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_crypto::stealth::{
    self, create_output, scan_output, CreatedOutput, OutputAmount, OutputFields, OutputKind,
    ScanOutcome,
};
use blacksilk_crypto::Point;
use common::spec::{self, cat, enc};
use common::{wide, Pins};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

const FILE: &str = "tests/vectors/stealth.txt";
const VECTORS: &str = include_str!("vectors/stealth.txt");

/// Seed A: bytes 1, 2, …, 32. Seed B: 32 × 0xa5.
fn seed_a() -> [u8; 32] {
    std::array::from_fn(|i| i as u8 + 1)
}
const SEED_B: [u8; 32] = [0xa5; 32];

const INDICES: [(u32, u32); 4] = [(0, 0), (0, 1), (1, 0), (7, 3)];

/// Independently derived wallet keys (spec §2.1, §2.2).
struct Keys {
    k_s: Scalar,
    k_v: Scalar,
}

impl Keys {
    fn new(seed: &[u8; 32]) -> Self {
        Self {
            k_s: spec::hs("wallet/spend-key", seed),
            k_v: spec::hs("wallet/view-key", seed),
        }
    }

    fn spend_public(&self) -> RistrettoPoint {
        self.k_s * spec::g()
    }

    /// `m(a,i)`.
    fn m(&self, a: u32, i: u32) -> Scalar {
        if (a, i) == (0, 0) {
            return Scalar::ZERO;
        }
        spec::hs(
            "subaddress",
            &cat(&[self.k_v.as_bytes(), &a.to_le_bytes(), &i.to_le_bytes()]),
        )
    }

    /// `(D, C)` of `(a, i)`.
    fn address(&self, a: u32, i: u32) -> (RistrettoPoint, RistrettoPoint) {
        let d = self.spend_public() + self.m(a, i) * spec::g();
        (d, self.k_v * d)
    }
}

fn check_keys(pins: &mut Pins, label: &str, seed: &[u8; 32], indices: &[(u32, u32)]) {
    let k = Keys::new(seed);
    let wallet = WalletKeys::from_seed(seed);
    let view = wallet.view_keys();
    assert_eq!(view.view_secret(), &k.k_v, "{label}: k_v");
    assert_eq!(
        view.spend_public().point(),
        &k.spend_public(),
        "{label}: K_s"
    );
    assert_eq!(
        wallet.subaddress_spend_secret(SubaddressIndex::PRIMARY),
        k.k_s,
        "{label}: k_s"
    );
    pins.check(&format!("{label}.seed"), seed);
    pins.check(&format!("{label}.k_s"), k.k_s.to_bytes());
    pins.check(&format!("{label}.k_v"), k.k_v.to_bytes());
    pins.check(&format!("{label}.K_s"), enc(&k.spend_public()));
    for &(a, i) in indices {
        let idx = SubaddressIndex::new(a, i);
        let (d, c) = k.address(a, i);
        let m = k.m(a, i);
        assert_eq!(view.subaddress_offset(idx), m, "{label} ({a},{i}): m");
        let address = wallet.address(idx);
        assert_eq!(address.spend().point(), &d, "{label} ({a},{i}): D");
        assert_eq!(address.view().point(), &c, "{label} ({a},{i}): C");
        assert_eq!(address.to_bytes()[..32], enc(&d));
        assert_eq!(address.to_bytes()[32..], enc(&c));
        assert_eq!(
            wallet.subaddress_spend_secret(idx),
            k.k_s + m,
            "{label} ({a},{i}): d"
        );
        let n = format!("{label}.sub.{a}_{i}");
        pins.check(&format!("{n}.m"), m.to_bytes());
        pins.check(&format!("{n}.D"), enc(&d));
        pins.check(&format!("{n}.C"), enc(&c));
        pins.check(&format!("{n}.d"), (k.k_s + m).to_bytes());
    }
}

#[test]
fn keys_and_subaddresses() {
    let mut pins = Pins::new(FILE, VECTORS, "keys.");
    check_keys(&mut pins, "a", &seed_a(), &INDICES);
    check_keys(&mut pins, "b", &SEED_B, &INDICES[..2]);
    pins.finish();
}

/// Two key images used as transfer inputs: `I = p·Hp("key-image", p·G)`.
fn input_key_images() -> [RistrettoPoint; 2] {
    [0x90u8, 0x91].map(|b| {
        let p = wide(b);
        p * spec::hp("key-image", &enc(&(p * spec::g())))
    })
}

fn nullifiers() -> [[u8; 32]; 2] {
    [[0x01; 32], [0x02; 32]]
}

fn transfer_ctx() -> [u8; 32] {
    let ki = input_key_images();
    spec::h32("input-context", &cat(&[&enc(&ki[0]), &enc(&ki[1])]))
}

fn coinbase_ctx(height: u64) -> [u8; 32] {
    spec::h32("input-context/coinbase", &height.to_le_bytes())
}

/// `H32("input-context/px", nullifiers ‖ key images)` (docs/px.md §11).
fn px_ctx(with_key_image: bool) -> [u8; 32] {
    let n = nullifiers();
    let ki = enc(&input_key_images()[0]);
    let mut parts: Vec<&[u8]> = vec![&n[0], &n[1]];
    if with_key_image {
        parts.push(&ki);
    }
    spec::h32("input-context/px", &cat(&parts))
}

#[test]
fn input_contexts() {
    let ki = input_key_images();
    let ki_points = ki.map(Point::from_point);
    // The key images are the implementation's too.
    for (b, image) in [0x90u8, 0x91].iter().zip(&ki_points) {
        let p = wide(*b);
        let key = Point::from_point(p * spec::g());
        assert_eq!(&clsag::key_image(&p, &key), image);
    }
    let mut pins = Pins::new(FILE, VECTORS, "ctx.");
    pins.check("key_images", cat(&[&enc(&ki[0]), &enc(&ki[1])]));

    assert_eq!(stealth::transfer_context(&ki_points), transfer_ctx());
    pins.check("transfer.two_inputs", transfer_ctx());
    let one = spec::h32("input-context", &enc(&ki[0]));
    assert_eq!(stealth::transfer_context(&ki_points[..1]), one);
    pins.check("transfer.one_input", one);

    for height in [0u64, 1, 1_000_000, u64::MAX] {
        assert_eq!(stealth::coinbase_context(height), coinbase_ctx(height));
        pins.check(&format!("coinbase.{height}"), coinbase_ctx(height));
    }

    let n = nullifiers();
    assert_eq!(stealth::px_context(&n, &ki_points[..1]), px_ctx(true));
    pins.check("px.nullifiers_and_key_image", px_ctx(true));
    assert_eq!(stealth::px_context(&n, &[]), px_ctx(false));
    pins.check("px.nullifiers_only", px_ctx(false));
    pins.finish();
}

/// One output vector: recipient, amount, context, anchor, kind.
struct OutputDef {
    name: &'static str,
    seed: [u8; 32],
    index: (u32, u32),
    amount: u64,
    ctx: [u8; 32],
    anchor: [u8; 16],
    kind: OutputKind,
}

fn output_defs() -> Vec<OutputDef> {
    vec![
        OutputDef {
            name: "transfer_primary",
            seed: seed_a(),
            index: (0, 0),
            amount: 1_000_000,
            ctx: transfer_ctx(),
            anchor: [0x3c; 16],
            kind: OutputKind::Transfer,
        },
        OutputDef {
            name: "transfer_subaddress_7_3",
            seed: seed_a(),
            index: (7, 3),
            amount: 0,
            ctx: transfer_ctx(),
            anchor: [0xc3; 16],
            kind: OutputKind::Transfer,
        },
        OutputDef {
            name: "coinbase_subaddress_1_0",
            seed: seed_a(),
            index: (1, 0),
            amount: 17_592_186_044_416,
            ctx: coinbase_ctx(12_345),
            anchor: [0x5a; 16],
            kind: OutputKind::Coinbase,
        },
        OutputDef {
            name: "px_primary_b",
            seed: SEED_B,
            index: (0, 0),
            amount: u64::MAX,
            ctx: px_ctx(true),
            anchor: std::array::from_fn(|i| i as u8),
            kind: OutputKind::Transfer,
        },
    ]
}

/// The spec §3.2 / §12.3 sender computation.
struct Derived {
    r: Scalar,
    ephemeral: RistrettoPoint,
    shared: [u8; 32],
    x: Scalar,
    one_time_key: RistrettoPoint,
    view_tag: u8,
    mask: Scalar,
    commitment: RistrettoPoint,
    enc_amount: [u8; 8],
    enc_anchor: [u8; 16],
}

fn derive(def: &OutputDef) -> Derived {
    let (d, c) = Keys::new(&def.seed).address(def.index.0, def.index.1);
    let r = spec::hs(
        "ephemeral",
        &cat(&[&def.anchor, &def.ctx, &enc(&d), &enc(&c)]),
    );
    let ephemeral = r * d;
    let shared = enc(&(r * c));
    let x = spec::hs("output-key", &shared);
    let one_time_key = x * spec::g() + d;
    let view_tag = spec::h32("view-tag", &shared)[0];
    let mask = match def.kind {
        OutputKind::Transfer => spec::hs("mask", &shared),
        OutputKind::Coinbase => Scalar::ONE,
    };
    let commitment = spec::com(def.amount, &mask);
    let amount_pad = spec::h64("amount", &shared);
    let enc_amount: [u8; 8] = std::array::from_fn(|i| def.amount.to_le_bytes()[i] ^ amount_pad[i]);
    let anchor_pad = spec::h64("anchor", &shared);
    let enc_anchor: [u8; 16] = std::array::from_fn(|i| def.anchor[i] ^ anchor_pad[i]);
    Derived {
        r,
        ephemeral,
        shared,
        x,
        one_time_key,
        view_tag,
        mask,
        commitment,
        enc_amount,
        enc_anchor,
    }
}

fn fields<'a>(out: &'a CreatedOutput, kind: OutputKind) -> OutputFields<'a> {
    OutputFields {
        one_time_key: &out.one_time_key,
        ephemeral: &out.ephemeral,
        view_tag: out.view_tag,
        amount: match kind {
            OutputKind::Transfer => OutputAmount::Hidden {
                commitment: &out.commitment,
                enc_amount: &out.enc_amount,
            },
            OutputKind::Coinbase => OutputAmount::Clear(out.amount),
        },
        enc_anchor: &out.enc_anchor,
    }
}

/// Outputs, view tags and anchors: `create_output` matches the spec derivation
/// field by field; the recipient's scan recovers the amount, mask and `x`; the
/// one-time secret and key image match §3.4.
#[test]
fn outputs_view_tags_and_anchors() {
    for def in output_defs() {
        let n = def.name;
        let keys = Keys::new(&def.seed);
        let wallet = WalletKeys::from_seed(&def.seed);
        let idx = SubaddressIndex::new(def.index.0, def.index.1);
        let address: Address = wallet.address(idx);
        let anchor = Anchor(def.anchor);
        let v = derive(&def);

        // Sender (spec §3.2).
        assert_eq!(
            janus::ephemeral_secret(&anchor, &def.ctx, &address),
            v.r,
            "{n}: r"
        );
        let out = create_output(&address, def.amount, &def.ctx, &anchor, def.kind).expect("r ≠ 0");
        assert_eq!(out.ephemeral.point(), &v.ephemeral, "{n}: R");
        assert_eq!(out.one_time_key.point(), &v.one_time_key, "{n}: O");
        assert_eq!(out.view_tag, v.view_tag, "{n}: view tag");
        assert_eq!(out.commitment.point(), &v.commitment, "{n}: Cm");
        assert_eq!(out.mask, v.mask, "{n}: mask");
        assert_eq!(out.amount, def.amount);
        assert_eq!(out.enc_anchor, v.enc_anchor, "{n}: enc_anchor");
        if def.kind == OutputKind::Transfer {
            assert_eq!(out.enc_amount, v.enc_amount, "{n}: enc_amount");
        }
        // S = r·C = k_v·R.
        assert_eq!(enc(&(keys.k_v * v.ephemeral)), v.shared, "{n}: S");

        // Janus check (spec §12.3).
        assert!(
            janus::verify(&anchor, &def.ctx, &address, &out.ephemeral),
            "{n}"
        );
        let mut other_ctx = def.ctx;
        other_ctx[0] ^= 1;
        assert!(
            !janus::verify(&anchor, &other_ctx, &address, &out.ephemeral),
            "{n}"
        );

        // Receiver (spec §3.3) and spending (§3.4).
        let table = SubaddressTable::new(wallet.view_keys(), 8, 4);
        let outcome = scan_output(
            wallet.view_keys(),
            &table,
            &def.ctx,
            &fields(&out, def.kind),
        );
        let received = outcome
            .owned()
            .unwrap_or_else(|| panic!("{n}: not received"));
        assert_eq!(received.subaddress, idx, "{n}");
        assert_eq!(received.amount, def.amount, "{n}");
        assert_eq!(received.mask, v.mask, "{n}");
        assert_eq!(received.output_key_offset, v.x, "{n}: x");
        let p = v.x + keys.k_s + keys.m(def.index.0, def.index.1);
        assert_eq!(
            wallet.one_time_secret(idx, &received.output_key_offset),
            p,
            "{n}: p"
        );
        assert_eq!(p * spec::g(), v.one_time_key, "{n}: p·G = O");
        let key_image = p * spec::hp("key-image", &enc(&v.one_time_key));
        assert_eq!(
            clsag::key_image(&p, &out.one_time_key).point(),
            &key_image,
            "{n}: I"
        );
        // The same output in another transaction context is a Janus probe.
        let copied = scan_output(
            wallet.view_keys(),
            &table,
            &other_ctx,
            &fields(&out, def.kind),
        );
        assert!(matches!(copied, ScanOutcome::Rejected { .. }), "{n}: copy");

        let mut pins = Pins::new(FILE, VECTORS, &format!("out.{n}."));
        pins.check_str("recipient", &format!("{}/{}", def.index.0, def.index.1));
        pins.check_str("amount", &def.amount.to_string());
        pins.check("ctx", def.ctx);
        pins.check("anchor", def.anchor);
        pins.check("r", v.r.to_bytes());
        pins.check("R", enc(&v.ephemeral));
        pins.check("S", v.shared);
        pins.check("x", v.x.to_bytes());
        pins.check("O", enc(&v.one_time_key));
        pins.check("view_tag", [v.view_tag]);
        pins.check("mask", v.mask.to_bytes());
        pins.check("Cm", enc(&v.commitment));
        if def.kind == OutputKind::Transfer {
            pins.check("enc_amount", v.enc_amount);
        }
        pins.check("enc_anchor", v.enc_anchor);
        pins.check("p", p.to_bytes());
        pins.check("I", enc(&key_image));
        pins.finish();
    }
}

/// A wallet with another seed does not receive the pinned outputs.
#[test]
fn other_wallet_does_not_receive() {
    let stranger = WalletKeys::from_seed(&[0x77; 32]);
    let table = SubaddressTable::new(stranger.view_keys(), 8, 4);
    for def in output_defs() {
        let wallet = WalletKeys::from_seed(&def.seed);
        let address = wallet.address(SubaddressIndex::new(def.index.0, def.index.1));
        let out = create_output(
            &address,
            def.amount,
            &def.ctx,
            &Anchor(def.anchor),
            def.kind,
        )
        .expect("r ≠ 0");
        let outcome = scan_output(
            stranger.view_keys(),
            &table,
            &def.ctx,
            &fields(&out, def.kind),
        );
        assert!(matches!(outcome, ScanOutcome::NotOwned), "{}", def.name);
    }
}
