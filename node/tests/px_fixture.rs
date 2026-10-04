//! The golden PX fixture (`src/px_fixture.bin`, `src/px_fixture.txt`;
//! `blacksilk_node::fingerprint::PxFixture`): a proven PX transaction that
//! bridges value in from the fingerprint fixture's first coinbase output
//! (with the fixture transfer's first ring), anchored at the empty PX tree,
//! and a deploy of the reference vault spending the second coinbase output.
//! Both are signed under `fixture_rules()` and valid at the fingerprint
//! fixture's height (docs/reviews/v3-consensus-changes.md#px-ciphertext-r,
//! decisions "RES-FREEZE verified", item 2).
//!
//! The fixture is pinned data: the rules fingerprint lists its ids, binding,
//! signature messages and verdicts (`fingerprint::px_transaction_samples`).
//! It is regenerated only when a reviewed rule change invalidates it, in a
//! PX-proving window (the generator proves one PX transaction, about 40 s
//! and several GB):
//!
//! ```text
//! cargo test --release -p blacksilk-node --test px_fixture -- --ignored regenerate
//! ```
//!
//! which rewrites both files from fixed seeds. Since the `p3-batch-stark`
//! patch (third_party/README.md, PXDET-1) the PX transaction is reproducible
//! too: two regenerations at different thread counts gave identical bytes.
//! The checked-in fixture was made before that patch, so a regeneration
//! gives a different, equally valid transaction. Never regenerate in CI. A regenerated
//! fixture changes the rules fingerprint and needs the re-pin procedure
//! (docs/reviews/v3-consensus-changes.md#fingerprint-v3).
//!
//! The other tests verify the checked-in proof (no proving): the full
//! verdicts (PX5 included) on the transaction and on its ciphertext `R`
//! variants.

use blacksilk_crypto::keys::{SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_node::fingerprint::{
    fixture_rules, px_fixture_anchor, px_fixture_verdict, Fixture, PxFixture,
};
use blacksilk_px::vault;
use blacksilk_px::wallet::{self as pxw, Account};
use blacksilk_tx::builder::{build_coinbase, Decoy, InputPlan, Payment};
use blacksilk_tx::params::RING_SIZE;
use blacksilk_tx::px::{Registration, Window};
use blacksilk_tx::px_builder::{build_deploy, build_px, px_standard_fee, PxPlan};
use blacksilk_tx::scan::{scan_block, OwnedOutput};
use blacksilk_tx::types::OutputKey;
use blacksilk_tx::{Transaction, TxError};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// The fingerprint fixture's seed (tests/fingerprint_fixture.rs): the
/// wallet, the payee and the two coinbases are rebuilt from it, in the same
/// order, so the PX transaction and the deploy spend the fixture's outputs.
const FIXTURE_SEED: u64 = 0x0B5F_1A6E;
/// The seed of everything the golden PX fixture adds.
const PX_SEED: u64 = 0x0B5F_9C71;
/// Value bridged into PX (from the 5 000 000 000 coinbase output).
const BRIDGED: u64 = 1_000_000_000;
fn point(n: u64) -> Point {
    Point::from_point(RistrettoPoint::mul_base(&Scalar::from(n)))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The fixture wallet and its two coinbase outputs, rebuilt exactly as
/// tests/fingerprint_fixture.rs builds them.
fn fixture_wallet() -> (WalletKeys, Vec<OwnedOutput>) {
    let mut rng = ChaCha20Rng::seed_from_u64(FIXTURE_SEED);
    let (keys, _) = WalletKeys::generate(&mut rng);
    let (_payee, _) = WalletKeys::generate(&mut rng);
    let table = SubaddressTable::new(keys.view_keys(), 1, 1);
    let me = keys.address(SubaddressIndex::new(0, 0));
    let mut owned = Vec::new();
    for (height, amount) in [(1u64, 5_000_000_000u64), (2, 7_000_000_000)] {
        let cb = build_coinbase(
            height,
            &[Payment {
                address: me,
                amount,
            }],
            &keys.hedge_secret(),
            &mut rng,
        )
        .expect("a coinbase");
        let txs = [Transaction::Coinbase(cb)];
        let report = scan_block(keys.view_keys(), &table, &txs, height, height - 1);
        assert_eq!(report.owned.len(), 1);
        owned.push(report.owned[0].clone());
    }
    // The rebuilt outputs are the fingerprint fixture's.
    let f = Fixture::get();
    for o in &owned {
        let rec = f.outputs.get(&o.global_index).expect("a fixture output");
        assert_eq!(rec.key, o.key, "output {}", o.global_index);
    }
    (keys, owned)
}

/// The input plan of coinbase output `k` with the fixture transfer's ring.
fn plan(owned: &[OwnedOutput], k: usize) -> InputPlan {
    let per_input = RING_SIZE as u64 - 1;
    InputPlan {
        real: (&owned[k]).into(),
        decoys: (0..per_input)
            .map(|j| {
                let i = 2 + k as u64 * per_input + j;
                Decoy {
                    global_index: i,
                    key: OutputKey {
                        one_time_key: point(1_000 + i),
                        commitment: point(2_000 + i),
                    },
                }
            })
            .collect(),
    }
}

/// Builds the fixture: the PX transaction (proven) and the deploy.
fn generate() -> (Vec<u8>, String) {
    let (keys, owned) = fixture_wallet();
    let me = keys.address(SubaddressIndex::new(0, 0));
    let rules = fixture_rules();
    let mut rng = ChaCha20Rng::seed_from_u64(PX_SEED);
    let to = Account::from_seed(&[0x21; 32]);

    // The PX transaction: one v1 input bridging BRIDGED into a record of
    // `to` (slot 0), an empty slot 1, change back to the wallet.
    let witness = pxw::witness(
        px_fixture_anchor(),
        BRIDGED,
        0,
        [pxw::dummy_input(&mut rng), pxw::dummy_input(&mut rng)],
        [
            pxw::output(&mut rng, to.owner(0), BRIDGED),
            pxw::empty_output(&mut rng),
        ],
    );
    let px = build_px(
        PxPlan {
            keys: Some(&keys),
            inputs: vec![plan(&owned, 0)],
            change: Some(me),
            payouts: vec![],
            witness,
            recipients: [Some(to.address(0)), None],
            functions: vec![],
            fee: px_standard_fee(),
            window: Window::UNBOUNDED,
            hedge_secret: [0x5e; 32],
        },
        &rules,
        &mut rng,
    )
    .expect("the golden PX transaction builds");

    // The deploy: the reference vault, paid from the second coinbase output.
    let deploy = build_deploy(
        &keys,
        vec![plan(&owned, 1)],
        &[Payment {
            address: me,
            amount: 1,
        }],
        &me,
        [0x33; 32],
        vec![Registration::new(
            vault::VAULT_ELF.to_vec(),
            vault::BUDGET,
            vault::OUT_WORDS,
        )],
        &rules,
        &mut rng,
    )
    .expect("the golden deploy builds");

    let bin = Transaction::Px(Box::new(px)).encode();
    let mut text = String::from(
        "# The golden PX fixture's deploy (node/src/fingerprint.rs, PxFixture); the PX\n\
         # transaction is px_fixture.bin. Generated by node/tests/px_fixture.rs; pinned\n\
         # data, do not edit.\n",
    );
    text.push_str(&format!(
        "deploy {}\n",
        hex(&Transaction::PxDeploy(Box::new(deploy)).encode())
    ));
    (bin, text)
}

/// Rewrites `src/px_fixture.bin` and `src/px_fixture.txt` (a reviewed rule
/// change only; proves one PX transaction).
#[test]
#[ignore = "proves a PX transaction: run only in a PX-proving window"]
fn regenerate_the_golden_px_fixture() {
    let (bin, text) = generate();
    let parsed = PxFixture::parse(&bin, &text).expect("the generated fixture parses");
    assert_eq!(px_fixture_verdict(&parsed.px, true), Ok(()));
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/");
    std::fs::write(format!("{dir}px_fixture.bin"), &bin).expect("write px_fixture.bin");
    std::fs::write(format!("{dir}px_fixture.txt"), text).expect("write px_fixture.txt");
}

/// The checked-in fixture has the documented shape: one v1 input with the
/// fixture transfer's first ring, the anchor of the empty tree, the
/// standard fee and the bridged value; the deploy registers the vault.
#[test]
fn the_golden_px_fixture_has_its_shape() {
    let p = PxFixture::get();
    let f = Fixture::get();
    assert_eq!(p.px.inputs.len(), 1);
    assert_eq!(p.px.inputs[0].ring, f.transfer.inputs[0].ring);
    assert_eq!(p.px.anchor, px_fixture_anchor());
    assert_eq!(
        (p.px.fee, p.px.bridge_in, p.px.bridge_out),
        (px_standard_fee(), BRIDGED, 0)
    );
    assert!(p.px.functions.is_empty());
    assert_eq!(p.deploy.programs.len(), 1);
    assert_eq!(p.deploy.programs[0].elf, vault::VAULT_ELF);
    for input in p.deploy.inputs.iter().chain(&p.px.inputs) {
        for i in input.ring {
            assert!(f.outputs.contains_key(&i), "ring member {i}");
        }
    }
}

/// The golden PX transaction is valid in full (PX5 included: the checked-in
/// proof verifies) at the fixture's height.
#[test]
fn the_golden_px_transaction_is_valid_in_full() {
    let p = PxFixture::get();
    assert_eq!(px_fixture_verdict(&p.px, true), Ok(()));
}

/// The ciphertext `R` rule on the proven transaction: with `R` replaced by
/// the identity, a non-canonical encoding, or the top bit set, full
/// validation refuses it with the `R` error, before the proof (whose binding
/// no longer matches) is looked at; and without PX5 too, so the rule, not
/// the proof, refuses it.
#[test]
fn the_ciphertext_r_rule_refuses_the_golden_variants() {
    let p = PxFixture::get();
    let mut p_bytes = [0xff; 32];
    p_bytes[0] = 0xed;
    p_bytes[31] = 0x7f;
    let cases: [(&str, usize, [u8; 32], TxError); 3] = [
        (
            "identity",
            0,
            [0; 32],
            TxError::PxCiphertextRIdentity { ciphertext: 0 },
        ),
        (
            "p",
            1,
            p_bytes,
            TxError::PxCiphertextRNonCanonical { ciphertext: 1 },
        ),
        (
            "top bit",
            0,
            {
                let mut r: [u8; 32] = p.px.ciphertexts[0][..32].try_into().unwrap();
                r[31] |= 0x80;
                r
            },
            TxError::PxCiphertextRNonCanonical { ciphertext: 0 },
        ),
    ];
    for (name, index, r, expected) in cases {
        let mut v = p.px.clone();
        v.ciphertexts[index][..32].copy_from_slice(&r);
        assert_eq!(px_fixture_verdict(&v, true), Err(expected), "{name}");
        assert_eq!(px_fixture_verdict(&v, false), Err(expected), "{name}");
        assert!(expected.is_stateless());
    }
}

/// Any other change of a ciphertext byte keeps the `R` rule satisfied but
/// is bound: the CLSAG signs the prefix (and `h_tx`, the proof's binding,
/// covers it), so the signature check, which precedes PX5, refuses it.
#[test]
fn a_changed_ciphertext_byte_is_bound() {
    let p = PxFixture::get();
    let mut v = p.px.clone();
    v.ciphertexts[1][100] ^= 1;
    for with_proof in [false, true] {
        assert!(
            matches!(
                px_fixture_verdict(&v, with_proof),
                Err(TxError::InvalidSignature { .. })
            ),
            "{with_proof}"
        );
    }
}

/// The deploy decodes, re-encodes and keeps its fixed fields.
#[test]
fn the_golden_deploy_round_trips() {
    let d = &PxFixture::get().deploy;
    let bytes = Transaction::PxDeploy(Box::new(d.clone())).encode();
    let Ok(Transaction::PxDeploy(back)) = Transaction::decode(&bytes) else {
        panic!("the deploy decodes");
    };
    assert_eq!(*back, *d);
    assert_eq!(d.salt, [0x33; 32]);
}
