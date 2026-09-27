//! Known-answer vectors for seed format v1 and every key a wallet derives
//! from it (docs/blocks.md §10, transactions.md §2.1 and §10, docs/px.md
//! §3.1 and §13.4; dossier 37 K1, K2, K3, K6).
//!
//! **Provenance.** `tests/data/seed_v1_vectors.txt` is produced by
//! `tools/vectors/seed_v1.py`, an independent Python implementation written
//! from the specification (standard library only, test tooling, not core):
//! its own bit packing, GF(2^11) arithmetic and check-symbol solver, BLAKE2b
//! from hashlib, scalars reduced with Python integers, and PX `Hk` from the
//! independent Poseidon2 of `tools/vectors/poseidon2_hk.py`. The word list is
//! checked there against the SHA-256 published with BIP-39.
//!
//! A consistent refactor of the Rust code that changed any of these values
//! would change every restored wallet; this test makes it fail instead.
//! Regenerate only for a deliberate wallet-format change:
//! `python tools/vectors/seed_v1.py --write`; `--check` verifies the file.

use blacksilk_consensus::Network;
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_px::perm::HostPerm;
use blacksilk_px::wallet::{Account, Derivation};
use blacksilk_px_core::record::Keys;
use blacksilk_px_core::Digest;
use blacksilk_wallet::seed::{Seed, EPOCH_BITS};
use blacksilk_wallet::Wallet;
use std::collections::BTreeMap;

const VECTORS: &str = include_str!("data/seed_v1_vectors.txt");

/// Vectors in the file: two for the word list and 18 per case.
const COUNT: usize = 2 + 4 * 18;

fn vectors() -> BTreeMap<&'static str, &'static str> {
    let mut map = BTreeMap::new();
    for line in VECTORS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once(" = ").expect("`name = value` line");
        assert!(map.insert(name, value).is_none(), "duplicate vector {name}");
    }
    map
}

fn digest_hex(d: &Digest) -> String {
    d.iter().map(|w| format!("{w:08x}")).collect()
}

fn digest_of(hex: &str) -> Digest {
    let mut d = [0u32; 8];
    for (i, x) in d.iter_mut().enumerate() {
        *x = u32::from_str_radix(&hex[8 * i..8 * i + 8], 16).unwrap();
    }
    d
}

fn network(name: &str) -> Network {
    match name {
        "mainnet" => Network::Mainnet,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        _ => panic!("network {name}"),
    }
}

#[test]
fn the_vector_file_is_complete() {
    assert_eq!(vectors().len(), COUNT);
}

#[test]
fn the_word_list_digest_matches_the_script() {
    let v = vectors();
    // The Rust test in crypto/src/wordlist.rs pins the same BLAKE2b-256; the
    // script ties it to the published BIP-39 SHA-256.
    assert_eq!(
        v["wordlist.sha256"],
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    );
    assert_eq!(v["wordlist.blake2b256"].len(), 64);
}

#[test]
fn seeds_and_keys_match_the_independent_script() {
    let v = vectors();
    let contract: Digest = std::array::from_fn(|k| 0x1234 + k as u32);
    let rho: Digest = std::array::from_fn(|k| 0x7000_0000 + 17 * k as u32);
    for case in ["a", "b", "c", "d"] {
        let get = |name: &str| v[format!("{case}.{name}").as_str()];
        let entropy: [u8; 32] = hex::decode(get("entropy")).unwrap().try_into().unwrap();
        let net = network(get("network"));
        let birthday: u16 = get("birthday").parse().unwrap();

        // Words both ways.
        let seed = Seed::new(entropy, net, birthday);
        assert_eq!(seed.words().as_str(), get("words"), "{case} words");
        let parsed = Seed::parse(get("words")).unwrap();
        assert_eq!(parsed.network(), net);
        assert_eq!(parsed.birthday(), birthday);
        let master = parsed.master();
        assert_eq!(hex::encode(*master), get("master"), "{case} master");

        // v1 keys and hedge key.
        let keys = WalletKeys::from_seed(&master);
        let k_s = keys.subaddress_spend_secret(SubaddressIndex::PRIMARY);
        assert_eq!(hex::encode(k_s.to_bytes()), get("k_s"), "{case} k_s");
        let k_v = keys.view_keys().view_secret();
        assert_eq!(hex::encode(k_v.to_bytes()), get("k_v"), "{case} k_v");
        assert_eq!(
            hex::encode(keys.hedge_secret()),
            get("hk_v1"),
            "{case} hk_v1"
        );

        // PX root and accounts. `sk` is private: it is pinned through the
        // keys it derives and through the hedge key (a hash of its bytes).
        let root = Account::from_seed_with(&master, Derivation::V2);
        let mut perm = HostPerm::new();
        assert_eq!(
            *root.keys(),
            Keys::derive(&mut perm, &digest_of(get("px.root"))),
            "{case} root"
        );
        let a0 = root.account(0);
        let a1 = root.account(1);
        assert_eq!(
            *a0.keys(),
            Keys::derive(&mut perm, &digest_of(get("px.sk0")))
        );
        assert_eq!(
            *a1.keys(),
            Keys::derive(&mut perm, &digest_of(get("px.sk1")))
        );
        assert_eq!(digest_hex(&a0.keys().nk), get("px.nk0"), "{case} nk");
        assert_eq!(digest_hex(&a0.keys().ak), get("px.ak0"), "{case} ak");
        assert_eq!(
            hex::encode(a0.hedge_secret()),
            get("px.hk_px0"),
            "{case} hk_px"
        );
        assert_eq!(digest_hex(&a0.owner(0)), get("px.owner0.0"));
        assert_eq!(digest_hex(&a0.owner(70_001)), get("px.owner0.70001"));
        assert_eq!(digest_hex(&a1.owner(0)), get("px.owner1.0"));

        // The wallet: the same words, PX account 0 and vault secret.
        let mut w = Wallet::from_seed(net, entropy, (birthday as u64) << EPOCH_BITS);
        assert_eq!(w.mnemonic().as_str(), get("words"));
        assert_eq!(
            digest_hex(&w.px_vault_secret_for(&contract, &rho)),
            get("vault_secret"),
            "{case} vault secret"
        );
        let px0 = blacksilk_chain::address::decode_px_address(net, &w.px_address(0)).unwrap();
        assert_eq!(digest_hex(&px0.owner), get("px.owner0.0"));
    }
}
