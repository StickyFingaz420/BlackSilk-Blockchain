//! The tagged-hash convention is defined twice (inventory-A D2, 2026-10-04):
//! `blacksilk-consensus` cannot depend on `blacksilk-crypto`, so it keeps its
//! own `DOMAIN_PREFIX` and `H::tagged`, and its own `MINING_HASH_TAG` name.
//! `blacksilk-tx` sees both crates; this file pins, in one place, that the
//! two definitions agree: the prefix bytes, the mining-hash tag name, and the
//! tagged hasher itself over every tag name crypto knows. The unit test
//! `state::tests::the_mining_hash_tag_is_the_crypto_crates` also checks the
//! header's mining hash end to end. No code changes; a guard only.

use blacksilk_consensus::hash::{Hash, DOMAIN_PREFIX as CONSENSUS_PREFIX, H};
use blacksilk_consensus::header::MINING_HASH_TAG;
use blacksilk_crypto::hash::{h32, tags, DOMAIN_PREFIX as CRYPTO_PREFIX};

#[test]
fn both_crates_use_the_same_domain_prefix() {
    assert_eq!(CONSENSUS_PREFIX, "BlackSilk/v1/");
    assert_eq!(CRYPTO_PREFIX, "BlackSilk/v1/");
    assert_eq!(CONSENSUS_PREFIX.as_bytes(), CRYPTO_PREFIX.as_bytes());
}

#[test]
fn the_mining_hash_tag_names_agree() {
    assert_eq!(MINING_HASH_TAG, "mining-hash");
    assert_eq!(MINING_HASH_TAG, tags::MINING_HASH);
    assert!(tags::ALL.contains(&MINING_HASH_TAG));
    assert!(tags::CONSENSUS.contains(&MINING_HASH_TAG));
}

/// `consensus::hash::H::tagged(name)` absorbs the same tag bytes as
/// `crypto::hash::h32(name, ..)`, for every tag name, with and without data.
#[test]
fn the_tagged_hashers_agree_on_every_tag() {
    let data: &[&[u8]] = &[b"", b"x", &[0xA5; 200]];
    for name in tags::ALL.iter().chain(tags::CONSENSUS) {
        for d in data {
            let consensus: Hash = H::tagged(name).chain(d).finish();
            assert_eq!(consensus, h32(name, &[d]), "tag {name}");
        }
        // Several parts are absorbed in order, as one concatenation.
        let consensus: Hash = H::tagged(name).chain(b"ab").chain(b"cd").finish();
        assert_eq!(consensus, h32(name, &[b"ab", b"cd"]), "tag {name}");
    }
}
