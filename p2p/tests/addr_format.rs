//! Address rules and the `Addr` wire format (docs/p2p.md §5, §9), through the
//! public API only: IP canonicalization, the routability filter, Tor v3
//! validation, network groups, and the timestamped, length-prefixed `Addr`
//! entries at byte level.

use blacksilk_p2p::message::Message;
use blacksilk_p2p::NetAddr;
use std::net::{IpAddr, Ipv4Addr};

fn a(s: &str) -> NetAddr {
    NetAddr::parse(s).unwrap_or_else(|| panic!("{s} parses"))
}

/// Real v3 onion services (torproject.org, duckduckgo.com) and addresses
/// computed with an independent implementation of rend-spec-v3 "Encoding
/// onion addresses" (Python `hashlib.sha3_256`), from the public keys named.
const TORPROJECT: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid";
const DUCKDUCKGO: &str = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad";
/// Keys `[b, 1, 2, ..., 31]` for b = 0x00, 0x01, 0x0f, 0x10, 0xff.
const KEY_00: &str = "aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dyp3kead";
const KEY_01: &str = "aeaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dyp4yaad";
const KEY_0F: &str = "b4aqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypwzxyd";
const KEY_10: &str = "caaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypuomad";
const KEY_FF: &str = "74aqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dyp4nvid";

fn onion(host: &str) -> NetAddr {
    a(&format!("{host}.onion:29334"))
}

/// W0 (F32-7): an IPv4-mapped IPv6 address is the IPv4 address. It parses to
/// the same `NetAddr`, so bans, per-IP limits, deduplication and groups key
/// on one form.
#[test]
fn ipv4_mapped_addresses_are_canonical() {
    let m = a("[::ffff:8.8.8.8]:29334");
    assert_eq!(m, a("8.8.8.8:29334"));
    assert_eq!(m.ip(), Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    assert_eq!(m.to_string(), "8.8.8.8:29334");
}

/// W0 (F32-7): special-purpose ranges, including private IPv4 embedded in
/// IPv6 (mapped, 6to4, NAT64, Teredo), are neither stored, relayed nor dialed.
#[test]
fn mapped_and_special_ranges_are_not_routable() {
    for s in [
        // IPv4-mapped private, loopback and unspecified addresses.
        "[::ffff:127.0.0.1]:1",
        "[::ffff:10.1.2.3]:1",
        "[::ffff:192.168.0.1]:1",
        "[::ffff:0.0.0.0]:1",
        // IPv4-compatible (deprecated) and the rest of ::/96.
        "[::10.1.2.3]:1",
        "[::8.8.8.8]:1",
        // 6to4 and NAT64 embedding a private IPv4.
        "[2002:0a00:0001::1]:1",
        "[2002:7f00:0001::1]:1",
        "[64:ff9b::10.0.0.1]:1",
        "[64:ff9b::127.0.0.1]:1",
        // Teredo embedding a private IPv4 (obfuscated: bitwise complement).
        "[2001:0:4136:e378:8000:63bf:f5ff:fffe]:1",
        // Site-local (deprecated), ORCHID, ORCHIDv2, discard-only.
        "[fec0::1]:1",
        "[2001:10::1]:1",
        "[2001:20::1]:1",
        "[100::1]:1",
        // IPv4 special purpose: benchmarking, reserved, IETF assignments,
        // shared address space edges.
        "198.18.0.1:1",
        "198.19.255.254:1",
        "240.0.0.1:1",
        "255.255.255.254:1",
        "192.0.0.8:1",
        "100.127.255.254:1",
        // Documentation (all three IPv4 blocks).
        "192.0.2.1:1",
        "198.51.100.1:1",
        "203.0.113.1:1",
    ] {
        assert!(!a(s).is_routable(), "{s} must not be routable");
    }
    for s in [
        "8.8.8.8:1",
        "[::ffff:8.8.8.8]:1",
        "[2002:0808:0808::1]:1",
        "[64:ff9b::8.8.8.8]:1",
        "[2001:0:4136:e378:8000:63bf:f7f7:f7f7]:1",
        "[2a00:1450::1]:1",
        "100.128.0.1:1",
        "198.20.0.1:1",
    ] {
        assert!(a(s).is_routable(), "{s} must be routable");
    }
}

/// W2 (R8-5): a Tor v3 name is `base32(key ‖ checksum ‖ version)` with
/// `checksum = SHA3-256(".onion checksum" ‖ key ‖ version)[..2]` and version
/// 3. Names with a wrong checksum or version are refused, not stored,
/// relayed or dialed.
#[test]
fn onion_v3_checksum_and_version_are_validated() {
    for h in [
        TORPROJECT, DUCKDUCKGO, KEY_00, KEY_01, KEY_0F, KEY_10, KEY_FF,
    ] {
        let o = onion(h);
        assert!(o.is_onion() && o.is_routable(), "{h}");
        assert_eq!(o.to_string(), format!("{h}.onion:29334"));
        // Upper case is accepted and canonicalized.
        assert_eq!(
            NetAddr::parse(&format!("{}.onion:29334", h.to_ascii_uppercase())),
            Some(o)
        );
    }
    // The old test vector: valid base32 characters, but no valid v3 name.
    let junk = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx";
    assert!(NetAddr::parse(&format!("{junk}.onion:1")).is_none());
    assert!(NetAddr::parse(&format!("{}.onion:1", "a".repeat(56))).is_none());
    // Single-character changes. Characters 52..56 hold only checksum and
    // version bits (the key ends inside character 51), so changing one of
    // them never gives a valid name. A change inside the key gives another
    // key, whose 16-bit checksum matches by chance with probability 2^-16:
    // the independent implementation confirms the one such name here.
    let alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    let mut accepted = Vec::new();
    for i in 0..56 {
        for c in alphabet.chars() {
            let mut h: Vec<char> = TORPROJECT.chars().collect();
            if h[i] == c {
                continue;
            }
            h[i] = c;
            let h: String = h.into_iter().collect();
            if NetAddr::parse(&format!("{h}.onion:1")).is_some() {
                assert!(i < 52, "{h}: a checksum or version change was accepted");
                accepted.push(h);
            }
        }
    }
    assert_eq!(
        accepted,
        ["23zyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid"],
        "of 56 x 31 = 1736 changed names"
    );
}

/// W2 (R8-5): onion names are free to create, so an onion's group is its
/// network plus the first 4 bits of its key: 16 groups in total (Bitcoin
/// Core's `GetGroup`), never one group per name.
#[test]
fn onion_groups_are_the_first_four_key_bits() {
    let g = |h| onion(h).group();
    assert_eq!(g(KEY_00), g(KEY_01));
    assert_eq!(g(KEY_00), g(KEY_0F));
    assert_ne!(g(KEY_00), g(KEY_10));
    assert_ne!(g(KEY_10), g(KEY_FF));
    // The port never matters.
    assert_eq!(
        a(&format!("{KEY_00}.onion:1")).group(),
        a(&format!("{KEY_00}.onion:2")).group()
    );
    // No onion shares a group with an IP address.
    assert_ne!(g(KEY_00), a("0.0.1.1:1").group());
    assert_ne!(g(KEY_00), a("[::]:1").group());
}

/// W2: IPv4 /16; IPv6 /32 (Hurricane Electric's 2001:470::/32 at /36); 6to4,
/// NAT64 and Teredo group by their embedded IPv4 /16, like the IPv4 address.
#[test]
fn ip_groups() {
    let g = |s| a(s).group();
    assert_eq!(g("8.8.1.1:1"), g("8.8.200.3:2"));
    assert_ne!(g("8.8.1.1:1"), g("8.9.1.1:1"));
    assert_eq!(g("[2a00:1450:1::1]:1"), g("[2a00:1450:ffff::2]:1"));
    assert_ne!(g("[2a00:1450::1]:1"), g("[2a00:1451::1]:1"));
    assert_ne!(g("[2001:470:1000::1]:1"), g("[2001:470:2000::1]:1"));
    assert_eq!(g("[2001:470:1000::1]:1"), g("[2001:470:1fff::1]:1"));
    assert_eq!(g("[2002:0808:0101::1]:1"), g("8.8.3.3:1"), "6to4");
    assert_eq!(g("[64:ff9b::8.8.4.4]:1"), g("8.8.3.3:1"), "NAT64");
    assert_eq!(
        g("[2001:0:4136:e378:8000:63bf:f7f7:fbfb]:1"),
        g("8.8.3.3:1"),
        "Teredo (the client IPv4 is stored complemented)"
    );
    assert_ne!(g("[2002:0808:0101::1]:1"), g("[2002:0909:0101::1]:1"));
}

// ------------------------------------------------------------ the Addr format

/// One `Addr` entry: `LE32 time ‖ u8 net ‖ varint len ‖ bytes ‖ LE16 port`.
fn entry(time: u32, net: u8, bytes: &[u8], port: u16) -> Vec<u8> {
    let mut v = time.to_le_bytes().to_vec();
    v.push(net);
    assert!(bytes.len() < 0x80, "one-byte varint in this helper");
    v.push(bytes.len() as u8);
    v.extend_from_slice(bytes);
    v.extend_from_slice(&port.to_le_bytes());
    v
}

fn addr_msg(entries: &[Vec<u8>]) -> Vec<u8> {
    assert!(entries.len() < 0x80);
    let mut v = vec![5u8, entries.len() as u8];
    for e in entries {
        v.extend_from_slice(e);
    }
    v
}

fn decodes_canonically(bytes: &[u8]) -> Message {
    let m = Message::decode(bytes).unwrap_or_else(|e| panic!("decodes: {e:?}"));
    assert_eq!(m.kind(), "addr");
    assert_eq!(m.encode(), bytes, "canonical");
    m
}

/// W3: the `Addr` entries are timestamped and length-prefixed (network ids
/// 1 = IPv4, 2 = IPv6, 4 = Tor v3 as its 32-byte key), and decode canonically.
#[test]
fn addr_entries_are_timestamped_and_length_prefixed() {
    let tor_key: [u8; 32] = {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    };
    let msg = addr_msg(&[
        entry(1_700_000_000, 1, &[8, 8, 8, 8], 29334),
        entry(
            1_700_000_001,
            2,
            &[0x2a, 0, 0x14, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            7,
        ),
        entry(1_700_000_002, 4, &tor_key, 29334),
    ]);
    let m = decodes_canonically(&msg);
    let text = format!("{m:?}");
    assert!(text.contains("8.8.8.8:29334"), "{text}");
    assert!(text.contains("2a00:1450::1"), "{text}");
    assert!(
        text.contains(KEY_00),
        "the Tor key is the onion name: {text}"
    );
    assert!(text.contains("1700000002"), "the time is kept: {text}");
    // An empty `Addr` is valid.
    decodes_canonically(&addr_msg(&[]));
}

/// W3 (30's P-10): an entry of a network this version does not know is
/// skipped by the node, not a decode error (a later version can add
/// networks); its length is still bounded, and it re-encodes as received.
#[test]
fn unknown_networks_decode_and_are_bounded() {
    decodes_canonically(&addr_msg(&[
        entry(1, 9, b"future", 1),
        entry(2, 1, &[8, 8, 8, 8], 2),
        entry(3, 5, &[7; 100], 3),
    ]));
    // 512 bytes is the most an address may have (BIP155's bound).
    let mut big = vec![5u8, 1];
    big.extend_from_slice(&0u32.to_le_bytes());
    big.push(200);
    big.extend_from_slice(&[0x80, 0x04]); // varint 512
    big.extend_from_slice(&[1; 512]);
    big.extend_from_slice(&1u16.to_le_bytes());
    decodes_canonically(&big);
    let mut too_big = vec![5u8, 1];
    too_big.extend_from_slice(&0u32.to_le_bytes());
    too_big.push(200);
    too_big.extend_from_slice(&[0x81, 0x04]); // varint 513
    too_big.extend_from_slice(&[1; 513]);
    too_big.extend_from_slice(&1u16.to_le_bytes());
    assert!(Message::decode(&too_big).is_err(), "513-byte address");
    // A huge claimed length with no data behind it fails before allocating.
    let mut huge = vec![5u8, 1];
    huge.extend_from_slice(&0u32.to_le_bytes());
    huge.push(200);
    huge.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
    assert!(Message::decode(&huge).is_err());
}

/// W3: a known network with the wrong address length, a non-canonical IPv6
/// form of an IPv4 address, or too many entries is malformed (the node
/// penalizes the sender for any malformed message).
#[test]
fn malformed_addr_entries_are_rejected() {
    for bad in [
        entry(1, 1, &[8, 8, 8], 1),
        entry(1, 1, &[8, 8, 8, 8, 8], 1),
        entry(1, 2, &[1; 15], 1),
        entry(1, 4, &[1; 31], 1),
        entry(1, 4, &[1; 33], 1),
        // ::ffff:8.8.8.8 must be sent as IPv4.
        entry(
            1,
            2,
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8],
            1,
        ),
    ] {
        let m = addr_msg(&[entry(1, 1, &[1, 1, 1, 1], 1), bad.clone()]);
        assert!(Message::decode(&m).is_err(), "{bad:?}");
    }
    // Truncations of a valid message.
    let good = addr_msg(&[entry(1, 1, &[1, 1, 1, 1], 1), entry(2, 9, b"xy", 2)]);
    decodes_canonically(&good);
    for len in 0..good.len() {
        assert!(Message::decode(&good[..len]).is_err(), "truncated to {len}");
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(Message::decode(&trailing).is_err(), "trailing byte");
    // More than 1000 entries.
    let mut many = vec![5u8];
    many.extend_from_slice(&[0xe9, 0x07]); // varint 1001
    for _ in 0..1001 {
        many.extend_from_slice(&entry(1, 1, &[1, 1, 1, 1], 1));
    }
    assert!(Message::decode(&many).is_err(), "1001 entries");
}

/// W3: random bytes behind the `Addr` type never panic the decoder, and what
/// decodes re-encodes to the same bytes.
#[test]
fn random_addr_payloads_never_panic() {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut decoded = 0;
    for i in 0..200_000u32 {
        let len = (next() % 96) as usize;
        let mut v = vec![5u8];
        // Mostly small counts and plausible networks, so decoding gets deep.
        v.push((next() % 4) as u8);
        for _ in 0..len {
            v.push(next() as u8);
        }
        if i % 3 == 0 && v.len() > 7 {
            v[6] = [1u8, 2, 4, 9][(next() % 4) as usize];
            v[7] = [4u8, 16, 32, 2][(next() % 4) as usize];
        }
        if let Ok(m) = Message::decode(&v) {
            decoded += 1;
            assert_eq!(m.encode(), v, "canonical");
        }
    }
    println!("{decoded} random Addr payloads decoded; no panic");
}
