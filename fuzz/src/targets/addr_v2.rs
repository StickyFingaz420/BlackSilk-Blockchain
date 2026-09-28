//! Target body: the `Addr` message codec, v2 entries (p2p/src/addr.rs and
//! p2p/src/message.rs, docs/p2p.md §5; W2-32). Every input is an `Addr`
//! payload (the type byte is prepended), so the whole budget goes into the
//! entry decoder rather than into choosing a message type.
//!
//! Invariants, beyond "no panic":
//! - canonical form: a decoded message re-encodes to exactly its input, so no
//!   two encodings carry the same message (no varint, length or IP-form
//!   malleability);
//! - at most `MAX_ADDRS` entries and `MAX_ADDR_LEN` address bytes each;
//! - every entry round-trips on its own;
//! - a known address is canonical (`canonical()` changes nothing), and its
//!   other two forms round-trip: the text form (`NetAddr::parse` of its
//!   `Display`) and the `Version.listen` encoding;
//! - a Tor v3 entry's name gives its key back (`onion_key`), and routability
//!   and network groups are defined for every address.

use blacksilk_p2p::addr::{onion_key, AddrEntry, EntryAddr, MAX_ADDR_LEN};
use blacksilk_p2p::message::{Message, MAX_ADDRS};
use blacksilk_p2p::NetAddr;
use blacksilk_tx::codec::{Reader, Writer};

const TYPE_ADDR: u8 = 5;

pub fn run(data: &[u8]) {
    let bytes = [&[TYPE_ADDR][..], data].concat();
    let Ok(msg) = Message::decode(&bytes) else {
        return;
    };
    let Message::Addr(entries) = &msg else {
        panic!("type {TYPE_ADDR} decodes to {msg:?}");
    };
    assert_eq!(msg.encode(), bytes, "decode then encode is the identity");
    assert!(entries.len() as u64 <= MAX_ADDRS);
    for e in entries {
        let mut w = Writer::new();
        e.encode(&mut w);
        let enc = w.into_bytes();
        let mut r = Reader::new(&enc);
        assert_eq!(
            AddrEntry::decode(&mut r).as_ref(),
            Ok(e),
            "an entry round-trips"
        );
        r.finish().expect("an entry is its whole encoding");
        match &e.addr {
            EntryAddr::Known(a) => known(a),
            EntryAddr::Unknown { bytes, .. } => {
                assert!(bytes.len() as u64 <= MAX_ADDR_LEN);
            }
        }
    }
}

fn known(a: &NetAddr) {
    assert_eq!(&a.clone().canonical(), a, "decoded addresses are canonical");
    assert_eq!(
        NetAddr::parse(&a.to_string()).as_ref(),
        Some(a),
        "the text form round-trips"
    );
    let mut w = Writer::new();
    a.encode(&mut w);
    let enc = w.into_bytes();
    let mut r = Reader::new(&enc);
    assert_eq!(
        NetAddr::decode(&mut r).as_ref(),
        Ok(a),
        "the listen form round-trips"
    );
    r.finish().expect("the listen form is its whole encoding");
    if let NetAddr::Onion { host, port } = a {
        let key = onion_key(host).expect("a decoded onion name is valid");
        assert_eq!(&NetAddr::from_onion_key(&key, *port), a);
        assert!(a.is_onion());
    }
    let _ = (a.is_routable(), a.group(), a.port(), a.ip());
}

fn entry(time: u32, net: u8, addr: &[u8], port: u16) -> Vec<u8> {
    let mut v = time.to_le_bytes().to_vec();
    v.push(net);
    v.push(addr.len() as u8);
    v.extend_from_slice(addr);
    v.extend_from_slice(&port.to_le_bytes());
    v
}

/// Seed inputs (named): payloads without the type byte.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let onion = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid";
    let msg = Message::Addr(vec![
        AddrEntry::new(1_700_000_000, NetAddr::parse("198.51.100.1:18333").unwrap()),
        AddrEntry::new(
            1_700_000_300,
            NetAddr::parse("[2001:db9::1]:18333").unwrap(),
        ),
        AddrEntry::new(0, NetAddr::parse(&format!("{onion}.onion:18333")).unwrap()),
        AddrEntry {
            time: 5,
            addr: EntryAddr::Unknown {
                net: 9,
                bytes: vec![1, 2, 3],
                port: 7,
            },
        },
    ]);
    let all = msg.encode()[1..].to_vec();
    let one = |e: Vec<u8>| [&[1u8][..], &e].concat();
    vec![
        ("mixed", all),
        ("empty", vec![0]),
        ("ipv4", one(entry(1, 1, &[8, 8, 8, 8], 29334))),
        (
            "ipv6",
            one(entry(
                2,
                2,
                &[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                1,
            )),
        ),
        (
            "ipv4_mapped",
            one(entry(
                3,
                2,
                &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4],
                1,
            )),
        ),
        ("torv3", one(entry(4, 4, &[7; 32], 29334))),
        ("unknown_long", one(entry(5, 0xfe, &[0xab; 100], 9))),
        ("wrong_length", one(entry(6, 1, &[1, 2, 3], 9))),
    ]
}
