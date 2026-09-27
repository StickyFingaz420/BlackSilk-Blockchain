//! Protocol messages (docs/p2p.md §4–§5). Every list is bounded before allocation;
//! decoding of known messages is strict (no trailing bytes), with one
//! exception kept for upgrades: `Version` may carry extension bytes after its
//! last known field, which are ignored. Unknown message types are not decoded
//! here: [`is_known_type`] lets the network skip them (docs/p2p.md §5).

use crate::addr::{AddrEntry, NetAddr};
use blacksilk_chain::block::MAX_BLOCK_BYTES;
use blacksilk_consensus::{BlockHeader, Hash, HEADER_SIZE};
use blacksilk_tx::codec::{DecodeError, Reader, Writer};

/// Our protocol version (docs/p2p.md §4).
/// - 1: the original protocol (unknown message types and `Version` extension
///   bytes were violations).
/// - 2: unknown message types are ignored, and `Version` may carry extension
///   bytes after `relay_txs`, which are ignored. The wire format of every
///   known message is unchanged. A later version adds optional features by
///   (a) appending fields to `Version` and (b) sending new message types only
///   to peers whose `protocol` is at least the version that defines them.
/// - 3: `Addr` (type 5) carries timestamped, length-prefixed entries
///   ([`AddrEntry`], docs/p2p.md §5) instead of bare `NetAddr`s. A wire change
///   made before the v3 testnet launch: a version-2 node cannot decode a
///   version-3 `Addr` (it would ban the sender), so each side refuses the
///   other at the handshake instead ([`MIN_PROTOCOL_VERSION`]).
pub const PROTOCOL_VERSION: u32 = 3;
pub const MIN_PROTOCOL_VERSION: u32 = 3;

/// The highest message type this version decodes (`StemTx`).
pub const MAX_KNOWN_TYPE: u8 = 14;

/// Whether a payload whose first byte is `tag` is a message type this version
/// knows. Frames of other types are ignored by the network (they still count
/// against the peer's message and byte budgets), so a later protocol version
/// can add messages without old nodes banning it (docs/p2p.md §5).
pub fn is_known_type(tag: u8) -> bool {
    tag <= MAX_KNOWN_TYPE
}

pub const MAX_ADDRS: u64 = 1000;
pub const MAX_LOCATOR: u64 = 64;
pub const MAX_HEADERS: u64 = 2000;
pub const MAX_BLOCK_REQUEST: u64 = 128;
pub const MAX_INV: u64 = 500;
/// Maximum frame payload: a maximum-size block plus framing.
/// Largest frame: a full block (with its PX budget) plus framing.
pub const MAX_FRAME: usize = MAX_BLOCK_BYTES + 64 * 1024;

/// Largest transaction payload of any kind (PX transactions carry proofs).
pub const MAX_ANY_TX_SIZE: usize = {
    let px = blacksilk_tx::params::MAX_PX_TX_SIZE;
    let deploy = blacksilk_tx::params::MAX_DEPLOY_TX_SIZE;
    if px > deploy {
        px
    } else {
        deploy
    }
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub protocol: u32,
    pub network: u32,
    pub nonce: u64,
    pub height: u64,
    pub tip: Hash,
    pub listen: Option<NetAddr>,
    pub relay_txs: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Version(Version),
    Verack,
    Ping(u64),
    Pong(u64),
    GetAddr,
    Addr(Vec<AddrEntry>),
    GetHeaders { locator: Vec<Hash>, stop: Hash },
    Headers(Vec<BlockHeader>),
    GetBlocks(Vec<Hash>),
    Block(Vec<u8>),
    NotFound(Vec<Hash>),
    InvTx(Vec<Hash>),
    GetTx(Vec<Hash>),
    Tx(Vec<u8>),
    StemTx(Vec<u8>),
}

impl Message {
    pub fn kind(&self) -> &'static str {
        match self {
            Message::Version(_) => "version",
            Message::Verack => "verack",
            Message::Ping(_) => "ping",
            Message::Pong(_) => "pong",
            Message::GetAddr => "getaddr",
            Message::Addr(_) => "addr",
            Message::GetHeaders { .. } => "getheaders",
            Message::Headers(_) => "headers",
            Message::GetBlocks(_) => "getblocks",
            Message::Block(_) => "block",
            Message::NotFound(_) => "notfound",
            Message::InvTx(_) => "invtx",
            Message::GetTx(_) => "gettx",
            Message::Tx(_) => "tx",
            Message::StemTx(_) => "stemtx",
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let hashes = |w: &mut Writer, t: u8, v: &[Hash]| {
            w.u8(t);
            w.varint(v.len() as u64);
            for h in v {
                w.bytes(h);
            }
        };
        let blob = |w: &mut Writer, t: u8, b: &[u8]| {
            w.u8(t);
            w.varint(b.len() as u64);
            w.bytes(b);
        };
        match self {
            Message::Version(v) => {
                w.u8(0);
                w.bytes(&v.protocol.to_le_bytes());
                w.bytes(&v.network.to_le_bytes());
                w.bytes(&v.nonce.to_le_bytes());
                w.varint(v.height);
                w.bytes(&v.tip);
                match &v.listen {
                    Some(a) => {
                        w.u8(1);
                        a.encode(&mut w);
                    }
                    None => w.u8(0),
                }
                w.u8(v.relay_txs as u8);
            }
            Message::Verack => w.u8(1),
            Message::Ping(n) => {
                w.u8(2);
                w.bytes(&n.to_le_bytes());
            }
            Message::Pong(n) => {
                w.u8(3);
                w.bytes(&n.to_le_bytes());
            }
            Message::GetAddr => w.u8(4),
            Message::Addr(entries) => {
                w.u8(5);
                w.varint(entries.len() as u64);
                for e in entries {
                    e.encode(&mut w);
                }
            }
            Message::GetHeaders { locator, stop } => {
                hashes(&mut w, 6, locator);
                w.bytes(stop);
            }
            Message::Headers(hs) => {
                w.u8(7);
                w.varint(hs.len() as u64);
                for h in hs {
                    w.bytes(&h.to_bytes());
                }
            }
            Message::GetBlocks(ids) => hashes(&mut w, 8, ids),
            Message::Block(b) => blob(&mut w, 9, b),
            Message::NotFound(ids) => hashes(&mut w, 10, ids),
            Message::InvTx(ids) => hashes(&mut w, 11, ids),
            Message::GetTx(ids) => hashes(&mut w, 12, ids),
            Message::Tx(b) => blob(&mut w, 13, b),
            Message::StemTx(b) => blob(&mut w, 14, b),
        }
        w.into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        fn hashes(
            r: &mut Reader<'_>,
            what: &'static str,
            max: u64,
        ) -> Result<Vec<Hash>, DecodeError> {
            let n = r.count(what, 0, max)?;
            (0..n).map(|_| r.array()).collect()
        }
        let tag = r.u8()?;
        let msg = match tag {
            0 => {
                let protocol = u32::from_le_bytes(r.array()?);
                let network = u32::from_le_bytes(r.array()?);
                let nonce = u64::from_le_bytes(r.array()?);
                let height = r.varint()?;
                let tip = r.array()?;
                let listen = match r.u8()? {
                    0 => None,
                    1 => Some(NetAddr::decode(&mut r)?),
                    k => return Err(DecodeError::UnknownKind(k)),
                };
                let relay_txs = match r.u8()? {
                    0 => false,
                    1 => true,
                    k => return Err(DecodeError::UnknownKind(k)),
                };
                // Extension area: fields a later protocol version appends
                // after `relay_txs`. Ignored (the frame size bounds them).
                let rest = bytes.len() - r.position();
                r.skip(rest)?;
                Message::Version(Version {
                    protocol,
                    network,
                    nonce,
                    height,
                    tip,
                    listen,
                    relay_txs,
                })
            }
            1 => Message::Verack,
            2 => Message::Ping(u64::from_le_bytes(r.array()?)),
            3 => Message::Pong(u64::from_le_bytes(r.array()?)),
            4 => Message::GetAddr,
            5 => {
                let n = r.count("addr", 0, MAX_ADDRS)?;
                Message::Addr(
                    (0..n)
                        .map(|_| AddrEntry::decode(&mut r))
                        .collect::<Result<_, _>>()?,
                )
            }
            6 => {
                let locator = hashes(&mut r, "locator", MAX_LOCATOR)?;
                let stop = r.array()?;
                Message::GetHeaders { locator, stop }
            }
            7 => {
                let n = r.count("headers", 0, MAX_HEADERS)?;
                let mut hs = Vec::with_capacity(n);
                for _ in 0..n {
                    let b: [u8; HEADER_SIZE] = r.array()?;
                    hs.push(BlockHeader::from_bytes(&b).ok_or(DecodeError::UnknownKind(7))?);
                }
                Message::Headers(hs)
            }
            8 => Message::GetBlocks(hashes(&mut r, "getblocks", MAX_BLOCK_REQUEST)?),
            9 | 13 | 14 => {
                let max = if tag == 9 {
                    MAX_BLOCK_BYTES
                } else {
                    MAX_ANY_TX_SIZE
                };
                let n = r.count("payload", 1, max as u64)?;
                let start = r.position();
                r.skip(n)?;
                let data = bytes[start..start + n].to_vec();
                match tag {
                    9 => Message::Block(data),
                    13 => Message::Tx(data),
                    _ => Message::StemTx(data),
                }
            }
            10 => Message::NotFound(hashes(&mut r, "notfound", MAX_BLOCK_REQUEST)?),
            11 => Message::InvTx(hashes(&mut r, "invtx", MAX_INV)?),
            12 => Message::GetTx(hashes(&mut r, "gettx", MAX_INV)?),
            k => return Err(DecodeError::UnknownKind(k)),
        };
        r.finish()?;
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<Message> {
        let header = BlockHeader {
            version: 1,
            height: 7,
            prev_id: [1; 32],
            timestamp: 99,
            difficulty: 5,
            tx_root: [2; 32],
            nonce: 3,
        };
        vec![
            Message::Version(Version {
                protocol: 1,
                network: 9,
                nonce: 42,
                height: 1000,
                tip: [7; 32],
                listen: NetAddr::parse("8.8.8.8:29334"),
                relay_txs: true,
            }),
            Message::Version(Version {
                protocol: 1,
                network: 9,
                nonce: 1,
                height: 0,
                tip: [0; 32],
                listen: None,
                relay_txs: false,
            }),
            Message::Verack,
            Message::Ping(5),
            Message::Pong(6),
            Message::GetAddr,
            Message::Addr(vec![
                AddrEntry::new(1_800_000_000, NetAddr::parse("1.2.3.4:5").unwrap()),
                AddrEntry::new(0, NetAddr::parse("[::2]:7").unwrap()),
                AddrEntry::new(
                    9,
                    NetAddr::from_onion_key(&[7; crate::addr::ONION_KEY_LEN], 29334),
                ),
                AddrEntry {
                    time: 3,
                    addr: crate::addr::EntryAddr::Unknown {
                        net: 200,
                        bytes: vec![1, 2, 3],
                        port: 4,
                    },
                },
            ]),
            Message::GetHeaders {
                locator: vec![[3; 32], [4; 32]],
                stop: [0; 32],
            },
            Message::Headers(vec![header, header]),
            Message::GetBlocks(vec![[9; 32]]),
            Message::Block(vec![1, 2, 3]),
            Message::NotFound(vec![[8; 32]]),
            Message::InvTx(vec![[5; 32]; 3]),
            Message::GetTx(vec![]),
            Message::Tx(vec![9; 10]),
            Message::StemTx(vec![8; 10]),
        ]
    }

    #[test]
    fn round_trip() {
        for m in samples() {
            let b = m.encode();
            assert_eq!(Message::decode(&b).unwrap(), m, "{}", m.kind());
        }
    }

    #[test]
    fn strictness() {
        for m in samples() {
            let mut b = m.encode();
            b.push(0);
            if matches!(m, Message::Version(_)) {
                // The extension area (P0-8): trailing bytes are ignored.
                assert_eq!(Message::decode(&b).as_ref(), Ok(&m), "version extension");
            } else {
                assert!(
                    Message::decode(&b).is_err(),
                    "trailing byte after {}",
                    m.kind()
                );
            }
            let b = m.encode();
            for len in 0..b.len() {
                assert!(
                    Message::decode(&b[..len]).is_err(),
                    "{} truncated to {len}",
                    m.kind()
                );
            }
        }
        assert!(Message::decode(&[99]).is_err(), "unknown type");
        // Every known type is below the unknown ones.
        for m in samples() {
            assert!(is_known_type(m.encode()[0]), "{}", m.kind());
        }
        assert!(!is_known_type(MAX_KNOWN_TYPE + 1) && !is_known_type(0xff));
    }

    /// P0-8: a `Version` from a later protocol version, with fields appended
    /// after `relay_txs`, decodes to the fields this version knows; broken
    /// known fields are still rejected.
    #[test]
    fn version_extensions_are_ignored_but_known_fields_stay_strict() {
        let v = samples().remove(0);
        let mut b = v.encode();
        b.extend_from_slice(&[0x07, 0xff, 0x00, 0x42, 1, 2, 3]);
        assert_eq!(Message::decode(&b), Ok(v.clone()));
        // A bad `relay_txs` flag (the last known field) is still an error.
        let mut bad = v.encode();
        *bad.last_mut().unwrap() = 2;
        bad.push(0);
        assert!(Message::decode(&bad).is_err());
        // So is a truncated known field.
        let b = v.encode();
        assert!(Message::decode(&b[..b.len() - 1]).is_err());
    }

    #[test]
    fn limits_are_enforced_before_allocation() {
        // Headers claiming 2001 entries, Inv claiming 501, with no data behind them.
        let mut w = Writer::new();
        w.u8(7);
        w.varint(MAX_HEADERS + 1);
        assert!(matches!(
            Message::decode(&w.into_bytes()),
            Err(DecodeError::CountOutOfRange { .. })
        ));
        let mut w = Writer::new();
        w.u8(11);
        w.varint(MAX_INV + 1);
        assert!(matches!(
            Message::decode(&w.into_bytes()),
            Err(DecodeError::CountOutOfRange { .. })
        ));
        let mut w = Writer::new();
        w.u8(13);
        w.varint(MAX_ANY_TX_SIZE as u64 + 1);
        assert!(Message::decode(&w.into_bytes()).is_err());
        let mut w = Writer::new();
        w.u8(5);
        w.varint(u64::MAX);
        assert!(Message::decode(&w.into_bytes()).is_err());
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut x = 0x1234_5678u64;
        for len in 0..600 {
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                })
                .collect();
            let _ = Message::decode(&bytes);
        }
    }
}
