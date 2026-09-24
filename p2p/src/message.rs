//! Protocol messages (docs/p2p.md §4–§5). Every list is bounded before allocation;
//! decoding is strict (no trailing bytes).

use crate::addr::NetAddr;
use blacksilk_chain::block::MAX_BLOCK_BYTES;
use blacksilk_consensus::{BlockHeader, Hash, HEADER_SIZE};
use blacksilk_tx::codec::{DecodeError, Reader, Writer};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MIN_PROTOCOL_VERSION: u32 = 1;

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
    Addr(Vec<NetAddr>),
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
            Message::Addr(addrs) => {
                w.u8(5);
                w.varint(addrs.len() as u64);
                for a in addrs {
                    a.encode(&mut w);
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
                        .map(|_| NetAddr::decode(&mut r))
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
                NetAddr::parse("1.2.3.4:5").unwrap(),
                NetAddr::parse("[::2]:7").unwrap(),
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
            assert!(
                Message::decode(&b).is_err(),
                "trailing byte after {}",
                m.kind()
            );
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
