//! Network addresses (docs/p2p.md §5, §9).

use blacksilk_tx::codec::{DecodeError, Reader, Writer};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const TAG_V4: u8 = 0x04;
const TAG_V6: u8 = 0x06;
const TAG_ONION: u8 = 0x0a;
/// Length of a Tor v3 host name without ".onion".
pub const ONION_LEN: usize = 56;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NetAddr {
    Ip(SocketAddr),
    /// Tor v3 hidden service: 56 lowercase base32 characters (without ".onion").
    Onion {
        host: String,
        port: u16,
    },
}

impl fmt::Display for NetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetAddr::Ip(a) => write!(f, "{a}"),
            NetAddr::Onion { host, port } => write!(f, "{host}.onion:{port}"),
        }
    }
}

fn valid_onion_host(host: &str) -> bool {
    host.len() == ONION_LEN
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

impl NetAddr {
    /// Parses `1.2.3.4:5`, `[::1]:5` or `<56 chars>.onion:5`.
    pub fn parse(s: &str) -> Option<Self> {
        if let Ok(a) = s.parse::<SocketAddr>() {
            return Some(NetAddr::Ip(a));
        }
        let (host, port) = s.rsplit_once(':')?;
        let host = host.strip_suffix(".onion")?.to_ascii_lowercase();
        let port: u16 = port.parse().ok()?;
        valid_onion_host(&host).then_some(NetAddr::Onion { host, port })
    }

    pub fn port(&self) -> u16 {
        match self {
            NetAddr::Ip(a) => a.port(),
            NetAddr::Onion { port, .. } => *port,
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            NetAddr::Ip(a) => Some(a.ip()),
            NetAddr::Onion { .. } => None,
        }
    }

    pub fn is_onion(&self) -> bool {
        matches!(self, NetAddr::Onion { .. })
    }

    /// Network group for diversity and bucketing: IPv4 /16, IPv6 /32, or the
    /// onion address itself.
    pub fn group(&self) -> Vec<u8> {
        match self {
            NetAddr::Ip(a) => match a.ip() {
                IpAddr::V4(v4) => {
                    let o = v4.octets();
                    vec![4, o[0], o[1]]
                }
                IpAddr::V6(v6) => {
                    if let Some(v4) = v6.to_ipv4_mapped() {
                        let o = v4.octets();
                        return vec![4, o[0], o[1]];
                    }
                    let o = v6.octets();
                    vec![6, o[0], o[1], o[2], o[3]]
                }
            },
            NetAddr::Onion { host, .. } => {
                let mut g = vec![10];
                g.extend_from_slice(host.as_bytes());
                g
            }
        }
    }

    /// Whether the address is worth storing and relaying on the public network
    /// (not loopback, private, link-local, unspecified, multicast or documentation).
    pub fn is_routable(&self) -> bool {
        match self {
            NetAddr::Onion { port, .. } => *port != 0,
            NetAddr::Ip(a) => {
                if a.port() == 0 {
                    return false;
                }
                match a.ip() {
                    IpAddr::V4(ip) => {
                        !(ip.is_loopback()
                            || ip.is_private()
                            || ip.is_link_local()
                            || ip.is_unspecified()
                            || ip.is_broadcast()
                            || ip.is_multicast()
                            || ip.is_documentation()
                            || ip.octets()[0] == 0
                            || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64))
                        // CGNAT
                    }
                    IpAddr::V6(ip) => {
                        let seg = ip.segments();
                        !(ip.is_loopback()
                            || ip.is_unspecified()
                            || ip.is_multicast()
                            || (seg[0] & 0xfe00) == 0xfc00 // unique local
                            || (seg[0] & 0xffc0) == 0xfe80 // link local
                            || (seg[0] == 0x2001 && seg[1] == 0x0db8)) // documentation
                    }
                }
            }
        }
    }

    pub fn encode(&self, w: &mut Writer) {
        match self {
            NetAddr::Ip(a) => {
                match a.ip() {
                    IpAddr::V4(v4) => {
                        w.u8(TAG_V4);
                        w.bytes(&v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        w.u8(TAG_V6);
                        w.bytes(&v6.octets());
                    }
                }
                w.bytes(&a.port().to_le_bytes());
            }
            NetAddr::Onion { host, port } => {
                w.u8(TAG_ONION);
                w.bytes(host.as_bytes());
                w.bytes(&port.to_le_bytes());
            }
        }
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let tag = r.u8()?;
        let addr = match tag {
            TAG_V4 => {
                let o: [u8; 4] = r.array()?;
                let port = u16::from_le_bytes(r.array()?);
                NetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(o)), port))
            }
            TAG_V6 => {
                let o: [u8; 16] = r.array()?;
                let port = u16::from_le_bytes(r.array()?);
                NetAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port))
            }
            TAG_ONION => {
                let h: [u8; ONION_LEN] = r.array()?;
                let port = u16::from_le_bytes(r.array()?);
                let host =
                    String::from_utf8(h.to_vec()).map_err(|_| DecodeError::UnknownKind(tag))?;
                if !valid_onion_host(&host) {
                    return Err(DecodeError::UnknownKind(tag));
                }
                NetAddr::Onion { host, port }
            }
            other => return Err(DecodeError::UnknownKind(other)),
        };
        Ok(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx";

    #[test]
    fn parse_and_round_trip() {
        for s in [
            "1.2.3.4:29334",
            "[2001:470::1]:5",
            &format!("{ONION}.onion:29334"),
        ] {
            let a = NetAddr::parse(s).unwrap();
            assert_eq!(a.to_string(), s);
            let mut w = Writer::new();
            a.encode(&mut w);
            let bytes = w.into_bytes();
            let mut r = Reader::new(&bytes);
            assert_eq!(NetAddr::decode(&mut r).unwrap(), a);
            r.finish().unwrap();
        }
        assert!(NetAddr::parse("bad.onion:1").is_none());
        assert!(NetAddr::parse("example.com:1").is_none());
    }

    #[test]
    fn groups() {
        let a = NetAddr::parse("8.8.1.1:1").unwrap();
        let b = NetAddr::parse("8.8.200.3:2").unwrap();
        let c = NetAddr::parse("8.9.1.1:1").unwrap();
        assert_eq!(a.group(), b.group());
        assert_ne!(a.group(), c.group());
        // IPv4-mapped IPv6 groups like IPv4.
        let m = NetAddr::parse("[::ffff:8.8.9.9]:1").unwrap();
        assert_eq!(m.group(), a.group());
    }

    #[test]
    fn routability() {
        for s in [
            "127.0.0.1:1",
            "10.1.2.3:1",
            "192.168.1.1:1",
            "169.254.1.1:1",
            "0.1.2.3:1",
            "100.64.0.1:1",
            "[::1]:1",
            "[fe80::1]:1",
            "[fd00::1]:1",
            "8.8.8.8:0",
        ] {
            assert!(!NetAddr::parse(s).unwrap().is_routable(), "{s}");
        }
        for s in ["8.8.8.8:1", "[2a00:1450::1]:1"] {
            assert!(NetAddr::parse(s).unwrap().is_routable(), "{s}");
        }
    }

    #[test]
    fn bad_encodings_are_rejected() {
        for bytes in [vec![7u8, 0, 0], vec![TAG_ONION; 20], vec![TAG_V4, 1, 2]] {
            let mut r = Reader::new(&bytes);
            assert!(NetAddr::decode(&mut r).is_err());
        }
        let mut bad_host = vec![TAG_ONION];
        bad_host.extend_from_slice(&[b'A'; ONION_LEN]); // uppercase is not canonical
        bad_host.extend_from_slice(&[1, 0]);
        assert!(NetAddr::decode(&mut Reader::new(&bad_host)).is_err());
    }
}
