//! Network addresses (docs/p2p.md §5, §9): the address type, its canonical
//! form, routability, network groups, Tor v3 names, and the two encodings
//! (`Version.listen` and the timestamped `Addr` entries).

use blacksilk_tx::codec::{DecodeError, Reader, Writer};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// `Version.listen` encoding.
const TAG_V4: u8 = 0x04;
const TAG_V6: u8 = 0x06;
const TAG_ONION: u8 = 0x0a;
/// Length of a Tor v3 host name without ".onion".
pub const ONION_LEN: usize = 56;
/// Length of a Tor v3 public key.
pub const ONION_KEY_LEN: usize = 32;
/// The version byte of Tor v3 names.
const ONION_VERSION: u8 = 3;

/// Network ids of `Addr` entries (docs/p2p.md §5; BIP155's numbering).
pub const NET_IPV4: u8 = 1;
pub const NET_IPV6: u8 = 2;
/// A Tor v3 service, as its 32-byte public key.
pub const NET_TORV3: u8 = 4;
/// The longest address an `Addr` entry may carry, of any network.
pub const MAX_ADDR_LEN: u64 = 512;

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

// ------------------------------------------------------------ Tor v3 names

const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn base32_value(c: u8) -> Option<u8> {
    match c {
        b'a'..=b'z' => Some(c - b'a'),
        b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    }
}

/// `SHA3-256(".onion checksum" ‖ key ‖ version)[..2]` (rend-spec-v3,
/// "Encoding onion addresses").
fn onion_checksum(key: &[u8; ONION_KEY_LEN], version: u8) -> [u8; 2] {
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(key);
    h.update([version]);
    let d = h.finalize();
    [d[0], d[1]]
}

/// The public key of a valid Tor v3 name (lowercase, without ".onion"):
/// `base32(key ‖ checksum ‖ version)` with version 3 and the checksum above.
pub fn onion_key(host: &str) -> Option<[u8; ONION_KEY_LEN]> {
    if host.len() != ONION_LEN {
        return None;
    }
    // 56 characters of 5 bits are exactly 35 bytes.
    let mut raw = [0u8; 35];
    let mut acc = 0u16;
    let mut bits = 0;
    let mut i = 0;
    for c in host.bytes() {
        acc = (acc << 5) | u16::from(base32_value(c)?);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            raw[i] = (acc >> bits) as u8;
            i += 1;
        }
    }
    let key: [u8; ONION_KEY_LEN] = raw[..ONION_KEY_LEN].try_into().expect("32 bytes");
    (raw[34] == ONION_VERSION && raw[32..34] == onion_checksum(&key, ONION_VERSION)).then_some(key)
}

/// The Tor v3 name (lowercase, without ".onion") of a public key.
pub fn onion_host(key: &[u8; ONION_KEY_LEN]) -> String {
    let mut raw = [0u8; 35];
    raw[..ONION_KEY_LEN].copy_from_slice(key);
    raw[32..34].copy_from_slice(&onion_checksum(key, ONION_VERSION));
    raw[34] = ONION_VERSION;
    let mut out = String::with_capacity(ONION_LEN);
    let mut acc = 0u16;
    let mut bits = 0;
    for b in raw {
        acc = (acc << 8) | u16::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[usize::from((acc >> bits) & 31)] as char);
        }
    }
    out
}

// ------------------------------------------------------------ IP rules

/// The IPv4 address an IPv6 address embeds, for the forms that route to an
/// IPv4 host: IPv4-mapped (`::ffff:0:0/96`), 6to4 (`2002::/16`), NAT64
/// (`64:ff9b::/96`) and Teredo (`2001::/32`, client address complemented).
fn embedded_v4(ip: &Ipv6Addr) -> Option<Ipv4Addr> {
    let o = ip.octets();
    let s = ip.segments();
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0; 4] {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    if s[0] == 0x2001 && s[1] == 0 {
        return Some(Ipv4Addr::new(!o[12], !o[13], !o[14], !o[15]));
    }
    None
}

fn v4_routable(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // shared address space (CGNAT)
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // benchmarking
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // IETF protocol assignments
        || o[0] >= 240) // reserved
}

fn v6_routable(ip: Ipv6Addr) -> bool {
    if let Some(v4) = embedded_v4(&ip) {
        return v4_routable(v4);
    }
    let s = ip.segments();
    !(ip.is_multicast()
        || s[..6] == [0; 6] // ::/96: unspecified, loopback, IPv4-compatible
        || (s[0] & 0xfe00) == 0xfc00 // unique local
        || (s[0] & 0xffc0) == 0xfe80 // link local
        || (s[0] & 0xffc0) == 0xfec0 // site local (deprecated)
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0010) // ORCHID
        || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0020) // ORCHIDv2
        || (s[0] == 0x0100 && s[1..4] == [0; 3])) // discard-only
}

impl NetAddr {
    /// Parses `1.2.3.4:5`, `[::1]:5` or `<56 chars>.onion:5`. IP addresses are
    /// canonical ([`NetAddr::canonical`]); an onion name must be a valid Tor
    /// v3 name (upper case is accepted and lowered).
    pub fn parse(s: &str) -> Option<Self> {
        if let Ok(a) = s.parse::<SocketAddr>() {
            return Some(NetAddr::Ip(a).canonical());
        }
        let (host, port) = s.rsplit_once(':')?;
        let host = host.strip_suffix(".onion")?.to_ascii_lowercase();
        let port: u16 = port.parse().ok()?;
        onion_key(&host)?;
        Some(NetAddr::Onion { host, port })
    }

    /// The onion address of a Tor v3 public key.
    pub fn from_onion_key(key: &[u8; ONION_KEY_LEN], port: u16) -> Self {
        NetAddr::Onion {
            host: onion_host(key),
            port,
        }
    }

    /// The one form of an address: an IPv4-mapped IPv6 address becomes the
    /// IPv4 address, and IPv6 flow and scope ids are dropped. Every address
    /// from the network or the configuration is made canonical, so bans,
    /// per-IP limits, deduplication and groups see one form per host.
    pub fn canonical(self) -> Self {
        match self {
            NetAddr::Ip(a) => NetAddr::Ip(SocketAddr::new(a.ip().to_canonical(), a.port())),
            onion => onion,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            NetAddr::Ip(a) => a.port(),
            NetAddr::Onion { port, .. } => *port,
        }
    }

    /// The IP address, in canonical form.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            NetAddr::Ip(a) => Some(a.ip().to_canonical()),
            NetAddr::Onion { .. } => None,
        }
    }

    pub fn is_onion(&self) -> bool {
        matches!(self, NetAddr::Onion { .. })
    }

    /// Network group for outbound diversity and bucketing (docs/p2p.md §9),
    /// as Bitcoin Core's `GetGroup` without asmap:
    /// - IPv4: the /16;
    /// - IPv6: the /32, except Hurricane Electric's 2001:470::/32 at /36;
    /// - IPv6 forms embedding an IPv4 address (mapped, 6to4, NAT64, Teredo):
    ///   the embedded IPv4 /16, the same group as that IPv4 address;
    /// - onion: the network plus the first 4 bits of the key (16 groups):
    ///   onion names are free to create, so one group per name would let
    ///   anyone occupy any number of groups.
    pub fn group(&self) -> Vec<u8> {
        match self {
            NetAddr::Ip(a) => match a.ip() {
                IpAddr::V4(v4) => {
                    let o = v4.octets();
                    vec![4, o[0], o[1]]
                }
                IpAddr::V6(v6) => {
                    if let Some(v4) = embedded_v4(&v6) {
                        let o = v4.octets();
                        return vec![4, o[0], o[1]];
                    }
                    let o = v6.octets();
                    if o[..4] == [0x20, 0x01, 0x04, 0x70] {
                        return vec![6, o[0], o[1], o[2], o[3], o[4] & 0xf0];
                    }
                    vec![6, o[0], o[1], o[2], o[3]]
                }
            },
            // The first base32 character holds the key's first 5 bits.
            NetAddr::Onion { host, .. } => {
                let first = host.bytes().next().and_then(base32_value).unwrap_or(0);
                vec![10, first >> 1]
            }
        }
    }

    /// Whether the address is worth storing, relaying and dialing on the
    /// public network: not loopback, private, link-local, unspecified,
    /// multicast, documentation or another special-purpose range, including
    /// such an IPv4 address embedded in IPv6; an onion address only with a
    /// valid Tor v3 name. Port 0 never is.
    pub fn is_routable(&self) -> bool {
        match self {
            NetAddr::Onion { host, port } => *port != 0 && onion_key(host).is_some(),
            NetAddr::Ip(a) => {
                a.port() != 0
                    && match a.ip() {
                        IpAddr::V4(ip) => v4_routable(ip),
                        IpAddr::V6(ip) => v6_routable(ip),
                    }
            }
        }
    }

    /// The `Version.listen` encoding: a tag (4, 6 or 10), the address (4 or
    /// 16 bytes, or the 56-character onion name) and the port (LE16).
    pub fn encode(&self, w: &mut Writer) {
        match self.clone().canonical() {
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
                let mut h = [b'a'; ONION_LEN];
                let n = host.len().min(ONION_LEN);
                h[..n].copy_from_slice(&host.as_bytes()[..n]);
                w.bytes(&h);
                w.bytes(&port.to_le_bytes());
            }
        }
    }

    /// Decodes the `Version.listen` encoding. Non-canonical forms (an
    /// IPv4-mapped IPv6 address) and invalid onion names are errors.
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
                ip6(o, port).ok_or(DecodeError::UnknownKind(tag))?
            }
            TAG_ONION => {
                let h: [u8; ONION_LEN] = r.array()?;
                let port = u16::from_le_bytes(r.array()?);
                let host =
                    String::from_utf8(h.to_vec()).map_err(|_| DecodeError::UnknownKind(tag))?;
                if onion_key(&host).is_none() {
                    return Err(DecodeError::UnknownKind(tag));
                }
                NetAddr::Onion { host, port }
            }
            other => return Err(DecodeError::UnknownKind(other)),
        };
        Ok(addr)
    }
}

/// An IPv6 address from the wire; `None` for an IPv4-mapped one (which must
/// be sent as IPv4).
fn ip6(o: [u8; 16], port: u16) -> Option<NetAddr> {
    let v6 = Ipv6Addr::from(o);
    v6.to_ipv4_mapped()
        .is_none()
        .then(|| NetAddr::Ip(SocketAddr::new(IpAddr::V6(v6), port)))
}

/// The identity inbound limits and bans key on (docs/p2p.md §9, §10;
/// dossier 32 W6): an IPv4 address itself, an IPv6 address's /64 (the low 64
/// bits cleared). One IPv6 host is routinely given a whole /64, so keying on
/// the full address would let it take one per-IP allowance per address, and
/// a ban of one address would not stop it. An IPv4-mapped IPv6 address is
/// its IPv4 address.
pub fn peer_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let masked = u128::from(v6) & !((1u128 << 64) - 1);
            IpAddr::V6(Ipv6Addr::from(masked))
        }
        v4 => v4,
    }
}

// ------------------------------------------------------------ Addr entries

/// The address of an `Addr` entry: one of the networks this version knows,
/// or one it does not (kept as received, never stored, dialed or relayed; a
/// later version may add networks without old nodes rejecting its messages).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryAddr {
    Known(NetAddr),
    Unknown { net: u8, bytes: Vec<u8>, port: u16 },
}

/// One `Addr` entry (docs/p2p.md §5):
/// `LE32 time ‖ u8 network ‖ varint length ‖ address ‖ LE16 port`.
///
/// `time` is the sender's claim of when the address was last seen (Unix
/// seconds; 0 = unknown). It is never trusted for a security decision: the
/// receiver uses it only to decide whether an address is fresh enough to
/// relay (docs/p2p.md §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrEntry {
    pub time: u32,
    pub addr: EntryAddr,
}

impl AddrEntry {
    pub fn new(time: u32, addr: NetAddr) -> Self {
        Self {
            time,
            addr: EntryAddr::Known(addr),
        }
    }

    /// The address, if of a network this version knows.
    pub fn known(&self) -> Option<&NetAddr> {
        match &self.addr {
            EntryAddr::Known(a) => Some(a),
            EntryAddr::Unknown { .. } => None,
        }
    }

    pub fn encode(&self, w: &mut Writer) {
        w.bytes(&self.time.to_le_bytes());
        let (net, bytes, port) = match &self.addr {
            EntryAddr::Known(a) => match a.clone().canonical() {
                NetAddr::Ip(s) => match s.ip() {
                    IpAddr::V4(v4) => (NET_IPV4, v4.octets().to_vec(), s.port()),
                    IpAddr::V6(v6) => (NET_IPV6, v6.octets().to_vec(), s.port()),
                },
                NetAddr::Onion { host, port } => {
                    // Only valid names are ever built by the node (parse and
                    // decode refuse others, and it sends only routable
                    // addresses); anything else is sent as the zero key.
                    let key = onion_key(&host).unwrap_or([0; ONION_KEY_LEN]);
                    (NET_TORV3, key.to_vec(), port)
                }
            },
            EntryAddr::Unknown { net, bytes, port } => (*net, bytes.clone(), *port),
        };
        w.u8(net);
        w.varint(bytes.len() as u64);
        w.bytes(&bytes);
        w.bytes(&port.to_le_bytes());
    }

    /// Decodes one entry. Errors (the sender is penalized for a malformed
    /// message): an address longer than [`MAX_ADDR_LEN`], a known network
    /// with the wrong length, or an IPv4-mapped IPv6 address.
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let time = u32::from_le_bytes(r.array()?);
        let net = r.u8()?;
        let len = r.count("address length", 0, MAX_ADDR_LEN)?;
        let start = r.position();
        r.skip(len)?;
        let bytes = r.slice(start, start + len);
        let port = u16::from_le_bytes(r.array()?);
        let wrong = || DecodeError::UnknownKind(net);
        let addr = match net {
            NET_IPV4 => {
                let o: [u8; 4] = bytes.try_into().map_err(|_| wrong())?;
                EntryAddr::Known(NetAddr::Ip(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(o)),
                    port,
                )))
            }
            NET_IPV6 => {
                let o: [u8; 16] = bytes.try_into().map_err(|_| wrong())?;
                EntryAddr::Known(ip6(o, port).ok_or_else(wrong)?)
            }
            NET_TORV3 => {
                let key: [u8; ONION_KEY_LEN] = bytes.try_into().map_err(|_| wrong())?;
                EntryAddr::Known(NetAddr::from_onion_key(&key, port))
            }
            _ => EntryAddr::Unknown {
                net,
                bytes: bytes.to_vec(),
                port,
            },
        };
        Ok(Self { time, addr })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// torproject.org's onion service (a real v3 name).
    const ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid";

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
            // The same through an `Addr` entry.
            let e = AddrEntry::new(77, a);
            let mut w = Writer::new();
            e.encode(&mut w);
            let bytes = w.into_bytes();
            let mut r = Reader::new(&bytes);
            assert_eq!(AddrEntry::decode(&mut r).unwrap(), e);
            r.finish().unwrap();
        }
        assert!(NetAddr::parse("bad.onion:1").is_none());
        assert!(NetAddr::parse("example.com:1").is_none());
    }

    /// The Tor key and name conversions invert each other, and every key
    /// gives a name that validates.
    #[test]
    fn onion_keys_and_names() {
        let key = onion_key(ONION).unwrap();
        assert_eq!(onion_host(&key), ONION);
        for b in 0..=255u8 {
            let k = [b; ONION_KEY_LEN];
            let h = onion_host(&k);
            assert_eq!(h.len(), ONION_LEN);
            assert_eq!(onion_key(&h), Some(k));
            assert_eq!(
                NetAddr::from_onion_key(&k, 1).group(),
                vec![10, b >> 4],
                "the group is the key's first 4 bits"
            );
        }
        // Wrong version byte, with a matching checksum for that version.
        let mut raw = key.to_vec();
        raw.extend_from_slice(&onion_checksum(&key, 2));
        raw.push(2);
        let mut h = String::new();
        let (mut acc, mut bits) = (0u16, 0);
        for b in raw {
            acc = (acc << 8) | u16::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                h.push(BASE32[usize::from((acc >> bits) & 31)] as char);
            }
        }
        assert!(onion_key(&h).is_none(), "version 2");
        assert!(
            onion_key(&ONION.to_ascii_uppercase()).is_none(),
            "lower case only"
        );
    }

    #[test]
    fn groups() {
        let a = NetAddr::parse("8.8.1.1:1").unwrap();
        let b = NetAddr::parse("8.8.200.3:2").unwrap();
        let c = NetAddr::parse("8.9.1.1:1").unwrap();
        assert_eq!(a.group(), b.group());
        assert_ne!(a.group(), c.group());
        // IPv4-mapped IPv6 groups like IPv4, even if not made canonical.
        let m = NetAddr::Ip("[::ffff:8.8.9.9]:1".parse().unwrap());
        assert_eq!(m.group(), a.group());
        assert_eq!(m.ip(), NetAddr::parse("8.8.9.9:1").unwrap().ip());
    }

    /// W6: one IPv6 /64 is one peer identity; IPv4 addresses are their own;
    /// an IPv4-mapped address is its IPv4 address.
    #[test]
    fn ipv6_slash64_counts_as_one_ip() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(
            peer_key(ip("2a00:1450:1:2:aaaa::1")),
            peer_key(ip("2a00:1450:1:2:ffff:ffff:ffff:ffff"))
        );
        assert_eq!(peer_key(ip("2a00:1450:1:2:aaaa::1")), ip("2a00:1450:1:2::"));
        assert_ne!(
            peer_key(ip("2a00:1450:1:2::1")),
            peer_key(ip("2a00:1450:1:3::1"))
        );
        assert_eq!(peer_key(ip("8.8.8.8")), ip("8.8.8.8"));
        assert_ne!(peer_key(ip("8.8.8.8")), peer_key(ip("8.8.8.9")));
        assert_eq!(peer_key(ip("::ffff:8.8.8.8")), ip("8.8.8.8"));
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
        // An onion name that was never validated (built directly).
        let junk = NetAddr::Onion {
            host: "a".repeat(ONION_LEN),
            port: 1,
        };
        assert!(!junk.is_routable());
    }

    #[test]
    fn bad_encodings_are_rejected() {
        for bytes in [vec![7u8, 0, 0], vec![TAG_ONION; 20], vec![TAG_V4, 1, 2]] {
            let mut r = Reader::new(&bytes);
            assert!(NetAddr::decode(&mut r).is_err());
        }
        let mut bad_host = vec![TAG_ONION];
        bad_host.extend_from_slice(ONION.to_ascii_uppercase().as_bytes()); // not canonical
        bad_host.extend_from_slice(&[1, 0]);
        assert!(NetAddr::decode(&mut Reader::new(&bad_host)).is_err());
        let mut mapped = vec![TAG_V6];
        mapped.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8]);
        mapped.extend_from_slice(&[1, 0]);
        assert!(NetAddr::decode(&mut Reader::new(&mapped)).is_err());
        // Encoding a mapped address writes the IPv4 form.
        let m = NetAddr::Ip("[::ffff:8.8.8.8]:1".parse().unwrap());
        let mut w = Writer::new();
        m.encode(&mut w);
        assert_eq!(w.into_bytes()[0], TAG_V4);
    }
}
