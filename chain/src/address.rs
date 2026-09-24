//! Address strings (docs/blocks.md §10).
//!
//! ```text
//! payload  = tag (1) ‖ D (32) ‖ C (32) ‖ checksum (4)
//! checksum = H32("address/checksum", tag ‖ D ‖ C)[0..4]
//! string   = base58(payload)
//! ```
//!
//! The tag is different per network, so an address for one network is rejected by
//! another. The checksum catches typos. Every address, primary or sub, has the same
//! format, so the string reveals nothing about which kind it is.

use blacksilk_consensus::Network;
use blacksilk_crypto::hash::{h32, tags};
use blacksilk_crypto::keys::Address;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressError {
    Base58,
    Length,
    WrongNetwork,
    Checksum,
    /// Not a canonical, non-identity pair of points.
    InvalidKeys,
}

fn tag(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0x1b,
        Network::Testnet => 0x5a,
        Network::Regtest => 0x7e,
    }
}

fn checksum(tag: u8, keys: &[u8; 64]) -> [u8; 4] {
    let h = h32(tags::ADDRESS_CHECKSUM, &[&[tag], keys]);
    [h[0], h[1], h[2], h[3]]
}

pub fn encode_address(network: Network, address: &Address) -> String {
    let keys = address.to_bytes();
    let t = tag(network);
    let mut payload = Vec::with_capacity(69);
    payload.push(t);
    payload.extend_from_slice(&keys);
    payload.extend_from_slice(&checksum(t, &keys));
    bs58::encode(payload).into_string()
}

pub fn decode_address(network: Network, s: &str) -> Result<Address, AddressError> {
    let payload = bs58::decode(s.trim())
        .into_vec()
        .map_err(|_| AddressError::Base58)?;
    if payload.len() != 69 {
        return Err(AddressError::Length);
    }
    let keys: [u8; 64] = payload[1..65].try_into().expect("length checked");
    if checksum(payload[0], &keys) != payload[65..69] {
        return Err(AddressError::Checksum);
    }
    if payload[0] != tag(network) {
        return Err(AddressError::WrongNetwork);
    }
    Address::from_bytes(&keys).ok_or(AddressError::InvalidKeys)
}

// ---- PX addresses (docs/px.md §6) ----

/// Length of an encoded PX address payload.
const PX_PAYLOAD: usize = 1 + 32 + 32 + blacksilk_px::delivery::EK_BYTES + 4;

fn px_tag(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0x2b,
        Network::Testnet => 0x6a,
        Network::Regtest => 0x4e,
    }
}

/// A PX address: `base58(tag ‖ owner ‖ view key ‖ ML-KEM key ‖ checksum)`,
/// with its own per-network tags (never confused with a v1 address).
pub fn encode_px_address(network: Network, a: &blacksilk_px::delivery::Address) -> String {
    let t = px_tag(network);
    let mut body = Vec::with_capacity(PX_PAYLOAD);
    body.push(t);
    body.extend_from_slice(&blacksilk_tx::px::digest_bytes(&a.owner));
    body.extend_from_slice(&a.view);
    body.extend_from_slice(&a.ek);
    let h = h32(tags::ADDRESS_CHECKSUM, &[&body]);
    body.extend_from_slice(&h[..4]);
    bs58::encode(body).into_string()
}

pub fn decode_px_address(
    network: Network,
    s: &str,
) -> Result<blacksilk_px::delivery::Address, AddressError> {
    let payload = bs58::decode(s.trim())
        .into_vec()
        .map_err(|_| AddressError::Base58)?;
    if payload.len() != PX_PAYLOAD {
        return Err(AddressError::Length);
    }
    let (body, sum) = payload.split_at(PX_PAYLOAD - 4);
    if h32(tags::ADDRESS_CHECKSUM, &[body])[..4] != *sum {
        return Err(AddressError::Checksum);
    }
    if body[0] != px_tag(network) {
        return Err(AddressError::WrongNetwork);
    }
    let mut owner = [0u32; 8];
    for (i, x) in owner.iter_mut().enumerate() {
        *x = u32::from_le_bytes(body[1 + 4 * i..5 + 4 * i].try_into().expect("4 bytes"));
        if *x >= blacksilk_px_core::P {
            return Err(AddressError::InvalidKeys);
        }
    }
    let view: [u8; 32] = body[33..65].try_into().expect("32 bytes");
    if blacksilk_crypto::Point::decode(&view).is_none() {
        return Err(AddressError::InvalidKeys);
    }
    Ok(blacksilk_px::delivery::Address {
        owner,
        view,
        ek: body[65..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};

    #[test]
    fn px_addresses_round_trip_and_are_separated() {
        let acct = blacksilk_px::wallet::Account::from_seed(&[3; 32]);
        let a = acct.address(4);
        for net in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            let s = encode_px_address(net, &a);
            assert_eq!(decode_px_address(net, &s), Ok(a.clone()));
            // Not a v1 address, and not valid on another network.
            assert!(decode_address(net, &s).is_err());
        }
        let s = encode_px_address(Network::Testnet, &a);
        assert_eq!(
            decode_px_address(Network::Mainnet, &s),
            Err(AddressError::WrongNetwork)
        );
        let mut bad = s.clone().into_bytes();
        let last = bad.len() - 1;
        bad[last] = if bad[last] == b'2' { b'3' } else { b'2' };
        assert!(decode_px_address(Network::Testnet, std::str::from_utf8(&bad).unwrap()).is_err());
    }

    #[test]
    fn round_trip_and_network_separation() {
        let w = WalletKeys::from_seed(&[7; 32]);
        for idx in [SubaddressIndex::PRIMARY, SubaddressIndex::new(2, 9)] {
            let a = w.address(idx);
            for net in [Network::Mainnet, Network::Testnet, Network::Regtest] {
                let s = encode_address(net, &a);
                assert_eq!(decode_address(net, &s), Ok(a));
            }
            let s = encode_address(Network::Testnet, &a);
            assert_eq!(
                decode_address(Network::Mainnet, &s),
                Err(AddressError::WrongNetwork)
            );
        }
    }

    #[test]
    fn typos_are_detected() {
        let w = WalletKeys::from_seed(&[8; 32]);
        let s = encode_address(Network::Testnet, &w.address(SubaddressIndex::PRIMARY));
        let chars: Vec<char> = s.chars().collect();
        let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        for i in 0..chars.len() {
            let mut c = chars.clone();
            c[i] = alphabet.chars().find(|&x| x != chars[i]).unwrap();
            let t: String = c.into_iter().collect();
            assert!(
                decode_address(Network::Testnet, &t).is_err(),
                "position {i}"
            );
        }
        assert_eq!(
            decode_address(Network::Testnet, "0OIl"),
            Err(AddressError::Base58)
        );
        assert_eq!(
            decode_address(Network::Testnet, "abc"),
            Err(AddressError::Length)
        );
    }

    #[test]
    fn primary_and_subaddress_strings_look_alike() {
        let w = WalletKeys::from_seed(&[9; 32]);
        let a = encode_address(Network::Mainnet, &w.address(SubaddressIndex::PRIMARY));
        let b = encode_address(Network::Mainnet, &w.address(SubaddressIndex::new(0, 1)));
        // Same payload layout and length; base58 length varies by at most one character.
        assert!(a.len().abs_diff(b.len()) <= 1);
        assert!(
            decode_address(Network::Mainnet, &a).is_ok()
                && decode_address(Network::Mainnet, &b).is_ok()
        );
    }
}
