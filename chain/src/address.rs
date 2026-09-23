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

#[cfg(test)]
mod tests {
    use super::*;
    use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};

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
