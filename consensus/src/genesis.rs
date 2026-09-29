//! Genesis construction from a committed beacon (docs/testnet-v3-genesis.md;
//! dossier 40, decision "Agent 40").
//!
//! Every genesis field is fixed and announced before the beacon exists, except
//! the nonce, which is **derived here** from the hash of a Bitcoin block at an
//! announced height `H`:
//!
//! ```text
//! beacon = the 32 bytes of Bitcoin block H's hash in DISPLAY order
//!          (the hex printed by `bitcoin-cli getblockhash H`, decoded left to right)
//! d      = Blake2b-256("BlackSilk/genesis-nonce/v1" ‖ LE32(network_id) ‖ LE64(H) ‖ beacon)
//! nonce  = LE64(d[0..8])
//! ```
//!
//! A network's genesis is a [`GenesisSpec`] constant. There is no nonce field to
//! paste and no runtime override: the nonce is a function of the committed
//! [`Beacon`], so a nonce can never disagree with its beacon. A network that needs
//! a beacon and has none yet is **not final** ([`GenesisSpec::is_final`]); its
//! nonce is 0 until the final commit sets `beacon: Some(..)`.

use crate::hash::{Hash, H};
use crate::header::BlockHeader;

/// The domain string of the nonce derivation.
pub const NONCE_DOMAIN: &[u8] = b"BlackSilk/genesis-nonce/v1";

/// A network id reserved for test vectors (the known answers here, in
/// `tools/genesis` and in the consensus manifest's samples). Never a
/// network's id, so a known answer never collides with a real genesis
/// (decisions "Agent 40": the final testnet id is `0x0001_D673`).
pub const TEST_VECTOR_NETWORK_ID: u32 = 0xFFFF_FF00;

/// The committed beacon: Bitcoin block `btc_height`'s hash, in display order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Beacon {
    pub btc_height: u64,
    /// The block hash as printed by Bitcoin Core and explorers, decoded left to
    /// right (no byte reversal): see [`parse_display_hex`].
    pub btc_hash_display: [u8; 32],
}

/// Everything a network's genesis is built from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisSpec {
    pub network_id: u32,
    /// `T_g`, Unix seconds.
    pub timestamp: u64,
    /// `D0`, the genesis and block-1 difficulty.
    pub difficulty: u64,
    /// Whether the genesis must carry beacon entropy before the network is
    /// usable (testnet, mainnet). A local network (regtest) needs none.
    pub needs_beacon: bool,
    /// The committed beacon, once it exists. `None`: nonce 0.
    pub beacon: Option<Beacon>,
}

impl GenesisSpec {
    /// The nonce: derived from the beacon, or 0 without one.
    pub fn nonce(&self) -> u64 {
        match &self.beacon {
            Some(b) => derive_genesis_nonce(self.network_id, b.btc_height, &b.btc_hash_display),
            None => 0,
        }
    }

    /// Whether this genesis is the final one: it needs no beacon, or its beacon
    /// is committed. Binaries refuse a network whose genesis is not final.
    pub fn is_final(&self) -> bool {
        !self.needs_beacon || self.beacon.is_some()
    }

    /// The genesis header. Every field but the nonce is fixed: `version` (the
    /// first epoch's header version), height 0, zero parent, the empty body's
    /// root (zero, docs/blocks.md §3), the announced timestamp and difficulty.
    pub fn header(&self, version: u32) -> BlockHeader {
        BlockHeader {
            version,
            height: 0,
            prev_id: [0; 32],
            timestamp: self.timestamp,
            difficulty: self.difficulty,
            tx_root: [0; 32],
            nonce: self.nonce(),
        }
    }
}

/// The exact bytes hashed for the nonce: 26 + 4 + 8 + 32 = 70 bytes.
pub fn nonce_preimage(network_id: u32, btc_height: u64, beacon: &[u8; 32]) -> Vec<u8> {
    let mut p = Vec::with_capacity(NONCE_DOMAIN.len() + 44);
    p.extend_from_slice(NONCE_DOMAIN);
    p.extend_from_slice(&network_id.to_le_bytes());
    p.extend_from_slice(&btc_height.to_le_bytes());
    p.extend_from_slice(beacon);
    p
}

/// The full 32-byte digest behind the nonce (for manual checks with
/// `b2sum -l 256`).
pub fn nonce_preimage_digest(network_id: u32, btc_height: u64, beacon: &[u8; 32]) -> Hash {
    H::new()
        .chain(&nonce_preimage(network_id, btc_height, beacon))
        .finish()
}

/// `LE64(Blake2b-256(NONCE_DOMAIN ‖ LE32(network_id) ‖ LE64(btc_height) ‖ beacon)[0..8])`.
pub fn derive_genesis_nonce(network_id: u32, btc_height: u64, beacon: &[u8; 32]) -> u64 {
    let d = nonce_preimage_digest(network_id, btc_height, beacon);
    u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

/// Decodes a 64-hex-digit block hash given in display order, left to right.
pub fn parse_display_hex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim().as_bytes();
    if s.len() != 64 {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16).map(|v| v as u8);
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = digit(s[2 * i])? << 4 | digit(s[2 * i + 1])?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bitcoin block 0's hash, display order (public).
    const BTC0: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// The known answer of tools/genesis: Bitcoin block 0, H = 0, the reserved
    /// test-vector network id (recomputed independently from the spec in
    /// Python, fingerprint v3). Before fingerprint v3 the known answer used
    /// 0x0001D673, now the final testnet id: digest `3c437d97…`, nonce
    /// `0x351e3bcf977d433c`, still reproduced here as a second vector.
    #[test]
    fn known_answer_bitcoin_block_0() {
        let beacon = parse_display_hex(BTC0).unwrap();
        assert_eq!(beacon[0], 0x00);
        assert_eq!(beacon[31], 0x6f);
        assert_eq!(
            hex(&nonce_preimage_digest(TEST_VECTOR_NETWORK_ID, 0, &beacon)),
            "5081810a27720a228d4620fd4d69d67d55b5b894d87642f49a1186e5049340a9"
        );
        assert_eq!(
            derive_genesis_nonce(TEST_VECTOR_NETWORK_ID, 0, &beacon),
            0x220a_7227_0a81_8150
        );
        assert!(hex(&nonce_preimage_digest(0x0001_D673, 0, &beacon)).starts_with("3c437d97"));
        assert_eq!(
            derive_genesis_nonce(0x0001_D673, 0, &beacon),
            0x351e_3bcf_977d_433c
        );
    }

    #[test]
    fn preimage_layout() {
        let p = nonce_preimage(0x0102_0304, 0x0506_0708_090a_0b0c, &[0xEE; 32]);
        assert_eq!(p.len(), 70);
        assert_eq!(&p[..26], NONCE_DOMAIN);
        assert_eq!(&p[26..30], &[4, 3, 2, 1]);
        assert_eq!(&p[30..38], &[0x0c, 0x0b, 0x0a, 9, 8, 7, 6, 5]);
        assert_eq!(&p[38..], &[0xEE; 32]);
    }

    #[test]
    fn display_hex_is_strict() {
        assert!(parse_display_hex(&BTC0[1..]).is_none());
        assert!(parse_display_hex(&format!("{BTC0}0")).is_none());
        assert!(parse_display_hex(&BTC0.replace('f', "g")).is_none());
        assert!(parse_display_hex(&BTC0.replace('0', "+")).is_none());
        assert_eq!(
            parse_display_hex(&BTC0.to_uppercase()),
            parse_display_hex(BTC0)
        );
    }

    /// A spec with a dummy beacon (tests only; no real genesis is generated):
    /// the nonce is the derivation of that beacon, every other field is the
    /// spec's, and the beacon alone decides finality.
    #[test]
    fn nonce_comes_from_the_committed_beacon() {
        let dummy = Beacon {
            btc_height: 123_456,
            btc_hash_display: [0xA5; 32],
        };
        let pending = GenesisSpec {
            network_id: 0xFFFF_FF00,
            timestamp: 1_800_000_000,
            difficulty: 700,
            needs_beacon: true,
            beacon: None,
        };
        assert!(!pending.is_final());
        assert_eq!(pending.nonce(), 0);
        let done = GenesisSpec {
            beacon: Some(dummy),
            ..pending
        };
        assert!(done.is_final());
        let h = done.header(1);
        assert_eq!(
            h.nonce,
            derive_genesis_nonce(0xFFFF_FF00, 123_456, &[0xA5; 32])
        );
        assert_ne!(h.nonce, 0);
        assert_eq!(
            (h.version, h.height, h.prev_id, h.tx_root),
            (1, 0, [0; 32], [0; 32])
        );
        assert_eq!((h.timestamp, h.difficulty), (1_800_000_000, 700));
        // Every beacon input moves the nonce.
        for other in [
            Beacon {
                btc_height: 123_457,
                ..dummy
            },
            Beacon {
                btc_hash_display: [0xA4; 32],
                ..dummy
            },
        ] {
            let g = GenesisSpec {
                beacon: Some(other),
                ..pending
            };
            assert_ne!(g.nonce(), h.nonce);
        }
        let other_net = GenesisSpec {
            network_id: 0xFFFF_FF01,
            ..done
        };
        assert_ne!(other_net.nonce(), h.nonce);
        // A local network needs no beacon.
        let local = GenesisSpec {
            needs_beacon: false,
            ..pending
        };
        assert!(local.is_final());
        assert_eq!(local.nonce(), 0);
    }
}
