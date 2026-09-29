//! Genesis construction for a BlackSilk network (docs/testnet-v3-genesis.md;
//! procedure from the R15 review, §4).
//!
//! Every genesis field is fixed and announced **before** the beacon exists,
//! except the nonce, which is derived from the hash of a Bitcoin block at an
//! announced height `H`:
//!
//! ```text
//! beacon = the 32 bytes of Bitcoin block H's hash in DISPLAY order
//!          (the hex printed by `bitcoin-cli getblockhash H`, decoded left to right)
//! d      = Blake2b-256("BlackSilk/genesis-nonce/v1" ‖ LE32(network_id) ‖ LE64(H) ‖ beacon)
//! nonce  = LE64(d[0..8])
//! ```
//!
//! So nobody, the maintainer included, can know the genesis id (and so the
//! first RandomX key) before Bitcoin block `H` is mined, and anyone can
//! recompute it afterwards with any Blake2b implementation (`b2sum -l 256`).
//!
//! The genesis is never validated (docs/blocks.md §3): the nonce is the only
//! field carrying entropy, and the tests pin every other field so that no edit
//! can move entropy elsewhere.
//!
//! The derivation itself lives in consensus (`blacksilk_consensus::genesis`), so
//! the tool and the compiled chain parameters cannot disagree. This crate builds
//! and checks a genesis. It does not change any network's parameters: at launch
//! the owner commits the network's beacon (`TESTNET_BEACON` in
//! `consensus/src/params.rs`), and the node derives the nonce from it.

#![forbid(unsafe_code)]

use blacksilk_consensus::genesis::{Beacon, GenesisSpec};
use blacksilk_consensus::hash::Hash;
use blacksilk_consensus::schedule::V3;
use blacksilk_consensus::BlockHeader;

pub use blacksilk_consensus::genesis::{
    derive_genesis_nonce, nonce_preimage, nonce_preimage_digest, NONCE_DOMAIN,
    TEST_VECTOR_NETWORK_ID,
};

/// The network id of testnet v3, final (decisions "Agent 40"; fingerprint v3):
/// `ChainParams::testnet().network_id`. Its genesis is generated at launch
/// (docs/testnet-v3-genesis.md §3), so it passes [`check_network_id`] until
/// then. No rehearsal or release candidate may use it.
pub const TESTNET_V3_NETWORK_ID: u32 = 0x0001_D673;

/// Every network id already given to a genesis, with what used it. An id is
/// never reused for another genesis: nodes and wallets of the old network
/// would otherwise accept the new one's signatures and blocks' ids.
pub const NETWORK_ID_REGISTRY: &[(u32, &str)] = &[
    (0x0001_D670, "testnet v1 (2026-09-23)"),
    (0x0001_D671, "testnet reset rehearsal (2026-09-25, local)"),
    (0x0001_D672, "testnet v2 (2026-09-26)"),
    (0x000B_1A6C, "mainnet (reserved)"),
    (0x00DE_B06E, "regtest"),
];

/// Bitcoin block 0's hash, in display order (public; used by the known-answer
/// test).
pub const BITCOIN_GENESIS_HASH_HEX: &str =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

/// Divisor applied to the measured honest hash rate when choosing the
/// starting difficulty (SX1: "err low"). A starting difficulty that is too
/// high stalls block 1: LWMA cannot lower it until blocks arrive. One that is
/// too low only makes the first blocks fast, and LWMA raises it within the
/// window.
pub const STARTING_DIFFICULTY_MARGIN: u64 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenesisError {
    /// The beacon is not 64 hexadecimal characters.
    BeaconHex,
    /// The network id is already in [`NETWORK_ID_REGISTRY`].
    NetworkIdReused(u32),
    /// Network id 0 is not allowed.
    NetworkIdZero,
    /// The starting difficulty must be at least 1.
    Difficulty,
    /// The genesis timestamp is later than the moment the genesis is computed:
    /// the timestamp must be fixed before the beacon, and so be in the past by
    /// the time the beacon is known (R15-4).
    TimestampInFuture { timestamp: u64, now: u64 },
    /// The recomputed genesis id differs from the expected one.
    IdMismatch { computed: Hash },
}

impl std::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BeaconHex => write!(f, "the beacon must be 64 hex characters (display order)"),
            Self::NetworkIdReused(id) => write!(
                f,
                "network id {id:#010x} was already used ({}); choose a new one",
                registry_name(*id).unwrap_or("?")
            ),
            Self::NetworkIdZero => write!(f, "network id 0 is not allowed"),
            Self::Difficulty => write!(f, "the starting difficulty must be at least 1"),
            Self::TimestampInFuture { timestamp, now } => write!(
                f,
                "genesis timestamp {timestamp} is after now ({now}): it must be fixed before \
                 the beacon, and so be in the past when the beacon is known"
            ),
            Self::IdMismatch { computed } => {
                write!(f, "genesis id mismatch: computed {}", hex(computed))
            }
        }
    }
}

impl std::error::Error for GenesisError {}

/// What a registered id was used for.
pub fn registry_name(id: u32) -> Option<&'static str> {
    NETWORK_ID_REGISTRY
        .iter()
        .find(|(i, _)| *i == id)
        .map(|(_, n)| *n)
}

/// Refuses network id 0 and every id in [`NETWORK_ID_REGISTRY`].
pub fn check_network_id(id: u32) -> Result<(), GenesisError> {
    if id == 0 {
        return Err(GenesisError::NetworkIdZero);
    }
    if registry_name(id).is_some() {
        return Err(GenesisError::NetworkIdReused(id));
    }
    Ok(())
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decodes a block hash given in **display order** (as printed by Bitcoin
/// Core and block explorers): the bytes are taken left to right, without the
/// little-endian reversal Bitcoin uses internally.
pub fn parse_beacon_hex(s: &str) -> Result<[u8; 32], GenesisError> {
    let s = s.trim();
    if s.len() != 64 || !s.is_ascii() {
        return Err(GenesisError::BeaconHex);
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| GenesisError::BeaconHex)?;
    }
    Ok(out)
}

/// Starting difficulty `D0` from the measured honest hash rate, in
/// milli-hashes per second, and the target block time: the expected work of
/// one block at that rate, divided by [`STARTING_DIFFICULTY_MARGIN`] (err
/// low), at least 1. A block at difficulty `D` takes `D` hashes on average
/// (docs/consensus.md §3), so the honest miners then find block 1 in about
/// `T / MARGIN` seconds.
pub fn starting_difficulty(honest_millihashes_per_s: u64, target_block_time: u64) -> u64 {
    let per_block = honest_millihashes_per_s as u128 * target_block_time as u128 / 1000;
    (per_block / STARTING_DIFFICULTY_MARGIN as u128).clamp(1, u64::MAX as u128) as u64
}

/// Everything a genesis is built from. All fields except the beacon hash are
/// announced before the beacon block exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisInputs {
    pub network_id: u32,
    /// `T_g`, Unix seconds; chosen before the beacon (about 2 h before the
    /// beacon block's expected time).
    pub timestamp: u64,
    /// `D0`, the genesis and block-1 difficulty.
    pub difficulty: u64,
    /// The Bitcoin height `H` of the beacon block.
    pub btc_height: u64,
    /// Bitcoin block `H`'s hash, display order.
    pub btc_hash: [u8; 32],
}

/// A constructed genesis block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Genesis {
    pub header: BlockHeader,
    pub nonce_digest: Hash,
    pub id: Hash,
}

impl Genesis {
    pub fn bytes(&self) -> [u8; blacksilk_consensus::HEADER_SIZE] {
        self.header.to_bytes()
    }
}

/// Builds the genesis header. Every field but the nonce is fixed:
/// version = the header version of the first epoch, height 0, zero parent,
/// the empty body's root (zero, docs/blocks.md §3), the announced timestamp
/// and difficulty. The id is `Blake2b-256("BlackSilk/block-id" ‖
/// LE32(network_id) ‖ header)`, as for every block.
pub fn build(inputs: &GenesisInputs) -> Result<Genesis, GenesisError> {
    check_network_id(inputs.network_id)?;
    if inputs.difficulty == 0 {
        return Err(GenesisError::Difficulty);
    }
    let nonce_digest =
        nonce_preimage_digest(inputs.network_id, inputs.btc_height, &inputs.btc_hash);
    let header: BlockHeader = spec(inputs).header(V3.epoch_at(0).header_version);
    Ok(Genesis {
        header,
        nonce_digest,
        id: header.id(inputs.network_id),
    })
}

/// The consensus genesis specification of `inputs`, with the beacon committed.
pub fn spec(inputs: &GenesisInputs) -> GenesisSpec {
    GenesisSpec {
        network_id: inputs.network_id,
        timestamp: inputs.timestamp,
        difficulty: inputs.difficulty,
        needs_beacon: true,
        beacon: Some(Beacon {
            btc_height: inputs.btc_height,
            btc_hash_display: inputs.btc_hash,
        }),
    }
}

/// [`build`], refusing a timestamp later than `now` (R15-4: the timestamp is
/// fixed before the beacon, so by the time the beacon is known the genesis is
/// in the past, and no block can be mined ahead with a future timestamp).
pub fn generate(inputs: &GenesisInputs, now: u64) -> Result<Genesis, GenesisError> {
    if inputs.timestamp > now {
        return Err(GenesisError::TimestampInFuture {
            timestamp: inputs.timestamp,
            now,
        });
    }
    build(inputs)
}

/// Recomputes the genesis from its inputs and compares its id with
/// `expected_id`. Independent of the clock.
pub fn verify(inputs: &GenesisInputs, expected_id: &Hash) -> Result<Genesis, GenesisError> {
    let g = build(inputs)?;
    if g.id != *expected_id {
        return Err(GenesisError::IdMismatch { computed: g.id });
    }
    Ok(g)
}

/// A human-readable report: inputs, the nonce derivation, the header fields,
/// its bytes and id.
pub fn report(inputs: &GenesisInputs, g: &Genesis) -> String {
    let h = &g.header;
    format!(
        "inputs\n\
         \x20 network id        {nid:#010x}\n\
         \x20 timestamp (T_g)   {ts}\n\
         \x20 difficulty (D0)   {d}\n\
         \x20 beacon height (H) {bh}\n\
         \x20 beacon hash       {bhash} (display order)\n\
         nonce derivation\n\
         \x20 preimage          {pre}\n\
         \x20 Blake2b-256       {dig}\n\
         \x20 nonce (LE64 d[0..8]) {nonce} ({nonce:#018x})\n\
         genesis header\n\
         \x20 version {v}, height {height}, prev_id 0, tx_root 0\n\
         \x20 timestamp {ts}, difficulty {d}, nonce {nonce}\n\
         \x20 bytes {bytes}\n\
         genesis id {id}\n",
        nid = inputs.network_id,
        ts = h.timestamp,
        d = h.difficulty,
        bh = inputs.btc_height,
        bhash = hex(&inputs.btc_hash),
        pre = hex(&nonce_preimage(
            inputs.network_id,
            inputs.btc_height,
            &inputs.btc_hash
        )),
        dig = hex(&g.nonce_digest),
        nonce = h.nonce,
        v = h.version,
        height = h.height,
        bytes = hex(&g.bytes()),
        id = hex(&g.id),
    )
}

/// The values the final commit sets in `consensus/src/params.rs` (and the pinned
/// id test) at launch. There is no nonce constant: consensus derives the nonce
/// from the committed beacon; it is printed as a comment for cross-checking only.
pub fn rust_constants(inputs: &GenesisInputs, g: &Genesis) -> String {
    let bytes: Vec<String> = inputs
        .btc_hash
        .iter()
        .map(|b| format!("{b:#04x}"))
        .collect();
    format!(
        "// Testnet genesis inputs, built by tools/genesis (docs/testnet-v3-genesis.md).\n\
         // network id {nid:#010x}, genesis time {ts}, D0 {d}\n\
         // beacon: Bitcoin block {bh}, hash (display order) {bhash}\n\
         pub const TESTNET_BEACON: Option<Beacon> = Some(Beacon {{\n\
         \x20   btc_height: {bh},\n\
         \x20   btc_hash_display: [{arr}],\n\
         }});\n\
         // derived nonce (not a constant; cross-check only): {nonce:#018x}\n\
         const TESTNET_GENESIS_ID: &str =\n    \"{id}\";\n",
        nid = inputs.network_id,
        ts = inputs.timestamp,
        d = inputs.difficulty,
        bh = inputs.btc_height,
        bhash = hex(&inputs.btc_hash),
        arr = bytes.join(", "),
        nonce = g.header.nonce,
        id = hex(&g.id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preimage_layout() {
        let p = nonce_preimage(0x0102_0304, 0x0506_0708_090A_0B0C, &[0xAA; 32]);
        assert_eq!(p.len(), 26 + 4 + 8 + 32);
        assert_eq!(&p[..26], NONCE_DOMAIN);
        assert_eq!(&p[26..30], &[4, 3, 2, 1]);
        assert_eq!(&p[30..38], &[0x0C, 0x0B, 0x0A, 9, 8, 7, 6, 5]);
        assert_eq!(&p[38..], &[0xAA; 32]);
    }

    #[test]
    fn beacon_hex_is_strict() {
        assert!(parse_beacon_hex(BITCOIN_GENESIS_HASH_HEX).is_ok());
        assert_eq!(parse_beacon_hex("00"), Err(GenesisError::BeaconHex));
        let bad = format!("{}zz", &BITCOIN_GENESIS_HASH_HEX[..62]);
        assert_eq!(parse_beacon_hex(&bad), Err(GenesisError::BeaconHex));
        // Upper case is the same bytes.
        assert_eq!(
            parse_beacon_hex(&BITCOIN_GENESIS_HASH_HEX.to_uppercase()),
            parse_beacon_hex(BITCOIN_GENESIS_HASH_HEX)
        );
    }
}
