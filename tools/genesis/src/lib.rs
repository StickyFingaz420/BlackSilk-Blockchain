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
use blacksilk_consensus::{BlockHeader, ChainParams};

pub use blacksilk_consensus::genesis::{
    derive_genesis_nonce, nonce_preimage, nonce_preimage_digest, NONCE_DOMAIN,
    TEST_VECTOR_NETWORK_ID,
};

/// The network id of testnet v3, final (decisions "Agent 40"; fingerprint v3):
/// `ChainParams::testnet().network_id`. Its genesis is generated at launch
/// (docs/testnet-v3-genesis.md §3), with `generate --final`, the only mode
/// that accepts it ([`RESERVED_IDS`]). No rehearsal or release candidate may
/// use it.
pub const TESTNET_V3_NETWORK_ID: u32 = 0x0001_D673;

/// The network ids reserved for genesis rehearsals (decisions "Agent 40"):
/// `generate --rehearsal` accepts only these, and only it does. A used
/// rehearsal id is registered in [`NETWORK_ID_REGISTRY`] afterwards.
pub const REHEARSAL_IDS: std::ops::RangeInclusive<u32> = 0x0001_D6E0..=0x0001_D6EF;

/// Why a genesis is generated: the purpose fixes which network ids it may use
/// ([`check_network_id`], [`RESERVED_IDS`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// The final testnet v3 genesis (`--final`): only [`TESTNET_V3_NETWORK_ID`].
    Final,
    /// A rehearsal (`--rehearsal`): only an id of [`REHEARSAL_IDS`].
    Rehearsal,
    /// Anything else (a private network): any id that is neither reserved
    /// nor registered.
    Other,
}

impl Purpose {
    /// The command-line flag of the purpose (none for [`Purpose::Other`]).
    pub fn flag(self) -> &'static str {
        match self {
            Purpose::Final => "--final",
            Purpose::Rehearsal => "--rehearsal",
            Purpose::Other => "(no flag)",
        }
    }
}

/// The reserved network ids (RTFP3-13): `(first, last, use)`. An id in one
/// of these ranges is generated only with the purpose that owns it, and the
/// test-vector id never.
pub const RESERVED_IDS: &[(u32, u32, &str)] = &[
    (
        TESTNET_V3_NETWORK_ID,
        TESTNET_V3_NETWORK_ID,
        "testnet v3, final: `generate --final` only",
    ),
    (
        *REHEARSAL_IDS.start(),
        *REHEARSAL_IDS.end(),
        "rehearsals: `generate --rehearsal` only",
    ),
    (
        TEST_VECTOR_NETWORK_ID,
        TEST_VECTOR_NETWORK_ID,
        "test vectors only: never a network",
    ),
];

/// What a reserved id is reserved for.
pub fn reserved_use(id: u32) -> Option<&'static str> {
    RESERVED_IDS
        .iter()
        .find(|(first, last, _)| (*first..=*last).contains(&id))
        .map(|(_, _, u)| *u)
}

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
    /// The id is reserved ([`RESERVED_IDS`]) for another purpose than the
    /// one given, or the purpose needs an id it does not have.
    Reserved { id: u32, purpose: Purpose },
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
            Self::Reserved { id, purpose } => match reserved_use(*id) {
                Some(u) if *purpose == Purpose::Other => write!(
                    f,
                    "network id {id:#010x} is reserved ({u}); without that flag, \
                     generate refuses it"
                ),
                Some(u) => write!(
                    f,
                    "network id {id:#010x} is reserved ({u}); not usable with {}",
                    purpose.flag()
                ),
                None => write!(
                    f,
                    "{} needs {}; network id {id:#010x} is not",
                    purpose.flag(),
                    match purpose {
                        Purpose::Final => "the testnet v3 id 0x0001d673",
                        _ => "a rehearsal id (0x0001d6e0..=0x0001d6ef)",
                    }
                ),
            },
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

/// Whether a new genesis for `purpose` may use `id`: never 0, never an id of
/// [`NETWORK_ID_REGISTRY`], never the test-vector id; [`Purpose::Final`] only
/// [`TESTNET_V3_NETWORK_ID`], [`Purpose::Rehearsal`] only [`REHEARSAL_IDS`],
/// and [`Purpose::Other`] no reserved id.
pub fn check_network_id(id: u32, purpose: Purpose) -> Result<(), GenesisError> {
    if id == 0 {
        return Err(GenesisError::NetworkIdZero);
    }
    if registry_name(id).is_some() {
        return Err(GenesisError::NetworkIdReused(id));
    }
    let allowed = match purpose {
        Purpose::Final => id == TESTNET_V3_NETWORK_ID,
        Purpose::Rehearsal => REHEARSAL_IDS.contains(&id),
        Purpose::Other => reserved_use(id).is_none(),
    };
    if !allowed {
        return Err(GenesisError::Reserved { id, purpose });
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
///
/// Construction only: which ids a new genesis may use is [`generate`]'s check
/// ([`check_network_id`]), and which registered ids a check may recompute is
/// [`verify`]'s.
pub fn build(inputs: &GenesisInputs) -> Result<Genesis, GenesisError> {
    if inputs.network_id == 0 {
        return Err(GenesisError::NetworkIdZero);
    }
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

/// A new genesis for `purpose`: [`build`], refusing an id the purpose may not
/// use ([`check_network_id`]: registered, reserved for another purpose) and a
/// timestamp later than `now` (R15-4: the timestamp is fixed before the
/// beacon, so by the time the beacon is known the genesis is in the past, and
/// no block can be mined ahead with a future timestamp).
pub fn generate(
    inputs: &GenesisInputs,
    now: u64,
    purpose: Purpose,
) -> Result<Genesis, GenesisError> {
    check_network_id(inputs.network_id, purpose)?;
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
///
/// An unregistered id is recomputed as given. A registered id (RTFP3-14) is
/// accepted only when it is a built-in network's id and the recomputed
/// genesis is that network's compiled genesis: so after the launch, when the
/// testnet id is registered, operators and anyone later still verify the
/// testnet genesis from its announced inputs, while a retired id's genesis
/// (v1, v2, a rehearsal) is refused.
pub fn verify(inputs: &GenesisInputs, expected_id: &Hash) -> Result<Genesis, GenesisError> {
    verify_against(
        inputs,
        expected_id,
        &[
            ChainParams::testnet(),
            ChainParams::mainnet(),
            ChainParams::regtest(),
        ],
    )
}

/// [`verify`] against the given built-in networks' parameters.
pub fn verify_against(
    inputs: &GenesisInputs,
    expected_id: &Hash,
    built_in: &[ChainParams],
) -> Result<Genesis, GenesisError> {
    let g = build(inputs)?;
    if g.id != *expected_id {
        return Err(GenesisError::IdMismatch { computed: g.id });
    }
    if registry_name(inputs.network_id).is_some() {
        let own = built_in.iter().any(|p| {
            p.network_id == inputs.network_id && p.genesis == g.header && p.genesis_id() == g.id
        });
        if !own {
            return Err(GenesisError::NetworkIdReused(inputs.network_id));
        }
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
         \x20 output_count 0, output_root 0, px_root {px} (the empty PX tree)\n\
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
        px = hex(&h.px_root),
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
