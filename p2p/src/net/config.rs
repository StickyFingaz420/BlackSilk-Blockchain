//! Network configuration and the public peer and statistics snapshots
//! (`NetConfig`, `PeerInfo`, `NetStats`).

use crate::addr::NetAddr;
use crate::connman::ConnKind;
use crate::dandelion::{DandelionParams, PeerId};
use crate::limits::PeerLimits;
use crate::transport::NetworkPsk;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct NetConfig {
    pub network_id: u32,
    /// Listen for inbound connections here (`None`: outbound only).
    pub listen: Option<SocketAddr>,
    /// A second listener for our Tor hidden service (`--onion-inbound`,
    /// docs/p2p.md §11): its peers are onion peers (`ConnKind::OnionInbound`),
    /// never IP-banned or counted per IP, capped as a class. When it is set,
    /// loopback connections on `listen` are no longer taken for Tor.
    pub onion_listen: Option<SocketAddr>,
    /// Our reachable address, advertised to peers. `None` keeps it private.
    pub public_address: Option<NetAddr>,
    pub seeds: Vec<NetAddr>,
    /// Peers to keep connected to at all times.
    pub connect: Vec<NetAddr>,
    /// Make outbound connections only to `connect` (no seeds, no discovered
    /// addresses). Inbound connections and address exchange still work.
    pub connect_only: bool,
    /// SOCKS5 proxy for outbound connections (e.g. Tor).
    pub proxy: Option<SocketAddr>,
    /// Only connect through the proxy.
    pub proxy_only: bool,
    /// Full-relay outbound connections (manual peers included).
    pub max_outbound: usize,
    /// Block-relay-only outbound connections besides them (default
    /// [`crate::connman::BLOCK_RELAY_ONLY`]; none with `connect_only`).
    pub block_relay_only: usize,
    pub max_inbound: usize,
    pub max_per_ip: usize,
    /// Accept and dial loopback/private addresses and skip network-group diversity
    /// (regtest and tests). Loopback peers are then disconnected, not IP-banned.
    pub allow_private: bool,
    /// Where `peers.json` and `bans.json` are kept.
    pub data_dir: Option<PathBuf>,
    pub dandelion: DandelionParams,
    pub trickle_outbound: Duration,
    pub trickle_inbound: Duration,
    pub pow_threads: usize,
    pub tick: Duration,
    /// Per-peer rate limits (docs/p2p.md §10). Tests shrink them.
    pub peer_limits: PeerLimits,
    /// A closed network's pre-shared key, mixed into every session key
    /// (docs/p2p.md §3, F48-1). `None` on public networks.
    pub network_psk: Option<NetworkPsk>,
    /// Mean time between feeler connections (docs/p2p.md §9). Tests shorten
    /// it; the default is [`crate::connman::FEELER_INTERVAL`].
    pub feeler_interval: Duration,
    /// The tip is stale after this long without a change (`None`: `3 × T ×
    /// STALE_TIP_FACTOR` for the chain's target block time `T`). Tests
    /// shorten it.
    pub stale_tip_after: Option<Duration>,
    /// While the tip is stale, one extra outbound connection at most this
    /// often (default [`crate::connman::STALE_CHECK_INTERVAL`]).
    pub stale_check_interval: Duration,
    /// An outbound peer younger than this is never rotated out (default
    /// [`crate::connman::MIN_CONNECT_TIME`]).
    pub min_connect_time: Duration,
    /// Time between pings to a peer (default 60 s). Tests shorten it.
    pub ping_interval: Duration,
    /// A seed's address fetch is closed after this long without an answer
    /// (default [`crate::connman::ADDR_FETCH_TIMEOUT`]).
    pub addr_fetch_timeout: Duration,
    /// Seeds are asked for addresses once fewer than two full-relay outbound
    /// peers were up this long (default
    /// [`crate::connman::SEED_FALLBACK_AFTER`]).
    pub seed_fallback_after: Duration,
    /// The proof-of-work budget for headers from untrusted inbound peers
    /// (docs/p2p.md §6, `HeaderPowBudget`). Tests change it.
    pub header_pow_budget: super::header_budget::HeaderPowBudget,
}

impl NetConfig {
    pub fn new(network_id: u32) -> Self {
        Self {
            network_id,
            listen: None,
            onion_listen: None,
            public_address: None,
            seeds: Vec::new(),
            connect: Vec::new(),
            connect_only: false,
            proxy: None,
            proxy_only: false,
            max_outbound: 8,
            block_relay_only: crate::connman::BLOCK_RELAY_ONLY,
            max_inbound: 64,
            max_per_ip: 2,
            allow_private: false,
            data_dir: None,
            dandelion: DandelionParams::default(),
            trickle_outbound: Duration::from_secs(2),
            trickle_inbound: Duration::from_secs(5),
            pow_threads: std::thread::available_parallelism().map_or(1, |n| n.get()),
            tick: Duration::from_millis(250),
            peer_limits: PeerLimits::default(),
            network_psk: None,
            feeler_interval: crate::connman::FEELER_INTERVAL,
            stale_tip_after: None,
            stale_check_interval: crate::connman::STALE_CHECK_INTERVAL,
            min_connect_time: crate::connman::MIN_CONNECT_TIME,
            ping_interval: Duration::from_secs(60),
            addr_fetch_timeout: crate::connman::ADDR_FETCH_TIMEOUT,
            seed_fallback_after: crate::connman::SEED_FALLBACK_AFTER,
            header_pow_budget: Default::default(),
        }
    }
}

/// Public view of a connected peer.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub id: PeerId,
    pub addr: NetAddr,
    pub inbound: bool,
    pub kind: ConnKind,
    pub height: u64,
    pub score: u32,
    /// The peer's `Version.protocol`.
    pub protocol: u32,
    /// The lowest ping round trip measured.
    pub min_ping: Option<Duration>,
    /// When the peer last delivered a new block that joined our best chain,
    /// and a new valid transaction.
    pub last_block: Option<std::time::Instant>,
    pub last_tx: Option<std::time::Instant>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetStats {
    pub peers: usize,
    /// Outbound peers of every kind (full-relay, block-relay-only, address
    /// fetches).
    pub outbound: usize,
    /// Of them, block-relay-only.
    pub block_relay: usize,
    pub inbound: usize,
    pub stempool: usize,
    pub banned: usize,
    pub known_addresses: (usize, usize),
    /// Peers disconnected for misbehavior since start.
    pub misbehaving_disconnects: u64,
    /// Peers disconnected because they did not read their messages fast enough.
    pub slow_disconnects: u64,
    /// Connections closed because a frame failed to decrypt, in the handshake
    /// or after it: tampering on the path, or a node of another network,
    /// genesis, transport version or pre-shared key. Never scored
    /// (docs/p2p.md §10).
    pub transport_failures: u64,
    /// Relayed transactions that reached full verification (signatures,
    /// proofs) since start.
    pub tx_verifications: u64,
    /// PX transactions dropped because the node-wide PX relay limit was
    /// exhausted (docs/p2p.md §10).
    pub px_global_drops: u64,
    /// Relayed transactions dropped unverified because the chain actor's
    /// transaction lane was full (best effort; the senders are not
    /// penalized; docs/p2p.md §10).
    pub tx_lane_drops: u64,
    /// Node-wide PX relay tokens taken since start: PX transactions that
    /// passed every cheap check and went on to full verification.
    pub px_global_taken: u64,
    /// Header proof-of-work hashes run for untrusted inbound peers that
    /// failed (charged to the header PoW budget and not refunded).
    pub header_pow_failed: u64,
    /// Header batches of untrusted inbound peers dropped unhashed because
    /// the header PoW budget was exhausted (docs/p2p.md §6).
    pub header_pow_throttled: u64,
}
