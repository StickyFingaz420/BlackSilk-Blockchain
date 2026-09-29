//! Shared network state: the per-peer record, the state behind the network
//! lock, worker jobs, and `Inner` lock access and message sending.

use super::chain_access;
use super::config::NetConfig;
use super::lock_or_exit;
use crate::addr::NetAddr;
use crate::addrman::{AddrMan, BanList};
use crate::addrman_gate::AddrGate;
use crate::clock::ClockMonitor;
use crate::connman::ConnKind;
use crate::dandelion::{Dandelion, PeerId};
use crate::limits::PeerLimits;
use crate::message::Message;
use crate::originated::Originated;
use blacksilk_chain::actor::{ChainHandle, Lane};
use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{ChainManager, SummaryCell};
use blacksilk_consensus::{BlockHeader, Hash};
use blacksilk_tx::types::Transaction;
use rand_chacha::ChaCha20Rng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Notify};

pub(super) struct Peer {
    pub(super) addr: NetAddr,
    /// What the connection is for (`connman::ConnKind`).
    pub(super) kind: ConnKind,
    /// `kind.is_inbound()`.
    pub(super) inbound: bool,
    /// The connection's IP is not the peer's: a proxied outbound connection,
    /// or an inbound one through our hidden service (`OnionInbound`). Such a
    /// peer is never IP-banned or counted per IP.
    pub(super) proxied: bool,
    pub(super) protocol: u32,
    /// Control messages; sent before anything queued in `bulk`.
    pub(super) out: mpsc::Sender<Message>,
    /// `Block` frames.
    pub(super) bulk: mpsc::Sender<Message>,
    pub(super) kill: Arc<Notify>,
    /// Transactions are announced and stemmed to this peer: it asked for them
    /// (`Version.relay_txs`) and the connection's kind relays them (not
    /// block-relay-only or an address fetch).
    pub(super) relay_txs: bool,
    /// Addresses are exchanged with this peer (`GetAddr`, `Addr`, our own
    /// address, relayed ones): not on a block-relay-only connection, ours
    /// or the peer's (docs/p2p.md §9).
    pub(super) addr_relay: bool,
    /// The listen address the peer's `Version` carried (canonical): its
    /// self-advertisement, which does not end a seed's address fetch.
    pub(super) listen: Option<NetAddr>,
    pub(super) height: u64,
    pub(super) score: u32,
    pub(super) limits: PeerLimits,
    pub(super) answered_getaddr: bool,
    /// What this peer may add to the address table (docs/p2p.md §9).
    pub(super) addr_gate: AddrGate,
    /// Addresses this peer sent us or we relayed to it: not relayed to it
    /// (again). Bounded by [`ADDR_KNOWN_MAX`].
    pub(super) addr_known: HashSet<NetAddr>,
    pub(super) inv_queue: Vec<Hash>,
    pub(super) next_inv: Instant,
    pub(super) announced_to: HashSet<Hash>,
    pub(super) known_txs: HashSet<Hash>,
    pub(super) ping: Option<(u64, Instant)>,
    /// The lowest ping round trip measured (inbound eviction protects the
    /// lowest; `None`: none answered yet).
    pub(super) min_ping: Option<Duration>,
    pub(super) last_ping: Instant,
    pub(super) last_recv: Instant,
    /// Blocks requested from this peer and not yet processed, and the bytes
    /// charged for them (`MAX_BLOCK_BYTES` each, `BLOCK_WINDOW_BYTES`).
    pub(super) blocks_in_flight: usize,
    pub(super) bytes_in_flight: usize,
    pub(super) headers_requested: Option<Instant>,
    /// `GetHeaders` requests whose reply may still come although nothing is
    /// outstanding any more, oldest first, by request time: one a single
    /// header took (it may have been a tip announcement racing the real
    /// reply), or one that timed out. Each lets one later batch of other
    /// than one header count as solicited within `HEADERS_TIMEOUT`
    /// (`headers::take_grace`, docs/p2p.md §6). A new request does not
    /// cancel them: their replies may still be in flight (P2P-FIX2). At most
    /// `headers::MAX_HEADER_GRACE`.
    pub(super) headers_grace: VecDeque<Instant>,
    /// A header batch from this peer is queued for, or under, verification by
    /// the header worker. At most one per peer: the queue is bounded by the
    /// number of peers, and the peer is not asked for more headers meanwhile.
    pub(super) headers_busy: bool,
    /// Headers arrived while `headers_busy`; ask again once the batch is done.
    pub(super) headers_pending: bool,
    /// Headers of a version above every version this node's schedule knows,
    /// with valid proof of work (`HeaderError::UnknownUpgrade`), this peer
    /// sent (RT-1; [`UNKNOWN_UPGRADE_DISCONNECT`]).
    pub(super) unknown_upgrades: u32,
    /// When the peer was registered (inbound eviction, outbound rotation,
    /// anchors).
    pub(super) connected_at: Instant,
    /// Chosen for inbound eviction and told to disconnect: no longer counted
    /// against `max_inbound` (docs/p2p.md §9).
    pub(super) evicted: bool,
    /// When this peer last delivered a validated new tip: a header batch
    /// that stored new headers on our best header chain, or a block that
    /// joined our best chain. Outbound rotation ranks by it (RTW3-4), never
    /// by `height`, which the peer claims.
    pub(super) last_new_tip: Option<Instant>,
    /// When this peer last delivered a new block that joined our best chain,
    /// and a new transaction that passed verification (accepted to the pool,
    /// or a valid stem transaction). Inbound eviction protects the most
    /// recent (docs/p2p.md §9).
    pub(super) last_block: Option<Instant>,
    pub(super) last_tx: Option<Instant>,
}

/// An inbound connection accepted but not yet registered (key exchange or
/// version handshake in progress): a candidate for eviction before any
/// registered peer (RTW3-3, docs/p2p.md §9).
pub(super) struct PendingHandshake {
    pub(super) started: Instant,
    /// The connection's IPv4 address or IPv6 /64 (`peer_key`); `None` on the
    /// onion listener, where the IP is the Tor daemon's.
    pub(super) ip: Option<IpAddr>,
    /// Its bucketing group (IPv4 /16, IPv6 /32; `AddrMan::bucket_group`), or
    /// the onion class ([`ONION_HANDSHAKE_GROUP`]).
    pub(super) group: Vec<u8>,
    /// Closes the connection.
    pub(super) kill: Arc<Notify>,
}

/// The handshake group of every connection on the onion listener: they share
/// one IP (the Tor daemon's), so they are bounded together.
pub(super) const ONION_HANDSHAKE_GROUP: &[u8] = &[10];

/// Per-peer known-address set size; the set is emptied when full (a relayed
/// address may then be sent to that peer once more).
pub(super) const ADDR_KNOWN_MAX: usize = 5000;

pub(super) struct StemEntry {
    pub(super) tx: Transaction,
    pub(super) embargo: Instant,
    /// A local transaction created while there was no stem peer: held here
    /// (not broadcast) until a stem route exists, or until the embargo fires
    /// (docs/p2p.md §8).
    pub(super) awaiting_stem: bool,
}

/// The most timed-out transaction requests remembered (`State::late_txs`);
/// beyond it a late answer is unrequested again.
pub(super) const LATE_TXS_MAX: usize = 10_000;

pub(super) struct State {
    pub(super) peers: HashMap<PeerId, Peer>,
    pub(super) addrman: AddrMan,
    pub(super) bans: BanList,
    pub(super) dandelion: Dandelion,
    pub(super) stempool: HashMap<Hash, StemEntry>,
    pub(super) stem_key_images: HashMap<[u8; 32], Hash>,
    /// All peers together: PX verification is expensive, so the node caps the
    /// PX transactions it accepts from the network per second, whatever the
    /// number of peers (docs/px.md §11.5).
    pub(super) px_global: crate::limits::TokenBucket,
    pub(super) block_requests: HashMap<Hash, (PeerId, Instant)>,
    pub(super) tx_requests: HashMap<Hash, (PeerId, Instant)>,
    pub(super) tx_announcers: HashMap<Hash, VecDeque<PeerId>>,
    pub(super) recent_rejects: VecDeque<Hash>,
    pub(super) recent_rejects_set: HashSet<Hash>,
    /// Block requests that timed out, kept for another `BLOCK_TIMEOUT`: the
    /// block arriving late from the peer we asked is an answer, not an
    /// unsolicited block (R8-9).
    pub(super) late_blocks: HashMap<Hash, (PeerId, Instant)>,
    /// Transaction requests that timed out and moved on, by (id, the peer
    /// asked), kept for another `TX_TIMEOUT`: the late answer is accepted
    /// from that peer, unpenalized, as a late block is (P2P-FIX2). At most
    /// [`LATE_TXS_MAX`].
    pub(super) late_txs: HashMap<(Hash, PeerId), Instant>,
    pub(super) local_nonces: HashSet<u64>,
    /// Addresses being dialed or connected outbound, with the kind of the
    /// connection (`peers::connect_outbound`).
    pub(super) connecting: HashMap<NetAddr, ConnKind>,
    pub(super) last_attempt: HashMap<NetAddr, Instant>,
    pub(super) announced_tip: Hash,
    pub(super) rng: ChaCha20Rng,
    pub(super) misbehaving_disconnects: u64,
    pub(super) slow_disconnects: u64,
    pub(super) transport_failures: u64,
    /// The ban list changed since it was last saved.
    pub(super) bans_dirty: bool,
    /// Inbound connections accepted but not yet registered (handshake in
    /// progress), by slot id, and their count per IP (counted against
    /// `max_per_ip` like registered peers). Bounded in total and per group
    /// (`peers::handshake_caps`); never counted against `max_inbound`.
    pub(super) handshakes: HashMap<u64, PendingHandshake>,
    pub(super) handshaking_ip: HashMap<IpAddr, usize>,
    pub(super) next_handshake: u64,
    /// Header batches queued for, or under, verification: in total and per
    /// sender origin (`queue_key`). Bounded (docs/p2p.md §6).
    pub(super) header_queue_len: usize,
    pub(super) header_queue_origin: HashMap<NetAddr, usize>,
    /// Transactions that failed a contextual rule at tip `ctx_rejects_tip`
    /// (not verified again until the tip changes; bounded).
    pub(super) ctx_rejects: HashSet<Hash>,
    pub(super) ctx_rejects_tip: Hash,
    pub(super) tx_verifications: u64,
    pub(super) px_global_drops: u64,
    /// Relayed transactions dropped because the chain actor's Tx lane was
    /// full (never penalized; `NetStats::tx_lane_drops`).
    pub(super) tx_lane_drops: u64,
    /// Node-wide PX relay tokens taken (`NetStats::px_global_taken`).
    pub(super) px_global_taken: u64,
    /// Unrequested blocks in the block worker's queue (`UNREQUESTED_QUEUE`).
    pub(super) unrequested_queued: usize,
    /// Ids of blocks received and waiting for, or under, processing by the
    /// block worker: not requested again meanwhile.
    pub(super) blocks_queued: HashSet<Hash>,
    /// Peers that reported a newer consensus version (RT-1).
    pub(super) upgrades: UpgradeReports,
    /// Transactions this node originated, persisted (docs/p2p.md §8.1).
    pub(super) originated: Originated,
    /// Anchors, feelers and the stale-tip watch (docs/p2p.md §9).
    pub(super) connman: crate::connman::ConnState,
}

/// A peer is disconnected (never banned) after this many headers of an unknown
/// version with valid proof of work (RT-1): it may be right, but this node
/// cannot use its chain, and its slot is better given to a peer it can.
pub(super) const UNKNOWN_UPGRADE_DISCONNECT: u32 = 3;

/// The operator is warned that an upgrade may be needed only once this many
/// distinct reporters sent a header of an unknown version with valid proof of
/// work, or once such a header extends a branch with at least our best work
/// (RT-1). Only qualifying reports count (RTW1-1, [`UpgradeReports`]): a single
/// attacker cannot trigger the warning cheaply, nor by reconnecting.
pub(super) const UNKNOWN_UPGRADE_WARN_PEERS: usize = 2;

/// Reports of headers of an unknown (newer) version with valid proof of work.
///
/// A report qualifies for the operator warning only if it comes from an
/// OUTBOUND peer (one this node chose) and the header's branch passes the
/// anti-DoS work threshold at the difficulty this node requires (RTW1-1).
/// Qualifying reporters are keyed by [`upgrade_reporter_key`], never by
/// connection, so reconnecting does not count twice. At most
/// [`UNKNOWN_UPGRADE_WARN_PEERS`] keys are ever held.
#[derive(Default)]
pub(super) struct UpgradeReports {
    reporters: HashSet<Vec<u8>>,
    warned: bool,
}

/// The identity a qualifying upgrade report is counted under: the peer's
/// network group (IPv4 /16, IPv6 /32, the onion address), or, when private
/// addresses are allowed (local test networks, where every peer shares one
/// group), the whole address. An outbound peer reconnects to the address this
/// node dialed, so the key survives reconnects.
pub(super) fn upgrade_reporter_key(addr: &NetAddr, allow_private: bool) -> Vec<u8> {
    if allow_private {
        addr.to_string().into_bytes()
    } else {
        addr.group()
    }
}

/// What to do after one report ([`UpgradeReports::report`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct UpgradeVerdict {
    /// Warn the operator (at most once per run).
    pub(super) warn: bool,
    /// Disconnect the reporting peer, without a ban.
    pub(super) disconnect: bool,
}

impl UpgradeReports {
    /// Records a report from a peer whose `count`-th it is (on this
    /// connection). `qualifying`: the reporter's key if the report counts
    /// toward the warning (see [`UpgradeReports`]), else `None`. `heavy`: the
    /// header extends a branch that, with the work this node requires of it,
    /// reaches our best chain's work; it warns at once, but only for a
    /// qualifying report.
    pub(super) fn report(
        &mut self,
        qualifying: Option<Vec<u8>>,
        count: u32,
        heavy: bool,
    ) -> UpgradeVerdict {
        let disconnect = count >= UNKNOWN_UPGRADE_DISCONNECT;
        let Some(key) = qualifying else {
            return UpgradeVerdict {
                warn: false,
                disconnect,
            };
        };
        if !self.warned && self.reporters.len() < UNKNOWN_UPGRADE_WARN_PEERS {
            self.reporters.insert(key);
        }
        let warn = !self.warned && (heavy || self.reporters.len() >= UNKNOWN_UPGRADE_WARN_PEERS);
        self.warned |= warn;
        UpgradeVerdict { warn, disconnect }
    }

    /// Whether the operator was warned (once per run).
    pub(super) fn warned(&self) -> bool {
        self.warned
    }
}

/// A block waiting for the block worker.
pub(super) struct BlockJob {
    pub(super) peer: PeerId,
    pub(super) block: Block,
    /// Requested from `peer` (it holds a place in the peer's window until
    /// processed); otherwise unrequested (processed only if its header is
    /// known, `UNREQUESTED_QUEUE`).
    pub(super) requested: bool,
    /// A request that timed out and was answered late: not in the window any
    /// more, but not unsolicited either.
    pub(super) late: bool,
}

/// A header batch waiting for the header worker, with its sender's address
/// (a sender that disconnects before its batch is verified is still banned).
pub(super) struct HeaderBatch {
    pub(super) peer: PeerId,
    pub(super) addr: NetAddr,
    /// The sender's IP is not its own (`Peer::proxied`): it is never banned,
    /// and its origin for the header queue bound is the connection.
    pub(super) proxied: bool,
    /// An answer to our `GetHeaders` (not a tip announcement).
    pub(super) solicited: bool,
    pub(super) headers: Vec<BlockHeader>,
}

pub(super) struct Inner {
    /// The chain actor: every chain operation is a command on one of its
    /// lanes (`chain_access`).
    pub(super) chain: ChainHandle,
    /// The chain's published snapshot (`ChainHandle::summary_cell`): the
    /// tip, header height, locator and missing bodies, read without a
    /// command by the handshake, header requests, download scheduling and
    /// the maintenance loop.
    pub(super) summary: Arc<SummaryCell>,
    pub(super) cfg: NetConfig,
    /// The chain's genesis id, bound into the session keys (R15-3).
    pub(super) genesis_id: Hash,
    /// To the header worker (`header_worker`): batches are verified there, one
    /// at a time, never on a peer's read loop.
    pub(super) header_queue: mpsc::UnboundedSender<HeaderBatch>,
    /// To the block worker (`block_worker`): bodies are validated and
    /// connected there, never on a peer's read loop. Bounded by the peers'
    /// request windows plus `UNREQUESTED_QUEUE`.
    pub(super) block_queue: mpsc::UnboundedSender<BlockJob>,
    pub(super) state: Mutex<State>,
    pub(super) next_id: AtomicU64,
    pub(super) local_addr: Option<SocketAddr>,
    /// The onion listener's bound address (`NetConfig::onion_listen`).
    pub(super) onion_addr: Option<SocketAddr>,
    /// Serializes writes of the originated set's file (taken before the
    /// state lock, only on blocking threads or at shutdown).
    pub(super) originated_io: Mutex<()>,
    /// The warn-only estimate of the local clock's offset against recent
    /// blocks (`crate::clock`); never used for validation. Taken alone,
    /// never with the state lock.
    pub(super) clock: Mutex<ClockMonitor>,
}

pub(super) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(super) fn short(h: &Hash) -> String {
    hex::encode(&h[..6])
}

impl Inner {
    pub(super) fn state(&self) -> MutexGuard<'_, State> {
        lock_or_exit(&self.state, "network state")
    }

    pub(super) fn clock(&self) -> MutexGuard<'_, ClockMonitor> {
        lock_or_exit(&self.clock, "clock monitor")
    }

    /// Runs `f` on the chain actor's Query lane and returns its result
    /// (`chain_access::call`): the task waits, no thread does. If the actor
    /// stopped (the node is shutting down), never resolves: the caller is
    /// being dropped too. A panic in `f` stops the node (the actor's
    /// fail-stop).
    pub(super) async fn with_chain<T: Send + 'static>(
        self: &Arc<Self>,
        f: impl FnOnce(&mut ChainManager) -> T + Send + 'static,
    ) -> T {
        self.chain_on(Lane::Query, f).await
    }

    /// [`Self::with_chain`] on `lane`.
    pub(super) async fn chain_on<T: Send + 'static>(
        &self,
        lane: Lane,
        f: impl FnOnce(&mut ChainManager) -> T + Send + 'static,
    ) -> T {
        match chain_access::call(&self.chain, lane, f).await {
            Some(t) => t,
            None => std::future::pending().await,
        }
    }

    /// Runs `f` on `lane` from a blocking thread (the header worker),
    /// waiting for room and for the result; `None` if the actor stopped.
    pub(super) fn chain_blocking<T: Send + 'static>(
        &self,
        lane: Lane,
        f: impl FnOnce(&mut ChainManager) -> T + Send + 'static,
    ) -> Option<T> {
        self.chain.call_blocking(lane, f).ok()
    }

    pub(super) fn save(&self) {
        let Some(dir) = &self.cfg.data_dir else {
            return;
        };
        {
            let st = self.state();
            if let Err(e) = st.addrman.save(&dir.join("peers.json")) {
                log::warn!("saving peers.json: {e}");
            }
            if let Err(e) = st.bans.save(&dir.join("bans.json")) {
                log::warn!("saving bans.json: {e}");
            }
        }
        self.write_originated(dir);
    }

    /// Queues `msg` for `peer`: `Block` frames in the bulk outbox, everything
    /// else in the control outbox, which the writer drains first (R8-11).
    pub(super) fn send(&self, st: &mut State, peer: PeerId, msg: Message) {
        let Some(p) = st.peers.get(&peer) else { return };
        let queue = if matches!(msg, Message::Block(_)) {
            &p.bulk
        } else {
            &p.out
        };
        if queue.try_send(msg).is_err() {
            // Outbox full: the peer does not read fast enough (or is gone).
            log::debug!("peer {} outbox full; disconnecting", p.addr);
            p.kill.notify_one();
            st.slow_disconnects += 1;
        }
    }

    pub(super) fn send_now(&self, peer: PeerId, msg: Message) {
        let mut st = self.state();
        self.send(&mut st, peer, msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RT-1 and RTW1-1: one reporter never triggers the operator warning,
    /// however often it reports or reconnects (same key); a second distinct
    /// qualifying reporter does, once. A qualifying report on a branch that
    /// reaches our best work warns at once. Non-qualifying reports (inbound, or
    /// below the work threshold) never warn, even heavy ones, and add no key.
    /// The reporting connection is disconnected at its third report.
    #[test]
    fn upgrade_reports_warn_past_a_threshold_and_disconnect_after_n() {
        let key = |n: u8| Some(vec![n]);
        let quiet = |disconnect| UpgradeVerdict {
            warn: false,
            disconnect,
        };
        let loud = UpgradeVerdict {
            warn: true,
            disconnect: false,
        };
        let mut r = UpgradeReports::default();
        assert_eq!(r.report(key(1), 1, false), quiet(false));
        assert_eq!(r.report(key(1), 2, false), quiet(false));
        assert_eq!(
            r.report(key(1), UNKNOWN_UPGRADE_DISCONNECT, false),
            quiet(true)
        );
        // Reconnected: a new connection, the same key.
        assert_eq!(r.report(key(1), 1, false), quiet(false));
        // Inbound or low-work reporters, many of them, heavy or not.
        for _ in 0..10 {
            assert_eq!(r.report(None, 1, true), quiet(false));
        }
        assert_eq!(r.report(None, 3, false), quiet(true));
        assert!(!r.warned());
        assert_eq!(r.report(key(2), 1, false), loud);
        assert!(r.warned());
        // Once per run.
        assert_eq!(r.report(key(3), 1, true), quiet(false));
        assert_eq!(r.reporters.len(), UNKNOWN_UPGRADE_WARN_PEERS, "bounded");

        let mut r = UpgradeReports::default();
        assert_eq!(r.report(key(9), 1, true), loud);
    }

    /// RTW1-1: reporters are keyed by network group on the public network, by
    /// the whole address with `allow_private`; the port never makes a public
    /// reporter new.
    #[test]
    fn upgrade_reporters_are_keyed_by_group() {
        let a = NetAddr::parse("1.2.3.4:5").unwrap();
        let b = NetAddr::parse("1.2.9.9:6").unwrap();
        let c = NetAddr::parse("1.3.3.4:5").unwrap();
        assert_eq!(
            upgrade_reporter_key(&a, false),
            upgrade_reporter_key(&b, false)
        );
        assert_ne!(
            upgrade_reporter_key(&a, false),
            upgrade_reporter_key(&c, false)
        );
        assert_ne!(
            upgrade_reporter_key(&a, true),
            upgrade_reporter_key(&b, true)
        );
    }
}
