//! Target body: one connection's handshake negotiation and per-peer protocol
//! (RT-FUZZ design 1; decisions "W4-FUZZ and RT-FUZZ"). Shared by
//! fuzz_targets/peer_protocol.rs and p2p/tests/fuzz_peer_protocol.rs, which
//! include `chain_fixture.rs` next to it.
//!
//! The victim is the node's own connection code (`conn::run_connection`,
//! through `net::fuzzing::Victim`, feature `test-hooks`) over an in-memory
//! stream, with a fresh regtest chain actor, on a single-threaded runtime
//! whose clock is paused: time moves only when every task waits, to the next
//! timer, so the handshake deadline and the key exchange timeout fire at
//! exact virtual instants. The attacker holds the session keys (it runs the
//! real key exchange), so every frame it sends is authentic and the victim's
//! negotiation logic is what decides.
//!
//! Input: a configuration (2 bytes), then a script of 4-byte steps
//! `op, a, b, c` (at most 48):
//! - byte 0: the connection's kind (inbound, onion inbound, full relay,
//!   block relay, address fetch), whether an outbound connection is proxied,
//!   the peer's address (routable IPv4 or IPv6, loopback, onion), whether
//!   our public address is an onion, and the pre-shared key setup (none,
//!   shared, or present on one side only);
//! - byte 1: a delay before the attacker starts its key exchange;
//! - steps: a `Version` (protocol, network, nonce, possibly the victim's
//!   own, listen address, relay flag, height, tip), a `Verack`, a frame of
//!   an unknown type, raw bytes of a known type, a delay, a frame over
//!   `MAX_HANDSHAKE_FRAME`, one of exactly that size, an empty frame, or a
//!   well-formed protocol message (pings, addresses, header and block
//!   requests, a valid next header and block, transaction inventory,
//!   transactions and stem transactions).
//!
//! A model of the negotiation (docs/p2p.md §4) predicts, from the script
//! alone, whether and when the victim registers the peer or closes, and how
//! many bytes it reads before `Verack`. Invariants, beyond "no panic":
//! - the victim registers the peer exactly when the model says so;
//!   otherwise it closes at the exact virtual instant the model predicts:
//!   at the deciding frame, at the key exchange timeout, or at
//!   `HANDSHAKE_DEADLINE` for a peer that stops negotiating (never later,
//!   and never earlier for a peer that is still within it);
//! - while the peer is unregistered nothing is scored or banned, and the
//!   address table and the peer table do not change (checked after every
//!   step, and at the end for a peer never registered); a frame that fails
//!   to decrypt counts as a transport failure only;
//! - before `Verack` the victim never asks its stream for more than one
//!   `MAX_HANDSHAKE_FRAME` frame and its tag at once (each read is the
//!   buffer it allocated), and never reads past the bytes the model says
//!   it consumed: a longer frame closes the connection after its 20-byte
//!   length;
//! - more than `HANDSHAKE_UNKNOWN_FRAMES` frames of unknown types before
//!   `Verack` close the connection (the model counts them);
//! - the victim's `Version` is ours: the network's id and protocol, a listen
//!   address that is either none or our public address, and on a
//!   block-relay-only connection no listen address and no transaction relay;
//!   before registration it sends nothing but `Version` and `Verack`; on a
//!   block-relay-only connection it never sends addresses or transaction
//!   messages; everything it sends decodes;
//! - when the connection ends, its peer is gone from the peer table, the
//!   Dandelion stems, and the block and transaction requests, and its
//!   handshake nonce is released.

use crate::chain_fixture;
use blacksilk_chain::actor::{self, ActorConfig, ChainHandle};
use blacksilk_consensus::{BlockHeader, Hash};
use blacksilk_p2p::addr::AddrEntry;
use blacksilk_p2p::connman::ConnKind;
use blacksilk_p2p::message::{Message, Version};
use blacksilk_p2p::net::fuzzing::{Snapshot, Victim};
use blacksilk_p2p::transport::{handshake_with, NetworkPsk, Session};
use blacksilk_p2p::{NetAddr, NetConfig};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::time::Instant;

/// Encrypted length (4) and its tag (16), then the payload's tag.
const LEN_CT: usize = 20;
const TAG: usize = 16;
const KEY: usize = 32;
const MAX_STEPS: usize = 48;
const ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion:18333";
const PUBLIC_IP: &str = "203.0.113.5:18333";
/// A nonce the victim never draws (its generator is seeded).
const PEER_NONCE: u64 = 0x5eed_0000_0000_0000;
/// The negotiation's limits, from its specification (docs/p2p.md §4), not
/// from the code under test: the whole handshake's deadline, the key
/// exchange's timeout (over Tor: a proxied connection, or a loopback one
/// taken for our hidden service), and the frames of unknown types skipped
/// between `Version` and `Verack`.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(20);
const KEY_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
const KEY_EXCHANGE_TIMEOUT_TOR: Duration = Duration::from_secs(10);
const HANDSHAKE_UNKNOWN_FRAMES: usize = 8;
/// The largest frame before `Verack`, from the specification (docs/p2p.md section 4:
/// 4096 bytes), not the product constant: a raised limit must fail
/// here (RT-STATEFUL: with the product constant, the model followed it).
const MAX_HANDSHAKE_FRAME: usize = 4096;
/// The protocol version a node of this release sends, and the lowest it
/// accepts (docs/p2p.md §4 and the table of §4.1: "currently 3", "peers
/// below MIN_PROTOCOL (3) are disconnected").
const PROTOCOL_VERSION: u32 = 3;
const MIN_PROTOCOL_VERSION: u32 = 3;
/// Message types this version knows: the table of docs/p2p.md §5 (0 to 14;
/// "unknown message types (above 14) are ignored").
fn spec_known_type(tag: u8) -> bool {
    tag <= 14
}

pub fn run(data: &[u8]) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("a runtime");
    let (chain, thread) = actor::spawn(chain_fixture::open(), ActorConfig::default());
    rt.block_on(session(data, chain));
    // Every task (and with them the network state's chain handles) ends here.
    drop(rt);
    thread.stop_and_join();
}

// ------------------------------------------------------------ the script

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Psk {
    None,
    Shared,
    VictimOnly,
    PeerOnly,
}

struct Config {
    kind: ConnKind,
    proxied: bool,
    addr: NetAddr,
    public: NetAddr,
    psk: Psk,
    /// Before the attacker's key exchange.
    key_delay: Duration,
}

#[derive(Clone, Debug)]
enum Act {
    Delay(Duration),
    /// A `Version`; with `echo`, carrying the victim's own nonce.
    Version(Version, bool),
    Frame(Vec<u8>),
}

fn kind_of(b: u8) -> ConnKind {
    [
        ConnKind::Inbound,
        ConnKind::OnionInbound,
        ConnKind::FullRelay,
        ConnKind::BlockRelay,
        ConnKind::AddrFetch,
    ][b as usize % 5]
}

/// A delay that never lands on a whole second (so never exactly on a
/// timeout: no tie for the model to guess).
fn delay(secs: u8) -> Duration {
    Duration::from_secs(secs as u64) + Duration::from_millis(333)
}

fn config(b0: u8, b1: u8) -> Config {
    let kind = kind_of(b0);
    let proxied = match kind {
        ConnKind::Inbound => false,
        ConnKind::OnionInbound => true,
        _ => b0 & 8 != 0,
    };
    let addr = match (b0 >> 4) & 3 {
        0 => "198.51.100.7:4444",
        1 => "127.0.0.1:4444",
        2 => ONION,
        _ => "[2a01:4f8::7]:4444",
    };
    let public = if b0 & 0x40 != 0 { ONION } else { PUBLIC_IP };
    let psk = match (b0 >> 7, b1 >> 6) {
        (0, _) => Psk::None,
        (_, 0) | (_, 1) => Psk::Shared,
        (_, 2) => Psk::VictimOnly,
        _ => Psk::PeerOnly,
    };
    Config {
        kind,
        proxied,
        addr: NetAddr::parse(addr).expect("an address"),
        public: NetAddr::parse(public).expect("an address"),
        psk,
        key_delay: if b1 & 0x20 != 0 {
            delay(b1 & 15)
        } else {
            Duration::ZERO
        },
    }
}

/// The next valid block on a fresh regtest chain, and its header.
fn next_block() -> &'static (BlockHeader, Vec<u8>) {
    static B: OnceLock<(BlockHeader, Vec<u8>)> = OnceLock::new();
    B.get_or_init(|| {
        let m = chain_fixture::open();
        let b = chain_fixture::Miner::new(1).block(&m);
        (b.header, b.encode())
    })
}

fn script(steps: &[u8], cfg: &Config, nid: u32, genesis: &Hash) -> Vec<Act> {
    let (h1, b1) = next_block();
    let h1_id = h1.id(nid);
    let mut acts = Vec::new();
    for step in steps.chunks(4).take(MAX_STEPS) {
        let [op, a, b, c] = [0, 1, 2, 3].map(|i| step.get(i).copied().unwrap_or(0));
        acts.push(match op % 10 {
            0 => {
                let listen = match c % 4 {
                    0 => None,
                    1 => Some(NetAddr::parse("203.0.113.9:18333").expect("an address")),
                    2 => cfg.addr.ip().map(|ip| NetAddr::Ip((ip, 18333).into())),
                    _ => Some(NetAddr::parse(ONION).expect("an address")),
                };
                let v = Version {
                    protocol: [
                        PROTOCOL_VERSION,
                        MIN_PROTOCOL_VERSION - 1,
                        PROTOCOL_VERSION + 1,
                        u32::MAX,
                    ][a as usize % 4],
                    network: if b & 1 != 0 { nid ^ 1 } else { nid },
                    nonce: PEER_NONCE + c as u64,
                    height: (a >> 2) as u64 * 1000,
                    tip: if b & 8 != 0 { *genesis } else { [c; 32] },
                    listen,
                    relay_txs: b & 4 != 0,
                };
                Act::Version(v, b & 2 != 0)
            }
            1 => Act::Frame(Message::Verack.encode()),
            2 => {
                let tag = 15 + a % 241;
                let mut f = vec![tag];
                f.resize(1 + b as usize % 64, c);
                Act::Frame(f)
            }
            3 => {
                let mut f = vec![a % 15];
                f.resize(1 + b as usize % 128, c);
                Act::Frame(f)
            }
            4 => Act::Delay(delay(a % 8)),
            5 => Act::Frame(vec![200; MAX_HANDSHAKE_FRAME + 1 + a as usize * 16]),
            6 => Act::Frame(vec![200 | (c & 7); MAX_HANDSHAKE_FRAME]),
            7 => Act::Frame(protocol_message(a, b, c, h1, &h1_id, b1, genesis).encode()),
            8 => Act::Frame(Vec::new()),
            _ => Act::Frame(vec![a, b, c]),
        });
    }
    acts
}

/// A well-formed protocol message.
fn protocol_message(
    a: u8,
    b: u8,
    c: u8,
    h1: &BlockHeader,
    h1_id: &Hash,
    b1: &[u8],
    genesis: &Hash,
) -> Message {
    let id = [c; 32];
    match a % 15 {
        0 => Message::Ping(c as u64),
        1 => Message::Pong(c as u64),
        2 => Message::GetAddr,
        3 => Message::Addr(
            (0..b % 4)
                .map(|i| {
                    let a =
                        NetAddr::parse(&format!("198.51.{c}.{}:18333", 1 + i)).expect("an address");
                    AddrEntry::new(1_700_000_000 + i as u32, a)
                })
                .collect(),
        ),
        4 => Message::GetHeaders {
            locator: vec![if b & 1 == 0 { *genesis } else { id }],
            stop: [0; 32],
        },
        5 => Message::Headers(vec![*h1]),
        6 => {
            // A header that fails validation (its timestamp).
            let mut h = *h1;
            h.timestamp = c as u64;
            Message::Headers(vec![h])
        }
        7 => Message::GetBlocks(vec![if b & 1 == 0 { *h1_id } else { *genesis }]),
        8 => Message::Block(b1.to_vec()),
        9 => Message::InvTx(vec![id]),
        10 => Message::GetTx(vec![id]),
        11 => Message::NotFound(vec![id]),
        12 => Message::Tx(vec![c; b as usize]),
        13 => Message::StemTx(vec![c; b as usize]),
        _ => Message::Block(vec![c; b as usize]),
    }
}

// ------------------------------------------------------------- the model

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// Registered when the `Verack` arrived, at this offset.
    Registered(Duration),
    /// Closed at this offset.
    Closed(Duration),
    /// The script ended during the negotiation: the victim must close at the
    /// deadline.
    Pending,
}

struct Prediction {
    outcome: Outcome,
    /// Bytes the victim reads before `Verack` (or before it closes).
    pre_bytes: usize,
    /// The victim answers the peer's `Version` with its `Verack`.
    sends_verack: bool,
    /// A frame fails to decrypt (pre-shared keys that differ).
    decrypt_failure: bool,
    /// The act whose `Verack` registers the peer, and the `relay_txs` of the
    /// peer's accepted `Version`.
    verack_at: Option<usize>,
    their_relay_txs: bool,
}

fn predict(cfg: &Config, acts: &[Act], nid: u32) -> Prediction {
    let via_tor = cfg.proxied
        || (cfg.kind == ConnKind::Inbound && cfg.addr.ip().is_some_and(|ip| ip.is_loopback()));
    let key_timeout = if via_tor {
        KEY_EXCHANGE_TIMEOUT_TOR
    } else {
        KEY_EXCHANGE_TIMEOUT
    };
    let mut p = Prediction {
        outcome: Outcome::Pending,
        pre_bytes: KEY,
        sends_verack: false,
        decrypt_failure: false,
        verack_at: None,
        their_relay_txs: false,
    };
    if cfg.key_delay >= key_timeout {
        p.outcome = Outcome::Closed(key_timeout);
        return p;
    }
    let keys_differ = matches!(cfg.psk, Psk::VictimOnly | Psk::PeerOnly);
    let mut t = cfg.key_delay;
    // `None`: waiting for `Version`; `Some(k)`: for `Verack`, k unknown
    // frames skipped.
    let mut skipped: Option<usize> = None;
    for (idx, act) in acts.iter().enumerate() {
        let (payload, echo) = match act {
            Act::Delay(d) => {
                t += *d;
                if t >= HANDSHAKE_DEADLINE {
                    p.outcome = Outcome::Closed(HANDSHAKE_DEADLINE);
                    return p;
                }
                continue;
            }
            Act::Version(v, echo) => (Message::Version(v.clone()).encode(), *echo),
            Act::Frame(f) => (f.clone(), false),
        };
        // Keys that differ: the first frame's length fails to decrypt.
        if keys_differ {
            p.pre_bytes += LEN_CT;
            p.decrypt_failure = true;
            p.outcome = Outcome::Closed(t);
            return p;
        }
        // Too long: refused once its length decrypts, before its payload.
        if payload.len() > MAX_HANDSHAKE_FRAME {
            p.pre_bytes += LEN_CT;
            p.outcome = Outcome::Closed(t);
            return p;
        }
        p.pre_bytes += LEN_CT + payload.len() + TAG;
        match skipped {
            None => match Message::decode(&payload) {
                // The negotiation's own checks; `echo`: our own nonce.
                Ok(Message::Version(v))
                    if v.protocol >= MIN_PROTOCOL_VERSION && v.network == nid && !echo =>
                {
                    skipped = Some(0);
                    p.sends_verack = true;
                    p.their_relay_txs = v.relay_txs;
                }
                _ => {
                    p.outcome = Outcome::Closed(t);
                    return p;
                }
            },
            Some(k) => {
                if payload.first().is_some_and(|&t| !spec_known_type(t))
                    && k < HANDSHAKE_UNKNOWN_FRAMES
                {
                    skipped = Some(k + 1);
                    continue;
                }
                // `Verack` has no body (docs/p2p.md §5): exactly its type byte.
                p.outcome = if payload == [1u8] {
                    p.verack_at = Some(idx);
                    Outcome::Registered(t)
                } else {
                    Outcome::Closed(t)
                };
                return p;
            }
        }
    }
    p
}

// ------------------------------------------------- scoring after `Verack`

/// What a frame sent after `Verack` costs the peer, by the table of
/// docs/p2p.md §10 ("Misbehavior, limits and bans") and its "Not penalized"
/// list. `None` where the specification does not fix the score for what the
/// script sent (the exact accounting stops there); each such case names the
/// ambiguity:
/// - a second `Version` or `Verack`: not in the §10 table;
/// - `Tx`: an unrequested `Tx` is 10, a stateless-invalid one 20, and §10
///   does not say which applies to an unrequested `Tx` that does not decode;
/// - any transaction, inventory or address message on a block-relay-only
///   connection, or an address message on an inbound one whose peer sent
///   `relay_txs = false` (§9: "no address is exchanged"; §10 gives no score);
///   a `StemTx` on an address fetch;
/// - an `Addr` on an address fetch: §9 closes the connection on it, unscored;
/// - `GetAddr` from an inbound peer that sent `relay_txs = false` (§9 says no
///   addresses there; §10 scores a second `GetAddr` from an inbound peer);
/// - a `Block` once its header was accepted (it may be requested by then),
///   and any other `Block` but the valid next one (body rule or unrequested,
///   whichever is checked first);
/// - `Headers` other than the two the script builds;
/// - a known message that decodes to anything else in a raw frame;
/// - any delay (pings and request timeouts are timed).
///
/// Malformed is decided by the codec (`Message::decode`): a strict decoder
/// of every message is the codec itself, fuzzed by `p2p_message`.
struct Scoring<'a> {
    kind: ConnKind,
    their_relay_txs: bool,
    h1: &'a BlockHeader,
    b1: &'a [u8],
    getaddrs: u32,
    header_accepted: bool,
}

impl Scoring<'_> {
    fn score(&mut self, act: &Act) -> Option<u32> {
        let payload = match act {
            Act::Delay(_) | Act::Version(..) => return None,
            Act::Frame(f) => f,
        };
        // §5: unknown types are ignored, not penalized.
        if payload.first().is_some_and(|&t| !spec_known_type(t)) {
            return Some(0);
        }
        // §10: a malformed known message (an empty frame among them) is 100.
        let Ok(msg) = Message::decode(payload) else {
            return Some(100);
        };
        let inbound = self.kind.is_inbound();
        let block_relay = self.kind == ConnKind::BlockRelay;
        let no_addrs = block_relay || (inbound && !self.their_relay_txs);
        match msg {
            Message::Version(_) | Message::Verack | Message::Tx(_) => None,
            // §10: `Pong` without a ping (the script never knows ours) is 10.
            Message::Pong(_) => Some(10),
            Message::Ping(_)
            | Message::GetHeaders { .. }
            | Message::GetBlocks(_)
            | Message::NotFound(_) => Some(0),
            Message::GetAddr if !inbound => Some(0),
            Message::GetAddr if no_addrs => None,
            // §10: a second `GetAddr` from an inbound peer is 10.
            Message::GetAddr => {
                self.getaddrs += 1;
                Some(if self.getaddrs > 1 { 10 } else { 0 })
            }
            // §10: an unsolicited `Addr` of more than 10 entries is 10.
            Message::Addr(_) if no_addrs => None,
            // §9 ("Seeds are one-shot address fetches"): an `Addr` closes an
            // address fetch, unscored; the accounting ends with it.
            Message::Addr(_) if self.kind == ConnKind::AddrFetch => None,
            Message::Addr(a) => (a.len() <= 10).then_some(0),
            Message::InvTx(_) | Message::GetTx(_) if block_relay => None,
            Message::InvTx(_) | Message::GetTx(_) => Some(0),
            Message::StemTx(_) if block_relay || self.kind == ConnKind::AddrFetch => None,
            // §10 step 0: a `StemTx` that does not decode is 20.
            Message::StemTx(b) => blacksilk_tx::types::Transaction::decode(&b)
                .is_err()
                .then_some(20),
            Message::Headers(h) if h == [*self.h1] => {
                self.header_accepted = true;
                Some(0)
            }
            // §10: a header whose timestamp is not after the median time
            // past (the genesis's, for the next header) is 100.
            Message::Headers(h)
                if h.len() == 1
                    && h[0].prev_id == self.h1.prev_id
                    && h[0].height == self.h1.height
                    && h[0].timestamp < chain_fixture::params().genesis.timestamp =>
            {
                Some(100)
            }
            Message::Headers(_) => None,
            // §10: an unrequested `Block` is 10 (its header is unknown, so it
            // was not requested).
            Message::Block(b) if !self.header_accepted && b == self.b1 => Some(10),
            Message::Block(_) => None,
        }
    }
}

/// The score threshold that disconnects and bans (docs/p2p.md §10).
const BAN_SCORE: u32 = 100;

// ------------------------------------------------------- the victim's stream

/// What the victim asked of its stream: each completed read as (bytes
/// consumed before it, bytes requested).
#[derive(Default)]
struct ReadLog {
    consumed: usize,
    reads: Vec<(usize, usize)>,
}

/// The victim's end of the connection, logging its reads.
struct Watched {
    io: DuplexStream,
    log: Arc<Mutex<ReadLog>>,
}

impl AsyncRead for Watched {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let (before, want) = (buf.filled().len(), buf.remaining());
        let r = Pin::new(&mut self.io).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = r {
            let got = buf.filled().len() - before;
            let mut log = self.log.lock().expect("the read log");
            let at = log.consumed;
            log.reads.push((at, want));
            log.consumed += got;
        }
        r
    }
}

impl AsyncWrite for Watched {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

// ------------------------------------------------------------ the session

/// Lets every ready task run (no virtual time passes).
async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

/// After a frame sent after `Verack`, with every frame since `Verack`
/// specified: the peer's score is `expected`; at `BAN_SCORE` or more it is
/// disconnected, and banned unless its address is not its own (proxied,
/// onion; docs/p2p.md §10). The victim handles some messages on other
/// tasks and the chain actor's thread (headers, the slow lane), so this
/// waits, in real time and without moving the paused clock, until the
/// expected state shows (a score below it), or a short while (a score at
/// it, which must then stay).
async fn check_score(victim: &Victim, expected: u32, bannable: bool, act: &Act, kind: ConnKind) {
    let reached = |s: &Snapshot| {
        if expected >= BAN_SCORE {
            s.peers == 0 && s.misbehaving_disconnects == 1
        } else {
            s.scores.first().is_some_and(|&x| x >= expected)
        }
    };
    // Up to about 2 s for the expected state, then a few more rounds in which
    // nothing more may happen.
    let mut s = victim.snapshot();
    for _ in 0..1_000 {
        settle().await;
        s = victim.snapshot();
        if reached(&s) {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    for _ in 0..4 {
        std::thread::sleep(Duration::from_millis(1));
        settle().await;
        s = victim.snapshot();
    }
    let k = match expected {
        0 => 0,
        e if e < BAN_SCORE => 1,
        _ => 2,
    };
    SCORED[k].fetch_add(1, Ordering::Relaxed);
    if expected >= BAN_SCORE {
        assert!(
            reached(&s),
            "not disconnected at score {expected} after {act:?}: {s:?}"
        );
        assert_eq!(
            s.banned, bannable as usize,
            "the ban after {act:?} (bannable: {bannable})"
        );
    } else {
        assert_eq!(
            s.scores,
            vec![expected],
            "the peer's score after {act:?} on a {:?} connection (docs/p2p.md §10)",
            kind
        );
        assert_eq!((s.banned, s.misbehaving_disconnects), (0, 0));
    }
}

fn assert_quiet(s: &Snapshot, initial: &Snapshot, when: &str) {
    assert_eq!(s.peers, 0, "{when}: a peer table entry before registration");
    assert!(s.scores.is_empty(), "{when}: a score before registration");
    assert_eq!(s.banned, 0, "{when}: a ban before registration");
    assert_eq!(
        s.misbehaving_disconnects, 0,
        "{when}: a misbehaviour before registration"
    );
    assert_eq!(
        s.known_addresses, initial.known_addresses,
        "{when}: the address table changed before registration"
    );
}

async fn session(data: &[u8], chain: ChainHandle) {
    let (b0, b1) = (
        data.first().copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
    );
    let cfg = config(b0, b1);
    let nid = chain_fixture::params().network_id;
    let genesis = chain.summary_cell().load().genesis_id;
    let acts = script(data.get(2..).unwrap_or(&[]), &cfg, nid, &genesis);
    let model = predict(&cfg, &acts, nid);
    tally(&cfg, &model);

    let psk = NetworkPsk::from_bytes([0x42; 32]).expect("a key");
    let mut net = NetConfig::new(nid);
    net.public_address = Some(cfg.public.clone());
    net.network_psk = matches!(cfg.psk, Psk::Shared | Psk::VictimOnly).then(|| psk.clone());
    let peer_psk = matches!(cfg.psk, Psk::Shared | Psk::PeerOnly).then_some(&psk);
    let victim = Arc::new(Victim::new(net, chain, 1));
    let initial = victim.snapshot();
    let start = Instant::now();

    let (victim_io, peer_io) = tokio::io::duplex(1 << 20);
    let log = Arc::new(Mutex::new(ReadLog::default()));
    let watched = Watched {
        io: victim_io,
        log: log.clone(),
    };
    let conn = {
        let (v, addr, kind, proxied) = (victim.clone(), cfg.addr.clone(), cfg.kind, cfg.proxied);
        tokio::spawn(async move {
            v.run_connection(watched, addr, kind, proxied).await;
            Instant::now()
        })
    };

    // The attacker.
    tokio::time::sleep(cfg.key_delay).await;
    let session = Session {
        network_id: nid,
        genesis_id: &genesis,
        psk: peer_psk,
    };
    let keyed = handshake_with(
        peer_io,
        cfg.kind.is_inbound(),
        session,
        Duration::from_secs(60),
    )
    .await;
    let sent: Arc<Mutex<Vec<Message>>> = Arc::default();
    let mut halves = None;
    let mut reader_task = None;
    let (nonce_tx, nonce_rx) = tokio::sync::oneshot::channel::<u64>();
    if let Ok((mut reader, writer)) = keyed {
        let sent = sent.clone();
        reader_task = Some(tokio::spawn(async move {
            let mut nonce_tx = Some(nonce_tx);
            // Until the victim closes (or a frame fails to decrypt: keys
            // that differ).
            while let Ok(f) = reader.recv().await {
                let m = Message::decode(&f).expect("everything the victim sends decodes");
                if let (Message::Version(v), Some(tx)) = (&m, nonce_tx.take()) {
                    let _ = tx.send(v.nonce);
                }
                sent.lock().expect("the sent log").push(m);
            }
        }));
        halves = Some(writer);
    }
    let mut nonce_rx = Some(nonce_rx);
    let (h1, b1) = next_block();
    let mut scoring = Scoring {
        kind: cfg.kind,
        their_relay_txs: model.their_relay_txs,
        h1,
        b1,
        getaddrs: 0,
        header_accepted: false,
    };
    // The score the specification gives the peer so far, while every frame
    // after `Verack` had a specified score (`None` once one had not).
    let mut expected: Option<u32> = Some(0);
    let bannable = !cfg.proxied && cfg.addr.ip().is_some();
    if let Some(writer) = halves.as_mut() {
        for (idx, act) in acts.iter().enumerate() {
            let after_verack = model.verack_at.is_some_and(|v| idx > v);
            if after_verack {
                if let Some(e) = expected {
                    expected = scoring.score(act).map(|s| e + s);
                }
            }
            settle().await;
            let s = victim.snapshot();
            if s.registered == 0 {
                assert_quiet(&s, &initial, "during the negotiation");
            }
            let payload = match act {
                Act::Delay(d) => {
                    tokio::time::sleep(*d).await;
                    continue;
                }
                Act::Version(v, echo) => {
                    let mut v = v.clone();
                    if *echo {
                        // The victim's nonce, from its own `Version`.
                        if let Some(rx) = nonce_rx.take() {
                            v.nonce = rx.await.unwrap_or(0);
                        }
                    }
                    Message::Version(v).encode()
                }
                Act::Frame(f) => f.clone(),
            };
            if writer.send(&payload).await.is_err() {
                break;
            }
            if let (true, Some(e)) = (after_verack, expected) {
                check_score(&victim, e, bannable, act, cfg.kind).await;
                if e >= BAN_SCORE {
                    break;
                }
            }
        }
    }
    settle().await;

    // The negotiation's result, as the model predicts it.
    let mut conn = Some(conn);
    let s = victim.snapshot();
    match model.outcome {
        Outcome::Registered(_) => {
            assert_eq!(s.registered, 1, "a valid negotiation registers the peer")
        }
        Outcome::Closed(_) | Outcome::Pending => {
            assert_eq!(
                s.registered, 0,
                "the peer was registered: {:?}",
                model.outcome
            );
            assert_quiet(&s, &initial, "after the negotiation");
            // The attacker keeps the connection open: the victim closes it,
            // at the predicted instant.
            let bound = match model.outcome {
                Outcome::Closed(t) => t,
                _ => HANDSHAKE_DEADLINE,
            };
            let deadline = start + bound + Duration::from_millis(1);
            let task = conn.take().expect("the connection task");
            let done = match tokio::time::timeout_at(deadline, task).await {
                Ok(r) => joined(r),
                Err(_) => panic!(
                    "an unregistered connection is still open after {bound:?} ({:?})",
                    model.outcome
                ),
            };
            let at = done - start;
            assert!(
                at >= bound && at <= bound + Duration::from_millis(1),
                "the victim closed at {at:?}, not at {bound:?} ({:?})",
                model.outcome
            );
        }
    }

    // The attacker leaves: a registered connection ends too.
    drop(halves);
    if let Some(task) = conn.take() {
        let r = tokio::time::timeout(Duration::from_secs(400), task)
            .await
            .expect("the connection ends once the peer leaves");
        joined(r);
    }
    if let Some(r) = reader_task {
        r.await.expect("the attacker's reader");
    }
    let end = victim.snapshot();

    // Cleanup.
    assert_eq!(
        end.peers, 0,
        "the peer stays registered after its connection ended"
    );
    assert_eq!(end.local_nonces, 0, "a handshake nonce was not released");
    assert_eq!(end.block_requests, 0, "a block request outlives its peer");
    assert_eq!(
        end.tx_requests, 0,
        "a transaction request outlives its peer"
    );
    assert_eq!(
        end.tx_announcers, 0,
        "a transaction announcer outlives its peer"
    );
    assert_eq!(end.stems, 0, "a Dandelion stem outlives its peer");
    assert_eq!(end.handshakes, 0);
    if end.registered == 0 {
        assert_quiet(&end, &initial, "after an unregistered connection");
        assert_eq!(
            end.transport_failures, model.decrypt_failure as u64,
            "transport failures"
        );
    }

    // What the victim read before `Verack`.
    {
        let log = log.lock().expect("the read log");
        for &(at, want) in &log.reads {
            if at < model.pre_bytes {
                assert!(
                    want <= MAX_HANDSHAKE_FRAME + TAG,
                    "a read of {want} bytes at offset {at}, before Verack"
                );
            }
        }
        if end.registered == 0 {
            assert!(
                log.consumed <= model.pre_bytes,
                "the victim read {} bytes, more than the {} the negotiation consumes",
                log.consumed,
                model.pre_bytes
            );
        }
    }

    // What the victim sent.
    let sent = sent.lock().expect("the sent log");
    if matches!(cfg.psk, Psk::None | Psk::Shared) && !sent.is_empty() {
        let Message::Version(v) = &sent[0] else {
            panic!("the victim's first message is {}", sent[0].kind());
        };
        assert_eq!((v.network, v.protocol), (nid, PROTOCOL_VERSION));
        assert!(v.listen.is_none() || v.listen.as_ref() == Some(&cfg.public));
        if cfg.kind == ConnKind::BlockRelay {
            assert!(
                v.listen.is_none(),
                "our address on a block-relay-only connection"
            );
            assert!(
                !v.relay_txs,
                "transaction relay on a block-relay-only connection"
            );
        }
        if end.registered == 0 {
            assert!(sent.len() <= 1 + model.sends_verack as usize, "{sent:?}");
            if let Some(m) = sent.get(1) {
                assert_eq!(*m, Message::Verack);
            }
        }
        if cfg.kind == ConnKind::BlockRelay {
            for m in sent.iter() {
                assert!(
                    !matches!(
                        m,
                        Message::Addr(_)
                            | Message::GetAddr
                            | Message::InvTx(_)
                            | Message::GetTx(_)
                            | Message::Tx(_)
                            | Message::StemTx(_)
                    ),
                    "{} on a block-relay-only connection",
                    m.kind()
                );
            }
        }
    }
}

/// The connection task's result: its end time, or its panic, resumed.
fn joined(r: Result<Instant, tokio::task::JoinError>) -> Instant {
    match r {
        Ok(at) => at,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(e) => panic!("the connection task was cancelled: {e}"),
    }
}

/// Seed inputs (named): honest negotiations of every connection kind, then
/// each way a negotiation fails, then traffic after `Verack`.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let mut unknown8 = vec![0, 0, 0, 0, 0, 0];
    let mut unknown9 = unknown8.clone();
    for _ in 0..8 {
        unknown8.extend([2, 1, 5, 0]);
        unknown9.extend([2, 1, 5, 0]);
    }
    unknown8.extend([1, 0, 0, 0]);
    unknown9.extend([2, 1, 5, 0, 1, 0, 0, 0]);
    vec![
        (
            "inbound",
            vec![0, 0, 0, 0, 8, 0, 1, 0, 0, 0, 7, 0, 0, 5, 7, 2, 0, 0],
        ),
        (
            "full_relay",
            vec![
                2, 0, 0, 0, 12, 1, 1, 0, 0, 0, 7, 5, 0, 0, 7, 8, 0, 0, 7, 4, 0, 0,
            ],
        ),
        (
            "block_relay",
            vec![
                3, 0, 0, 0, 4, 1, 1, 0, 0, 0, 7, 13, 5, 1, 7, 3, 2, 1, 7, 9, 0, 1,
            ],
        ),
        ("addr_fetch", vec![4, 0, 0, 0, 0, 0, 1, 0, 0, 0, 7, 3, 3, 9]),
        ("onion_inbound", vec![1, 0, 0, 0, 0, 3, 1, 0, 0, 0]),
        ("own_listen", vec![0, 0, 0, 0, 4, 2, 1, 0, 0, 0]),
        ("unknown_8", unknown8),
        ("unknown_9", unknown9),
        ("oversize", vec![0, 0, 0, 0, 0, 0, 5, 0, 0, 0]),
        ("max_frame", vec![0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 1, 0, 0, 0]),
        (
            "stall",
            vec![0, 0, 0, 0, 0, 0, 4, 7, 0, 0, 4, 7, 0, 0, 4, 7, 0, 0],
        ),
        (
            "stall_before_version",
            vec![2, 0, 4, 7, 0, 0, 4, 7, 0, 0, 4, 7, 0, 0],
        ),
        ("echo_nonce", vec![0, 0, 0, 0, 2, 0, 1, 0, 0, 0]),
        ("version_only", vec![0, 0, 0, 0, 0, 0]),
        ("wrong_network", vec![0, 0, 0, 0, 1, 0]),
        ("old_protocol", vec![0, 0, 0, 1, 0, 0]),
        ("psk_shared", vec![0x80, 0, 0, 0, 0, 0, 1, 0, 0, 0]),
        ("psk_victim_only", vec![0x80, 0x80, 0, 0, 0, 0]),
        ("psk_peer_only", vec![0x80, 0xc0, 0, 0, 0, 0]),
        ("key_delay", vec![0, 0x26, 0, 0, 0, 0, 1, 0, 0, 0]),
        ("key_delay_tor", vec![10, 0x26, 0, 0, 0, 0, 1, 0, 0, 0]),
        ("verack_first", vec![0, 0, 1, 0, 0, 0]),
        ("empty_frame", vec![0, 0, 0, 0, 0, 0, 8, 0, 0, 0]),
        (
            "after_verack_junk",
            vec![0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 9, 1, 2, 3],
        ),
        (
            "after_verack_large",
            vec![0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 5, 10, 0, 0],
        ),
        (
            "headers_then_block",
            vec![
                2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 7, 5, 0, 0, 7, 8, 0, 0, 7, 7, 0, 0,
            ],
        ),
        ("bad_header", vec![2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 7, 6, 0, 0]),
        (
            "stem_and_tx",
            vec![0, 0, 0, 0, 4, 0, 1, 0, 0, 0, 7, 13, 9, 1, 7, 12, 9, 2],
        ),
        // Scoring after `Verack` (docs/p2p.md §10).
        ("pong_10", vec![0, 0, 0, 0, 4, 0, 1, 0, 0, 0, 7, 1, 0, 3]),
        (
            "getaddr_twice_10",
            vec![0, 0, 0, 0, 4, 0, 1, 0, 0, 0, 7, 2, 0, 0, 7, 2, 0, 0],
        ),
        (
            "unrequested_block_10",
            vec![2, 0, 0, 0, 4, 0, 1, 0, 0, 0, 7, 8, 0, 0],
        ),
        (
            "stem_undecodable_20",
            vec![0, 0, 0, 0, 4, 0, 1, 0, 0, 0, 7, 13, 9, 1],
        ),
        (
            "bad_header_100_proxied",
            vec![10, 0, 0, 0, 0, 0, 1, 0, 0, 0, 7, 6, 0, 0],
        ),
        (
            "bad_header_100_onion",
            vec![0x22, 0, 0, 0, 0, 0, 1, 0, 0, 0, 7, 6, 0, 0],
        ),
        (
            "malformed_100",
            vec![0, 0, 0, 0, 4, 0, 1, 0, 0, 0, 3, 7, 3, 9],
        ),
        ("pongs_to_ban", {
            let mut s = vec![0, 0, 0, 0, 4, 0, 1, 0, 0, 0];
            for i in 0..11 {
                s.extend([7, 1, 0, i]);
            }
            s
        }),
    ]
}

/// How far the inputs went (the stable twin prints it): registered, closed
/// at a frame, at the key exchange timeout, at the handshake deadline, and
/// on a frame that failed to decrypt.
pub static REACHED: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

pub fn reached() -> String {
    let [r, f, k, d, x] = REACHED.each_ref().map(|c| c.load(Ordering::Relaxed));
    let [z, p, b] = SCORED.each_ref().map(|c| c.load(Ordering::Relaxed));
    format!("registered {r}, closed at a frame {f}, at the key exchange timeout {k}, at the deadline {d} (of them decrypt failures: {x}); scores checked after Verack: at 0 {z}, above 0 {p}, at the ban {b}")
}

/// Score checks after `Verack` (`check_score`): at a score of 0, above 0
/// and below the ban, and at the ban.
pub static SCORED: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

fn tally(cfg: &Config, model: &Prediction) {
    let via_tor = cfg.proxied
        || (cfg.kind == ConnKind::Inbound && cfg.addr.ip().is_some_and(|ip| ip.is_loopback()));
    let key_timeout = if via_tor {
        KEY_EXCHANGE_TIMEOUT_TOR
    } else {
        KEY_EXCHANGE_TIMEOUT
    };
    let i = match model.outcome {
        Outcome::Registered(_) => 0,
        Outcome::Closed(t) if t == key_timeout && cfg.key_delay >= key_timeout => 2,
        Outcome::Closed(t) if t == HANDSHAKE_DEADLINE => 3,
        Outcome::Closed(_) => 1,
        Outcome::Pending => 3,
    };
    REACHED[i].fetch_add(1, Ordering::Relaxed);
    if model.decrypt_failure {
        REACHED[4].fetch_add(1, Ordering::Relaxed);
    }
}
