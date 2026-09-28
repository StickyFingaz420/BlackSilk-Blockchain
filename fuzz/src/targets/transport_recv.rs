//! Target body: the transport's receive path (p2p/src/transport.rs,
//! docs/p2p.md §3; W2-30): frame decryption and length handling in
//! `FrameReader::recv_limited`.
//!
//! Each input runs a real handshake between a victim (responder) and the
//! target's own peer (initiator) through an in-memory relay the target
//! controls, so the peer holds the session keys and every frame it sends is
//! authentic. The input then scripts what reaches the victim, 4 bytes per
//! step: `op, a, b, c`, with a limit `max` for the victim's
//! `recv_limited(max)` from `b, c` and a payload length from `a, b`:
//! - 0: an authentic frame, forwarded as is;
//! - 1: an authentic frame with one bit flipped;
//! - 2: only the frame's encrypted length, then the connection closes;
//! - 3: the frame cut short, then the connection closes;
//! - 4: raw bytes (the rest of the input), then the connection closes;
//! - 5: a frame delivered twice, or a later frame before an earlier one.
//!
//! Invariants, beyond "no panic":
//! - an authentic frame within the limit arrives intact, in order;
//! - an authentic frame over `min(max, MAX_FRAME)` is refused with
//!   `FrameTooLarge` as soon as its length decrypts, before its payload is
//!   read: step 2 (payload never sent) gets `FrameTooLarge`, not an end of
//!   stream. So nothing is allocated for a payload over the cap;
//! - anything tampered with, replayed or reordered fails authentication
//!   (`Decrypt`), and unauthenticated bytes never produce a payload or a
//!   length (they cannot pass the length's tag). Before a length
//!   authenticates, the reader holds only its fixed 20-byte buffer;
//! - a stream that ends early is an I/O error, never a payload.
//!
//! The first failure ends the session (every caller drops the connection).

use blacksilk_p2p::message::MAX_FRAME;
use blacksilk_p2p::transport::{handshake, FrameWriter, TransportError};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, WriteHalf};

const NETWORK: u32 = 7;
const GENESIS: [u8; 32] = [0x6E; 32];
/// Encrypted length (4) and its tag (16).
const LEN_CT: usize = 20;
const TAG: usize = 16;
/// Room for the largest frame a step sends.
const PIPE: usize = 1 << 21;

thread_local! {
    static RUNTIME: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime");
}

pub fn run(data: &[u8]) {
    RUNTIME.with(|rt| rt.block_on(session(data)));
}

struct Peer {
    writer: FrameWriter<WriteHalf<DuplexStream>>,
    /// The relay's end of the peer's pipe: what the peer sent.
    sent: DuplexStream,
}

impl Peer {
    /// The bytes of one authentic frame carrying `payload`.
    async fn frame(&mut self, payload: &[u8]) -> Vec<u8> {
        self.writer.send(payload).await.expect("send a frame");
        let mut f = vec![0u8; LEN_CT + payload.len() + TAG];
        self.sent.read_exact(&mut f).await.expect("read the frame");
        f
    }
}

async fn session(data: &[u8]) {
    let (peer_io, peer_relay) = tokio::io::duplex(PIPE);
    let (victim_io, mut victim_relay) = tokio::io::duplex(PIPE);
    let t = Duration::from_secs(60);
    let mut to_peer = peer_relay;
    let relay = async {
        let mut k = [0u8; 32];
        to_peer.read_exact(&mut k).await.expect("the peer's key");
        victim_relay.write_all(&k).await.expect("forward");
        victim_relay
            .read_exact(&mut k)
            .await
            .expect("the victim's key");
        to_peer.write_all(&k).await.expect("forward");
    };
    let (p, v, ()) = tokio::join!(
        handshake(peer_io, true, NETWORK, &GENESIS, t),
        handshake(victim_io, false, NETWORK, &GENESIS, t),
        relay
    );
    let (_peer_reader, writer) = p.expect("the peer's handshake");
    let (mut victim, _victim_writer) = v.expect("the victim's handshake");
    let mut peer = Peer {
        writer,
        sent: to_peer,
    };
    let mut to_victim = Some(victim_relay);
    for (k, step) in data.chunks(4).enumerate() {
        let [op, a, b, c] = [0, 1, 2, 3].map(|i| step.get(i).copied().unwrap_or(0));
        let max = limit(b, c);
        let len = ((a as usize) << 8 | b as usize) % 4096;
        let payload: Vec<u8> = (0..len).map(|i| (i as u8) ^ c).collect();
        let pipe = to_victim.as_mut().expect("open while the session runs");
        let over = len > max.min(MAX_FRAME);
        match op % 6 {
            0 => {
                let f = peer.frame(&payload).await;
                pipe.write_all(&f).await.expect("deliver");
                let got = victim.recv_limited(max).await;
                if over {
                    assert_too_large(got, len);
                    return;
                }
                assert_eq!(got.expect("an authentic frame"), payload);
            }
            1 => {
                let mut f = peer.frame(&payload).await;
                let at = ((c as usize) << 8 | a as usize) % f.len();
                f[at] ^= 1 << (b % 8);
                pipe.write_all(&f).await.expect("deliver");
                let got = victim.recv_limited(max).await;
                if at >= LEN_CT && over {
                    assert_too_large(got, len);
                } else {
                    assert!(matches!(got, Err(TransportError::Decrypt)), "{got:?}");
                }
                return;
            }
            2 | 3 => {
                let f = peer.frame(&payload).await;
                let cut = if op % 6 == 2 {
                    LEN_CT
                } else {
                    (c as usize) % f.len()
                };
                pipe.write_all(&f[..cut]).await.expect("deliver");
                drop(to_victim.take());
                let got = victim.recv_limited(max).await;
                if cut >= LEN_CT && over {
                    assert_too_large(got, len);
                } else {
                    assert_eof(got);
                }
                return;
            }
            4 => {
                let raw = &data[data.len().min(4 * k + 4)..];
                pipe.write_all(raw).await.expect("deliver");
                drop(to_victim.take());
                let got = victim.recv_limited(max).await;
                if raw.len() >= LEN_CT {
                    assert!(matches!(got, Err(TransportError::Decrypt)), "{got:?}");
                } else {
                    assert_eof(got);
                }
                return;
            }
            _ => {
                let first = peer.frame(&payload).await;
                let second = peer.frame(&[c; 3]).await;
                if a & 1 == 0 {
                    // A replay: the first frame arrives, then again.
                    pipe.write_all(&first).await.expect("deliver");
                    let got = victim.recv_limited(max).await;
                    if over {
                        assert_too_large(got, len);
                        return;
                    }
                    assert_eq!(got.expect("an authentic frame"), payload);
                    pipe.write_all(&first).await.expect("deliver");
                } else {
                    // Reordered: the second frame first.
                    pipe.write_all(&second).await.expect("deliver");
                }
                let got = victim.recv_limited(max).await;
                assert!(matches!(got, Err(TransportError::Decrypt)), "{got:?}");
                return;
            }
        }
    }
}

/// The victim's limit: often small, sometimes `MAX_FRAME` or above.
fn limit(b: u8, c: u8) -> usize {
    match c % 8 {
        0 => MAX_FRAME,
        1 => usize::MAX,
        2 => MAX_FRAME + 1 + b as usize,
        _ => ((c as usize) << 4 | b as usize) % 4200,
    }
}

fn assert_too_large(got: Result<Vec<u8>, TransportError>, len: usize) {
    match got {
        Err(TransportError::FrameTooLarge(n)) => assert_eq!(n, len),
        other => panic!("a frame of {len} bytes over the limit: {other:?}"),
    }
}

fn assert_eof(got: Result<Vec<u8>, TransportError>) {
    match got {
        Err(TransportError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof),
        other => panic!("a stream that ends early: {other:?}"),
    }
}

/// Seed inputs (named).
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "frames",
            vec![0, 0, 5, 3, 0, 1, 0, 3, 0, 15, 255, 3, 0, 0, 0, 0],
        ),
        ("over_limit", vec![0, 0, 5, 3, 0, 4, 0, 4]),
        ("bit_flip_length", vec![0, 0, 9, 3, 1, 3, 0, 0]),
        ("bit_flip_payload", vec![1, 40, 1, 3]),
        ("length_only_over", vec![2, 4, 0, 4]),
        ("length_only_within", vec![2, 0, 7, 3]),
        ("truncated", vec![3, 0, 50, 27]),
        ("garbage", [&[4u8, 0, 0, 0][..], &[0x5a; 64]].concat()),
        ("garbage_short", vec![4, 0, 0, 0, 1, 2, 3]),
        ("replay", vec![5, 0, 4, 3]),
        ("reorder", vec![5, 1, 4, 3]),
    ]
}
