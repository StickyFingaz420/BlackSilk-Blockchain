//! Target body: the transport's key exchange (p2p/src/transport.rs,
//! docs/p2p.md §3), the first bytes a node reads from an unauthenticated
//! peer, then the first frame after it.
//!
//! Input: a mode byte, then up to 32 bytes of the attacker's public key,
//! then raw bytes sent after the key. Mode bits: 1 = the victim opened the
//! connection (initiator), else it accepted it (responder); 2 = replace the
//! key bytes with a valid group element (the key bytes, as a scalar, times
//! the base point), so inputs reach the frame reader past the key check.
//! The attacker writes the key and the raw bytes, then closes its sending
//! side (the victim's own key still goes through).
//!
//! Invariants, beyond "no panic":
//! - a key cut short is an end of stream, never a session;
//! - the handshake succeeds exactly when the key is a canonical,
//!   non-identity Ristretto255 encoding, and refuses anything else with
//!   `BadKey`;
//! - after a successful handshake, bytes from a peer that does not hold the
//!   session keys never produce a payload: 20 bytes or more fail
//!   authentication (`Decrypt`, the encrypted length's tag), fewer are an
//!   end of stream. The victim's ephemeral secret is fresh per session, so
//!   no input can hold its keys.

use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_p2p::message::MAX_FRAME;
use blacksilk_p2p::transport::{handshake, TransportError};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

const NETWORK: u32 = 7;
const GENESIS: [u8; 32] = [0x6E; 32];
/// Encrypted length (4) and its tag (16).
const LEN_CT: usize = 20;
const PIPE: usize = 1 << 17;

const INITIATOR: u8 = 1;
const VALID_KEY: u8 = 2;

thread_local! {
    static RUNTIME: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime");
}

pub fn run(data: &[u8]) {
    RUNTIME.with(|rt| rt.block_on(session(data)));
}

async fn session(data: &[u8]) {
    let mode = data.first().copied().unwrap_or(0);
    let rest = data.get(1..).unwrap_or(&[]);
    let n = rest.len().min(32);
    let mut key = [0u8; 32];
    key[..n].copy_from_slice(&rest[..n]);
    let raw = &rest[n..];
    if mode & VALID_KEY != 0 && n == 32 {
        let s = Scalar::from_bytes_mod_order(key);
        key = *Point::from_point(RistrettoPoint::mul_base(&s)).bytes();
    }
    let (victim_io, mut attacker) = tokio::io::duplex(PIPE);
    // The whole input is written before the victim runs: the pipe holds it.
    attacker.write_all(&key[..n]).await.expect("the key");
    attacker.write_all(raw).await.expect("the raw bytes");
    attacker.shutdown().await.expect("close the sending side");
    let initiator = mode & INITIATOR != 0;
    let got = handshake(
        victim_io,
        initiator,
        NETWORK,
        &GENESIS,
        Duration::from_secs(60),
    )
    .await;
    if n < 32 {
        assert_eof(got.map(|_| ()));
        return;
    }
    let valid = Point::decode(&key).is_some_and(|p| !p.is_identity());
    let (mut reader, _writer) = match got {
        Ok(halves) => {
            assert!(valid, "a session from an invalid key: {key:02x?}");
            halves
        }
        Err(TransportError::BadKey) => {
            assert!(!valid, "a valid key refused: {key:02x?}");
            return;
        }
        Err(e) => panic!("the handshake failed otherwise: {e:?}"),
    };
    let frame = reader.recv_limited(MAX_FRAME).await;
    if raw.len() >= LEN_CT {
        assert!(matches!(frame, Err(TransportError::Decrypt)), "{frame:?}");
    } else {
        assert_eof(frame);
    }
    drop(attacker);
}

fn assert_eof<T: std::fmt::Debug>(got: Result<T, TransportError>) {
    match got {
        Err(TransportError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof),
        other => panic!("a stream that ends early: {other:?}"),
    }
}

/// Seed inputs (named).
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    // The Ristretto255 base point's encoding (RFC 9496 A.1).
    let base: [u8; 32] = *Point::from_point(RistrettoPoint::mul_base(&Scalar::ONE)).bytes();
    let with = |mode: u8, key: &[u8], raw: &[u8]| [&[mode][..], key, raw].concat();
    vec![
        ("base_responder", with(0, &base, &[])),
        ("base_initiator", with(INITIATOR, &base, &[])),
        ("base_frame", with(0, &base, &[0x5a; 40])),
        ("base_short_frame", with(INITIATOR, &base, &[1, 2, 3])),
        ("identity", with(0, &[0; 32], &[])),
        ("non_canonical", with(0, &[0xff; 32], &[])),
        ("scalar_key_frame", with(VALID_KEY, &[7; 32], &[0; 64])),
        ("short_key", with(0, &base[..20], &[])),
        ("empty", vec![]),
    ]
}
