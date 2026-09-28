//! Encrypted transport (docs/p2p.md §3).
//!
//! ```text
//! initiator → responder: A = a·G      responder → initiator: B = b·G   (Ristretto255)
//! S = a·B = b·A
//! k = H64("p2p/session", LE32(network_id) ‖ genesis_id ‖ LE32(TRANSPORT_VERSION)
//!                        ‖ psk_flag ‖ psk ‖ A ‖ B ‖ S)
//! frame = AES-256-GCM(k_dir, n, LE32(len)) ‖ AES-256-GCM(k_dir, n+1, payload)
//! ```
//!
//! The genesis id binds the session to one chain, not only one network id: a
//! node of the same network id on another genesis (a release candidate, a
//! rehearsal, a retired identity) derives other keys, and its first frame fails
//! to decrypt (R15-3). The transport version binds it to this transport: a
//! later transport derives other keys, so two transports never talk and
//! nothing falls back silently to a weaker one (dossier 30 W5). An optional
//! network pre-shared key ([`NetworkPsk`], F48-1) closes a network to everyone
//! without it, including a man in the middle.
//!
//! Ephemeral keys; no magic bytes or version travel in the clear. Peers are
//! *not* authenticated: without a pre-shared key this protects against passive
//! observers, not against an active man in the middle (docs/p2p.md §1).

use crate::message::MAX_FRAME;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use blacksilk_crypto::hash::{h64, tags};
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use zeroize::{Zeroize, Zeroizing};

const TAG: usize = 16;

/// The version of this transport, bound into the session keys (docs/p2p.md
/// §3). It is not negotiated: a node of another transport version derives
/// other keys and its first frame fails to decrypt. A later transport is a
/// flag day or an in-band extension after the key exchange, never a fallback.
pub const TRANSPORT_VERSION: u32 = 1;

#[derive(Debug)]
pub enum TransportError {
    Io(std::io::Error),
    /// The peer's key is not a canonical, non-identity group element.
    BadKey,
    /// Authentication failed: tampering on the path, a wrong network, genesis,
    /// transport version or pre-shared key, or not a BlackSilk peer. Not
    /// attributable to the peer (docs/p2p.md §10).
    Decrypt,
    FrameTooLarge(usize),
    Timeout,
    Rng,
}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        TransportError::Io(e)
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A closed network's pre-shared key (F48-1, docs/p2p.md §3): 32 secret bytes
/// every member holds, mixed into the session keys. A node without it cannot
/// complete a session with a member, and neither can a man in the middle.
/// Optional, for private test networks; never required on a public network.
#[derive(Clone)]
pub struct NetworkPsk([u8; 32]);

#[derive(Debug)]
pub enum PskError {
    Io(std::io::Error),
    /// Not 64 hexadecimal characters (32 bytes), or all zero.
    Format,
}

impl std::fmt::Display for PskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PskError::Io(e) => write!(f, "cannot read the network key file: {e}"),
            PskError::Format => write!(
                f,
                "the network key file must hold 64 hexadecimal characters (32 bytes, not all zero)"
            ),
        }
    }
}

impl NetworkPsk {
    /// The key from its 32 bytes. An all-zero key is refused: it is what a
    /// missing or truncated secret most often looks like.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PskError> {
        if bytes == [0; 32] {
            return Err(PskError::Format);
        }
        Ok(Self(bytes))
    }

    /// The key from 64 hexadecimal characters; surrounding whitespace (a
    /// trailing newline) is ignored.
    pub fn from_hex(text: &str) -> Result<Self, PskError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(text.trim(), &mut bytes[..]).map_err(|_| PskError::Format)?;
        Self::from_bytes(*bytes)
    }

    /// Reads the key from a file holding its 64 hexadecimal characters
    /// (for example `openssl rand -hex 32`).
    pub fn load(path: &Path) -> Result<Self, PskError> {
        let text = Zeroizing::new(std::fs::read_to_string(path).map_err(PskError::Io)?);
        Self::from_hex(&text)
    }
}

impl Drop for NetworkPsk {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for NetworkPsk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NetworkPsk(<secret>)")
    }
}

/// What both ends of a session must share: the network, the chain's genesis
/// block id and, on a closed network, the pre-shared key.
#[derive(Clone, Copy, Debug)]
pub struct Session<'a> {
    pub network_id: u32,
    pub genesis_id: &'a [u8; 32],
    pub psk: Option<&'a NetworkPsk>,
}

/// The 64-byte session key of `version` over the public keys `a` (initiator)
/// and `b` (responder) and the shared point `s`. Every input has a fixed
/// length, so the encoding is unambiguous; without a pre-shared key its flag
/// is 0 and its 32 bytes are zero.
fn session_key(
    version: u32,
    session: &Session<'_>,
    a: &[u8; 32],
    b: &[u8; 32],
    s: &[u8; 32],
) -> [u8; 64] {
    const NO_PSK: [u8; 32] = [0; 32];
    let (flag, psk) = match session.psk {
        Some(p) => (1u8, &p.0),
        None => (0u8, &NO_PSK),
    };
    h64(
        tags::P2P_SESSION,
        &[
            &session.network_id.to_le_bytes(),
            session.genesis_id,
            &version.to_le_bytes(),
            &[flag],
            psk,
            a,
            b,
            s,
        ],
    )
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_le_bytes());
    n
}

pub struct FrameWriter<W> {
    inner: W,
    cipher: Aes256Gcm,
    counter: u64,
}

/// The receiving half. [`FrameReader::recv`] is not cancellation-safe: a
/// cancelled receive leaves the stream inside a frame, so the connection
/// must then be dropped (every caller does).
pub struct FrameReader<R> {
    inner: R,
    cipher: Aes256Gcm,
    counter: u64,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        if payload.len() > MAX_FRAME {
            return Err(TransportError::FrameTooLarge(payload.len()));
        }
        let len = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce(self.counter)),
                &(payload.len() as u32).to_le_bytes()[..],
            )
            .map_err(|_| TransportError::Decrypt)?;
        let body = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce(self.counter + 1)), payload)
            .map_err(|_| TransportError::Decrypt)?;
        self.counter += 2;
        let mut frame = len;
        frame.extend_from_slice(&body);
        self.inner.write_all(&frame).await?;
        self.inner.flush().await?;
        Ok(())
    }
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// The next frame's payload, at most [`MAX_FRAME`] bytes.
    pub async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        self.recv_limited(MAX_FRAME).await
    }

    /// The next frame's payload, at most `max` bytes: a longer frame is
    /// refused right after its length decrypts, before its payload is read
    /// or anything is allocated for it.
    pub async fn recv_limited(&mut self, max: usize) -> Result<Vec<u8>, TransportError> {
        let mut len_ct = [0u8; 4 + TAG];
        self.inner.read_exact(&mut len_ct).await?;
        let len_pt = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce(self.counter)), &len_ct[..])
            .map_err(|_| TransportError::Decrypt)?;
        let len = u32::from_le_bytes(len_pt[..4].try_into().expect("4 bytes")) as usize;
        if len > max.min(MAX_FRAME) {
            return Err(TransportError::FrameTooLarge(len));
        }
        let mut body = vec![0u8; len + TAG];
        self.inner.read_exact(&mut body).await?;
        let pt = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce(self.counter + 1)), &body[..])
            .map_err(|_| TransportError::Decrypt)?;
        self.counter += 2;
        Ok(pt)
    }
}

type Halves<S> = (FrameReader<ReadHalf<S>>, FrameWriter<WriteHalf<S>>);

/// Runs the key exchange on `stream` and returns the two encrypted halves.
/// `initiator` is the side that opened the connection. Both sides must use
/// the same `network_id` and `genesis_id` (the chain's genesis block id).
/// No pre-shared key: see [`handshake_with`].
pub async fn handshake<S>(
    stream: S,
    initiator: bool,
    network_id: u32,
    genesis_id: &[u8; 32],
    timeout: Duration,
) -> Result<Halves<S>, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let session = Session {
        network_id,
        genesis_id,
        psk: None,
    };
    handshake_with(stream, initiator, session, timeout).await
}

/// [`handshake`] for `session`, with its pre-shared key if it has one. A key
/// mismatch (network, genesis, pre-shared key) is detected by the first frame,
/// which fails to decrypt ([`TransportError::Decrypt`]).
pub async fn handshake_with<S>(
    stream: S,
    initiator: bool,
    session: Session<'_>,
    timeout: Duration,
) -> Result<Halves<S>, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handshake_version(stream, initiator, &session, TRANSPORT_VERSION, timeout).await
}

async fn handshake_version<S>(
    mut stream: S,
    initiator: bool,
    session: &Session<'_>,
    version: u32,
    timeout: Duration,
) -> Result<Halves<S>, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Wiped on every return path, including the errors below.
    let mut wide = Zeroizing::new([0u8; 64]);
    getrandom::getrandom(&mut wide[..]).map_err(|_| TransportError::Rng)?;
    let secret = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&wide));
    drop(wide);
    let ours = Point::from_point(RistrettoPoint::mul_base(&secret));

    let exchange = async {
        let mut theirs = [0u8; 32];
        if initiator {
            stream.write_all(ours.bytes()).await?;
            stream.flush().await?;
            stream.read_exact(&mut theirs).await?;
        } else {
            stream.read_exact(&mut theirs).await?;
            stream.write_all(ours.bytes()).await?;
            stream.flush().await?;
        }
        Ok::<_, std::io::Error>(theirs)
    };
    let theirs = tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| TransportError::Timeout)??;
    let theirs = Point::decode(&theirs).ok_or(TransportError::BadKey)?;
    if theirs.is_identity() {
        return Err(TransportError::BadKey);
    }
    let shared = Point::from_point(*secret * theirs.point());
    drop(secret);
    if shared.is_identity() {
        return Err(TransportError::BadKey);
    }
    let (a, b) = if initiator {
        (&ours, &theirs)
    } else {
        (&theirs, &ours)
    };
    let mut s = *shared.bytes();
    let mut k = session_key(version, session, a.bytes(), b.bytes(), &s);
    s.zeroize();
    let i2r = Aes256Gcm::new_from_slice(&k[..32]).expect("32-byte key");
    let r2i = Aes256Gcm::new_from_slice(&k[32..]).expect("32-byte key");
    k.zeroize();
    let (send, recv) = if initiator { (i2r, r2i) } else { (r2i, i2r) };
    let (rh, wh) = tokio::io::split(stream);
    Ok((
        FrameReader {
            inner: rh,
            cipher: recv,
            counter: 0,
        },
        FrameWriter {
            inner: wh,
            cipher: send,
            counter: 0,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    const T: Duration = Duration::from_secs(5);
    /// A genesis id for the tests.
    const G: [u8; 32] = [0x6E; 32];

    #[tokio::test]
    async fn frames_round_trip_both_ways() {
        let (a, b) = duplex(1 << 22);
        let (ra, rb) = tokio::join!(handshake(a, true, 7, &G, T), handshake(b, false, 7, &G, T));
        let (mut ar, mut aw) = ra.unwrap();
        let (mut br, mut bw) = rb.unwrap();
        // Send and receive concurrently, as peers do: the largest frame is
        // bigger than the pipe's buffer.
        for msg in [&b"hello"[..], &[0u8; 0][..], &vec![7u8; MAX_FRAME][..]] {
            let (sent, got) = tokio::join!(aw.send(msg), br.recv());
            sent.unwrap();
            assert_eq!(got.unwrap(), msg);
            let (sent, got) = tokio::join!(bw.send(msg), ar.recv());
            sent.unwrap();
            assert_eq!(got.unwrap(), msg);
        }
    }

    #[tokio::test]
    async fn different_networks_cannot_talk() {
        let (a, b) = duplex(1 << 16);
        let (ra, rb) = tokio::join!(handshake(a, true, 1, &G, T), handshake(b, false, 2, &G, T));
        let (_, mut aw) = ra.unwrap();
        let (mut br, _) = rb.unwrap();
        aw.send(b"version").await.unwrap();
        assert!(matches!(br.recv().await, Err(TransportError::Decrypt)));
    }

    /// R15-3: the same network id on another genesis (a release candidate,
    /// a rehearsal, a retired identity) cannot talk either.
    #[tokio::test]
    async fn different_genesis_ids_cannot_talk() {
        let (a, b) = duplex(1 << 16);
        let other = [0x6F; 32];
        let (ra, rb) = tokio::join!(
            handshake(a, true, 1, &G, T),
            handshake(b, false, 1, &other, T)
        );
        let (_, mut aw) = ra.unwrap();
        let (mut br, _) = rb.unwrap();
        aw.send(b"version").await.unwrap();
        assert!(matches!(br.recv().await, Err(TransportError::Decrypt)));
    }

    #[tokio::test]
    async fn ciphertext_hides_content_and_tampering_is_detected() {
        // A man in the middle relays bytes and flips one bit of the payload.
        let (a, m1) = duplex(1 << 16);
        let (m2, b) = duplex(1 << 16);
        let relay = tokio::spawn(async move {
            let (mut m1r, mut m1w) = tokio::io::split(m1);
            let (mut m2r, mut m2w) = tokio::io::split(m2);
            let mut ka = [0u8; 32];
            m1r.read_exact(&mut ka).await.unwrap();
            m2w.write_all(&ka).await.unwrap();
            let mut kb = [0u8; 32];
            m2r.read_exact(&mut kb).await.unwrap();
            m1w.write_all(&kb).await.unwrap();
            let mut frame = vec![0u8; 4 + TAG + 11 + TAG];
            m1r.read_exact(&mut frame).await.unwrap();
            assert!(
                !frame.windows(11).any(|w| w == b"secret-data"),
                "plaintext visible"
            );
            frame[4 + TAG + 3] ^= 1;
            m2w.write_all(&frame).await.unwrap();
        });
        let (ra, rb) = tokio::join!(handshake(a, true, 1, &G, T), handshake(b, false, 1, &G, T));
        let (_, mut aw) = ra.unwrap();
        let (mut br, _) = rb.unwrap();
        aw.send(b"secret-data").await.unwrap();
        assert!(matches!(br.recv().await, Err(TransportError::Decrypt)));
        relay.await.unwrap();
    }

    #[tokio::test]
    async fn bad_keys_and_silence_are_rejected() {
        // Identity key.
        let (a, mut b) = duplex(1 << 16);
        let hs = tokio::spawn(handshake(a, true, 1, &G, T));
        let mut k = [0u8; 32];
        b.read_exact(&mut k).await.unwrap();
        b.write_all(&[0u8; 32]).await.unwrap();
        assert!(matches!(hs.await.unwrap(), Err(TransportError::BadKey)));
        // Non-canonical key.
        let (a, mut b) = duplex(1 << 16);
        let hs = tokio::spawn(handshake(a, true, 1, &G, T));
        b.read_exact(&mut k).await.unwrap();
        b.write_all(&[0xff; 32]).await.unwrap();
        assert!(matches!(hs.await.unwrap(), Err(TransportError::BadKey)));
        // Silent peer.
        let (a, _b) = duplex(1 << 16);
        let r = handshake(a, true, 1, &G, Duration::from_millis(100)).await;
        assert!(matches!(r, Err(TransportError::Timeout)));
    }

    #[tokio::test]
    async fn oversized_length_is_rejected_before_reading_payload() {
        let (a, b) = duplex(1 << 16);
        let (ra, rb) = tokio::join!(handshake(a, true, 1, &G, T), handshake(b, false, 1, &G, T));
        let (_, mut aw) = ra.unwrap();
        let (mut br, _) = rb.unwrap();
        // Forge a frame header claiming a huge length with the sender's own cipher.
        let len = aw
            .cipher
            .encrypt(Nonce::from_slice(&nonce(0)), &(u32::MAX).to_le_bytes()[..])
            .unwrap();
        aw.inner.write_all(&len).await.unwrap();
        assert!(matches!(
            br.recv().await,
            Err(TransportError::FrameTooLarge(_))
        ));
    }

    fn session(network_id: u32, psk: Option<&NetworkPsk>) -> Session<'_> {
        Session {
            network_id,
            genesis_id: &G,
            psk,
        }
    }

    /// A pre-shared key for the tests.
    fn psk(byte: u8) -> NetworkPsk {
        NetworkPsk::from_bytes([byte; 32]).unwrap()
    }

    /// W5: the transport version is bound into the session key. Two ends of
    /// different transport versions derive different keys, and the first
    /// frame fails closed: no session, no fallback.
    #[tokio::test]
    async fn mismatching_transport_versions_derive_different_keys_and_fail() {
        let s = session(1, None);
        let (a, b, x) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let k1 = session_key(TRANSPORT_VERSION, &s, &a, &b, &x);
        let k2 = session_key(TRANSPORT_VERSION + 1, &s, &a, &b, &x);
        assert_ne!(k1, k2);
        let (sa, sb) = duplex(1 << 16);
        let (ra, rb) = tokio::join!(
            handshake_version(sa, true, &s, TRANSPORT_VERSION, T),
            handshake_version(sb, false, &s, TRANSPORT_VERSION + 1, T)
        );
        let (_, mut aw) = ra.unwrap();
        let (mut br, _) = rb.unwrap();
        aw.send(b"version").await.unwrap();
        assert!(matches!(br.recv().await, Err(TransportError::Decrypt)));
    }

    /// Every input of the key derivation changes the key, and the pre-shared
    /// key's presence is distinct from any key value.
    #[test]
    fn the_session_key_binds_every_input() {
        let (a, b, x) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let other_g = [0x6F; 32];
        let (p1, p2) = (psk(1), psk(2));
        let base = session_key(1, &session(1, None), &a, &b, &x);
        let variants = [
            session_key(2, &session(1, None), &a, &b, &x),
            session_key(1, &session(2, None), &a, &b, &x),
            session_key(
                1,
                &Session {
                    network_id: 1,
                    genesis_id: &other_g,
                    psk: None,
                },
                &a,
                &b,
                &x,
            ),
            session_key(1, &session(1, Some(&p1)), &a, &b, &x),
            session_key(1, &session(1, Some(&p2)), &a, &b, &x),
            session_key(1, &session(1, None), &b, &a, &x),
            session_key(1, &session(1, None), &a, &b, &a),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(*v, base, "input {i} not bound");
        }
        assert_ne!(variants[3], variants[4]);
    }

    /// A known answer for the key derivation (network 1, genesis 0x6E…,
    /// version 1, no pre-shared key, fixed 32-byte inputs). It pins the input
    /// layout: a change of the tag, the field order or a field's width fails
    /// here, although both ends of every other test would change together.
    #[test]
    fn the_session_key_matches_its_known_answer() {
        let k = session_key(
            TRANSPORT_VERSION,
            &session(1, None),
            &[1; 32],
            &[2; 32],
            &[3; 32],
        );
        assert_eq!(hex::encode(k), KDF_KAT);
    }

    /// Computed independently of this code (Python `hashlib.blake2b`, 64-byte
    /// digest, over `len ‖ "BlackSilk/v1/p2p/session"` and the inputs in the
    /// order of docs/p2p.md §3).
    const KDF_KAT: &str = "92f365dbf1f273dc8e6397856e4e375c27958339af6e7111883d6a43dd246a4c\
                           8c661a144afed38c73749038f2e32b534cba943058ac64a75400d0447d772a03";

    /// F48-1: members sharing the pre-shared key talk; a node without it, or
    /// with another key, fails at the first frame.
    #[tokio::test]
    async fn a_psk_session_talks_and_a_missing_or_wrong_psk_fails() {
        let (p, q) = (psk(9), psk(10));
        let (sa, sb) = duplex(1 << 16);
        let (ra, rb) = tokio::join!(
            handshake_with(sa, true, session(1, Some(&p)), T),
            handshake_with(sb, false, session(1, Some(&p)), T)
        );
        let (_, mut aw) = ra.unwrap();
        let (mut br, _) = rb.unwrap();
        aw.send(b"version").await.unwrap();
        assert_eq!(br.recv().await.unwrap(), b"version");
        for theirs in [None, Some(&q)] {
            let (sa, sb) = duplex(1 << 16);
            let (ra, rb) = tokio::join!(
                handshake_with(sa, true, session(1, Some(&p)), T),
                handshake_with(sb, false, session(1, theirs), T)
            );
            let (_, mut aw) = ra.unwrap();
            let (mut br, _) = rb.unwrap();
            aw.send(b"version").await.unwrap();
            assert!(matches!(br.recv().await, Err(TransportError::Decrypt)));
        }
    }

    #[test]
    fn psk_files_are_parsed_strictly_and_never_printed() {
        let hex64 = "ab".repeat(32);
        let k = NetworkPsk::from_hex(&format!("  {hex64}\r\n")).unwrap();
        assert_eq!(k.0, [0xab; 32]);
        assert!(!format!("{k:?}").contains("ab"), "the key is not printed");
        for bad in [
            String::new(),
            "ab".repeat(31),
            "ab".repeat(33),
            "zz".repeat(32),
            "00".repeat(32),
        ] {
            assert!(
                matches!(NetworkPsk::from_hex(&bad), Err(PskError::Format)),
                "{bad}"
            );
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("network.psk");
        std::fs::write(&path, format!("{hex64}\n")).unwrap();
        assert_eq!(NetworkPsk::load(&path).unwrap().0, [0xab; 32]);
        assert!(matches!(
            NetworkPsk::load(&dir.path().join("missing")),
            Err(PskError::Io(_))
        ));
    }

    /// A reflected key exchange: a party that echoes the initiator's own key
    /// and frames back. The two directions use different keys, so the
    /// reflected first frame fails.
    #[tokio::test]
    async fn a_reflected_session_fails_at_the_first_frame() {
        let (a, mirror) = duplex(1 << 16);
        let echo = tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(mirror);
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        let (mut ar, mut aw) = handshake(a, true, 1, &G, T).await.unwrap();
        aw.send(b"version").await.unwrap();
        assert!(matches!(ar.recv().await, Err(TransportError::Decrypt)));
        echo.abort();
    }

    /// Replayed, reordered and truncated frames fail: every frame is bound to
    /// its position by the nonce counter.
    #[tokio::test]
    async fn replayed_reordered_and_truncated_frames_fail() {
        const FRAME: usize = 4 + TAG + 5 + TAG;
        // 0: the first frame twice; 1: the two frames swapped; 2: the first
        // frame without its last byte, then the end of the stream.
        for case in 0..3 {
            let (a, m1) = duplex(1 << 16);
            let (m2, b) = duplex(1 << 16);
            let relay = tokio::spawn(async move {
                let (mut m1r, mut m1w) = tokio::io::split(m1);
                let (mut m2r, mut m2w) = tokio::io::split(m2);
                let mut ka = [0u8; 32];
                m1r.read_exact(&mut ka).await.unwrap();
                m2w.write_all(&ka).await.unwrap();
                let mut kb = [0u8; 32];
                m2r.read_exact(&mut kb).await.unwrap();
                m1w.write_all(&kb).await.unwrap();
                let mut f1 = [0u8; FRAME];
                let mut f2 = [0u8; FRAME];
                m1r.read_exact(&mut f1).await.unwrap();
                m1r.read_exact(&mut f2).await.unwrap();
                match case {
                    0 => {
                        m2w.write_all(&f1).await.unwrap();
                        m2w.write_all(&f1).await.unwrap();
                    }
                    1 => {
                        m2w.write_all(&f2).await.unwrap();
                        m2w.write_all(&f1).await.unwrap();
                    }
                    _ => {
                        m2w.write_all(&f1[..FRAME - 1]).await.unwrap();
                        m2w.shutdown().await.unwrap();
                    }
                }
                (m1r, m1w, m2r)
            });
            let (ra, rb) =
                tokio::join!(handshake(a, true, 1, &G, T), handshake(b, false, 1, &G, T));
            let (_, mut aw) = ra.unwrap();
            let (mut br, _) = rb.unwrap();
            aw.send(b"first").await.unwrap();
            aw.send(b"secnd").await.unwrap();
            let _keep = relay.await.unwrap();
            match case {
                0 => {
                    assert_eq!(br.recv().await.unwrap(), b"first");
                    assert!(matches!(br.recv().await, Err(TransportError::Decrypt)));
                }
                1 => assert!(matches!(br.recv().await, Err(TransportError::Decrypt))),
                _ => assert!(matches!(br.recv().await, Err(TransportError::Io(_)))),
            }
        }
    }

    /// W1: a frame over the receiver's limit is refused after its length
    /// decrypts; a frame at the limit is received.
    #[tokio::test]
    async fn recv_limited_refuses_frames_over_its_limit() {
        let (a, b) = duplex(1 << 16);
        let (ra, rb) = tokio::join!(handshake(a, true, 1, &G, T), handshake(b, false, 1, &G, T));
        let (_, mut aw) = ra.unwrap();
        let (mut br, _) = rb.unwrap();
        aw.send(&[1; 100]).await.unwrap();
        assert_eq!(br.recv_limited(100).await.unwrap(), vec![1; 100]);
        aw.send(&[1; 101]).await.unwrap();
        assert!(matches!(
            br.recv_limited(100).await,
            Err(TransportError::FrameTooLarge(101))
        ));
    }
}
