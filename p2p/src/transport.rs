//! Encrypted transport (docs/p2p.md §3).
//!
//! ```text
//! initiator → responder: A = a·G      responder → initiator: B = b·G   (Ristretto255)
//! S = a·B = b·A;  k = H64("p2p/session", LE32(network_id) ‖ A ‖ B ‖ S)
//! frame = AES-256-GCM(k_dir, n, LE32(len)) ‖ AES-256-GCM(k_dir, n+1, payload)
//! ```
//!
//! Ephemeral keys give forward secrecy. No magic bytes or version travel in the
//! clear. Peers are *not* authenticated: this protects against passive observers,
//! not against an active man in the middle (docs/p2p.md §1).

use crate::message::MAX_FRAME;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use blacksilk_crypto::hash::{h64, tags};
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use zeroize::Zeroize;

const TAG: usize = 16;

#[derive(Debug)]
pub enum TransportError {
    Io(std::io::Error),
    /// The peer's key is not a canonical, non-identity group element.
    BadKey,
    /// Authentication failed: tampering, a wrong network, or not a BlackSilk peer.
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
    pub async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut len_ct = [0u8; 4 + TAG];
        self.inner.read_exact(&mut len_ct).await?;
        let len_pt = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce(self.counter)), &len_ct[..])
            .map_err(|_| TransportError::Decrypt)?;
        let len = u32::from_le_bytes(len_pt[..4].try_into().expect("4 bytes")) as usize;
        if len > MAX_FRAME {
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

/// Runs the key exchange on `stream` and returns the two encrypted halves.
/// `initiator` is the side that opened the connection.
pub async fn handshake<S>(
    mut stream: S,
    initiator: bool,
    network_id: u32,
    timeout: Duration,
) -> Result<(FrameReader<ReadHalf<S>>, FrameWriter<WriteHalf<S>>), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut wide = [0u8; 64];
    getrandom::getrandom(&mut wide).map_err(|_| TransportError::Rng)?;
    let mut secret = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
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
    let shared = Point::from_point(secret * theirs.point());
    secret.zeroize();
    if shared.is_identity() {
        return Err(TransportError::BadKey);
    }
    let (a, b) = if initiator {
        (&ours, &theirs)
    } else {
        (&theirs, &ours)
    };
    let mut k = h64(
        tags::P2P_SESSION,
        &[
            &network_id.to_le_bytes(),
            a.bytes(),
            b.bytes(),
            shared.bytes(),
        ],
    );
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

    #[tokio::test]
    async fn frames_round_trip_both_ways() {
        let (a, b) = duplex(1 << 22);
        let (ra, rb) = tokio::join!(handshake(a, true, 7, T), handshake(b, false, 7, T));
        let (mut ar, mut aw) = ra.unwrap();
        let (mut br, mut bw) = rb.unwrap();
        for msg in [&b"hello"[..], &[0u8; 0][..], &vec![7u8; MAX_FRAME][..]] {
            aw.send(msg).await.unwrap();
            assert_eq!(br.recv().await.unwrap(), msg);
            bw.send(msg).await.unwrap();
            assert_eq!(ar.recv().await.unwrap(), msg);
        }
    }

    #[tokio::test]
    async fn different_networks_cannot_talk() {
        let (a, b) = duplex(1 << 16);
        let (ra, rb) = tokio::join!(handshake(a, true, 1, T), handshake(b, false, 2, T));
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
        let (ra, rb) = tokio::join!(handshake(a, true, 1, T), handshake(b, false, 1, T));
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
        let hs = tokio::spawn(handshake(a, true, 1, T));
        let mut k = [0u8; 32];
        b.read_exact(&mut k).await.unwrap();
        b.write_all(&[0u8; 32]).await.unwrap();
        assert!(matches!(hs.await.unwrap(), Err(TransportError::BadKey)));
        // Non-canonical key.
        let (a, mut b) = duplex(1 << 16);
        let hs = tokio::spawn(handshake(a, true, 1, T));
        b.read_exact(&mut k).await.unwrap();
        b.write_all(&[0xff; 32]).await.unwrap();
        assert!(matches!(hs.await.unwrap(), Err(TransportError::BadKey)));
        // Silent peer.
        let (a, _b) = duplex(1 << 16);
        let r = handshake(a, true, 1, Duration::from_millis(100)).await;
        assert!(matches!(r, Err(TransportError::Timeout)));
    }

    #[tokio::test]
    async fn oversized_length_is_rejected_before_reading_payload() {
        let (a, b) = duplex(1 << 16);
        let (ra, rb) = tokio::join!(handshake(a, true, 1, T), handshake(b, false, 1, T));
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
}
