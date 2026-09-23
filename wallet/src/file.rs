//! Encrypted wallet file.
//!
//! ```text
//! file = "BSW1" ‖ LE32 m_kib ‖ LE32 t ‖ LE32 p ‖ salt (16) ‖ nonce (12) ‖ ciphertext
//! key  = Argon2id(password, salt, m_kib, t, p) → 32 bytes
//! ciphertext = AES-256-GCM(key, nonce, plaintext, aad = everything before the ciphertext)
//! ```
//!
//! - The plaintext is the wallet JSON. It contains the seed, so it is secret.
//! - A fresh salt and nonce are drawn from the OS RNG on every save.
//! - Files are replaced atomically: written to `*.tmp`, fsynced, then renamed.
//! - The KDF parameters are stored in the header, so they can be raised later
//!   without breaking old files.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use std::io::Write;
use std::path::Path;
use zeroize::Zeroize;

const MAGIC: &[u8; 4] = b"BSW1";
const HEADER_LEN: usize = 4 + 12 + 16 + 12;

/// Argon2id cost. The default (64 MiB, 3 passes) follows OWASP/RFC 9106 guidance
/// for interactive use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_kib: 64 * 1024,
            t: 3,
            p: 1,
        }
    }
}

#[derive(Debug)]
pub enum FileError {
    Io(std::io::Error),
    Format,
    /// Wrong password or tampered file (the two are indistinguishable by design).
    Decrypt,
    Kdf,
    Rng,
}

impl std::fmt::Display for FileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileError::Io(e) => write!(f, "{e}"),
            FileError::Format => write!(f, "not a BlackSilk wallet file"),
            FileError::Decrypt => write!(f, "wrong password or damaged wallet file"),
            FileError::Kdf => write!(f, "key derivation failed"),
            FileError::Rng => write!(f, "OS random number generator failed"),
        }
    }
}

impl std::error::Error for FileError {}

fn derive_key(password: &[u8], salt: &[u8; 16], kdf: KdfParams) -> Result<[u8; 32], FileError> {
    let params = Params::new(kdf.m_kib, kdf.t, kdf.p, Some(32)).map_err(|_| FileError::Kdf)?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| FileError::Kdf)?;
    Ok(key)
}

pub fn encrypt(plaintext: &[u8], password: &[u8], kdf: KdfParams) -> Result<Vec<u8>, FileError> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut salt).map_err(|_| FileError::Rng)?;
    getrandom::getrandom(&mut nonce).map_err(|_| FileError::Rng)?;
    let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + 16);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&kdf.m_kib.to_le_bytes());
    out.extend_from_slice(&kdf.t.to_le_bytes());
    out.extend_from_slice(&kdf.p.to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    let mut key = derive_key(password, &salt, kdf)?;
    let cipher = Aes256Gcm::new(&key.into());
    key.zeroize();
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &out,
            },
        )
        .map_err(|_| FileError::Decrypt)?;
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(file: &[u8], password: &[u8]) -> Result<Vec<u8>, FileError> {
    if file.len() < HEADER_LEN + 16 || &file[..4] != MAGIC {
        return Err(FileError::Format);
    }
    let u32_at = |i: usize| u32::from_le_bytes(file[i..i + 4].try_into().expect("4 bytes"));
    let kdf = KdfParams {
        m_kib: u32_at(4),
        t: u32_at(8),
        p: u32_at(12),
    };
    // Refuse absurd parameters from a tampered header (memory exhaustion).
    if kdf.m_kib > 4 * 1024 * 1024 || kdf.t > 100 || kdf.p == 0 || kdf.p > 64 {
        return Err(FileError::Format);
    }
    let salt: [u8; 16] = file[16..32].try_into().expect("16 bytes");
    let nonce: [u8; 12] = file[32..44].try_into().expect("12 bytes");
    let mut key = derive_key(password, &salt, kdf)?;
    let cipher = Aes256Gcm::new(&key.into());
    key.zeroize();
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &file[HEADER_LEN..],
                aad: &file[..HEADER_LEN],
            },
        )
        .map_err(|_| FileError::Decrypt)
}

/// Writes `bytes` to `path` atomically (temp file, fsync, rename).
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), FileError> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp).map_err(FileError::Io)?;
        f.write_all(bytes).map_err(FileError::Io)?;
        f.sync_all().map_err(FileError::Io)?;
    }
    std::fs::rename(&tmp, path).map_err(FileError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams {
        m_kib: 256,
        t: 1,
        p: 1,
    };

    #[test]
    fn round_trip() {
        let f = encrypt(b"secret wallet", b"pw", FAST).unwrap();
        assert_eq!(decrypt(&f, b"pw").unwrap(), b"secret wallet");
        // Fresh salt and nonce each time.
        assert_ne!(encrypt(b"secret wallet", b"pw", FAST).unwrap(), f);
        assert!(
            !f.windows(6).any(|w| w == b"secret"),
            "plaintext not visible"
        );
    }

    #[test]
    fn wrong_password_and_tampering_are_rejected() {
        let f = encrypt(b"data", b"pw", FAST).unwrap();
        assert!(matches!(decrypt(&f, b"pW"), Err(FileError::Decrypt)));
        for i in 0..f.len() {
            let mut g = f.clone();
            g[i] ^= 1;
            assert!(decrypt(&g, b"pw").is_err(), "byte {i}");
        }
        assert!(matches!(decrypt(b"nope", b"pw"), Err(FileError::Format)));
    }

    #[test]
    fn atomic_write() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w.wallet");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert!(!p.with_extension("tmp").exists());
    }
}
