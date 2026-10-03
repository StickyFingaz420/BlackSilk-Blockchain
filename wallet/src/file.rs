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
//! - Files are replaced atomically: written to `*.tmp<pid>`, fsynced, then
//!   renamed; on Unix the directory is fsynced too, and the file is created
//!   owner-only (0600).
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

/// Passwords shorter than this many characters are weak: accepted for a
/// new wallet, with a warning ([`check_new_password`]). Argon2id (64 MiB,
/// three passes) slows each guess, but a short or common password still
/// falls to an offline search of a copied file (a synced folder, a backup).
pub const WEAK_PASSWORD_CHARS: usize = 12;

/// Whether `password` is empty in practice: no characters, or only
/// whitespace (Unicode whitespace included, e.g. a no-break space). Such a
/// wallet file is readable by anyone who gets it.
pub fn is_empty_password(password: &[u8]) -> bool {
    String::from_utf8_lossy(password)
        .chars()
        .all(char::is_whitespace)
}

/// The check of a new wallet password (create, restore, change-password;
/// the second threat-model round): an empty one is refused (`Err`, the
/// message for the user); one shorter than [`WEAK_PASSWORD_CHARS`]
/// characters is accepted with a warning (`Ok(Some(_))`).
pub fn check_new_password(password: &[u8]) -> Result<Option<String>, String> {
    if is_empty_password(password) {
        return Err(
            "an empty password is refused: the wallet file holds the seed, and a \
                    file with an empty password gives it to anyone who gets a copy (a synced \
                    folder, a backup)"
                .into(),
        );
    }
    let chars = String::from_utf8_lossy(password).chars().count();
    Ok((chars < WEAK_PASSWORD_CHARS).then(|| {
        format!(
            "weak password ({chars} characters, fewer than {WEAK_PASSWORD_CHARS}): anyone who \
             gets a copy of the wallet file can try passwords offline; use a longer one \
             (several random words)"
        )
    }))
}

/// Makes an existing wallet file owner-only (0600) on Unix if other users
/// have any access (a file created before, or copied); returns the mode it
/// had. A no-op on Windows (the file inherits its directory's ACL) and for
/// a missing file.
pub fn tighten(path: &Path) -> std::io::Result<Option<u32>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mode = meta.permissions().mode() & 0o7777;
        if !meta.file_type().is_file() || mode & 0o077 == 0 {
            return Ok(None);
        }
        // Through a handle that is the checked file (TOCTOU): a name
        // swapped for a link after the check is refused.
        use std::os::unix::fs::MetadataExt;
        let f = std::fs::File::open(path)?;
        let opened = f.metadata()?;
        if opened.dev() != meta.dev() || opened.ino() != meta.ino() {
            return Err(std::io::Error::other("it changed while being checked"));
        }
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(Some(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(None)
    }
}

/// Opens `path` for writing, creating it if needed. On Unix a new file is
/// created readable and writable by its owner only (0600), whatever the umask.
/// On Windows it inherits the directory's access control list.
pub fn open_private(path: &Path, truncate: bool) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(truncate);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Creates `path`, which must not exist, owner-only on Unix (as `open_private`).
pub fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Writes `bytes` to `path` atomically: a temporary file (owner-only on
/// Unix), fsync, rename, and on Unix an fsync of the directory so that the
/// rename itself survives a crash.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), FileError> {
    let tmp = tmp_path(path);
    // A leftover from a crashed run may have other permissions; the mode
    // applies only to a file this call creates.
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(FileError::Io(e)),
    }
    {
        let mut f = open_private(&tmp, true).map_err(FileError::Io)?;
        f.write_all(bytes).map_err(FileError::Io)?;
        f.sync_all().map_err(FileError::Io)?;
    }
    std::fs::rename(&tmp, path).map_err(FileError::Io)?;
    #[cfg(unix)]
    {
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(FileError::Io)?;
    }
    Ok(())
}

fn tmp_path(path: &Path) -> std::path::PathBuf {
    path.with_extension(format!("tmp{}", std::process::id()))
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
        // A stale temporary file (a crashed save) is replaced, not appended to.
        std::fs::write(tmp_path(&p), b"stale stale stale").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        // No temporary file is left behind. (The old check looked for
        // `w.tmp`, a name that is never used: the real one is `w.tmp<pid>`.)
        assert!(!tmp_path(&p).exists());
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["w.wallet"]);
    }

    /// An empty (or whitespace-only) password is refused, a short one
    /// warned about, a long one accepted silently; characters, not bytes.
    #[test]
    fn new_password_policy() {
        for empty in [&b""[..], b" ", b"\t \n", "\u{a0}\u{3000}".as_bytes()] {
            let e = check_new_password(empty).unwrap_err();
            assert!(e.contains("empty password"), "{e}");
            assert!(is_empty_password(empty));
        }
        let w = check_new_password(b"pw").unwrap().unwrap();
        assert!(w.contains("weak password (2 characters"), "{w}");
        assert!(check_new_password("ü".repeat(11).as_bytes())
            .unwrap()
            .is_some());
        assert_eq!(check_new_password("ü".repeat(12).as_bytes()), Ok(None));
        assert_eq!(check_new_password(b"correct horse battery"), Ok(None));
        assert!(!is_empty_password(b" x "));
    }

    /// A wallet file left readable by others is made owner-only.
    #[cfg(unix)]
    #[test]
    fn an_open_wallet_file_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w.wallet");
        assert_eq!(tighten(&p).unwrap(), None, "missing");
        std::fs::write(&p, b"x").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(tighten(&p).unwrap(), Some(0o644));
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(tighten(&p).unwrap(), None, "already private");
    }

    #[cfg(unix)]
    #[test]
    fn wallet_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w.wallet");
        write_atomic(&p, b"one").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let l = dir.path().join("w.lock");
        open_private(&l, false).unwrap();
        let mode = std::fs::metadata(&l).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
