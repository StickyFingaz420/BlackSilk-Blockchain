//! The RPC credential ("cookie"; docs/blocks.md §9.1).
//!
//! At every start the node draws 32 bytes from the OS RNG and writes them, as
//! 64 lowercase hex digits, to `<data dir>/rpc.cookie`
//! ([`blacksilk_rpc::COOKIE_FILE`]). Every RPC request must carry them as
//! `Authorization: Bearer <hex>`. The file is written to a temporary name and
//! renamed into place, and removed at a clean shutdown; a stale file from a
//! crashed run is replaced at the next start. This follows Bitcoin Core's
//! `.cookie`.
//!
//! **Permissions.** On Unix the file is created with mode 0600 (owner only).
//! On Windows it inherits the ACL of its directory: the default data
//! directory is under the user's `%APPDATA%`, which only that user (and
//! administrators) can read. There is no safe-Rust way to set a Windows ACL
//! without FFI, so a data directory outside the user profile gets a warning
//! instead (an accepted, documented limitation).
//!
//! The cookie keeps other local users and web pages out. It cannot keep out
//! malware running as the same user, which can read the file.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// A credential: [`blacksilk_rpc::TOKEN_HEX_LEN`] lowercase hex digits.
#[derive(Clone)]
pub struct Token(String);

impl Token {
    /// A fresh credential from the OS RNG.
    pub fn generate() -> io::Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|e| io::Error::other(format!("OS RNG: {e}")))?;
        Ok(Self(hex::encode(bytes)))
    }

    /// A credential given as text (tests, configured tokens).
    pub fn parse(s: &str) -> Option<Self> {
        blacksilk_rpc::is_token(s).then(|| Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(..)")
    }
}

/// The cookie file of a running node; removed when dropped.
#[derive(Debug)]
pub struct CookieFile {
    path: PathBuf,
    token: Token,
}

/// Creates `path` for writing, owner-only on Unix; fails if it exists.
fn create_private(path: &Path) -> io::Result<fs::File> {
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

impl CookieFile {
    /// Writes a fresh credential to `<data_dir>/rpc.cookie`, replacing any
    /// previous file.
    pub fn create(data_dir: &Path) -> io::Result<Self> {
        let token = Token::generate()?;
        let path = data_dir.join(blacksilk_rpc::COOKIE_FILE);
        let tmp = data_dir.join(format!("{}.tmp", blacksilk_rpc::COOKIE_FILE));
        // A temporary file left by a crash: never write through an existing
        // file (it may have wider permissions or be a link).
        match fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut f = create_private(&tmp)?;
        f.write_all(token.as_str().as_bytes())?;
        f.sync_all()?;
        drop(f);
        // A rename replaces the destination on Unix and on Windows (std uses
        // MoveFileEx with MOVEFILE_REPLACE_EXISTING).
        fs::rename(&tmp, &path)?;
        #[cfg(windows)]
        warn_outside_profile(data_dir);
        Ok(Self { path, token })
    }

    pub fn token(&self) -> &Token {
        &self.token
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CookieFile {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_file(&self.path) {
            if e.kind() != io::ErrorKind::NotFound {
                log::warn!("removing {}: {e}", self.path.display());
            }
        }
    }
}

/// Windows: the cookie is protected only by its directory's ACL, which is
/// per-user under the profile (`%USERPROFILE%`, `%APPDATA%`) but may be
/// readable by other users elsewhere.
#[cfg(windows)]
fn warn_outside_profile(data_dir: &Path) {
    let inside = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .zip(fs::canonicalize(data_dir).ok())
        .is_some_and(|(profile, dir)| {
            fs::canonicalize(profile).is_ok_and(|profile| dir.starts_with(profile))
        });
    if !inside {
        log::warn!(
            "the data directory {} is outside your user profile: on Windows the RPC cookie \
             is protected only by that directory's permissions; make sure other users \
             cannot read it",
            data_dir.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cookie_is_fresh_private_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(blacksilk_rpc::COOKIE_FILE);
        // A stale cookie and temporary file from a crashed run.
        fs::write(&path, "stale").unwrap();
        fs::write(dir.path().join("rpc.cookie.tmp"), "junk").unwrap();
        let a = CookieFile::create(dir.path()).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text, a.token().as_str());
        assert!(blacksilk_rpc::is_token(&text));
        assert_eq!(blacksilk_rpc::read_cookie(&path).unwrap(), text);
        assert!(!dir.path().join("rpc.cookie.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        drop(a);
        assert!(!path.exists(), "removed at shutdown");
        let b = CookieFile::create(dir.path()).unwrap();
        assert_ne!(b.token().as_str(), text, "a new credential at every start");
    }

    #[test]
    fn tokens_parse_only_in_their_form() {
        let t = Token::generate().unwrap();
        assert!(Token::parse(t.as_str()).is_some());
        assert!(Token::parse(&t.as_str().to_uppercase()).is_none());
        assert!(Token::parse(&t.as_str()[1..]).is_none());
        assert!(Token::parse("").is_none());
        assert_eq!(format!("{t:?}"), "Token(..)", "never logged");
    }
}
