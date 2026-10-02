//! Writing the node's private files (docs/testnet.md §4.5): the address
//! table (`peers.json`, with its bucketing key), the anchors and the bans
//! reveal this node's contacts, and `originated.json` its own transactions.
//!
//! [`write_atomic`] writes a temporary file next to the target, owner-only
//! (0600) on Unix whatever the process umask, syncs it and renames it over
//! the target, so the file is never readable by other local users, not even
//! for the moment between creation and a later `chmod`. On Windows a new
//! file inherits its directory's access control list (the default data
//! directory is in the user's profile; there is no safe-Rust way to set an
//! ACL).

use std::io::Write;
use std::path::{Path, PathBuf};

/// The temporary file of [`write_atomic`] for `path`: `<stem>.tmp` next to
/// it (the names the node has always used, e.g. `peers.tmp`).
pub fn tmp_path(path: &Path) -> PathBuf {
    path.with_extension("tmp")
}

/// Writes `bytes` to `path` atomically and owner-only (module docs): a
/// stale temporary file from a crash is removed first (it may have wider
/// permissions, or be a link), the new one is created exclusively with mode
/// 0600 on Unix, synced, and renamed over `path`.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = tmp_path(path);
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The content replaces the old file, no temporary file is left, and a
    /// stale temporary file is replaced rather than written through.
    #[test]
    fn writes_atomically_over_a_stale_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("peers.json");
        write_atomic(&p, b"one").unwrap();
        std::fs::write(tmp_path(&p), b"stale stale stale").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert!(!tmp_path(&p).exists());
    }

    /// Owner-only on Unix, also when the file existed with a wider mode.
    #[cfg(unix)]
    #[test]
    fn files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("originated.json");
        std::fs::write(&p, b"old").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(tmp_path(&p), b"stale").unwrap();
        std::fs::set_permissions(tmp_path(&p), std::fs::Permissions::from_mode(0o666)).unwrap();
        write_atomic(&p, b"new").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
