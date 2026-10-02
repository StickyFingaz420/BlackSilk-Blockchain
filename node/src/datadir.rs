//! The data directory's permissions (docs/testnet.md §4.5; threat-model
//! round 2, "origin data at rest").
//!
//! The data directory holds files that are private to the operator:
//! `originated.json` (the transactions this node originated), `peers.json`
//! (its contacts and bucketing key), `anchors.json`, `bans.json`, the RPC
//! cookie, and the block store with the operator's verdicts. On Unix:
//!
//! - the node creates the directory, and any missing parent, owner-only
//!   (0700), whatever the umask ([`create`]); its own files are created
//!   0600 (`LOCK` here, the store in `blacksilk-chain`, the cookie in
//!   `cookie.rs`, the P2P files in `blacksilk_p2p::private_file`);
//! - at every start, a directory and node files that other local users can
//!   read (left by an earlier run under umask 022, or by a copy) are
//!   **tightened**, with a warning ([`tighten`]). Tightening, not only a
//!   warning: these files are the node's own, the change loses nothing and
//!   the operator can undo it, while a warning alone would leave
//!   `originated.json` readable for the whole run. Only the node's own
//!   files are touched ([`is_node_file`]), and the directory itself only
//!   if it holds nothing else and is not a shared sticky directory such as
//!   `/tmp`: a data directory pointed at a shared place is reported, never
//!   changed.
//!
//! On Windows nothing here changes anything: files inherit the access
//! control list of their directory, and the default data directory under
//! `%APPDATA%` is private to the user (there is no safe-Rust way to set an
//! ACL; `cookie.rs` warns about a data directory outside the profile).

use std::io;
use std::path::{Path, PathBuf};

/// Creates `dir` and any missing parent: owner-only (0700) on Unix,
/// whatever the umask (an existing directory is left to [`tighten`]).
pub fn create(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Creates or opens (truncating) a file of the node, owner-only (0600) on
/// Unix when created.
pub fn create_file(path: &Path) -> io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Whether `name` is a file the node writes in its data directory
/// (docs/testnet.md §4.5), or the temporary file of one.
pub fn is_node_file(name: &str) -> bool {
    const FILES: [&str; 8] = [
        "blocks.dat",
        "originated.json",
        "peers.json",
        "anchors.json",
        "bans.json",
        "LOCK",
        "rpc.cookie",
        "rpc.cookie.tmp",
    ];
    const TMP: [&str; 4] = ["originated.tmp", "peers.tmp", "anchors.tmp", "bans.tmp"];
    FILES.contains(&name) || TMP.contains(&name) || name.starts_with("blocks.dat.damaged-")
}

/// What [`tighten`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Tightened {
    /// Made owner-only, with the mode each had.
    pub changed: Vec<(PathBuf, u32)>,
    /// Left as they are, and why (the operator must act).
    pub left: Vec<(PathBuf, String)>,
}

/// Sets `mode` on the file or directory `path` through an open handle
/// (`fchmod`), never through the name (RT-NODEOPS, TOCTOU): the handle is
/// opened after `lstat` and must be the same object (device and inode), so
/// a name swapped for a symbolic link between the check and the change is
/// refused, and a swap after the open changes the object that was checked.
#[cfg(unix)]
pub fn chmod_checked(path: &Path, expected: &std::fs::Metadata, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let f = std::fs::File::open(path)?;
    let opened = f.metadata()?;
    if opened.dev() != expected.dev() || opened.ino() != expected.ino() {
        return Err(io::Error::other("it changed while being checked"));
    }
    f.set_permissions(std::fs::Permissions::from_mode(mode))
}

/// Makes the data directory `dir` (0700) and the node files in it (0600)
/// owner-only where group or other users have any access (module docs).
/// Symbolic links are never followed or changed, and modes are set through
/// a checked handle ([`chmod_checked`]). Never fails: whatever cannot be
/// read or changed is reported in [`Tightened::left`] (a warning, not a
/// reason to stop). A no-op on Windows.
pub fn tighten(dir: &Path) -> Tightened {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut out = Tightened::default();
        let mut foreign = Vec::new();
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                out.left
                    .push((dir.to_path_buf(), format!("cannot list it: {e}")));
                return out;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    out.left
                        .push((dir.to_path_buf(), format!("cannot list it: {e}")));
                    continue;
                }
            };
            let path = entry.path();
            let name = entry.file_name();
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    out.left.push((path, format!("cannot read its mode: {e}")));
                    continue;
                }
            };
            if !name.to_str().is_some_and(is_node_file) || !meta.file_type().is_file() {
                foreign.push(name.to_string_lossy().into_owned());
                continue;
            }
            let mode = meta.permissions().mode() & 0o7777;
            if mode & 0o077 != 0 {
                match chmod_checked(&path, &meta, 0o600) {
                    Ok(()) => out.changed.push((path, mode)),
                    Err(e) => out.left.push((path, format!("mode {mode:o}: {e}"))),
                }
            }
        }
        let meta = match std::fs::symlink_metadata(dir) {
            Ok(m) => m,
            Err(e) => {
                out.left
                    .push((dir.to_path_buf(), format!("cannot read its mode: {e}")));
                return out;
            }
        };
        let mode = meta.permissions().mode() & 0o7777;
        if mode & 0o077 != 0 {
            let why = if meta.file_type().is_symlink() {
                Some("a symbolic link".to_string())
            } else if mode & 0o1000 != 0 {
                Some("a shared directory (sticky bit)".to_string())
            } else if !foreign.is_empty() {
                foreign.sort();
                foreign.truncate(5);
                Some(format!(
                    "it holds other files than the node's ({})",
                    foreign.join(", ")
                ))
            } else {
                None
            };
            match why {
                Some(why) => out.left.push((
                    dir.to_path_buf(),
                    format!("mode {mode:o}, not changed: {why}; use a directory of its own"),
                )),
                None => match chmod_checked(dir, &meta, 0o700) {
                    Ok(()) => out.changed.push((dir.to_path_buf(), mode)),
                    Err(e) => out
                        .left
                        .push((dir.to_path_buf(), format!("mode {mode:o}: {e}"))),
                },
            }
        }
        out
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Tightened::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory that cannot be listed is reported, not an error.
    #[test]
    fn an_unreadable_directory_is_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let t = tighten(&dir.path().join("missing"));
        if cfg!(unix) {
            assert_eq!(t.left.len(), 1, "{t:?}");
        } else {
            assert_eq!(t, Tightened::default());
        }
    }

    /// A name swapped for another object after the check is refused.
    #[cfg(unix)]
    #[test]
    fn a_swapped_file_is_not_changed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("peers.json"), dir.path().join("other"));
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        std::fs::set_permissions(&b, PermissionsExt::from_mode(0o644)).unwrap();
        let checked = std::fs::symlink_metadata(&a).unwrap();
        std::fs::remove_file(&a).unwrap();
        std::os::unix::fs::symlink(&b, &a).unwrap();
        assert!(chmod_checked(&a, &checked, 0o600).is_err());
        let mode = std::fs::metadata(&b).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "the link's target is untouched");
    }

    #[test]
    fn node_files_are_recognized() {
        for name in [
            "blocks.dat",
            "blocks.dat.damaged-1759400000",
            "originated.json",
            "originated.tmp",
            "peers.json",
            "anchors.json",
            "bans.json",
            "LOCK",
            "rpc.cookie",
            "rpc.cookie.tmp",
        ] {
            assert!(is_node_file(name), "{name}");
        }
        for name in ["node.log", "me.wallet", ".bashrc", "blocks.dat.bak"] {
            assert!(!is_node_file(name), "{name}");
        }
    }

    /// A fresh data directory and its new parents are owner-only; a
    /// directory with wider modes is tightened with its node files, and
    /// nothing changes on a second run.
    #[cfg(unix)]
    #[test]
    fn tightens_the_directory_and_the_node_files() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("a").join("b");
        create(&dir).unwrap();
        assert_eq!(mode(&root.path().join("a")), 0o700);
        assert_eq!(mode(&dir), 0o700);
        drop(create_file(&dir.join("LOCK")).unwrap());
        assert_eq!(mode(&dir.join("LOCK")), 0o600);

        std::fs::write(dir.join("originated.json"), b"{}").unwrap();
        std::fs::set_permissions(
            dir.join("originated.json"),
            PermissionsExt::from_mode(0o644),
        )
        .unwrap();
        std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o755)).unwrap();
        let t = tighten(&dir);
        assert!(t.left.is_empty(), "{t:?}");
        assert_eq!(t.changed.len(), 2, "{t:?}");
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("originated.json")), 0o600);
        assert_eq!(tighten(&dir), Tightened::default());
    }

    /// A directory that holds files of others is reported, not changed;
    /// those files are never touched.
    #[cfg(unix)]
    #[test]
    fn leaves_a_shared_directory_alone() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::write(d.join("notes.txt"), b"x").unwrap();
        std::fs::set_permissions(d.join("notes.txt"), PermissionsExt::from_mode(0o644)).unwrap();
        std::fs::write(d.join("peers.json"), b"{}").unwrap();
        std::fs::set_permissions(d.join("peers.json"), PermissionsExt::from_mode(0o644)).unwrap();
        std::fs::set_permissions(d, PermissionsExt::from_mode(0o755)).unwrap();
        let t = tighten(d);
        assert_eq!(mode(d), 0o755);
        assert_eq!(mode(&d.join("notes.txt")), 0o644);
        assert_eq!(mode(&d.join("peers.json")), 0o600);
        assert_eq!(t.left.len(), 1, "{t:?}");
        assert!(t.left[0].1.contains("notes.txt"), "{t:?}");
    }
}
