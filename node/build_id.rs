//! Build identification for `build.rs`: the git commit the sources were built
//! from, read directly from the `.git` directory (no `git` process).
//!
//! Shared by `build.rs` and by `tests/build_id.rs`, which tests the parsing
//! on sample `HEAD`, `.git`-file and `packed-refs` contents. Plain `std` only.
//!
//! Resolution order:
//! 1. `BLACKSILK_BUILD_COMMIT` set (non-empty) in the build environment wins.
//!    This is how builds without `.git` (Docker: `.dockerignore` excludes it;
//!    source tarballs) carry their commit.
//! 2. Otherwise `.git` is found by walking up from the crate directory. It may
//!    be a directory, or a file `gitdir: <path>` (worktrees, submodules), in
//!    which case `commondir` names the directory that holds the shared refs.
//!    `HEAD` is either a commit id (detached) or `ref: refs/heads/<name>`,
//!    looked up as a loose ref file, then in `packed-refs`.
//! 3. Otherwise `unknown`.
//!
//! **Dirty trees (RTFP3-9).** With a commit read from `.git`, the reader also
//! compares every tracked build input with the index (`.git/index`, formats
//! 2 to 4), as `git status` does for modified files: a file whose size and
//! modification time match its index entry is clean; otherwise its content
//! is hashed as a git blob (SHA-1; also with CRLF line ends turned into LF,
//! the `core.autocrlf` checkout form) and compared with the entry's object
//! id. A deleted or unmerged file is dirty. The commit is then reported as
//! `<commit>-dirty` ([`DIRTY_SUFFIX`]), and `build.rs` refuses a release build
//! of a dirty tree unless `BLACKSILK_ALLOW_DIRTY=1`.
//!
//! Limits, stated: documentation (`docs/`, `*.md`) is not a build input and
//! is not compared; untracked files and changes staged in the index but not
//! committed are not detected (that needs the commit's tree, which is
//! compressed); a SHA-256 repository is compared by size and time only. An
//! override is taken as given: `BLACKSILK_BUILD_COMMIT=$(git describe
//! --always --dirty)` carries git's own dirty mark.

use std::path::{Path, PathBuf};

/// The suffix of a build commit whose tracked build inputs differ from it.
pub const DIRTY_SUFFIX: &str = "-dirty";

/// The value used when no commit can be determined.
pub const UNKNOWN: &str = "unknown";

/// The longest override accepted (a `git describe --dirty` string fits).
pub const MAX_OVERRIDE_LEN: usize = 96;

/// What `HEAD` contains.
#[derive(Debug, PartialEq, Eq)]
pub enum Head {
    /// A commit id (detached HEAD).
    Detached(String),
    /// A symbolic ref, e.g. `refs/heads/main`.
    Ref(String),
}

/// A commit id: 40 (SHA-1) or 64 (SHA-256) lowercase hex digits.
pub fn is_commit_id(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parses the contents of a `HEAD` file.
pub fn parse_head(content: &str) -> Option<Head> {
    let line = content.lines().next()?.trim();
    if let Some(r) = line.strip_prefix("ref:") {
        let r = r.trim();
        // A ref name is a relative path under the git directory; never follow
        // anything that could leave it.
        if r.starts_with("refs/")
            && !r.contains("..")
            && !r.contains('\\')
            && !r.contains(':')
            && !r.is_empty()
        {
            return Some(Head::Ref(r.to_string()));
        }
        return None;
    }
    is_commit_id(line).then(|| Head::Detached(line.to_string()))
}

/// Parses a `.git` *file* (`gitdir: <path>`), as in a worktree.
pub fn parse_gitdir_file(content: &str) -> Option<&str> {
    let p = content.lines().next()?.strip_prefix("gitdir:")?.trim();
    (!p.is_empty()).then_some(p)
}

/// Looks `name` up in the contents of a `packed-refs` file. Comment lines
/// (`#`) and peeled-tag lines (`^`) are skipped.
pub fn lookup_packed_ref(content: &str, name: &str) -> Option<String> {
    content
        .lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with('^'))
        .find_map(|l| {
            let (id, r) = l.trim().split_once(' ')?;
            (r == name && is_commit_id(id)).then(|| id.to_string())
        })
}

/// Accepts an override: non-empty after trimming, printable ASCII without
/// whitespace, at most [`MAX_OVERRIDE_LEN`] bytes. Anything else is ignored,
/// so an odd build environment cannot put control characters in logs.
pub fn sanitize_override(v: &str) -> Option<String> {
    let v = v.trim();
    (!v.is_empty() && v.len() <= MAX_OVERRIDE_LEN && v.bytes().all(|b| b.is_ascii_graphic()))
        .then(|| v.to_string())
}

/// The result of a lookup: the commit, and the files whose change must make
/// cargo run the build script again.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Found {
    pub commit: Option<String>,
    pub watch: Vec<PathBuf>,
    /// The repository's git directory (per worktree: it holds `index`).
    pub git_dir: Option<PathBuf>,
    /// The directory of the shared refs and `config`.
    pub common_dir: Option<PathBuf>,
}

/// Resolves the commit of the repository whose `.git` entry is `dot_git`,
/// through `read` (returns a file's contents, `None` when it does not exist or
/// cannot be read) and `is_dir`.
pub fn resolve(
    dot_git: &Path,
    read: &dyn Fn(&Path) -> Option<String>,
    is_dir: &dyn Fn(&Path) -> bool,
) -> Found {
    let mut found = Found::default();
    let git_dir = if is_dir(dot_git) {
        dot_git.to_path_buf()
    } else {
        let Some(content) = read(dot_git) else {
            return found;
        };
        found.watch.push(dot_git.to_path_buf());
        let Some(p) = parse_gitdir_file(&content) else {
            return found;
        };
        let p = Path::new(p);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            dot_git.parent().unwrap_or(Path::new(".")).join(p)
        }
    };
    // Shared refs live in `commondir` for worktrees, in the git dir otherwise.
    let common = match read(&git_dir.join("commondir")) {
        Some(c) if !c.trim().is_empty() => {
            let c = Path::new(c.trim());
            if c.is_absolute() {
                c.to_path_buf()
            } else {
                git_dir.join(c)
            }
        }
        _ => git_dir.clone(),
    };
    found.git_dir = Some(git_dir.clone());
    found.common_dir = Some(common.clone());
    let head_path = git_dir.join("HEAD");
    let Some(head) = read(&head_path) else {
        return found;
    };
    found.watch.push(head_path);
    match parse_head(&head) {
        Some(Head::Detached(id)) => found.commit = Some(id),
        Some(Head::Ref(name)) => {
            // Loose ref: per-worktree first, then shared.
            for dir in [&git_dir, &common] {
                let p = dir.join(&name);
                if let Some(id) = read(&p) {
                    let id = id.trim();
                    found.watch.push(p);
                    if is_commit_id(id) {
                        found.commit = Some(id.to_string());
                        break;
                    }
                }
            }
            // A new commit on a packed branch writes a loose file that did
            // not exist before: watch the refs directory for it.
            let heads = common.join("refs").join("heads");
            if is_dir(&heads) {
                found.watch.push(heads);
            }
            let packed = common.join("packed-refs");
            if let Some(content) = read(&packed) {
                found.watch.push(packed);
                if found.commit.is_none() {
                    found.commit = lookup_packed_ref(&content, &name);
                }
            }
        }
        None => {}
    }
    found
}

/// Walks up from `start`, through at most `levels` directories, to the first
/// one containing a `.git` entry. The bound keeps a source tree without `.git`
/// (a Docker context, a tarball) from picking up an unrelated repository
/// further up.
pub fn find_dot_git(
    start: &Path,
    levels: usize,
    exists: &dyn Fn(&Path) -> bool,
) -> Option<PathBuf> {
    start
        .ancestors()
        .take(levels)
        .map(|d| d.join(".git"))
        .find(|p| exists(p))
}

/// One entry of the git index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    /// Relative to the work tree, `/`-separated.
    pub path: String,
    pub mtime_s: u32,
    pub mtime_ns: u32,
    /// The file size, truncated to 32 bits (as git stores it).
    pub size: u32,
    pub mode: u32,
    pub oid: Vec<u8>,
    /// 0 for a merged entry; 1 to 3 for the sides of a conflict.
    pub stage: u8,
    /// `assume-unchanged` or `skip-worktree`: git does not compare the file.
    pub skip: bool,
}

/// Parses a git index (`DIRC`, versions 2, 3 and 4) whose object ids are
/// `oid_len` bytes (20 for SHA-1, 32 for SHA-256). Extensions after the
/// entries are ignored. `None` on anything malformed.
pub fn parse_index(bytes: &[u8], oid_len: usize) -> Option<Vec<IndexEntry>> {
    let u32_at = |at: usize| -> Option<u32> {
        Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
    };
    if bytes.get(..4)? != b"DIRC" {
        return None;
    }
    let version = u32_at(4)?;
    if !(2..=4).contains(&version) {
        return None;
    }
    let count = u32_at(8)? as usize;
    let mut at = 12;
    let mut entries = Vec::with_capacity(count.min(1 << 20));
    let mut prev_path: Vec<u8> = Vec::new();
    for _ in 0..count {
        let start = at;
        let mtime_s = u32_at(at + 8)?;
        let mtime_ns = u32_at(at + 12)?;
        let mode = u32_at(at + 24)?;
        let size = u32_at(at + 36)?;
        let oid = bytes.get(at + 40..at + 40 + oid_len)?.to_vec();
        at += 40 + oid_len;
        let flags = u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?);
        at += 2;
        let mut skip = flags & 0x8000 != 0;
        if flags & 0x4000 != 0 {
            if version < 3 {
                return None;
            }
            let ext = u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?);
            skip |= ext & 0x4000 != 0;
            at += 2;
        }
        let stage = ((flags >> 12) & 3) as u8;
        let path = if version == 4 {
            // A varint (git's offset encoding): bytes to drop from the end of
            // the previous path, then the NUL-terminated rest.
            let mut c = *bytes.get(at)?;
            at += 1;
            let mut strip = u64::from(c & 0x7f);
            while c & 0x80 != 0 {
                c = *bytes.get(at)?;
                at += 1;
                strip = strip.checked_add(1)?.checked_mul(128)? | u64::from(c & 0x7f);
            }
            let keep = prev_path.len().checked_sub(usize::try_from(strip).ok()?)?;
            let end = at + bytes.get(at..)?.iter().position(|&b| b == 0)?;
            let mut p = prev_path[..keep].to_vec();
            p.extend_from_slice(&bytes[at..end]);
            at = end + 1;
            p
        } else {
            let end = at + bytes.get(at..)?.iter().position(|&b| b == 0)?;
            let p = bytes[at..end].to_vec();
            // Entries are padded with 1 to 8 NULs to a multiple of 8 bytes.
            at = start + ((end - start) + 8) / 8 * 8;
            p
        };
        prev_path.clone_from(&path);
        entries.push(IndexEntry {
            path: String::from_utf8(path).ok()?,
            mtime_s,
            mtime_ns,
            size,
            mode,
            oid,
            stage,
            skip,
        });
    }
    Some(entries)
}

/// SHA-1 (FIPS 180-4). Used only to name git blobs, as git does; it is not
/// a security function here.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    let (blocks, rest) = msg.as_chunks::<64>();
    debug_assert!(rest.is_empty());
    for block in blocks {
        let mut w = [0u32; 80];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (o, x) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        *o = x.to_be_bytes();
    }
    out
}

/// The git blob id of `content`: `SHA-1("blob <len>\0" ‖ content)`.
pub fn blob_id(content: &[u8]) -> [u8; 20] {
    let mut data = format!("blob {}\0", content.len()).into_bytes();
    data.extend_from_slice(content);
    sha1(&data)
}

/// `content` with every CRLF turned into LF (git's `core.autocrlf` clean
/// conversion of a text file).
pub fn crlf_to_lf(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len());
    for (i, &b) in content.iter().enumerate() {
        if !(b == b'\r' && content.get(i + 1) == Some(&b'\n')) {
            out.push(b);
        }
    }
    out
}

/// Whether a tracked path is a build input: documentation is not.
pub fn is_build_input(path: &str) -> bool {
    !(path.starts_with("docs/") || path.ends_with(".md"))
}

/// A file's size and modification time (seconds and nanoseconds since the
/// Unix epoch), as git records them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub size: u64,
    pub mtime_s: u32,
    pub mtime_ns: u32,
}

/// The tracked build inputs under `root` that differ from the index
/// `entries`: deleted, unmerged, or with a content whose blob id (raw, or
/// with CRLF turned into LF) is not the entry's. `stat` and `read` return
/// `None` for a missing file; `hash` is false for a repository whose ids
/// this reader cannot compute (SHA-256), which then compares size and time
/// only.
pub fn dirty_paths(
    root: &Path,
    entries: &[IndexEntry],
    stat: &dyn Fn(&Path) -> Option<Stat>,
    read: &dyn Fn(&Path) -> Option<Vec<u8>>,
    hash: bool,
) -> Vec<String> {
    const TYPE_MASK: u32 = 0o170_000;
    const REGULAR: u32 = 0o100_000;
    let mut dirty: Vec<String> = Vec::new();
    for e in entries.iter().filter(|e| is_build_input(&e.path)) {
        if e.stage != 0 {
            if dirty.last() != Some(&e.path) {
                dirty.push(e.path.clone());
            }
            continue;
        }
        // Symbolic links and submodules are not compared; skipped entries
        // are not compared by git either.
        if e.skip || e.mode & TYPE_MASK != REGULAR {
            continue;
        }
        let file = root.join(&e.path);
        let Some(s) = stat(&file) else {
            dirty.push(e.path.clone());
            continue;
        };
        let same_stat = s.size as u32 == e.size
            && s.mtime_s == e.mtime_s
            && (e.mtime_ns == 0 || s.mtime_ns == e.mtime_ns);
        if same_stat {
            continue;
        }
        let clean = hash
            && read(&file).is_some_and(|c| {
                blob_id(&c)[..] == e.oid[..] || blob_id(&crlf_to_lf(&c))[..] == e.oid[..]
            });
        if !clean {
            dirty.push(e.path.clone());
        }
    }
    dirty
}

/// The object-id length of the repository whose `config` is `config`: 32
/// for `objectformat = sha256`, else 20.
pub fn oid_len(config: Option<&str>) -> usize {
    let sha256 = config.is_some_and(|c| {
        c.lines().any(|l| {
            let l = l.trim().to_ascii_lowercase().replace(' ', "");
            l == "objectformat=sha256"
        })
    });
    if sha256 {
        32
    } else {
        20
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const A: &str = "2f8f193aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "42320acd02168a2b4d51a7ac5a666dab8d181048";

    struct Fs {
        files: HashMap<PathBuf, String>,
        dirs: Vec<PathBuf>,
    }

    impl Fs {
        fn new(files: &[(&str, &str)], dirs: &[&str]) -> Self {
            Self {
                files: files
                    .iter()
                    .map(|(p, c)| (PathBuf::from(p), c.to_string()))
                    .collect(),
                dirs: dirs.iter().map(PathBuf::from).collect(),
            }
        }

        fn resolve(&self, dot_git: &str) -> Found {
            resolve(Path::new(dot_git), &|p| self.files.get(p).cloned(), &|p| {
                self.dirs.iter().any(|d| d == p)
            })
        }
    }

    #[test]
    fn head_parsing() {
        assert_eq!(
            parse_head("ref: refs/heads/main\n"),
            Some(Head::Ref("refs/heads/main".into()))
        );
        assert_eq!(
            parse_head(&format!("{A}\n")),
            Some(Head::Detached(A.into()))
        );
        assert_eq!(parse_head(""), None);
        assert_eq!(parse_head("garbage"), None);
        assert_eq!(parse_head("ref: ../../etc/passwd"), None);
        assert_eq!(parse_head("ref: refs/../../x"), None);
        assert_eq!(parse_head("ref: C:/x"), None);
        // Uppercase or short ids are not what git writes.
        assert_eq!(parse_head(&A.to_uppercase()), None);
        assert_eq!(parse_head("2f8f193"), None);
    }

    #[test]
    fn gitdir_file_parsing() {
        assert_eq!(
            parse_gitdir_file("gitdir: C:/repo/.git/worktrees/w1\n"),
            Some("C:/repo/.git/worktrees/w1")
        );
        assert_eq!(parse_gitdir_file("gitdir: \n"), None);
        assert_eq!(parse_gitdir_file("something else"), None);
    }

    #[test]
    fn packed_refs_lookup() {
        let packed = format!(
            "# pack-refs with: peeled fully-peeled sorted \n\
             {A} refs/heads/main\n\
             {B} refs/tags/v1\n\
             ^{A}\n\
             {B} refs/heads/main-2\n"
        );
        assert_eq!(
            lookup_packed_ref(&packed, "refs/heads/main"),
            Some(A.into())
        );
        assert_eq!(
            lookup_packed_ref(&packed, "refs/heads/main-2"),
            Some(B.into())
        );
        assert_eq!(lookup_packed_ref(&packed, "refs/heads/other"), None);
        assert_eq!(lookup_packed_ref("", "refs/heads/main"), None);
    }

    #[test]
    fn override_sanitizing() {
        assert_eq!(sanitize_override(" abc-dirty \n"), Some("abc-dirty".into()));
        assert_eq!(sanitize_override(""), None);
        assert_eq!(sanitize_override("   "), None);
        assert_eq!(sanitize_override("a b"), None);
        assert_eq!(sanitize_override("a\x1b[31m"), None);
        assert_eq!(sanitize_override(&"a".repeat(MAX_OVERRIDE_LEN + 1)), None);
    }

    #[test]
    fn loose_ref_in_a_plain_repository() {
        let fs = Fs::new(
            &[
                ("/r/.git/HEAD", "ref: refs/heads/main\n"),
                ("/r/.git/refs/heads/main", &format!("{A}\n")),
            ],
            &["/r/.git", "/r/.git/refs/heads"],
        );
        let f = fs.resolve("/r/.git");
        assert_eq!(f.commit.as_deref(), Some(A));
        assert!(f.watch.contains(&PathBuf::from("/r/.git/HEAD")));
        assert!(f.watch.contains(&PathBuf::from("/r/.git/refs/heads/main")));
        assert!(f.watch.contains(&PathBuf::from("/r/.git/refs/heads")));
    }

    #[test]
    fn packed_ref_is_the_fallback() {
        let fs = Fs::new(
            &[
                ("/r/.git/HEAD", "ref: refs/heads/main\n"),
                ("/r/.git/packed-refs", &format!("{B} refs/heads/main\n")),
            ],
            &["/r/.git"],
        );
        let f = fs.resolve("/r/.git");
        assert_eq!(f.commit.as_deref(), Some(B));
        assert!(f.watch.contains(&PathBuf::from("/r/.git/packed-refs")));
    }

    #[test]
    fn detached_head() {
        let fs = Fs::new(&[("/r/.git/HEAD", A)], &["/r/.git"]);
        assert_eq!(fs.resolve("/r/.git").commit.as_deref(), Some(A));
    }

    #[test]
    fn worktree_uses_commondir_for_refs() {
        let fs = Fs::new(
            &[
                ("/r/wt/.git", "gitdir: /r/.git/worktrees/wt\n"),
                ("/r/.git/worktrees/wt/HEAD", "ref: refs/heads/feature\n"),
                ("/r/.git/worktrees/wt/commondir", "../..\n"),
                (
                    "/r/.git/worktrees/wt/../../packed-refs",
                    &format!("{B} refs/heads/feature\n"),
                ),
            ],
            &["/r/.git"],
        );
        let f = fs.resolve("/r/wt/.git");
        assert_eq!(f.commit.as_deref(), Some(B));
        assert!(f.watch.contains(&PathBuf::from("/r/wt/.git")));
        assert!(f
            .watch
            .contains(&PathBuf::from("/r/.git/worktrees/wt/HEAD")));
    }

    #[test]
    fn missing_or_broken_repository_gives_none() {
        // No .git at all.
        assert_eq!(Fs::new(&[], &[]).resolve("/r/.git"), Found::default());
        // A .git directory without HEAD.
        assert_eq!(Fs::new(&[], &["/r/.git"]).resolve("/r/.git").commit, None);
        // A branch that does not exist yet (fresh repository, no commit).
        let fs = Fs::new(&[("/r/.git/HEAD", "ref: refs/heads/main\n")], &["/r/.git"]);
        assert_eq!(fs.resolve("/r/.git").commit, None);
        // A corrupt loose ref and no packed entry.
        let fs = Fs::new(
            &[
                ("/r/.git/HEAD", "ref: refs/heads/main\n"),
                ("/r/.git/refs/heads/main", "not a hash\n"),
            ],
            &["/r/.git"],
        );
        assert_eq!(fs.resolve("/r/.git").commit, None);
        // A .git file that is not a gitdir pointer.
        let fs = Fs::new(&[("/r/.git", "junk")], &[]);
        assert_eq!(fs.resolve("/r/.git").commit, None);
    }

    #[test]
    fn find_dot_git_walks_up() {
        let exists = |p: &Path| p == Path::new("/r/.git");
        assert_eq!(
            find_dot_git(Path::new("/r/node"), 2, &exists),
            Some(PathBuf::from("/r/.git"))
        );
        assert_eq!(find_dot_git(Path::new("/r/a/node"), 2, &exists), None);
        assert_eq!(find_dot_git(Path::new("/elsewhere/node"), 2, &exists), None);
    }

    fn hexs(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// FIPS 180-4 examples, a two-block message, and git's blob ids (`echo
    /// hello | git hash-object --stdin`, and the empty blob).
    #[test]
    fn sha1_and_blob_ids() {
        assert_eq!(hexs(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hexs(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hexs(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            hexs(&blob_id(b"hello\n")),
            "ce013625030ba8dba906f756967f9e9ca394464a"
        );
        assert_eq!(
            hexs(&blob_id(b"")),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        );
        assert_eq!(crlf_to_lf(b"a\r\nb\rc\r\n\r"), b"a\nb\rc\n\r");
    }

    /// Builds an index of `entries` (path, stage, extended flags) in `version`.
    fn index(version: u32, entries: &[(&str, u8, Option<u16>)]) -> Vec<u8> {
        let mut out = b"DIRC".to_vec();
        out.extend(version.to_be_bytes());
        out.extend((entries.len() as u32).to_be_bytes());
        let mut prev = String::new();
        for (i, (path, stage, ext)) in entries.iter().enumerate() {
            let start = out.len();
            let mut fixed = [0u32; 10];
            fixed[2] = 1_700_000_000 + i as u32; // mtime s
            fixed[3] = 5; // mtime ns
            fixed[6] = 0o100_644; // mode
            fixed[9] = 6; // size
            for v in fixed {
                out.extend(v.to_be_bytes());
            }
            out.extend(blob_id(b"hello\n"));
            let mut flags = (u16::from(*stage) << 12) | path.len().min(0xfff) as u16;
            if ext.is_some() {
                flags |= 0x4000;
            }
            out.extend(flags.to_be_bytes());
            if let Some(x) = ext {
                out.extend(x.to_be_bytes());
            }
            if version == 4 {
                let common = prev
                    .bytes()
                    .zip(path.bytes())
                    .take_while(|(a, b)| a == b)
                    .count();
                let strip = prev.len() - common;
                assert!(strip < 128, "one-byte varint in this helper");
                out.push(strip as u8);
                out.extend(&path.as_bytes()[common..]);
                out.push(0);
            } else {
                out.extend(path.as_bytes());
                let len = out.len() - start;
                out.resize(start + (len + 8) / 8 * 8, 0);
            }
            prev = path.to_string();
        }
        out.extend(b"TREE\0\0\0\0"); // an extension, ignored
        out
    }

    #[test]
    fn index_parsing() {
        let entries = [
            ("Cargo.toml", 0, None),
            ("node/build.rs", 0, None),
            ("node/build_id.rs", 0, Some(0x4000)),
            ("zz", 2, None),
        ];
        for v in [3, 4] {
            let parsed = parse_index(&index(v, &entries), 20).expect("parses");
            let paths: Vec<&str> = parsed.iter().map(|e| e.path.as_str()).collect();
            assert_eq!(
                paths,
                ["Cargo.toml", "node/build.rs", "node/build_id.rs", "zz"]
            );
            assert_eq!(parsed[0].mtime_s, 1_700_000_000);
            assert_eq!((parsed[0].mtime_ns, parsed[0].size), (5, 6));
            assert_eq!(parsed[0].oid, blob_id(b"hello\n"));
            assert!(!parsed[1].skip && parsed[2].skip, "skip-worktree");
            assert_eq!(parsed[3].stage, 2);
        }
        let v2 = [("a", 0, None), ("b/c", 0, None)];
        assert_eq!(parse_index(&index(2, &v2), 20).unwrap().len(), 2);
        // Extended flags need version 3; bad magic, version and truncation.
        assert_eq!(parse_index(&index(2, &entries), 20), None);
        assert_eq!(parse_index(b"DIRX\0\0\0\x02\0\0\0\0", 20), None);
        assert_eq!(parse_index(b"DIRC\0\0\0\x05\0\0\0\0", 20), None);
        let whole = index(2, &v2);
        assert_eq!(parse_index(&whole[..whole.len() - 20], 20), None);
    }

    #[test]
    fn dirty_paths_compares_like_git_status() {
        let mut entries = parse_index(
            &index(
                3,
                &[
                    ("a.rs", 0, None),
                    ("b.rs", 0, None),
                    ("c.rs", 0, None),
                    ("d.rs", 0, None),
                    ("docs/x.txt", 0, None),
                    ("e.md", 0, None),
                    ("gone.rs", 0, None),
                    ("skipped.rs", 0, Some(0x4000)),
                    ("u.rs", 1, None),
                    ("u.rs", 2, None),
                ],
            ),
            20,
        )
        .unwrap();
        entries[4].size = 99; // docs: never compared
        let root = Path::new("/w");
        let files: HashMap<PathBuf, (Stat, Vec<u8>)> = [
            // a: same size and time.
            ("a.rs", 1_700_000_000, 6, b"xxxxxx".to_vec()),
            // b: touched (time differs), same content.
            ("b.rs", 1, 6, b"hello\n".to_vec()),
            // c: CRLF checkout of the LF blob.
            ("c.rs", 1, 7, b"hello\r\n".to_vec()),
            // d: changed content.
            ("d.rs", 1, 6, b"hellO\n".to_vec()),
            ("docs/x.txt", 1, 1, b"?".to_vec()),
            ("e.md", 1, 1, b"?".to_vec()),
            ("skipped.rs", 1, 1, b"?".to_vec()),
        ]
        .into_iter()
        .map(|(p, s, size, c)| {
            let stat = Stat {
                size,
                mtime_s: s,
                mtime_ns: 5,
            };
            (root.join(p), (stat, c))
        })
        .collect();
        let stat = |p: &Path| files.get(p).map(|f| f.0);
        let read = |p: &Path| files.get(p).map(|f| f.1.clone());
        assert_eq!(
            dirty_paths(root, &entries, &stat, &read, true),
            ["d.rs", "gone.rs", "u.rs"]
        );
        // Without hashing (SHA-256 repositories), a changed time is dirty.
        assert_eq!(
            dirty_paths(root, &entries, &stat, &read, false),
            ["b.rs", "c.rs", "d.rs", "gone.rs", "u.rs"]
        );
        assert!(is_build_input("node/build.rs") && !is_build_input("docs/testnet.md"));
    }

    #[test]
    fn object_format() {
        assert_eq!(oid_len(None), 20);
        assert_eq!(oid_len(Some("[core]\n\tbare = false\n")), 20);
        assert_eq!(oid_len(Some("[extensions]\n\tobjectFormat = sha256\n")), 32);
    }
}
