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
//! There is no dirty flag: detecting uncommitted changes needs the index and a
//! hash of every tracked file (what `git status` does), which this reader does
//! not do. A release build that must record a dirty tree sets the override,
//! for example `BLACKSILK_BUILD_COMMIT=$(git describe --always --dirty)`.

use std::path::{Path, PathBuf};

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
}
