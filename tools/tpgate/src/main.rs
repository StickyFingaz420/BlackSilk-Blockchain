//! `blacksilk-tpgate`: the dependency-identity part of the third-party patch gate
//! (`.github/scripts/third-party-gate.sh`, RT-TPGATE2).
//!
//! ```text
//! blacksilk-tpgate <repo root> <workspace root>... [--standalone <crate dir>...]
//! ```
//!
//! For each workspace root (a directory with a tracked `Cargo.lock`) it reads
//! `cargo metadata --no-deps --offline --format-version 1` (cargo's own view of
//! the workspace members and their declared dependencies; nothing is
//! downloaded) and the root's `Cargo.lock`, and the `Cargo.toml` of every crate
//! under `<repo>/third_party/`. It then requires:
//!
//! 1. no workspace member is named like a third_party/ crate;
//! 2. every dependency with a `path` points at a workspace member (of any root)
//!    or at `third_party/<name>`, and the package found there has the
//!    dependency's package name;
//! 3. a dependency on a third_party/ crate, or one renamed to a third_party/
//!    name, is not renamed (no aliasing of patched crates);
//! 4. every dependency `source` is crates.io, and no alternative `registry`;
//! 5. in every `Cargo.lock`: every `source` is crates.io; every package without
//!    a source is a workspace member or a third_party/ crate (name and
//!    version); no package locks a third_party/ crate's version from the
//!    registry (that workspace would bypass the patch); the file has only the
//!    keys cargo writes (`version`, `package`; per package `name`, `version`,
//!    `source`, `checksum`, `dependencies`).
//!
//! Standalone path crates outside every workspace (`--standalone`, e.g.
//! `zkvm/sdk`) count as members; each must have no dependency tables at all.
//!
//! Anything it cannot parse is an error (fail closed). Exit 0 when every rule
//! holds, 1 with one line per violation, 2 on a usage or input error.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// The only registry source allowed.
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// A crate under `third_party/`.
#[derive(Clone, Debug)]
struct ThirdParty {
    name: String,
    version: String,
    dir: PathBuf,
}

/// A workspace member, from `cargo metadata`.
#[derive(Clone, Debug)]
struct Member {
    name: String,
    version: String,
    dir: PathBuf,
}

/// A declared dependency of a member, from `cargo metadata`.
#[derive(Clone, Debug, Default)]
struct Dep {
    owner: String,
    name: String,
    rename: Option<String>,
    path: Option<PathBuf>,
    source: Option<String>,
    registry: Option<String>,
}

/// One `[[package]]` of a `Cargo.lock`.
#[derive(Clone, Debug)]
struct LockPkg {
    name: String,
    version: String,
    source: Option<String>,
}

fn opt_str(v: &serde_json::Value, key: &str, what: &str) -> Result<Option<String>, String> {
    match v.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(format!("{what}: `{key}` is not a string")),
    }
}

fn req_str(v: &serde_json::Value, key: &str, what: &str) -> Result<String, String> {
    opt_str(v, key, what)?.ok_or_else(|| format!("{what}: no `{key}`"))
}

/// The members and their dependencies from `cargo metadata --no-deps` JSON.
/// `canon` maps a path from the metadata to its comparable form.
fn parse_metadata(
    json: &str,
    canon: &dyn Fn(&Path) -> Result<PathBuf, String>,
) -> Result<(Vec<Member>, Vec<Dep>), String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("cargo metadata: {e}"))?;
    let pkgs = v
        .get("packages")
        .and_then(|p| p.as_array())
        .ok_or("cargo metadata: no `packages` array")?;
    let mut members = Vec::new();
    let mut deps = Vec::new();
    for p in pkgs {
        let name = req_str(p, "name", "package")?;
        let what = format!("package {name}");
        let version = req_str(p, "version", &what)?;
        let manifest = req_str(p, "manifest_path", &what)?;
        let dir = Path::new(&manifest)
            .parent()
            .ok_or_else(|| format!("{what}: manifest path without a directory"))?;
        members.push(Member {
            name: name.clone(),
            version,
            dir: canon(dir)?,
        });
        let ds = p
            .get("dependencies")
            .and_then(|d| d.as_array())
            .ok_or_else(|| format!("{what}: no `dependencies` array"))?;
        for d in ds {
            let dname = req_str(d, "name", &what)?;
            let dwhat = format!("{what}, dependency {dname}");
            deps.push(Dep {
                owner: name.clone(),
                name: dname,
                rename: opt_str(d, "rename", &dwhat)?,
                path: opt_str(d, "path", &dwhat)?
                    .map(|s| canon(Path::new(&s)))
                    .transpose()?,
                source: opt_str(d, "source", &dwhat)?,
                registry: opt_str(d, "registry", &dwhat)?,
            });
        }
    }
    Ok((members, deps))
}

/// The packages of a `Cargo.lock`, refusing keys cargo does not write.
fn parse_lock(text: &str) -> Result<Vec<LockPkg>, String> {
    let t: toml::Table = text.parse().map_err(|e| format!("Cargo.lock: {e}"))?;
    for k in t.keys() {
        if k != "version" && k != "package" {
            return Err(format!("Cargo.lock: unexpected top-level key `{k}`"));
        }
    }
    let Some(pkgs) = t.get("package") else {
        return Ok(Vec::new());
    };
    let pkgs = pkgs
        .as_array()
        .ok_or("Cargo.lock: `package` is not an array")?;
    let mut out = Vec::new();
    for p in pkgs {
        let p = p.as_table().ok_or("Cargo.lock: a package is not a table")?;
        for k in p.keys() {
            if !matches!(
                k.as_str(),
                "name" | "version" | "source" | "checksum" | "dependencies"
            ) {
                return Err(format!("Cargo.lock: unexpected package key `{k}`"));
            }
        }
        let s = |k: &str| -> Result<Option<String>, String> {
            match p.get(k) {
                None => Ok(None),
                Some(toml::Value::String(s)) => Ok(Some(s.clone())),
                Some(_) => Err(format!("Cargo.lock: package `{k}` is not a string")),
            }
        };
        out.push(LockPkg {
            name: s("name")?.ok_or("Cargo.lock: a package has no name")?,
            version: s("version")?.ok_or("Cargo.lock: a package has no version")?,
            source: s("source")?,
        });
    }
    Ok(out)
}

/// Name and version of a `third_party/<dir>/Cargo.toml`.
fn parse_third_party(text: &str) -> Result<(String, String), String> {
    let t: toml::Table = text.parse().map_err(|e: toml::de::Error| e.to_string())?;
    let p = t
        .get("package")
        .and_then(|p| p.as_table())
        .ok_or("no [package] table")?;
    let get = |k: &str| p.get(k).and_then(|v| v.as_str()).map(str::to_owned);
    Ok((
        get("name").ok_or("no package name")?,
        get("version").ok_or("no package version")?,
    ))
}

/// Name and version of a standalone path crate (a crate outside every
/// workspace, such as `zkvm/sdk`, which `cargo metadata --no-deps` cannot
/// read). It may have no dependencies of any kind and only the tables listed
/// here, so it cannot pull anything in.
fn parse_standalone(text: &str) -> Result<(String, String), String> {
    let t: toml::Table = text.parse().map_err(|e: toml::de::Error| e.to_string())?;
    for k in t.keys() {
        if !matches!(k.as_str(), "package" | "lib" | "features") {
            return Err(format!(
                "standalone crate has a `{k}` table (allowed: package, lib, features)"
            ));
        }
    }
    parse_third_party(text)
}

/// Every violation of the rules in the module documentation.
fn check(
    tp: &[ThirdParty],
    members: &[Member],
    deps: &[Dep],
    locks: &[(String, Vec<LockPkg>)],
) -> Vec<String> {
    let mut errs = Vec::new();
    let tp_names: BTreeSet<&str> = tp.iter().map(|t| t.name.as_str()).collect();
    for m in members {
        if tp_names.contains(m.name.as_str()) {
            errs.push(format!(
                "workspace member {} ({}) is named like the third_party/ crate; the only copy allowed is third_party/{}",
                m.name,
                m.dir.display(),
                m.name
            ));
        }
    }
    for d in deps {
        let at = format!("{} -> {}", d.owner, d.name);
        match &d.source {
            Some(s) if s != CRATES_IO => errs.push(format!("{at}: source {s} is not crates.io")),
            _ => {}
        }
        if let Some(r) = &d.registry {
            errs.push(format!("{at}: alternative registry {r}"));
        }
        if let Some(r) = &d.rename {
            if tp_names.contains(d.name.as_str()) || tp_names.contains(r.as_str()) {
                errs.push(format!(
                    "{at}: renamed to `{r}`; a third_party/ crate may not be aliased"
                ));
            }
        }
        match &d.path {
            Some(p) => {
                let member = members.iter().any(|m| &m.dir == p && m.name == d.name);
                let third = tp.iter().any(|t| &t.dir == p && t.name == d.name);
                if !member && !third {
                    errs.push(format!(
                        "{at}: path {} is neither a workspace member nor third_party/{} with that package name",
                        p.display(),
                        d.name
                    ));
                }
            }
            None if d.source.is_none() => errs.push(format!("{at}: neither a path nor a source")),
            None => {}
        }
    }
    for (lock, pkgs) in locks {
        for p in pkgs {
            let at = format!("{lock}: {} {}", p.name, p.version);
            match &p.source {
                Some(s) if s == CRATES_IO => {
                    if tp
                        .iter()
                        .any(|t| t.name == p.name && t.version == p.version)
                    {
                        errs.push(format!(
                            "{at} comes from crates.io, bypassing third_party/{}; add the [patch.crates-io] line to that workspace",
                            p.name
                        ));
                    }
                }
                Some(s) => errs.push(format!("{at}: source {s} is not crates.io")),
                None => {
                    let known = members
                        .iter()
                        .any(|m| m.name == p.name && m.version == p.version)
                        || tp
                            .iter()
                            .any(|t| t.name == p.name && t.version == p.version);
                    if !known {
                        errs.push(format!("{at}: a path crate that is neither a workspace member nor a third_party/ crate"));
                    }
                }
            }
        }
    }
    errs
}

fn canonical(p: &Path) -> Result<PathBuf, String> {
    std::fs::canonicalize(p).map_err(|e| format!("{}: {e}", p.display()))
}

fn run(repo: &Path, roots: &[PathBuf], standalone: &[PathBuf]) -> Result<Vec<String>, String> {
    let mut tp = Vec::new();
    let third = repo.join("third_party");
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&third)
        .map_err(|e| format!("{}: {e}", third.display()))?
        .map(|e| e.map(|e| e.path()).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    dirs.sort();
    for dir in dirs {
        let manifest = dir.join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&manifest)
            .map_err(|e| format!("{}: {e}", manifest.display()))?;
        let (name, version) =
            parse_third_party(&text).map_err(|e| format!("{}: {e}", manifest.display()))?;
        tp.push(ThirdParty {
            name,
            version,
            dir: canonical(&dir)?,
        });
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let (mut members, mut deps, mut locks) = (Vec::new(), Vec::new(), Vec::new());
    for root in roots {
        let manifest = root.join("Cargo.toml");
        let out = Command::new(&cargo)
            .args([
                "metadata",
                "--no-deps",
                "--offline",
                "--format-version",
                "1",
                "--manifest-path",
            ])
            .arg(&manifest)
            .output()
            .map_err(|e| format!("cargo metadata for {}: {e}", manifest.display()))?;
        if !out.status.success() {
            return Err(format!(
                "cargo metadata for {} failed: {}",
                manifest.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let json =
            String::from_utf8(out.stdout).map_err(|e| format!("cargo metadata output: {e}"))?;
        let (m, d) = parse_metadata(&json, &canonical)?;
        members.extend(m);
        deps.extend(d);
        let lock = root.join("Cargo.lock");
        let text =
            std::fs::read_to_string(&lock).map_err(|e| format!("{}: {e}", lock.display()))?;
        locks.push((lock.display().to_string(), parse_lock(&text)?));
    }
    for dir in standalone {
        let manifest = dir.join("Cargo.toml");
        let text = std::fs::read_to_string(&manifest)
            .map_err(|e| format!("{}: {e}", manifest.display()))?;
        let (name, version) =
            parse_standalone(&text).map_err(|e| format!("{}: {e}", manifest.display()))?;
        members.push(Member {
            name,
            version,
            dir: canonical(dir)?,
        });
    }
    Ok(check(&tp, &members, &deps, &locks))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!(
            "usage: blacksilk-tpgate <repo root> <workspace root>... [--standalone <crate dir>...]"
        );
        return ExitCode::from(2);
    }
    let repo = PathBuf::from(&args[0]);
    let split = args
        .iter()
        .position(|a| a == "--standalone")
        .unwrap_or(args.len());
    let roots: Vec<PathBuf> = args[1..split].iter().map(|r| repo.join(r)).collect();
    let standalone: Vec<PathBuf> = args[split..].iter().skip(1).map(|r| repo.join(r)).collect();
    if roots.is_empty() {
        eprintln!("blacksilk-tpgate: no workspace root");
        return ExitCode::from(2);
    }
    match run(&repo, &roots, &standalone) {
        Ok(errs) if errs.is_empty() => {
            println!("blacksilk-tpgate: {} workspaces, every crate is a member, third_party/ or crates.io", roots.len());
            ExitCode::SUCCESS
        }
        Ok(errs) => {
            for e in &errs {
                println!("{e}");
            }
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("blacksilk-tpgate: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tp() -> Vec<ThirdParty> {
        vec![ThirdParty {
            name: "p3-fri".into(),
            version: "0.7.0".into(),
            dir: "/r/third_party/p3-fri".into(),
        }]
    }
    fn members() -> Vec<Member> {
        vec![
            Member {
                name: "blacksilk-zk".into(),
                version: "0.1.0".into(),
                dir: "/r/zk".into(),
            },
            Member {
                name: "blacksilk-crypto".into(),
                version: "0.1.0".into(),
                dir: "/r/crypto".into(),
            },
        ]
    }
    fn reg(owner: &str, name: &str) -> Dep {
        Dep {
            owner: owner.into(),
            name: name.into(),
            source: Some(CRATES_IO.into()),
            ..Dep::default()
        }
    }
    fn path(owner: &str, name: &str, p: &str) -> Dep {
        Dep {
            owner: owner.into(),
            name: name.into(),
            path: Some(p.into()),
            ..Dep::default()
        }
    }
    fn lock(entries: &[(&str, &str, Option<&str>)]) -> Vec<(String, Vec<LockPkg>)> {
        vec![(
            "Cargo.lock".into(),
            entries
                .iter()
                .map(|(n, v, s)| LockPkg {
                    name: (*n).into(),
                    version: (*v).into(),
                    source: s.map(Into::into),
                })
                .collect(),
        )]
    }
    fn good_lock() -> Vec<(String, Vec<LockPkg>)> {
        lock(&[
            ("blacksilk-zk", "0.1.0", None),
            ("blacksilk-crypto", "0.1.0", None),
            ("p3-fri", "0.7.0", None),
            ("serde", "1.0.0", Some(CRATES_IO)),
        ])
    }
    fn good_deps() -> Vec<Dep> {
        vec![
            reg("blacksilk-zk", "p3-fri"),
            path("blacksilk-zk", "blacksilk-crypto", "/r/crypto"),
            reg("blacksilk-zk", "serde"),
        ]
    }

    #[test]
    fn the_real_shape_passes() {
        assert!(check(&tp(), &members(), &good_deps(), &good_lock()).is_empty());
    }

    #[test]
    fn a_member_named_like_a_patched_crate_fails() {
        let mut m = members();
        m.push(Member {
            name: "p3-fri".into(),
            version: "0.7.0".into(),
            dir: "/r/vendor/p3-fri".into(),
        });
        assert_eq!(check(&tp(), &m, &good_deps(), &good_lock()).len(), 1);
    }

    #[test]
    fn a_renamed_path_copy_fails() {
        // p3-fri = { package = "blacksilk-fri", path = "../evil/p3-fri" }
        let mut d = good_deps();
        d.push(Dep {
            rename: Some("p3-fri".into()),
            ..path("blacksilk-zk", "blacksilk-fri", "/r/evil/p3-fri")
        });
        let errs = check(&tp(), &members(), &d, &good_lock());
        assert_eq!(errs.len(), 2, "{errs:?}"); // the alias and the unknown path
    }

    #[test]
    fn an_alias_of_a_patched_crate_fails() {
        let mut d = good_deps();
        d.push(Dep {
            rename: Some("fri".into()),
            ..reg("blacksilk-zk", "p3-fri")
        });
        assert_eq!(check(&tp(), &members(), &d, &good_lock()).len(), 1);
    }

    #[test]
    fn a_path_to_a_non_member_fails_and_the_wrong_name_at_a_member_fails() {
        let mut d = good_deps();
        d.push(path("blacksilk-zk", "blacksilk-x", "/r/vendor/x"));
        d.push(path("blacksilk-zk", "blacksilk-zk2", "/r/crypto"));
        assert_eq!(check(&tp(), &members(), &d, &good_lock()).len(), 2);
    }

    #[test]
    fn a_path_to_third_party_passes_only_under_its_own_name() {
        let mut d = good_deps();
        d.push(path("blacksilk-zk", "p3-fri", "/r/third_party/p3-fri"));
        assert!(check(&tp(), &members(), &d, &good_lock()).is_empty());
        d.push(path("blacksilk-zk", "p3-dft", "/r/third_party/p3-fri"));
        assert_eq!(check(&tp(), &members(), &d, &good_lock()).len(), 1);
    }

    #[test]
    fn git_and_alternative_registry_dependencies_fail() {
        let mut d = good_deps();
        d.push(Dep {
            source: Some("git+https://x/y#abc".into()),
            ..reg("blacksilk-zk", "rand")
        });
        d.push(Dep {
            registry: Some("other".into()),
            ..reg("blacksilk-zk", "rand")
        });
        assert_eq!(check(&tp(), &members(), &d, &good_lock()).len(), 2);
    }

    #[test]
    fn lockfile_rules() {
        let bad = lock(&[
            ("p3-fri", "0.7.0", Some(CRATES_IO)),       // bypasses the patch
            ("p3-fri", "0.6.0", Some(CRATES_IO)),       // another version: fine
            ("rand", "0.8.5", Some("git+https://x#a")), // git
            ("serde-fork", "1.0.0", None),              // unknown path crate
            ("blacksilk-zk", "9.9.9", None),            // member name, wrong version
        ]);
        assert_eq!(check(&tp(), &members(), &good_deps(), &bad).len(), 4);
    }

    #[test]
    fn lockfile_parser_refuses_unknown_keys_and_types() {
        assert!(
            parse_lock("version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n").is_ok()
        );
        assert!(parse_lock("version = 4\n[[package]]\nname='a'\nversion=\"1.0.0\"\n").is_ok());
        assert!(
            parse_lock("[[package]]\nname = \"a\"\nversion = \"1\"\nreplace = \"x\"\n").is_err()
        );
        assert!(parse_lock("[metadata]\nx = 1\n").is_err());
        assert!(parse_lock("[[package]]\nname = 1\nversion = \"1\"\n").is_err());
        assert!(parse_lock("[[package]]\nversion = \"1\"\n").is_err());
        assert!(parse_lock("not toml [").is_err());
    }

    #[test]
    fn metadata_parser_reads_cargo_output_and_fails_closed() {
        let json = r#"{"packages":[{"name":"blacksilk-zk","version":"0.1.0","manifest_path":"/r/zk/Cargo.toml",
            "dependencies":[{"name":"blacksilk-fri","rename":"p3-fri","path":"/r/evil","source":null,"registry":null},
                            {"name":"serde","rename":null,"source":"registry+https://github.com/rust-lang/crates.io-index","registry":null}]}]}"#;
        let id = |p: &Path| Ok(p.to_path_buf());
        let (m, d) = parse_metadata(json, &id).unwrap();
        assert_eq!(m[0].dir, PathBuf::from("/r/zk"));
        assert_eq!(d[0].rename.as_deref(), Some("p3-fri"));
        assert_eq!(d[0].path, Some(PathBuf::from("/r/evil")));
        assert!(parse_metadata(r#"{"packages":[{"name":"a"}]}"#, &id).is_err());
        assert!(parse_metadata(r#"{"packages":[{"name":"a","version":"1","manifest_path":"/a/Cargo.toml","dependencies":[{"name":"b","path":5}]}]}"#, &id).is_err());
        assert!(parse_metadata("{", &id).is_err());
    }

    #[test]
    fn standalone_crates_may_not_have_dependencies() {
        let ok = "[package]
name = \"blacksilk-zkvm-sdk\"
version = \"0.1.0\"
[lib]
name = \"x\"
";
        assert!(parse_standalone(ok).is_ok());
        assert!(parse_standalone(&format!(
            "{ok}[dependencies]
evil = {{ path = \"../e\" }}
"
        ))
        .is_err());
        assert!(parse_standalone(&format!(
            "{ok}[target.x.dependencies]
evil = \"1\"
"
        ))
        .is_err());
        assert!(parse_standalone(&format!(
            "{ok}[patch.crates-io]
"
        ))
        .is_err());
    }

    #[test]
    fn third_party_manifest_is_parsed_as_toml_not_text() {
        assert_eq!(
            parse_third_party("[package]\nname='p3-fri'\nversion=\"0.7.0\"\n")
                .unwrap()
                .0,
            "p3-fri"
        );
        assert!(parse_third_party("[lib]\nname = \"x\"\n").is_err());
    }
}
