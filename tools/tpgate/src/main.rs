//! `blacksilk-tpgate`: the dependency-identity part of the third-party patch gate
//! (`.github/scripts/third-party-gate.sh`, RT-TPGATE2, RT-TPGATE3).
//!
//! ```text
//! blacksilk-tpgate <repo root> <workspace root>... [--standalone <crate dir>...] [--config <file>...]
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
//! 6. (RT-TPGATE3) `[patch]` only in a workspace root manifest, only as
//!    `[patch.crates-io]`, each entry exactly `{ path = ... }` resolving to
//!    `third_party/<entry name>`; `[replace]` nowhere (every root and member
//!    manifest, parsed as TOML);
//! 7. (RT-TPGATE3) every `--config` file (`.cargo/config[.toml]`) holds only
//!    `build.target` and `target.<triple>.rustflags`: no runner, linker,
//!    rustc, wrappers, target-dir, env, alias, patch, paths, source or
//!    registries. Their exact bytes are pinned by the gate script.
//!
//! Standalone path crates outside every workspace (`--standalone`, e.g.
//! `zkvm/sdk`) count as members; each must have no dependency tables at all.
//!
//! `cargo metadata` runs with its working directory outside the repository
//! (the system temporary directory), so no repository `.cargo/config` or
//! `rust-toolchain` file is read. Configuration under `CARGO_HOME` still is;
//! on CI that is the runner's clean one.
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
    // No source or build code from elsewhere: [lib] may only name the crate,
    // and the package may not declare a build script or native links.
    if let Some(lib) = t.get("lib").and_then(|l| l.as_table()) {
        if let Some(k) = lib.keys().find(|k| k.as_str() != "name") {
            return Err(format!(
                "standalone crate: lib.{k} is not allowed (only lib.name)"
            ));
        }
    }
    if let Some(pkg) = t.get("package").and_then(|p| p.as_table()) {
        for k in ["build", "links", "workspace"] {
            if pkg.contains_key(k) {
                return Err(format!("standalone crate: package.{k} is not allowed"));
            }
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

/// Rule 6: the `[patch]` and `[replace]` tables of a manifest. In a
/// workspace root manifest (`is_root`) the only allowed form is
/// `[patch.crates-io]` with entries `<name> = { path = "<...>" }` whose path
/// (resolved by `resolve` from the manifest's directory) is
/// `third_party/<name>`; any other manifest may have neither table.
fn check_manifest_patch(
    what: &str,
    text: &str,
    is_root: bool,
    tp: &[ThirdParty],
    resolve: &dyn Fn(&str) -> Result<PathBuf, String>,
) -> Vec<String> {
    let t: toml::Table = match text.parse() {
        Ok(t) => t,
        Err(e) => {
            let e: toml::de::Error = e;
            return vec![format!("{what}: not TOML: {e}")];
        }
    };
    let mut errs = Vec::new();
    if t.contains_key("replace") {
        errs.push(format!("{what}: [replace] is not allowed"));
    }
    let Some(patch) = t.get("patch") else {
        return errs;
    };
    if !is_root {
        errs.push(format!("{what}: [patch] outside a workspace root manifest"));
        return errs;
    }
    let Some(patch) = patch.as_table() else {
        errs.push(format!("{what}: `patch` is not a table"));
        return errs;
    };
    for (registry, entries) in patch {
        if registry != "crates-io" {
            errs.push(format!(
                "{what}: [patch.{registry}]: only [patch.crates-io] is allowed"
            ));
            continue;
        }
        let Some(entries) = entries.as_table() else {
            errs.push(format!("{what}: [patch.crates-io] is not a table"));
            continue;
        };
        for (name, entry) in entries {
            let at = format!("{what}: [patch.crates-io] {name}");
            let path = entry
                .as_table()
                .filter(|e| e.len() == 1)
                .and_then(|e| e.get("path"))
                .and_then(|p| p.as_str());
            let Some(path) = path else {
                errs.push(format!(
                    "{at}: must be exactly {{ path = \"<to root>third_party/{name}\" }}"
                ));
                continue;
            };
            let ok = match resolve(path) {
                Ok(dir) => tp.iter().any(|t| &t.name == name && t.dir == dir),
                Err(_) => false,
            };
            if !ok {
                errs.push(format!("{at}: path {path} is not third_party/{name}"));
            }
        }
    }
    errs
}

/// Rule 7: a `.cargo/config[.toml]` may hold only `build.target` and
/// `target.<triple>.rustflags`, nothing else (no patch, paths, source,
/// registries, env, alias, runner, linker, rustc or wrapper, target-dir, ...).
/// The exact contents are pinned separately (.github/cargo-config.sha256).
fn check_config(what: &str, text: &str) -> Vec<String> {
    let t: toml::Table = match text.parse() {
        Ok(t) => t,
        Err(e) => {
            let e: toml::de::Error = e;
            return vec![format!("{what}: not TOML: {e}")];
        }
    };
    let mut errs = Vec::new();
    for (k, v) in &t {
        match (k.as_str(), v.as_table()) {
            ("build", Some(b)) => {
                for bk in b.keys() {
                    if bk != "target" {
                        errs.push(format!(
                            "{what}: build.{bk} is not allowed (only build.target)"
                        ));
                    }
                }
            }
            ("target", Some(targets)) => {
                for (triple, tv) in targets {
                    match tv.as_table() {
                        Some(tt) => {
                            for tk in tt.keys() {
                                if tk != "rustflags" {
                                    errs.push(format!(
                                        "{what}: target.{triple}.{tk} is not allowed (only rustflags)"
                                    ));
                                }
                            }
                        }
                        None => errs.push(format!("{what}: target.{triple} is not a table")),
                    }
                }
            }
            _ => errs.push(format!(
                "{what}: `{k}` is not allowed (only build.target and target.<triple>.rustflags)"
            )),
        }
    }
    errs
}

/// The arguments: `<repo> <root>... [--standalone <dir>...] [--config <file>...]`.
struct Args {
    repo: PathBuf,
    roots: Vec<PathBuf>,
    standalone: Vec<PathBuf>,
    configs: Vec<PathBuf>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let (repo, rest) = args.split_first().ok_or("no repository root")?;
    let repo = PathBuf::from(repo);
    let (mut roots, mut standalone, mut configs) = (Vec::new(), Vec::new(), Vec::new());
    let mut mode = 0;
    for a in rest {
        match a.as_str() {
            "--standalone" => mode = 1,
            "--config" => mode = 2,
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            s => match mode {
                0 => roots.push(repo.join(s)),
                1 => standalone.push(repo.join(s)),
                _ => configs.push(repo.join(s)),
            },
        }
    }
    if roots.is_empty() {
        return Err("no workspace root".into());
    }
    Ok(Args {
        repo,
        roots,
        standalone,
        configs,
    })
}

fn read(p: &Path) -> Result<String, String> {
    std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))
}

fn run(a: &Args) -> Result<Vec<String>, String> {
    let mut tp = Vec::new();
    let third = a.repo.join("third_party");
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
        let (name, version) = parse_third_party(&read(&manifest)?)
            .map_err(|e| format!("{}: {e}", manifest.display()))?;
        tp.push(ThirdParty {
            name,
            version,
            dir: canonical(&dir)?,
        });
    }
    // cargo runs outside the repository, so no repository .cargo/config or
    // rust-toolchain file is read (RT-TPGATE3); --manifest-path names the
    // workspace.
    let cwd = std::env::temp_dir();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let (mut members, mut deps, mut locks, mut errs) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut root_manifests = BTreeSet::new();
    for root in &a.roots {
        let manifest = root.join("Cargo.toml");
        root_manifests.insert(canonical(&manifest)?);
        let out = Command::new(&cargo)
            .current_dir(&cwd)
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
        locks.push((lock.display().to_string(), parse_lock(&read(&lock)?)?));
    }
    for dir in &a.standalone {
        let manifest = dir.join("Cargo.toml");
        let (name, version) = parse_standalone(&read(&manifest)?)
            .map_err(|e| format!("{}: {e}", manifest.display()))?;
        members.push(Member {
            name,
            version,
            dir: canonical(dir)?,
        });
    }
    // [patch] and [replace] in every root and member manifest.
    let mut manifests: BTreeSet<PathBuf> = root_manifests.clone();
    for m in &members {
        manifests.insert(canonical(&m.dir.join("Cargo.toml"))?);
    }
    for manifest in &manifests {
        let dir = manifest.parent().unwrap_or(Path::new("/")).to_path_buf();
        let resolve = |p: &str| canonical(&dir.join(p));
        errs.extend(check_manifest_patch(
            &manifest.display().to_string(),
            &read(manifest)?,
            root_manifests.contains(manifest),
            &tp,
            &resolve,
        ));
    }
    for config in &a.configs {
        errs.extend(check_config(&config.display().to_string(), &read(config)?));
    }
    errs.extend(check(&tp, &members, &deps, &locks));
    Ok(errs)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a = match parse_args(&args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("blacksilk-tpgate: {e}");
            eprintln!("usage: blacksilk-tpgate <repo root> <workspace root>... [--standalone <crate dir>...] [--config <file>...]");
            return ExitCode::from(2);
        }
    };
    match run(&a) {
        Ok(errs) if errs.is_empty() => {
            println!(
                "blacksilk-tpgate: {} workspaces, {} cargo configs: every crate is a member, third_party/ or crates.io",
                a.roots.len(),
                a.configs.len()
            );
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
        let lib_path = ok.replace("[lib]\n", "[lib]\npath = \"../../evil.rs\"\n");
        assert!(parse_standalone(&lib_path).is_err());
        let build = ok.replace(
            "version = \"0.1.0\"\n",
            "version = \"0.1.0\"\nbuild = \"b.rs\"\n",
        );
        assert!(parse_standalone(&build).is_err());
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

    fn resolver(p: &str) -> Result<PathBuf, String> {
        match p {
            "third_party/p3-fri" | "../third_party/p3-fri" => Ok("/r/third_party/p3-fri".into()),
            "vendor/p3-fri" => Ok("/r/vendor/p3-fri".into()),
            _ => Err("missing".into()),
        }
    }

    #[test]
    fn root_patch_tables_must_be_canonical() {
        let ok = "[workspace]\n[patch.crates-io]\np3-fri = { path = \"third_party/p3-fri\" }\n";
        assert!(check_manifest_patch("m", ok, true, &tp(), &resolver).is_empty());
        // Spacing and quoting do not matter to a TOML parser.
        let spaced = "[workspace]\n[ patch . \"crates-io\" ]\n\"p3-fri\" = { path = \"third_party/p3-fri\" }\n";
        assert!(check_manifest_patch("m", spaced, true, &tp(), &resolver).is_empty());
        for bad in [
            "[patch.crates-io]\np3-fri = { path = \"vendor/p3-fri\" }\n",
            "[patch.crates-io]\np3-fri = { git = \"https://x\" }\n",
            "[patch.crates-io]\np3-fri = { path = \"third_party/p3-fri\", package = \"x\" }\n",
            "[patch.crates-io]\np3-dft = { path = \"third_party/p3-fri\" }\n",
            "[patch.\"https://github.com/x/y\"]\np3-fri = { path = \"third_party/p3-fri\" }\n",
            "patch.crates-io.p3-fri.path = \"vendor/p3-fri\"\n",
            "\"\\u0070atch\".crates-io.p3-fri.path = \"vendor/p3-fri\"\n",
            "[replace]\n\"p3-fri:0.7.0\" = { path = \"vendor/p3-fri\" }\n",
            "[patch\n",
        ] {
            assert!(
                !check_manifest_patch("m", bad, true, &tp(), &resolver).is_empty(),
                "{bad}"
            );
        }
        assert!(!check_manifest_patch("m", ok, false, &tp(), &resolver).is_empty());
    }

    #[test]
    fn cargo_configs_hold_only_target_and_rustflags() {
        let ok = "[build]\ntarget = \"riscv32i-unknown-none-elf\"\n[target.x]\nrustflags = [\"-C\", \"a\"]\n";
        assert!(check_config("c", ok).is_empty());
        for bad in [
            "[build]\nrustc-wrapper = \"evil\"\n",
            "[build]\nrustc = \"evil\"\n",
            "[build]\ntarget-dir = \"x\"\n",
            "[target.x]\nrunner = \"evil\"\n",
            "[target.x]\nlinker = \"evil\"\n",
            "[env]\nX = \"1\"\n",
            "[alias]\nb = \"run\"\n",
            "paths = [\"x\"]\n",
            "[source.crates-io]\nreplace-with = \"v\"\n",
            "[patch.crates-io]\np3-fri = { path = \"third_party/p3-fri\" }\n",
            "[registries.x]\nindex = \"y\"\n",
            "build.rustc-workspace-wrapper = \"evil\"\n",
            "not toml [",
        ] {
            assert!(!check_config("c", bad).is_empty(), "{bad}");
        }
    }

    #[test]
    fn arguments() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let a = parse_args(&s(&["/r", ".", "--standalone", "s", "--config", "c"])).unwrap();
        assert_eq!(
            (a.roots.len(), a.standalone.len(), a.configs.len()),
            (1, 1, 1)
        );
        assert!(parse_args(&s(&["/r"])).is_err());
        assert!(parse_args(&s(&["/r", ".", "--x"])).is_err());
    }
}
