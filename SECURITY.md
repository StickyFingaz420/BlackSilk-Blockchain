# Security policy

BlackSilk is **experimental software**. Nothing in it has been independently audited,
and no external audit is planned at present (docs/reviews/review-status.md). The
testnet's coins have no value. The current status, open items and accepted
limitations are in docs/STATUS.md; AUDIT.md is the historical internal findings log,
and docs/reviews/ holds the review material.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Report it privately through
GitHub's private vulnerability reporting for this repository ("Security" tab, "Report
a vulnerability").

**If the Security tab offers no "Report a vulnerability" button,** private reporting is
not enabled yet (it is a repository setting; checked disabled on 2026-09-27, and its
activation is pending with the maintainer).
- In that case, open a public issue titled only "Security contact request", with **no
  details** of the vulnerability.
- The maintainer will answer with a private channel.
- Never put vulnerability details in a public issue, a pull request or a commit
  message.

Please include:
- the affected component and commit;
- how to reproduce it;
- what an attacker gains (a consensus split, inflation, theft, a privacy leak, a
  denial of service);
- whether you want to be credited.

## What happens next

The response process is docs/testnet-incident-response.md:
- acknowledgement within 2 working days;
- private handling until a fixed release is running;
- publication afterwards, with credit if you wish.

## Scope

Everything in this repository is in scope. These are especially valuable:
- the proof system and its configuration (`zk/`, `zkvm/`, `px-core/`, `px/`,
  `third_party/`);
- consensus rules (`consensus/`, `tx/`, `chain/`);
- anything that reveals private data (docs/reviews/privacy-review.md lists the known
  limitations; those are not new findings).

## Dependency policy

BlackSilk's core is pure Rust: no C, C++ or assembly is compiled or linked into the
node, miner, wallet or tools, and BlackSilk's own crates forbid `unsafe` code.
Dependencies do contain `unsafe` internally (docs/reviews/unsafe-inventory.md).
The rules, checked by the CI job `deny` on every push and weekly:
- crates come from crates.io only, with the checksums in the committed `Cargo.lock`
  files, and every CI build uses `--locked`; the one exception is the patched copies
  in `third_party/` (`[patch.crates-io]`), and CI checks that each is the published
  crate (sha256 pinned in `third_party/PRISTINE.sha256`) plus exactly its
  allow-listed diff and file manifest in `third_party/patches/`, and that no lockfile,
  manifest or `.cargo/` configuration redirects a crate anywhere else (dependency
  identity from `cargo metadata`, checked by `tools/tpgate`), and that no file there
  holds control bytes outside `third_party/BINARY-ALLOWLIST`
  (`.github/scripts/third-party-gate.sh`, third_party/README.md). Its check for
  code that reaches outside the diff (`include*!`, `path`, `..`, build scripts) is a
  lint, not a guarantee. The allow-list
  certifies itself: a commit that changes a patched crate can regenerate its patch
  in the same commit. The gate only makes that change exact and visible. The
  control is human review of every `third_party/` diff. Required review of
  `third_party/`, `.cargo/`, the gate scripts, `tools/tpgate` and the CI workflow
  (CODEOWNERS plus branch protection)
  is a repository setting for the owner, and is not configured by this
  repository. In CI the gate code comes from a trusted revision (the pull
  request's base or the push's previous head), so a commit that changes a gate is
  judged by the old one. The workflow file itself still comes from the commit under
  test. What the identity check (`tools/tpgate`) cannot see:
  - cargo makes any path crate under a workspace root a member automatically. A
    verbatim copy of a published crate committed there under another name is
    accepted, as visible first-party code. Only review notices that it is a copy.
  - the standalone `zkvm/sdk` is read as TOML, not through cargo. It may have no
    dependencies, no build script and no `[lib]` path, but `#[path]` attributes and
    `include!` in its own source are not checked. Like every first-party file, they
    are seen only in review.
  - cargo configuration outside the repository (`CARGO_HOME`, parent directories),
    environment variables and `--config` flags;
- no known vulnerable, unsound, unmaintained (except the reviewed exceptions listed
  in `deny.toml`) or yanked crate (`deny.toml`, `fuzz/deny.toml`);
- no C toolchain or C-library binding crate, no build script that compiles native
  code, and only reviewed build scripts, by exact version (`deny.toml`,
  `.github/scripts/sys-crates.sh`);
- hazardous-material APIs (deterministic ML-KEM encapsulation, single-round AES)
  only in the crates reviewed for them (`.github/scripts/hazmat-policy.sh`);
- a second version of a crate, a new licence or a new source fails until reviewed;
- a commit that changes any tracked lockfile names every crate it adds, re-versions, moves
  to another source (such as a registry crate replaced by a path or git copy at the
  same version) or locks with another checksum (`.github/scripts/lockfile-gate.sh`).

A new dependency needs a recorded decision before it is added; the verdicts, the
reasons, and what was and was not reviewed are in docs/reviews/dependency-review.md.
No dependency is described as audited unless a specific third-party review of the
locked version is cited there. A weakness in a dependency that affects BlackSilk is
in scope for the reporting process above.
