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
  files, and every CI build uses `--locked`;
- no known vulnerable, unsound, unmaintained (except the reviewed exceptions listed
  in `deny.toml`) or yanked crate (`deny.toml`, `fuzz/deny.toml`);
- no C toolchain or C-library binding crate, no build script that compiles native
  code, and only reviewed build scripts, by exact version (`deny.toml`,
  `.github/scripts/sys-crates.sh`);
- hazardous-material APIs (deterministic ML-KEM encapsulation, single-round AES)
  only in the crates reviewed for them (`.github/scripts/hazmat-policy.sh`);
- a second version of a crate, a new licence or a new source fails until reviewed;
- a commit that changes a lockfile names every crate it adds or re-versions
  (`.github/scripts/lockfile-gate.sh`).

A new dependency needs a recorded decision before it is added; the verdicts, the
reasons, and what was and was not reviewed are in docs/reviews/dependency-review.md.
No dependency is described as audited unless a specific third-party review of the
locked version is cited there. A weakness in a dependency that affects BlackSilk is
in scope for the reporting process above.
