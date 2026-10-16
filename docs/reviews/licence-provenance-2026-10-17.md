# Licence provenance review, 2026-10-17

**What this is.** An internal engineering review of where the code in this tree comes
from, made to decide which parts can be licensed `MIT OR Apache-2.0` (owner approval,
subject to this review). It is **not a legal review** and gives no legal advice. It reads
the git history, the comments, the docs and the dependency graph; it does not compare
the code textually against every possible upstream source.

**Tree reviewed:** `rebuild/core` at `db12c0c` (worktree branch `chore/license-dual`),
1,968 tracked files.

## 1. Authorship

`git log` over the whole history (1,221 commits, 2025-05-19 to 2026-10-16):

| Identity | Commits | Notes |
|---|---|---|
| Owner account `StickyFingaz420`, local identity | 1,137 | authored and committed |
| Owner account `StickyFingaz420`, GitHub noreply identity (display name `StickyFingaz`) | 84 | 77 committed locally, 7 committed by GitHub (web UI or PR merge) |

- Both identities belong to the one GitHub account `StickyFingaz420` (the noreply
  address names that login). No other author or committer appears.
- **AI-assisted commits:** 801 commits carry `Co-Authored-By: Claude Opus 5.5 (1M context)`.
  No other `Co-Authored-By` or `Signed-off-by` trailer exists.
- **Pull requests:** the merged PRs (#1, #2, #4, #5, #6, #7, #10) come from branches of
  `StickyFingaz420` or this repository's own branches. **No third-party contributor.**
- Email addresses are deliberately not recorded here.

## 2. Licence statements and notices in the tree

Searched (tracked files, `target/` is untracked): `LICENSE`, `COPYING`, `NOTICE`,
`AUTHORS`, `SPDX`, `Copyright`, `licen[cs]e`, `GPL`, `AGPL`, `LGPL`, `BSD`, `MIT`, `Apache`.

| Path | Finding |
|---|---|
| `randomx/LICENSE` | The only licence file before this branch. States the crate is "a Rust port of the RandomX reference implementation (https://github.com/tevador/RandomX)", with the BSD-3-Clause text and both upstream notices: "Copyright (c) 2018-2019, tevador" and "Copyright (c) 2014-2019, The Monero Project". `randomx/Cargo.toml`: `license = "BSD-3-Clause"`. |
| `randomx/src/*.rs` headers | Credit upstream: `randomx/src/lib.rs:3-4` "This is a port of the reference implementation by tevador (<https://github.com/tevador/RandomX>, BSD-3-Clause)"; `randomx/src/superscalar.rs:5-6` "a faithful port of the reference `superscalar.cpp` (tevador/RandomX, BSD-3-Clause)". Other files name the reference files they follow (`config.rs:1` "reference `configuration.h`, `common.hpp`"; `vm.rs:2` "reference `bytecode_machine`, `vm_interpreted`"). BSD-3-Clause needs no per-file header; the crate-level notice is preserved. |
| `third_party/p3-{batch-stark,dft,fri,merkle-tree}` | `license = "MIT OR Apache-2.0"`, `repository = "https://github.com/Plonky3/Plonky3"` in each `Cargo.toml`. **No licence text files**: the published 0.7.0 `.crate` files (checked in the local cargo registry) contain none either, so the copies match upstream (the third-party gate pins them byte for byte). Upstream's notice is "Copyright (c) 2022 The Plonky3 Authors" (Plonky3 repository `LICENSE-MIT`). Already raised in 2026-09 as R14 D-10. |
| `legacy/` | Not in the tree (removed 2026-10-04; root `Cargo.toml` comment). It stays in git history, which this review does not cover. |
| `contracts/`, `contracts/fuzz/` | Separate workspaces, own `Cargo.lock`; no licence field, no third-party notice. |
| `fuzz/`, `tools/tpgate/`, `zkvm/guests/`, `zkvm/sdk/` | No licence field, no third-party notice. |
| `crypto/src/wordlist.rs` | The BIP-39 English list (see §3). |
| `blacksilklogos/` (14 PNG) | No provenance record. One file carried a C2PA content-credentials manifest, stripped on 2026-10-05 (commit `6cf70f8`); C2PA manifests are typically written by image-generation or editing tools, so these images are likely tool-generated. Their terms are unknown to this review. |
| GPL / AGPL / LGPL | No GPL-family code in the tree. The only hits are prose: the xmrig gate (xmrig is GPL-3.0; built off-tree, never committed) and `docs/reviews/phase2-2026-09-27/research/05-randomx-conformance.md:581`, a rejected LGPL-2.1 crate. `docs/evidence/xmrig-gate-2026-10-09/` holds xmrig's logs, configs and checksums, not its source. |

Embedded data and binaries:

| Path | Origin |
|---|---|
| `randomx/tests/data/randomx-reference-light-v1.txt` | Hashes printed by tevador/RandomX v1.2.3 with only the salt changed (header lines 5-6); program output, inside the BSD-3-Clause crate. |
| `docs/evidence/randomx-reference-2026-10-04/README.md` | Includes `kat.cpp`, a ~90-line driver written for this project against RandomX's public API (C++ in an evidence record, not built here). |
| `px/kernel.elf`, `px/vault.elf`, `zkvm/tests/fixtures/guest-*.elf` | Built from `zkvm/guests/` (deps: `blacksilk-px-core`, `blacksilk-zkvm-sdk` only, per `zkvm/guests/Cargo.lock`) plus the Rust toolchain's `core` (MIT OR Apache-2.0). |
| `node/src/px_fixture.bin`, `node/tests/fixtures/px_fixture_2fn.bin` | Generated by this project's tests. |
| `third_party/p3-batch-stark/tests/fixtures/*.postcard` | Upstream Plonky3 files (`third_party/BINARY-ALLOWLIST`). |
| `tools/vectors/*.py` | Project test tooling. `poseidon2_hk.py:13-15` transcribes the Poseidon2 round constants from Plonky3 0.7.0 (`p3-baby-bear`, MIT OR Apache-2.0), which states they come from the Poseidon2 authors' generator script; the permutation is written from the paper. |

## 3. Code derived from external sources

Searched comments and docs for "port of", "ported", "based on", "adapted from", "derived
from", "translated", "reference implementation", "copied", "verbatim", "Monero",
"monero-rs", "monero-oxide", "dalek", "curve25519", "bulletproofs", "CLSAG", "tevador",
"xmrig", "Plonky3", "RustCrypto", "Zcash", "Bitcoin Core", and C/C++ file names.

Classes: (a) original, eligible; (b) derived from a permissive source, eligible only with
its notice kept; (c) uncertain, a blocker for that file; (d) third-party, upstream licence
kept.

| Path | Evidence | Class |
|---|---|---|
| `randomx/` | §2: a port (translation) of tevador/RandomX C++. | **(b)**, stays `BSD-3-Clause` |
| `third_party/p3-*` | Published Plonky3 crates with allow-listed patches. | **(d)** |
| `crypto/src/wordlist.rs` | `:1-5` "The BIP-39 English word list ... Only the list is taken from BIP-39 ... vendored as data". BIP-39's header says `License: MIT` (bitcoin/bips, checked 2026-10-17). | **(b)**, data; credited in README Licence |
| `crypto/src/clsag.rs` | `:3-4` Goodell, Noether, Blue, "Concise Linkable Ring Signatures ...", IACR ePrint 2019/654; Monero named only for behaviour (`:278`). | (a): from the paper |
| `crypto/src/bulletproofs_plus.rs` | `:3-5` Chung, Han, Ju, Kim, Seo, ePrint 2020/735, §4. | (a): from the paper |
| `crypto/src/membership.rs` | `:4-5` Tsang & Wei (2004), Liu & Wong (2005), bLSAG form. | (a): from the literature |
| `crypto/src/janus.rs`, `stealth.rs`, `keys.rs` | CryptoNote/Monero named as the model (`janus.rs:5`, `:155`); own spec (docs/transactions.md). | (a) |
| `p2p/src/addrman.rs`, `p2p/src/addr.rs` | `addrman.rs:1-2` "after Bitcoin Core's `addrman` with test-before-evict"; `addr.rs:225` "as Bitcoin Core's `GetGroup` without asmap". Design and parameters, own hashing and code. Bitcoin Core is MIT in any case. | (a) |
| `chain/src/sync_policy.rs` | `:417-418` "Monero's `rx_seedheight` / `rx_seedheights`, transcribed independently ... (src/crypto/rx-slow-hash.c)": a ~10-line test oracle of an arithmetic formula. | (a), low residual risk; Monero is BSD-3-Clause |
| `chain/src/mempool.rs`, `p2p/src/dandelion.rs`, `p2p/src/connman.rs`, `consensus/src/params.rs` | Parameter values cited from Monero, Zcash, Bitcoin Core (e.g. `dandelion.rs:45` "Monero's pair: q = 0.2 with a 39 s mean embargo (PR #7025)"). Values, not code. | (a) |
| `zk/src/config.rs` | `:211` "Mirrors Plonky3 0.7.0's `DuplexChallenger::grind`" and then scans in order on one thread: a reimplementation of upstream behaviour. Even if read as derived, Plonky3 is MIT OR Apache-2.0. | (a), low residual risk |
| `deny.toml` (bans) | monero-oxide rejected, "port the needed map instead" (decisions, Agent 44). No such port is in the tree (`git log -S monero-oxide` finds only comments). | n/a |
| `randomx/src/fpu_oracle.rs` | Uses `rustc_apfloat` (a dev-dependency), no copied code. | (a) |
| all other crates | No derivation markers found. | (a) |

**No (c) blocker was found in the code.** `blacksilklogos/` is uncertain (§2) and is left
out of the licence; it is not code.

## 4. Dependencies

`cargo deny --offline check licenses` on the root workspace: **licenses ok**
(cargo-deny 0.20.2). Inbound licences of the root graph (`cargo deny list`): Apache-2.0,
MIT, `Apache-2.0 WITH LLVM-exception` (rustix, linux-raw-sys, rustc_apfloat dev-only),
BSD-2-Clause (zerocopy, dual), BSD-3-Clause (curve25519-dalek 4.1.3, subtle, matchit, and
blacksilk-randomx), BSL-1.0 (ryu, dual), MPL-2.0 (option-ext, via dirs-sys), Unicode-3.0
(icu_*, unicode-ident), Unlicense (memchr, dual), Zlib (foldhash).

Other workspaces: `fuzz/` and `contracts/fuzz/` add NCSA (libfuzzer-sys, which bundles
C++ libFuzzer; fuzzing only, never shipped); `contracts/` and `tools/tpgate/` add nothing
new; `zkvm/guests/` has no external crates.

- **Nothing incompatible** with distributing the workspace binaries under `MIT OR
  Apache-2.0`: no GPL, AGPL, SSPL or unknown licence. MPL-2.0 is file-level copyleft: it
  binds only option-ext's own files, which stay MPL-2.0 and are available from crates.io.
- **Notice obligations for binary releases:** BSD-3-Clause (randomx, curve25519-dalek,
  subtle), MIT, Apache-2.0 and Unicode-3.0 require their notices with redistributed
  binaries. `tools/release-build.sh` and `deploy/docker/Dockerfile` ship none today. Not a
  blocker for licensing the source; a release task.
- The patched xmrig used for the compatibility gate (GPL-3.0) is not in the repository.

## 5. Conclusion

**Eligible for `MIT OR Apache-2.0` now (class a):** every crate except `randomx`:
`consensus`, `crypto`, `tx`, `chain`, `p2p`, `rpc`, `node`, `miner`, `wallet`, `zk`,
`zkvm`, `px-core`, `px`, `tools/{labnet,supply-audit,genesis,daa-sim,stratum-bridge}`,
`tools/tpgate`, `fuzz`, `contracts`, `contracts/fuzz`, `zkvm/sdk`,
`zkvm/guests/{sum,arith,kernel,vault}`, and the scripts, configs and docs of the tree.

**Eligible with a notice kept:**
- `crypto/src/wordlist.rs`: the word list is BIP-39's (MIT); credited in the README
  Licence section.
- `tools/vectors/poseidon2_hk.py`: Plonky3's Poseidon2 constants (MIT OR Apache-2.0), credited
  in the file.

**Keeps its own licence:** `randomx/` (`BSD-3-Clause`, notices of tevador and The Monero
Project in `randomx/LICENSE`); `third_party/p3-*` (`MIT OR Apache-2.0`, The Plonky3
Authors).

**Not licensed by this change:** `blacksilklogos/` (provenance and terms unknown); git
history before this change, including the removed `legacy/` tree.

**Open points for the owner:**
1. Copyright holder line: the branch uses "The BlackSilk developers" (a common neutral
   form). The owner may prefer a personal or entity name.
2. AI-assisted authorship: 801 of 1,221 commits are co-authored with an AI assistant.
   Some jurisdictions grant copyright only to human authorship, so protection of purely
   AI-generated portions may be limited. A permissive licence still grants what rights
   exist; this does not block the choice but is worth knowing.
3. `third_party/p3-*` have no licence text; adding Plonky3's texts would need a file
   outside the gated crate directories (the third-party gate rejects added files inside).
4. A third-party notices file for binary releases (§4).
5. The logos' terms (licence, trademark or reserved).
6. The README's inbound-contribution clause (contributions dual-licensed unless stated
   otherwise) is the common Rust convention, added on the branch; keep or drop.
