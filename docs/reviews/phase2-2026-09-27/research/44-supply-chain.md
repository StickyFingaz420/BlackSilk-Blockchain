# 44 supply-chain: dossier (phase 2, research and briefing)

Agent 44. Date 2026-09-27. Repository `rebuild/core` at **`9e422d8`** (`git rev-parse --short HEAD`),
working tree clean. Internal engineering work, not an audit.

Evidence classes: **[math]** mathematically established · **[tested: name]** · **[source-read]** ·
**[tool-run]** (read-only command output: `cargo tree --locked --offline`, lockfile parsing, advisory-db
matching, crates.io sparse index) · **[web]** primary web source · **[assumed]** · **[unknown]**.

---

## 1. Scope and what I read

**Brief, roster, decisions:** `C:/bszkeval/p2/brief.md`, `roster.md` (entries 40–50, especially 43 and
29/30 as neighbours), `decisions.md` (all entries).

**Dependency requests collected from the dossiers** (`C:/bszkeval/p2/research/*.md`, 24 dossiers present):

| Request | From | Where requested |
|---|---|---|
| `proptest` (dev) | 12, 02, 17, 20, 01, 41 (R13 T-4) | 12 §W6, 02 Q3, 17 Q3, 20 Q3; decisions "Agent 12/17/20/02" |
| `rustc_apfloat` (dev, randomx) | 05 | 05 C3 (`randomx/Cargo.toml [dev-dependencies] rustc_apfloat = "=0.2.3+llvm-462a31f5a5ab"`) |
| RustCrypto `sha3` (dev, out of workspace); possibly monero-oxide | 15 W10, 05 C6 | 15 §C2 tier 3 and §6; 05 "44 supply-chain" |
| `curve25519-dalek 5.0.0` + `lizard` in p2p only; `ml-kem =0.3.2` in p2p | 30 | 30 §W6, §6, Q2 |
| `aes` 0.9 upgrade | 06 W10, 08 W7 | 06 F7/W10, 08 W7 (owner 44) |
| `getrandom` 0.2 → 0.3 consolidation | 18 W11 | 18 W11 ("44 owns") |
| `aes`/`aes-gcm` `zeroize` features, aes-gcm version | 30 | 30 §P-7, decisions "Agent 30" |
| blake2 zeroize question | 18 | 18 F18-8, §6 |
| `cross` tool pin | 08 | 08 §6 (CI tooling; owner 43, noted only) |
| `tools/daa-sim` workspace member, no new dependency | 03 | 03 W1 |
| C++ RandomX refgen as off-tree oracle | 05 | decisions "Agent 05" |
| Python vector scripts as non-core test tooling | 01, 19 | decisions "Agent 01", "R2-C6" |

**Required reading:** `docs/reviews/full-review-2026-09-27.md` (§3.13, register rows R13 T-11,
R16-3, R2-C12/A14, "wasmi unsafe", R10-14, P0-17, P2-20/21); `docs/reviews/autonomous-session-2026-09-27.md`
("Build, CI and supply chain"); `docs/reviews/full-review-2026-09-27/R13-testing-supplychain.md` (all);
`docs/reviews/dependency-review.md` (all); `third_party/README.md`; `.github/workflows/ci.yml`.

**Manifests and locks:** root `Cargo.toml` and every workspace member's `Cargo.toml` (randomx,
consensus, crypto, tx, chain, p2p, rpc, node, miner, wallet, contracts, zk, zkvm, zkvm/sdk, px-core, px,
tools/labnet, tools/supply-audit, tools/genesis), `fuzz/Cargo.toml`, `zkvm/guests/**/Cargo.toml`,
`Cargo.lock` (325 packages), `fuzz/Cargo.lock` (177), `zkvm/guests/Cargo.lock` (6, all local).

**Dependency source read (local registry, plus crates downloaded to my scratchpad, not the repo):**
build scripts of every build-script crate in `Cargo.lock`; `aes-0.8.4`, `aes-gcm-0.10.3`, `ghash-0.5.1`,
`polyval-0.6.2`, `ml-kem-0.3.2` (`pke.rs`, README), `keccak-0.2.2`, `sha3-0.11.0`, `wit-bindgen-rt-0.39.0`,
`curve25519-dalek-5.0.0` (`src/lizard/*`, `src/ristretto.rs`, `src/ristretto/elligator.rs`, CHANGELOG, build.rs),
`proptest-1.11.0` (manifest, `unsafe` sites), `rustc_apfloat-0.2.3+llvm-462a31f5a5ab` (manifest, build.rs,
LICENSE-DETAILS), `aes-0.9.3` (lib.rs, hazmat.rs, CHANGELOG), `aes-gcm-0.11.1` (manifest),
`getrandom-0.3.4` and `0.4.3` (windows backend, CHANGELOG), `cipher-0.5.1`, `sha3-0.12.0`.
`unsafe` counts for 55 key crates (§2.4).

**Read-only commands run** (nothing compiled; `git status` clean before and after):
`cargo tree --locked --offline -e normal,build -p blacksilk-node -p blacksilk-miner -p blacksilk-wallet
--target {x86_64-unknown-linux-gnu, x86_64-pc-windows-msvc, aarch64-unknown-linux-gnu}`;
`cargo tree ... -i curve25519-dalek`, `-e features -i aes`.

**Advisory data:** RustSec advisory-db `main` at `e2111519` (2026-09-25T17:51Z), full tree fetched and
intersected with every crate name in all three lockfiles; each matching advisory's `[versions]` read.
GitHub advisories for wasmi, Plonky3, dalek, RustCrypto KEMs/AEADs/hashes/password-hashes.
crates.io sparse index: yanked status of all 333 distinct locked (name, version) pairs.
cargo-vet public audit sets (google, mozilla, zcash, isrg, bytecode-alliance) fetched and searched.

---

## 2. Current state

### 2.1 What exists and is correct

| Claim | Evidence |
|---|---|
| All 304 registry packages in `Cargo.lock` and 162 in `fuzz/Cargo.lock` come from crates.io; zero git or alternate-registry sources; every one has a checksum. `zkvm/guests/Cargo.lock` has only local crates. | [tool-run] |
| Consensus-byte crates are pinned exactly: `blake2 =0.10.6`, `aes =0.8.4`, `curve25519-dalek =4.1.3`, all `p3-* =0.7.0`, `postcard =1.1.3`, `serde =1.0.229`, `ml-kem =0.3.2`, `wasmi =0.38.0` (commit `249d4f0`). | [source-read] |
| CI builds with `--locked`; actions SHA-pinned; token read-only; `cargo audit` 0.22.2 runs on the main and fuzz lockfiles, weekly by cron too. | [source-read: `.github/workflows/ci.yml:3-24,163-180`] |
| Every BlackSilk crate that ships declares `#![forbid(unsafe_code)]` (22 lib/main roots). The only `unsafe` is the zkVM SDK `ecall` (`zkvm/sdk/src/lib.rs:29`), guest-only. | [source-read] |
| **No C/C++ in the product graph.** No `cc`, `cmake`, `bindgen`, `pkg-config` or `vcpkg` in `Cargo.lock`. The only `links` keys are `rayon-core` (marker) and `wasm-bindgen-shared` (wasm only). | [tool-run] |
| All 30 build scripts in `Cargo.lock` were read. None compiles native code. They probe `rustc --version` (paste, semver, serde, serde_core, zmij, thiserror, proc-macro2, rustversion, rustix, libc, getrandom 0.3, httparse, zerocopy), emit cfgs (curve25519-dalek backend choice, crossbeam, ahash, num-traits, libm, icu data), or add a link search path (windows_* import libraries, winapi). `wasm-bindgen-shared` runs `git` (wasm targets only). | [source-read] |
| **RustSec: zero applicable vulnerabilities** in the main and fuzz locks. 71 historical advisories match crate names; every locked version is in a patched or unaffected range. The one live informational is `paste` 1.0.15 unmaintained (RUSTSEC-2024-0436, already ignored with a reason). | [tool-run + web] |
| **No yanked versions** among all 333 locked (name, version) pairs (sparse index, 2026-09-27). | [tool-run] |
| **Plonky3:** no new GitHub advisory since the 2026-09-25 check (the five listed in dependency-review.md §5a are still the complete set). | [web] |
| No published advisories for curve25519-dalek, RustCrypto KEMs (`ml-kem`), hashes (`blake2`, `sha3`) or password-hashes (`argon2`). RustCrypto AEADs has GHSA-423w-p2w9-r7vq (aes-gcm < 0.10.3; locked is 0.10.3, and BlackSilk uses only the allocating `decrypt`). | [web; source-read] |
| **wasmi is not in any shipped binary.** `cargo tree` of node+miner+wallet (normal+build edges, three targets) contains no wasmi. Only `contracts` and `fuzz` depend on `blacksilk-contracts`. | [tool-run; source-read] |
| The production graph (node+miner+wallet, normal edges, Linux x86-64) has **206 external crates**; with build edges 239 (Linux), 245 (Windows MSVC), 238 (aarch64 Linux). | [tool-run] |
| `ml-kem 0.3.2` performs the FIPS 203 §7.2 encapsulation-key modulus check. | [source-read: `ml-kem-0.3.2/src/pke.rs:167-184`] |

### 2.2 What the tests actually prove

- **No test enforces any supply-chain property.** "Pure Rust, no C" is a manual claim
  (dependency-review.md §1), re-verified here by hand [source-read, tool-run], but nothing in CI would
  catch a new `cc` build-dependency, a new `*-sys` crate or a new build script.
- `cargo audit` in CI proves only "no *vulnerability* advisory at run time". By default it does not fail
  on `unsound`, `unmaintained` or `yanked` warnings [assumed from cargo-audit defaults; CI passes no
  `--deny`] (§4, SC-3).
- Consensus-byte crate behaviour is guarded by pinned vectors (Poseidon2 `zk/tests/pins.rs`, RandomX
  vectors, golden vectors from `f6c98c3`) [tested], which is what makes a dependency bump detectable.
  **Wallet-format dependencies (argon2, aes-gcm, bip39) have no pinned known-answer test** [source-read:
  `wallet/src/file.rs:200-270` tests are round-trip and tamper only] (SC-9).

### 2.3 Graph facts that matter for the requests

- `sha3 0.11.0` and `keccak 0.2.2` are **already in the production graph** (dependency of `ml-kem`)
  [tool-run]. The CLSAG harness request adds no new crate if it uses the same version.
- `getrandom 0.3.3` is reachable **only through `tempfile`**, a dev-dependency [tool-run]. The
  production binaries use only `getrandom 0.2.17`. dependency-review.md §2 "two major versions coexist"
  is true for the lockfile, not for the binaries.
- The RustCrypto crates are split across two generations: `ml-kem` pulls `digest 0.11`,
  `block-buffer 0.12`, `crypto-common 0.2`, `hybrid-array`, `cpufeatures 0.3`, `rand_core 0.10`, while
  blake2/aes/aes-gcm/chacha20poly1305 sit on 0.10/0.4/0.5. There are 24 duplicated crate names in
  `Cargo.lock`, mostly this split plus the Windows target crates [tool-run].
- `aes 0.8.4` is **one shared crate** for randomx (`hazmat`) and aes-gcm (p2p, wallet) [tool-run:
  `cargo tree -e features -i aes`]. Feature changes by p2p unify into the randomx build.
- `fuzz/Cargo.lock` differs from `Cargo.lock` for **30 shared crates** (for example zeroize 1.9.0 vs
  1.8.1, tokio 1.53.1 vs 1.50.0, libc 0.2.189 vs 0.2.174, getrandom 0.4.3). The fuzz campaigns therefore
  ran over a different transitive graph from the product [tool-run] (SC-5).

### 2.4 `unsafe` inside dependencies (occurrences of the keyword in `src/`) [tool-run]

| Crate | `unsafe` | Note |
|---|---|---|
| tokio 1.50.0 | 1044 | runtime; universally deployed |
| p3-monty-31 / p3-field / p3-util / p3-matrix 0.7.0 | 296 / 123 / 123 / 114 | SIMD field arithmetic, unchecked indexing |
| spin 0.12.3 | 131 | Plonky3 locks (the patched sites) |
| wasmi 0.38.0 | 120 | not shipped (above) |
| aes 0.8.4 | 110 | AES-NI/ARMv8 intrinsics behind runtime detection |
| hyper 1.11.1 | 67 | RPC server |
| getrandom 0.2.17 | 58 | OS boundary |
| poly1305 / chacha20 0.9 / polyval | 50 / 23 / 23 | SIMD backends |
| hybrid-array 0.4.15 | 43 | ml-kem generation |
| curve25519-dalek 4.1.3 | 37 | AVX2/IFMA backends |
| cmov 0.5.4 | 28 | constant-time selects (ml-kem) |
| blake2 0.10.6 | 26 | SIMD (not enabled) |
| ml-kem 0.3.2, module-lattice, kem, sha3 0.11, axum, aes-gcm, bip39, chacha20poly1305, p3-poseidon2, p3-uni-stark, p3-lookup | 0 | several `forbid(unsafe_code)` |

"Pure Rust" in this project means **no foreign code**, not "no `unsafe` in dependencies". That is the
accepted position (dependency-review.md §1) and is correct as stated.

### 2.5 Native artefacts in the lock (target-aware view) [tool-run, source-read]

| Crate | Artefact | Compiled for BlackSilk targets? | Assessment |
|---|---|---|---|
| `windows_{x86_64,i686,aarch64}_{msvc,gnu,gnullvm}` 0.48/0.52/0.53 | pre-built import libraries (`windows.0.5x.lib`, `libwindows.*.a`) | the MSVC ones on Windows | OS import stubs, no code. Accepted OS boundary |
| `winapi-{x86_64,i686}-pc-windows-gnu` 0.4.0 | `libwinapi_*.a` import libs | only `*-windows-gnu` targets | through `fs2` → `winapi` (SC-7) |
| `wit-bindgen-rt` 0.39.0 | `cabi_realloc.c`, `.o`, `.a` | **no**: `build.rs` returns unless `target_family = "wasm"` | reached via `tempfile` → `getrandom 0.3.3` → `wasi 0.14` (dev, wasm only). A target-unaware "no C" scan reports a false positive (SC-14) |
| `libc`, `linux-raw-sys`, `rustix`, `windows-sys`, `dirs-sys`, `getrandom` | OS bindings (`extern`, raw syscalls, `raw-dylib`) | yes | the unavoidable OS boundary; Rust `std` itself links the platform C runtime |

---

## 3. Problems in scope

### P1. "No C / pure Rust" is verified by hand only (R13 T-11; sharpened)

- **Problem.** The pure-Rust policy is enforced by reviewer diligence. dependency-review.md §1 was
  written once. About 50 agents are about to add dependencies in parallel (proptest, apfloat,
  dalek 5, ml-kem in p2p, the sha3 harness). A transitive `cc`, `ring`, `zstd-sys` or `openssl-sys` (for
  example from enabling `reqwest`'s TLS or compression features) would enter silently. `cargo audit` does
  not look at this.
- **Security consequence.** C code outside Rust's memory-safety guarantees in the node or wallet; a C
  toolchain in the build (larger attack surface for reproducibility and build-time compromise); a
  violated owner policy with no signal.
- **Class.** Security and architecture (policy); not consensus. It is privacy-relevant because the wallet
  and node handle keys.
- **Prior art.**
  - cargo-deny `[bans] deny` (with `wrappers`) blocks named crates; `[bans.build]` allow-lists build
    scripts, can pin a build script by SHA-256 (`bypass.build-script`), and flags executables and archives
    in compile-time crates (`executables = "deny"`, `include-archives`) [web: cargo-deny bans docs].
  - Zcash, Mozilla and Google record per-version audits with cargo-vet [web: cargo-vet registry].
  - Bitcoin Core keeps the dependency set minimal and reproducible (Guix) [web].
- **My method ("no C" verification), in four layers:**
  1. **Graph bans (cargo-deny).** Deny `cc`, `cmake`, `bindgen`, `pkg-config`, `vcpkg`, `openssl-sys`,
     `openssl`, `native-tls`, `ring`, `aws-lc-sys`, `aws-lc-rs`, `libz-sys`, `zstd-sys`, `bzip2-sys`,
     `lzma-sys`, `libsqlite3-sys`, `secp256k1-sys`, `blst`, `randomx-rs`, `libfuzzer-sys` in the main
     workspace (`fuzz/` gets its own config that allows `libfuzzer-sys`/`cc` with wrappers).
  2. **Build-script allow-list pinned by checksum.** `[bans.build] allow-build-scripts` = the 30 reviewed
     crates (§2.1). Each gets a `bypass` entry with the SHA-256 of its build script, so a changed build
     script in a new version fails CI until re-read.
  3. **Target-aware native-file scan.** A small Rust tool (no new dependency: `serde_json` is already in
     the lock) runs `cargo metadata --locked --offline --format-version 1 --filter-platform <triple>` for
     each release triple (x86_64/aarch64 Linux, x86_64 Windows MSVC, macOS) and walks each resolved
     package's source directory for `*.c *.cc *.cpp *.h *.S *.s *.asm *.o *.obj *.a *.lib *.so *.dll
     *.dylib`, plus the `links` key. Allow-list: the windows_* import libraries by SHA-256, `rayon-core`
     `links`. `--filter-platform` removes `wit-bindgen-rt` and the wasm-bindgen family correctly.
  4. **Binary check** (release job, owner 43): `readelf -d` NEEDED ⊆ {libc.so.6, libm.so.6,
     libgcc_s.so.1, ld-linux-*.so}; on Windows, `dumpbin /dependents` ⊆ the system DLLs plus the MSVC
     runtime. This catches a native library that arrives through a path the graph checks miss.
- **Trade-offs.** cargo-deny's `bans.build` scans compile-time crates only; layer 3 covers normal
  dependencies. Checksum pins cost a re-review on each version bump of a build-script crate (~30 crates),
  which is the point. The OS boundary (libc, windows-sys) must be allow-listed explicitly and documented.
  It is not "C we added".
- **Tests.** A CI job that fails on a synthetic violation: a throwaway branch adding `cc` as a
  build-dependency of `rpc` must fail layers 1 and 2. Record that negative run once as evidence.
- **Invariants.** No foreign code in node/miner/wallet/labnet/genesis/supply-audit. Test oracles
  (libFuzzer C++, the tevador C++ refgen of decision 05) stay outside the product workspaces with their
  own locks.

### P2. No per-version review trail (cargo-vet) (R13 T-11)

- **Problem.** A `cargo update` pulls unreviewed code silently, and `--locked` only freezes what was
  locked, not what was reviewed.
- **Coverage today.** I searched the public audit sets of google, mozilla, zcash, isrg and
  bytecode-alliance [tool-run, web]:
  - **Covered** (at least partially, often as deltas): curve25519-dalek up to 4.1.3 (zcash, google
    `ub-risk-1`), aes 0.8.4 (google, isrg), aes-gcm up to 0.10.2 (isrg), getrandom, zeroize, subtle,
    chacha20poly1305 0.10.1, postcard 1.1.3, tokio, hyper, serde, serde_json, rand family, fiat-crypto,
    paste, crc32fast, bs58, cpufeatures, digest, keccak 0.1.x, sha3 0.10.x, proptest up to 1.4.0.
  - **Not covered anywhere:** `blake2` (consensus), `ml-kem` 0.3.2 and `module-lattice`/`kem`/`cmov`/
    `ctutils`, **all of Plonky3 `p3-*`**, `argon2`, `bip39` / `bitcoin_hashes`, `polyval`, `ctr`,
    `reqwest`, `rustc_apfloat`, `wasmi` 0.38 (only 0.20 `safe-to-run`).
- **Consequence.** The consensus- and privacy-critical crates are exactly the ones nobody else has
  recorded a review of. cargo-vet will show this precisely; it cannot make them reviewed.
- **Trade-off.** Under the owner policy there are no external auditors. Internal reviews must be
  recorded under a **custom criterion** (for example `blacksilk-internal-review`), never as
  `safe-to-deploy` "audits", so that nothing claims more than was done.
- **Tests.** `cargo vet --locked` in CI: fails when a new or changed version has no import, review or
  exemption.

### P3. Requested dependencies

The verdicts are in §4a. The analysis per request follows.

#### P3.1 `proptest` (dev-dependency)

- **Facts** [source-read, web]: 1.11.0 (2026-03-24), MIT OR Apache-2.0, MSRV 1.85, no build script, no
  C. Eleven `unsafe` sites (panic-hook scoping, the RNG, `Cell` arbitrary). Default features `std`,
  `fork`, `timeout`, `bit-set`. `fork`/`timeout` pull `rusty-fork` and `tempfile` and spawn
  subprocesses. `std` enables `rand 0.9` `os_rng` → `getrandom 0.3`.
- **With `default-features = false, features = ["std"]`** it adds (dev only): rand 0.9, rand_core 0.9,
  rand_chacha 0.9, rand_xorshift 0.4, regex-syntax 0.8, unarray, bit-vec/bit-set (no), num-traits
  (present), bitflags (present). That is a third `rand_core` generation, **dev only**.
- **Why exact pin.** `proptest-regressions/` files replay a seed through proptest's own RNG and
  shrinking. A minor version bump may change the value tree and invalidate persisted cases, so pin
  `=1.11.0`.
- **Consensus/privacy.** None: dev-dependencies are not linked into binaries (resolver 2 does not unify
  dev-dependency features into normal builds).

#### P3.2 `rustc_apfloat` (dev-dependency of randomx)

- **Facts** [source-read]:
  - `#![forbid(unsafe_code)]` (`src/lib.rs:34`); the crate says it "contains no unsafe code, global state,
    or side-effects".
  - `build.rs` only validates that the version metadata matches the LLVM commit in `src/lib.rs`. No
    compiler call.
  - Its dependencies are `bitflags 2` and `smallvec 1` (features `const_generics`, `union`), both already
    in the lock.
  - License Apache-2.0 WITH LLVM-exception. LICENSE-DETAILS.md lists 7 LLVM commits not formally
    relicensed; LLVM treats them as below the originality threshold. This is acceptable for test-only
    use.
  - Published by rust-lang and used by rustc and Miri [web]. Last release 2025-06-11.
- **Caveats:**
  - APFloat has **no sqrt**, so 05's exact u128 oracle is needed for FSQRT (05 already plans this).
  - NaN payload semantics are LLVM's. That does not matter, because RandomX's operand domains exclude
    NaN (05's samplers).
  - Pin `=0.2.3` **without** the `+llvm-…` build metadata: Cargo ignores metadata in requirements and
    warns about it.

#### P3.3 RustCrypto `sha3` for the out-of-workspace CLSAG harness (15 W10); monero-oxide

- `sha3 0.11.0` (`#![forbid(unsafe_code)]`) and `keccak 0.2.2` are **already linked into the node** via
  `ml-kem` [tool-run]. `sha3::Keccak256` (original Keccak padding, `KECCAK_PAD`) is what Monero's `Hs`
  uses [source-read: `sha3-0.11.0/src/lib.rs:80`].
- keccak 0.2.2 contains ARMv8 SHA3 intrinsics (`unsafe`, runtime-selected). RUSTSEC-2026-0012 (unsound
  opt-in `asm` backend) affects `< 0.1.6` only.
- **monero-oxide** is 0.1.0 (2026-07-31), about 2.4k downloads, with a large tree. Its predecessor
  (monero-serai) had a Cypher Stack review of its multisig protocol and there is a bug bounty [web]. It
  is too heavy for a test oracle. The preferred route is to port Monero's `ge_fromfe_frombytes_vartime`
  (about 100 lines) and check it against Monero's own `tests/crypto` vectors.

#### P3.4 curve25519-dalek 5.0.0 with `lizard`, p2p only (30 W6)

- **Facts** [source-read: dalek 5.0.0, web: PR #826]:
  - Released 2026-07-06, BSD-3-Clause, MSRV 1.85, edition 2024. No dalek advisories.
  - 4.2.0 was **yanked** because `hash_to_curve` was implemented wrongly. That is a data point on
    new-feature risk in this crate.
  - `lizard = ["digest"]` pulls `digest 0.11`, already in the lock, so the only new crate is
    `curve25519-dalek 5.0.0` itself. `rand_core`, `group` and `serde` stay optional; `cpufeatures 0.3`
    and `curve25519-dalek-derive` are already present.
  - `map_to_curve_inverse(&self) -> [CtOption<[u8; 32]>; 16]` is in `src/lizard/lizard_ristretto.rs:217`.
    Slots 0–7 are "positive" preimages and slots 8–15 their negatives.
  - It is built from `to_jacobi_quartic_ristretto`, with an explicit special case for X = 0 or Y = 0 that
    **repeats** a quartic point (`:117-190`).
  - The code comes from Signal's long-vendored dalek fork, was co-prepared with Signal engineers and has
    test vectors from `vendor/ristretto.sage`. libsignal adopted it.
  - `RistrettoPoint::from_uniform_bytes` is `map_to_curve(b[0..32]) + map_to_curve(b[32..64])`, and
    `FieldElement::from_bytes` **masks bit 255** of each half (`src/ristretto.rs:774-790`,
    `src/ristretto/elligator.rs:62-66`).
- **Facts an Elligator-Squared encoder must honour** (30 owns the design; I state what the dependency
  implies):
  1. The encoder must randomize bit 255 of each 32-byte half, because the decoder ignores it.
     Otherwise the top bits are always 0 and trivially distinguishing. Byte-level check: bits 255 and 511
     of the representative must be uniform.
  2. Canonical outputs are < p, so the 19 values in [p, 2^255) never appear. The bias is about 2^-250:
     negligible [math].
  3. Tibouchi's sampling needs the true preimage multiset. The 16-slot array contains duplicates for the
     X = 0 / Y = 0 special points. Those are reached with negligible probability for random points, but a
     unit test must pin the behaviour.
  4. `map_to_curve_inverse` is not claimed to be constant-time as an encoder loop. The retry loop acts on
     an ephemeral public value, so timing leaks nothing about the long-term identity, but the loop must
     not touch secrets.
- **Coexistence with 4.1.3.** The two versions are distinct types. p2p must never pass a 5.x point into
  `blacksilk-crypto` or the reverse; the transport keys are self-contained, so this is achievable. Two
  copies of the field and backend code cost binary size, and the review surface of both versions is
  unmodelled in cargo-vet (5.0.0 has no public audit entry yet).
- **Alternative.** Keep only 4.1.3 and drop uniform key encoding: this is what happens if transport v2
  is not ready (the decisions already say "no silent partial v2"). A 4.1.3-only Elligator inverse is not
  possible without re-implementing field arithmetic, because `FieldElement` is not public in 4.1.3
  [source-read]. That route is rejected.

#### P3.5 `aes` 0.9 upgrade (06 W10, 08 W7)

- **Facts** [source-read: aes 0.9.3 CHANGELOG, lib.rs; crates.io]:
  - 0.9.0 (2026-04-10) was **yanked**; 0.9.1 fixed the minimal `zeroize` version. 0.9.2 (2026-07-27)
    rewrote the backend internals twice (#560, #575, one of them a performance regression fix). 0.9.3
    (2026-08-28) raised MSRV to 1.89 and **turned on VAES-256/512 by default** (#580), removing the
    `aes_backend = "avx256"/"avx512"` cfgs. The lib.rs docs still describe the removed cfgs, which is
    stale upstream documentation.
  - The hazmat single-round functions RandomX uses (`cipher_round`, `equiv_inv_cipher_round`) dispatch
    to AES-NI or ARMv8 or soft code [source-read: `aes-0.9.3/src/hazmat.rs`], not VAES.
- **The coupling nobody listed.** aes-gcm 0.10.3 depends on `aes 0.8`. Upgrading randomx to aes 0.9
  either leaves **two aes versions** in the node (contradicting decision 30's "shared `aes` with
  randomx") or forces `aes-gcm 0.11.x` (released 2026-06-28 / 2026-08-21; `aead 0.6`, `cipher 0.5`,
  `ghash 0.6`, `ctr 0.10`) into p2p **and wallet** (the wallet file format, whose bytes must not change).
- **Gain.** Default ARMv8 hardware AES on aarch64 Linux and macOS. aes 0.8.4 gives the same with
  `--cfg aes_armv8` (08 W1 documents this), and 08's W2 proves the hashes are identical.
- **Verdict.** Defer. See §4a.

#### P3.6 getrandom consolidation (18 W11)

- **Facts** [source-read]:
  - getrandom 0.3.4 and 0.4.3 use the **same** Windows backend: `ProcessPrng` in `bcryptprimitives.dll`
    through `raw-dylib`, with `windows_legacy` (RtlGenRandom) only for old targets.
  - Linux behaviour matches 0.2: the `getrandom(2)` syscall with a `/dev/urandom` fallback after polling
    `/dev/random`.
  - 0.4.0 (2026-02-02) changed the edition and MSRV (1.85) and added `SysRng`/`sys_rng`, WASIp3 and
    `extern_impl`. The API `getrandom::fill(&mut [u8])` is the same in 0.3 and 0.4.
  - 0.4 is the current line; the fuzz lock already resolves 0.4.3.
- **Graph.** The production binaries use 0.2.17 only. Moving the five direct users (node, miner, wallet,
  p2p, labnet) removes 0.2 from the binaries. 0.2 stays in the **lockfile** only through
  `dirs-sys` → `redox_users` (Redox target, never compiled here).
- **Value.** Liveness on Windows: BCryptGenRandom "Access is denied" failures (getrandom #314, #414)
  make the process refuse to start (fail-closed, 18 F18-10). This matters if trial devices run Windows
  (R15-11 "Windows hygiene" suggests they do).

#### P3.7 aes-gcm version and `zeroize` (30 P-7)

- **Version.** 0.10.3 is locked and is the first fixed version for GHSA-423w-p2w9-r7vq /
  RUSTSEC-2023-0096. The manifests say `"0.10"`. Pin `=0.10.3` so that a lock regeneration can never
  choose 0.10.0–0.10.2.
- **The decision's zeroize mechanism is incomplete** [source-read]:
  - In aes-gcm **0.10.3**, `zeroize` is only an implicit optional-dependency feature. It wipes the
    temporary `ghash_key` in `From<Aes>` (`src/lib.rs:239-240`) and **does not forward** to `aes/zeroize`
    or `ghash`/`polyval`.
  - The AES round keys get `ZeroizeOnDrop` only when **`aes`** itself has its `zeroize` feature
    (`aes-0.8.4/src/{soft,autodetect,armv8}.rs`).
  - The GHASH key `H` and accumulator are wiped only by **`polyval`**'s `zeroize` feature, and only in
    its clmul (x86) and soft backends. The aarch64 PMULL backend has the drop code commented out
    ("TODO(tarcieri): zeroize support", `polyval-0.6.2/src/backend/pmull.rs:192-198`).
  - `ghash 0.5.1` does not forward the feature to polyval.
  - aes-gcm **0.11** does forward (`zeroize = ["dep:zeroize", "aes?/zeroize", "ghash/zeroize"]`), but it
    belongs to the aes 0.9 generation (P3.5).
- **Correct recipe on 0.10.3.** Enable `aes = { version = "=0.8.4", features = ["zeroize"] }` (unifies
  into randomx's `aes`: it adds `Drop` impls to the key-schedule types, and the hazmat free functions
  take caller round keys and are unaffected). Add `polyval = { version = "=0.6.2", features =
  ["zeroize"] }` as a direct dependency purely for feature unification, and keep `aes-gcm/zeroize`. The
  residual is aarch64 PMULL state plus moved or copied stack values: best effort, documented.
- **Consequence without the fix.** Expanded AES-256 round keys and H of every closed P2P session remain
  in freed heap. A memory-disclosure bug or a core dump would then recover past session keys, which
  weakens forward secrecy of the stem traffic (privacy). The severity is Low, because it needs a
  separate memory-disclosure primitive.

### P4. wasmi 0.38 in the workspace (R7, A14, P0-17)

- **Advisories** [web]:
  - GHSA-75jp-vq8x-h4cq / CVE-2024-28123 (OOB write, host→Wasm calls with > 128 parameters):
    0.15.0–0.31.0.
  - GHSA-g4v2-cjqp-rfmq / CVE-2025-66627 (use-after-free in linear memory on grow; CVSS 7.8–8.4):
    0.41.0–0.41.1, 0.42.0–0.47.0, 0.50.0–0.51.2 and 1.0.0.
  - **0.38.0 is outside both published ranges.** The UAF advisory does not state that pre-0.41
    versions were examined [unknown].
  - Neither advisory is in RustSec (no `crates/wasmi` directory in advisory-db [tool-run]). **`cargo
    audit` would not report them**; cargo-deny with only the RustSec DB would not either. GitHub
    advisories are the primary source for this crate.
- **Maintenance.** The 0.36–0.38 line had one external audit (Runtime Verification, 2024-11-27, per the
  wasmi README; not verified by us). The current release is 2.0.0 (2026-09-01); 0.38 is unsupported.
- **Exposure.** None in shipped binaries [tool-run]. It is in the main lock, `cargo test --workspace`
  and the fuzz workspace.
- **Supply-chain recommendation** (the freeze decision itself belongs to 29/28 under ADR-28-1): move
  `contracts` out of the workspace (`exclude`, own lockfile, like `fuzz/`). That removes **18 crates**
  from `Cargo.lock` [tool-run: reachability]: ahash, downcast-rs, hashbrown 0.14, indexmap-nostd,
  leb128fmt, multi-stash, spin 0.9.9, string-interner, unicode-width, wasm-encoder, wasmi, wasmi_collections,
  wasmi_core, wasmi_ir, wasmparser-nostd, wasmparser, wast, wat. It also removes the `spin` 0.9/0.12
  duplicate.

### P5. third_party provenance is checked by hand

Path dependencies carry no checksum in `Cargo.lock`. `third_party/README.md:63-81` records a manual
`diff -r` against the registry copies (2026-09-27). Nothing re-checks this on each push, so an
accidental or malicious edit to `third_party/p3-*` changes the prover or verifier with no lockfile signal.

**Fix:** a CI step downloads `p3-{fri,merkle-tree,dft}-0.7.0.crate` from `static.crates.io`, verifies
its SHA-256 against the crates.io index `cksum`, extracts it and diffs it against `third_party/`. The
diff must equal a committed expected-diff digest (the three documented files plus the removed metadata
files).

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **SC-1** | **Medium** | Not implemented | `.github/workflows/ci.yml:163-180` (only `cargo audit`); `docs/reviews/dependency-review.md:13-29` (manual) | A dependency or feature change pulls `cc`/`*-sys`/a new build script (for example enabling a `reqwest` TLS or compression feature brings `ring`/`zstd-sys`); CI stays green; C code ships in the node or wallet against owner policy | High |
| **SC-2** | Medium | Not implemented | no `supply-chain/` dir | `cargo update` or a lock regeneration moves a crate (for example p3-util 0.7.x, polyval, cmov) to an unreviewed version; `--locked` does not detect it, because the new lock is what gets committed. The critical crates (blake2, ml-kem, all p3-*, argon2, bip39) have **no public audit record at all** | High |
| **SC-3** | Low | Partially implemented | `ci.yml:179-180` | An `unsound` or `yanked` informational advisory for a locked crate appears; `cargo audit` without `--deny warnings` prints it and exits 0. Also: **wasmi's two GHSA advisories are not in RustSec**, so no RustSec-based tool can see a future wasmi issue | High (cargo-audit default behaviour [assumed from docs]; RustSec absence [tool-run]) |
| **SC-4** | Low (privacy, forward secrecy) | Not implemented; decision 30's recipe is incomplete | `p2p/Cargo.toml` (aes-gcm `features=["aes","alloc"]`); `wallet/Cargo.toml` same; `aes-gcm-0.10.3/src/lib.rs:239`; `polyval-0.6.2/src/backend/pmull.rs:192` | Enabling only `aes-gcm/zeroize` leaves the AES round keys and GHASH H of every closed session in freed memory; a later memory disclosure recovers past stem-traffic keys | High |
| **SC-5** | Low | Not implemented | `fuzz/Cargo.lock` vs `Cargo.lock` | 30 shared crates resolve to different versions, so the "0 crashes" fuzz evidence covers different transitive code (for example zeroize 1.9, tokio 1.53, libc 0.2.189) from the product | High |
| **SC-6** | Informational | Accepted limitation | `Cargo.lock` (24 duplicated names) | Two RustCrypto generations are linked into the node (digest 0.10/0.11, chacha20 0.9/0.10, cpufeatures 0.2/0.3, rand_core 0.6/0.10…), which doubles the review surface. Convergence needs blake2/aes/aes-gcm/chacha20poly1305 on the new generation. The first two are consensus-byte crates, so this comes after the freeze | High |
| **SC-7** | Low | Not implemented | `node/Cargo.toml` (`fs2 = "0.4"`, `env_logger 0.8`, `dirs 5`); `node/src/main.rs:17,62` | `fs2` 0.4.3 is long unmaintained and drags in `winapi 0.3` (plus pre-built gnu import archives). std's `File::try_lock` is stable since Rust 1.89 (toolchain 1.98.1). `env_logger 0.8.4` is 3 majors behind; `dirs 5` pulls `option-ext` (MPL-2.0) and `windows-sys 0.48` | High |
| **SC-8** | Low (legal / release) | Not implemented | no root `LICENSE`; only `randomx/Cargo.toml` has `license =`; `randomx/LICENSE` (BSD-3-Clause, tevador/Monero) | The public repository grants no licence to operators or reviewers. Binary releases carry BSD-3-Clause (RandomX, dalek) notice obligations, plus MPL-2.0 (`option-ext`), Unicode-3.0, Zlib and CC0 components, and no third-party notices file exists. A cargo-deny licence check cannot be configured meaningfully without an outbound licence | High |
| **SC-9** | Low–Medium (funds recovery) | Not implemented | `wallet/Cargo.toml` (`argon2 "0.5"`, `aes-gcm "0.10"`, `bip39 "2.2"`); `wallet/src/file.rs:200-270` (no KAT) | argon2 0.6.0 (2026-08-27) and bip39 3.0.0 (2026-09-17, "better language preservation during entropy recovery"; 2.3.0 yanked the same day) are out. A bump could change mnemonic↔seed or file-key bytes with no failing test, leaving existing wallets unopenable or restoring different keys | Medium (no evidence that any bump changes bytes; the gap is the missing guard) |
| **SC-10** | Low | Accepted limitation (pending 29) | root `Cargo.toml` members line `"contracts"`; `contracts/Cargo.toml` `wasmi =0.38.0` | Unsupported wasmi line with 120 unreviewed `unsafe` sites in the main lock and CI build; outside both published advisory ranges; not shipped | High |
| **SC-11** | Low | Not implemented | `third_party/`, `Cargo.toml [patch.crates-io]` | An edit to patched Plonky3 sources has no checksum signal; integrity rests on a manual diff | High |
| **SC-12** | Informational | Not implemented | `README.md:93`; `docs/testnet.md:45,321,373` | Operator build instructions omit `--locked`. Cargo uses the committed lock anyway while it satisfies the manifests, so the risk is only on a manifest/lock mismatch; install-linux.sh and the Dockerfile already use `--locked` | High |
| **SC-13** | Informational | Not implemented (docs) | `docs/reviews/dependency-review.md:43-46` | Stale entries: `aes-gcm 0.10`/`argon2 0.5` without the patch version; `aes =0.8.4` and `sha3`/`keccak` (via ml-kem) not listed; "getrandom 0.2/0.3 coexist" omits that 0.3 is dev-only; wasmi's non-RustSec advisories not mentioned | High |
| **SC-14** | Informational | Complete and verified | `wit-bindgen-rt-0.39.0/src/cabi_realloc.{c,o}`, `libwit_bindgen_cabi_realloc.a`, `build.rs` | C source and prebuilt objects are in the lock but compiled only for wasm targets. Any "no C" scanner must be target-aware, or it will be either noisy or (worse) silenced wholesale | High |
| **SC-15** | Informational | Complete and verified | the 30 build-script crates (§2.1) | All build scripts were reviewed: no native compilation. They should be pinned by checksum (SC-1 layer 2) | High |
| **SC-16** | Informational | Complete and verified | advisory-db `e2111519`; sparse index | 0 applicable RustSec vulnerabilities, 1 unmaintained (paste), 0 yanked in 333 locked versions; no new Plonky3/dalek/RustCrypto advisories | High |

(A14's M1/M2 malleability, R2-C12 ml-kem unaudited and the paste warning are known items and are not
repeated as new findings.)

### 4a. Verdict on each requested dependency

| Request | Verdict | Conditions |
|---|---|---|
| **proptest** (dev) | **APPROVED** | `proptest = { version = "=1.11.0", default-features = false, features = ["std"] }` in `[dev-dependencies]` only. No `fork`/`timeout` (no subprocess spawning), no `hardware-rng` (`x86` crate). CI fixes `PROPTEST_RNG_SEED` (random seed only in the nightly job). Commit `proptest-regressions/`. Adds dev-only rand 0.9 generation crates, recorded in deny `skip`. Pure Rust, no build script. |
| **rustc_apfloat** (dev, randomx) | **APPROVED** | `rustc_apfloat = "=0.2.3"` (no `+llvm` metadata) in `randomx` `[dev-dependencies]` only. `forbid(unsafe_code)`; the build script is a string check. Licence Apache-2.0 WITH LLVM-exception added to the dev licence allow-list. sqrt from 05's u128 oracle. |
| **RustCrypto sha3** (dev, out of workspace) | **APPROVED** | `sha3 = "=0.11.0"`, the same version already linked via ml-kem. The tool crate (`tools/clsag-conformance/`) is `exclude`d from the workspace with its **own committed `Cargo.lock`**, audited by the supply-chain job. **monero-oxide: NOT approved** by default; port `ge_fromfe_frombytes_vartime` with Monero test vectors instead. If the coordinator insists, only there, exact-pinned, own lock. |
| **curve25519-dalek 5.0.0 + lizard (p2p)** | **CONDITIONALLY APPROVED** | Only if transport v2 is actually merged (not "just in case"). The conditions are listed after this table. |
| **ml-kem =0.3.2 in p2p** | **APPROVED** | Same version as `px`, so no new crate. Note that Cargo feature unification enables `hazmat` in p2p's build too (px enables it). p2p must use only `encapsulate`/`decapsulate`: enforce with a `clippy.toml` `disallowed-methods` entry for the hazmat deterministic API in p2p, or a grep test. The crate is unaudited (its README says so); the hybrid design is required; fuzz decapsulation and ek parsing (41). |
| **aes 0.9 upgrade** | **DEFERRED** (P3, after the freeze and the trial) | Consensus-byte crate. 4 releases in 5 months, 0.9.0 yanked, backends rewritten in 0.9.2 and 0.9.3, MSRV 1.89. It **forces aes-gcm 0.11 into p2p and wallet** or duplicates aes. The benefit is available today with `--cfg aes_armv8` (08 W1/W2). When done: exact pin; aes, aes-gcm and the wallet KATs (SC-9) move in one change; 05 C1–C3, 06 W2 and 08 W2/W3 green before and after; a wallet-file fixture still opens. |
| **getrandom 0.2 → 0.3** | **APPROVED, target 0.4.x instead** (`=0.4.3`); 0.3.4 acceptable | Same ProcessPrng/raw-dylib Windows backend in both; 0.4 is the current line and matches the rand_core 0.10 generation. `getrandom::getrandom(buf)` → `getrandom::fill(buf)` at every call site. The fail-closed error handling stays unchanged. Windows CI leg green. P2 (P1 if trial devices run Windows). |
| **aes-gcm zeroize and version** | **APPROVED, with a corrected recipe** | `aes-gcm = { version = "=0.10.3", default-features = false, features = ["aes", "alloc", "zeroize"] }` + `aes = { version = "=0.8.4", features = ["hazmat", "zeroize"] }` (hazmat only where needed) + `polyval = { version = "=0.6.2", default-features = false, features = ["zeroize"] }` in p2p **and wallet**. Zeroize the DH `shared` (30). Document the aarch64 PMULL residual. The randomx vectors must be unchanged (feature unification). |
| **blake2 zeroize** (18 F18-8) | **No change now** | blake2 0.11.0 (2026-08-26) has `zeroize = ["digest/zeroize"]`, but it is the consensus hash and a generation change (digest 0.11). F18-8 stays an accepted limitation until a post-freeze RustCrypto generation move (SC-6). |

**Conditions for curve25519-dalek 5.0.0 in p2p:**

1. **Manifest line.**
   ```toml
   curve25519-dalek-5 = { package = "curve25519-dalek", version = "=5.0.0", default-features = false, features = ["alloc", "precomputed-tables", "zeroize", "lizard"] }
   ```
   in `p2p/Cargo.toml` only. No `rand_core`, `group` or `serde`. Generate scalars from 64 getrandom bytes
   with `from_bytes_mod_order_wide`.
2. **Ban rule.** A cargo-deny ban `{ name = "curve25519-dalek", version = ">=5", wrappers = ["blacksilk-p2p"] }`
   keeps 5.x out of every other crate. The consensus crates stay on `=4.1.3` (decision 30).
3. **No type crossing.** No 5.x type appears in p2p's public API.
4. **Tests (owner 30):**
   - `map_to_curve_inverse ∘ map_to_curve` contains the input, over ≥ 10⁵ random inputs, including
     inputs with bit 255 set;
   - encoder → `from_uniform_bytes` round trip over ≥ 10⁵ keys;
   - statistical uniformity of representatives: per-bit balance and a χ² test on bytes, with bits 255
     and 511 explicitly;
   - the X = 0 / Y = 0 special-case points pinned;
   - independent vectors for the inverse, from dalek's `vendor/ristretto.sage` or libsignal's
     lizard/Elligator tests.
5. **Record.** An internal review note of `src/lizard/` recorded under the cargo-vet custom criterion.

---

## 5. Implementation plan for phase 2

All items are **policy or tooling only** unless stated. **None changes consensus or identity**,
except that a dependency move in a consensus-byte crate (aes 0.9, blake2 0.11) would need the full
consensus record; both are deferred.

| # | Work item | Files (ownership) | External effect | Identity | Tests to add | Bench | Docs | Size | Pri |
|---|---|---|---|---|---|---|---|---|---|
| **S1** | **cargo-deny gate** (advisories, bans with the §P1 deny list and wrappers, build-script allow-list pinned by SHA-256, sources = crates.io only, licences, `multiple-versions = "deny"` with a reasoned `skip` list of today's 24 duplicates). A second config for `fuzz/` (allows `libfuzzer-sys`/`cc` with wrapper `blacksilk-fuzz`) and one for each out-of-workspace tool crate. `graph.targets` = the release triples. Advisories: `yanked = "deny"`, `unmaintained = "all"`, ignore RUSTSEC-2024-0436 with reason. | **new** `deny.toml`, `fuzz/deny.toml` (44); **new** `.github/workflows/supply-chain.yml` (44, reviewed by 43; separate file per the 08 precedent) | none (CI) | none | a recorded negative run (throwaway branch adding `cc` to `rpc` must fail); the job is weekly plus on every push | – | dependency-review.md §1/§6 | S | **P0**: must land before implementation wave 1 merges new dependencies |
| **S2** | **Target-aware no-native scan** (layer 3) and **third_party verification** (P5), as one pure-Rust tool: `cargo metadata --locked --offline --filter-platform` per triple → forbidden file types and `links` allow-list; download the three p3 crates, check the index checksum, diff against `third_party/`, compare with a committed digest. No new dependency (`serde_json` only). | **new** `tools/supply-check/` (workspace member; 44); workspace `members` line (coordinate with 03's daa-sim line, 43) | none | none | unit tests over fixture metadata JSON (a synthetic `.c` file and `links` key are flagged; `wit-bindgen-rt` is not flagged under Linux/Windows triples); CI step | – | dependency-review.md §1; third_party/README.md "verification" | M | **P1** |
| **S3** | **Apply the approved dependencies** exactly as in §4a, each in the owner's own change, with the S1 config updated in the same commit (skip entries, wrappers, licences) | proptest lines: 41 (adoption) in `{consensus,chain,crypto,tx,px}/Cargo.toml`; `randomx/Cargo.toml` dev line: 05; `tools/clsag-conformance/` + its lock: 15; `p2p/Cargo.toml` dalek 5 / ml-kem: 30; `deny.toml`: **44** reviews each | none (dev) / policy (p2p) | none | the owners' tests; S1 green | – | dependency-review.md table | S each | as the owners' items |
| **S4** | **Zeroize recipe** (SC-4): aes/aes-gcm/polyval features in p2p and wallet; pin aes-gcm `=0.10.3`. Add a compile-time assertion `fn _z<T: zeroize::ZeroizeOnDrop>(){}; _z::<aes::Aes256>();` in p2p tests | `p2p/Cargo.toml` (30; 44 supplies the lines), `wallet/Cargo.toml` (37) | none | none | the static assertion; the randomx vector suite unchanged; transport and wallet round-trip tests | – | p2p.md key-hygiene note; dependency-review.md | S | **P1** |
| **S5** | **getrandom → 0.4.3** in the five direct users; call sites `getrandom::fill` | `node/Cargo.toml`, `miner/Cargo.toml`, `wallet/Cargo.toml`, `p2p/Cargo.toml`, `tools/labnet/Cargo.toml` + their `getrandom::` call sites (**44**, 18 reviews) | none | none | the full suite on Linux and Windows; the existing fail-closed error-path tests | – | 18's W9 "one native boundary" note | S | P2 (P1 if the trial has Windows devices) |
| **S6** | **Drop `fs2`** (std `File::try_lock`, Rust ≥ 1.89); evaluate `env_logger` 0.11 and `dirs` 6 (or std `home_dir`) | `node/Cargo.toml`, `node/src/main.rs:17,62` (node owner / 35; 44 proposes); `miner/Cargo.toml` (09) for env_logger | none | none | existing lock test (two nodes on one datadir refused); an add-if-missing test | – | R10-14 row closed | S | P2 |
| **S7** | **Contracts out of the workspace** (SC-10): add `contracts` to `exclude`, give it its own lock, keep `fuzz` pointing at it | root `Cargo.toml`, `contracts/Cargo.lock` (new), `.github/workflows/ci.yml` test step (43) — **owner 29**, 44 advises | none | none | contracts suite runs from its own dir in CI; `cargo tree` shows no wasmi in the root lock | – | contracts.md / dependency-review.md | S | **P1** (supports P0-17) — only if 29/28 agree |
| **S8** | **Wallet-format KATs** before any argon2/bip39/aes-gcm bump (SC-9): RFC 9106 §5.3 Argon2id vector; BIP-39 reference vectors (English, with and without passphrase as used); a committed small wallet-file fixture (fixed salt/nonce, cheap KDF params) that must decrypt to a known payload | `wallet/src/file.rs` tests, `wallet/tests/vectors/` (**37**) | none | none | the three KATs | – | wallet docs | S | **P1** |
| **S9** | **cargo-vet** init: imports (google, mozilla, zcash, isrg, bytecode-alliance); exemptions for the remainder; custom criterion `blacksilk-internal-review` (never presented as an audit); internal reviews recorded first for blake2 0.10.6, ml-kem 0.3.2 (+module-lattice, kem, cmov, ctutils), p3-* 0.7.0, argon2 0.5.3, bip39 2.2.2, polyval 0.6.2, curve25519-dalek 5.0.0 `lizard` | **new** `supply-chain/{config.toml,audits.toml,imports.lock}` (44) | none | none | `cargo vet --locked` job in `supply-chain.yml` | – | dependency-review.md §6 | M (setup) + L (reviews) | P2 |
| **S10** | **Fuzz lock alignment** (SC-5): regenerate `fuzz/Cargo.lock` seeded from the root lock's versions; CI check that shared crates have equal versions | `fuzz/Cargo.lock` (41), check in `tools/supply-check` (44) | none | none | the check | – | AUDIT.md fuzz section | S | P2 |
| **S11** | **Docs**: rewrite dependency-review.md as the dependency risk table below plus the policy (OS-boundary allow-list, test-oracle exemptions: libFuzzer, tevador refgen, Python vector scripts; "unsafe in dependencies" position; the upgrade procedure; the wasmi GitHub-advisory source); add `--locked` to README/testnet.md build lines | `docs/reviews/dependency-review.md` (44), `README.md:93`, `docs/testnet.md:45,321,373` (47 coordinates) | none | none | – | – | as listed | S | **P1** |
| **S12** | **Release obligations** (SC-8): a project LICENSE decision (owner); `license` fields; a third-party notices file generated per release (cargo-about or the SBOM) covering BSD-3-Clause/MPL-2.0/Unicode; NEEDED-library check on release binaries (layer 4) | root `LICENSE` (owner), manifests; release workflow (**43**) | none | none | the release-job check | – | SECURITY.md/README | S | P1 before any outside operator |
| **S13** | **Deferred moves** (record only): aes 0.9 + aes-gcm 0.11 together; RustCrypto 0.11 generation (blake2 0.11 zeroize) after the freeze with the full consensus record; Plonky3 0.8 (removes the p3-dft patch) under the dependency-review §3.3 procedure | — | consensus-byte (future) | kernel id if Plonky3 moves | — | — | dependency-review.md §3.3 | — | P3 |

### Dependency risk table (deliverable; the basis of S11)

| Crate (locked) | Role | Consensus / privacy | Pin | Native / `unsafe` | Advisories | Maintenance | Public review record | Risk |
|---|---|---|---|---|---|---|---|---|
| blake2 0.10.6 | every tagged hash, RandomX | **consensus** | `=` | none / 26 (SIMD off) | none | 0.11.0 out (2026-08) | none | Med: unreviewed consensus hash lib; no zeroize |
| aes 0.8.4 | RandomX AES; AEAD | **consensus** / privacy | `=` | intrinsics / 110 | none | 0.9.3 current | google, isrg | Low–Med |
| curve25519-dalek 4.1.3 | CLSAG, BP+, stealth, PX delivery | **consensus** / privacy | `=` | SIMD / 37 | RUSTSEC-2024-0344 fixed in 4.1.3 | 5.0.0 current; 4.x maintenance | zcash, google | Low |
| p3-* 0.7.0 (+3 patched) | PX STARK | **consensus** / ZK privacy | `=` | SIMD, unchecked / 700+ | 5 GHSA, none applicable (§5a) | 0.8.0 out | **none** | **High** (unaudited hiding mode; largest unsafe surface) |
| postcard 1.1.3, serde 1.0.229 | proof wire format | **consensus** | `=` | – / 12 | none | active | bca, google | Low |
| ml-kem 0.3.2 (+ module-lattice, kem, hybrid-array, cmov, ctutils, sha3 0.11, keccak 0.2.2) | PX delivery PQ half; p2p v2 | privacy | `=` (ml-kem) | 0 in ml-kem; 43/28 in helpers | none (cmov < 0.4.4 ARM32 fixed; keccak asm < 0.1.6 fixed) | young, pre-1.0, "never independently audited" | **none** | Med (hybrid limits the impact) |
| chacha20poly1305 0.10.1 | PX record AEAD | privacy | caret | SIMD / 50+23 | none | active | zcash | Low |
| aes-gcm 0.10.3 (+ghash, polyval, ctr) | P2P transport, wallet file | privacy | caret → `=` (S4) | – / 23 (polyval) | GHSA-423w fixed in 0.10.3 | 0.11.1 current | isrg to 0.10.2 | Low (SC-4) |
| argon2 0.5.3 | wallet file KDF | privacy / funds | caret | – / 2 | none | 0.6.0 out | **none** | Low–Med (SC-9) |
| bip39 2.2.2 (+bitcoin_hashes, unicode-normalization) | mnemonic | funds | caret | – / 17 | none | 3.0.0 out | partial | Low–Med (SC-9) |
| getrandom 0.2.17 | OS entropy | privacy | caret | OS FFI / 58 | none | 0.4.3 current | mozilla, zcash | Low (Windows liveness) |
| zeroize 1.8.1, subtle 2.6.1 | hygiene / CT | privacy | caret | – / 15 / 2 | none | active | mozilla, isrg, zcash | Low |
| rand 0.10.3 / rand_chacha 0.3.1 | STARK hiding RNG; seeded streams | ZK privacy | caret | – / 20 / 1 | RUSTSEC-2026-0097 fixed in 0.10.1 | active | isrg, google | Low |
| tokio, hyper, axum, reqwest (no TLS), serde_json | node runtime, RPC | availability | caret | tokio 1044 / hyper 67 | all historical fixed | active | zcash, mozilla (partial) | Low |
| rayon, crossbeam-*, spin 0.12.3 | prover parallelism | liveness | caret | many | crossbeam-epoch 2026-0204 fixed in 0.9.20 | active | isrg, mozilla | Low (spin locks: the ZK-F11/F21 history) |
| fs2 0.4.3, winapi 0.3.9, env_logger 0.8.4, dirs 5 | node datadir lock, logging | – | caret | – | none | **stale** | partial | Low (S6) |
| wasmi 0.38.0 (+wasmparser-nostd) | contracts (not shipped) | – | `=` | – / 120 | GHSA ranges exclude 0.38; **not in RustSec** | **unsupported** | bca (0.20 only) | Low exposure / High if integrated |
| paste 1.0.15 | proc macro (Plonky3) | – | transitive | compile-time | RUSTSEC-2024-0436 unmaintained | archived | mozilla | Low |
| libfuzzer-sys (fuzz only) | test oracle | – | caret | **C++** | – | active | – | accepted exemption |

---

## 6. Dependencies and conflicts with other workstreams

- **43 ci-reproducibility.** Owns `ci.yml` and the release workflow. S1/S2/S9 live in a separate
  `supply-chain.yml` (my proposal, following the 08 precedent). Release-side items (S12 notices, NEEDED
  check, SBOM and cargo-auditable) are theirs. The existing `audit` job can later be retired in favour of
  cargo-deny, or kept as a second opinion.
- **41 fuzzing.** proptest adoption owner (S3). The fuzz lock alignment (S10) and the fuzz deny config.
- **05/06/08 RandomX.** rustc_apfloat line (05). aes 0.9 deferral (06 W10, 08 W7). The S4 zeroize
  feature unifies into randomx's `aes`, so 05/08 vectors must stay green.
- **15 CLSAG.** `tools/clsag-conformance/` gets its own lock and a deny config. monero-oxide not
  approved.
- **18 crypto-randomness.** Reviews S5. F18-8 (blake2) stays an accepted limitation.
- **24 plonky3-verifier-security.** S2's third_party verifier; a Plonky3 0.8 move is theirs (P3).
- **29 wasm-contracts / 28.** S7 decision (contracts out of the workspace); the wasmi advisory source.
- **30 p2p-transport.** dalek 5 conditions, ml-kem in p2p, the S4 recipe (they own `p2p/Cargo.toml`).
- **37/38 wallet.** S4 wallet lines, S8 KATs.
- **35 / node owner.** S6 (fs2).
- **47 docs.** S11 edits outside dependency-review.md.
- **48 threat model / 50 red team.** A supply-chain branch of the attack tree: a malicious crate update,
  a build-script compromise, a typosquat, third_party tampering. S1/S2/S9 are the controls to attack.
- **03 daa-sim.** A workspace members-line edit touches the same line as S2; merge sequentially.

---

## 7. Open questions for the coordinator

1. **S1 as P0.** R13 rated cargo-deny P1. I ask for P0 (S), so the gate exists **before** the wave-1
   dependency additions merge. Accept?
2. **getrandom target.** 0.4.3 (my recommendation: current line, same backend) or 0.3.4 (the literal
   request)?
3. **Contracts out of the workspace (S7).** Can 29/28 confirm now? It removes 18 crates and the only
   unsupported dependency line from the main lock.
4. **Project licence (SC-8).** The owner must choose an outbound licence before a public release. Until
   then cargo-deny's `[licenses]` checks inbound licences only (`private.ignore = true`).
5. **cargo-vet criterion wording.** I propose `blacksilk-internal-review` (an explicitly non-audit
   criterion) so the audit files never read as external audits. Is that acceptable under the
   self-reliant review policy?
6. **dalek 5.** Confirm that the dependency is added only in the same change that lands transport v2,
   not earlier.
7. **monero-oxide.** Do you accept my "not approved; port the 100-line map" verdict for 15 W10 and 05 C6?

---

## 8. Sources

- RustSec advisory database (read at commit `e2111519`, 2026-09-25): https://github.com/rustsec/advisory-db ; listing https://rustsec.org/advisories/
  - RUSTSEC-2024-0436 (paste unmaintained), RUSTSEC-2024-0344 (dalek Scalar sub timing), RUSTSEC-2023-0096 (aes-gcm), RUSTSEC-2026-0003 (cmov ARM32), RUSTSEC-2026-0012 (keccak asm), RUSTSEC-2026-0097 (rand logger unsound), RUSTSEC-2026-0204 (crossbeam-epoch), RUSTSEC-2026-0007 (bytes), RUSTSEC-2025-0047 (slab), RUSTSEC-2025-0023 (tokio broadcast): files under `crates/<name>/` in the repository above.
- wasmi advisories: GHSA-g4v2-cjqp-rfmq / CVE-2025-66627 https://github.com/advisories/GHSA-g4v2-cjqp-rfmq ; GHSA-75jp-vq8x-h4cq / CVE-2024-28123 https://github.com/advisories/GHSA-75jp-vq8x-h4cq ; list https://github.com/wasmi-labs/wasmi/security/advisories ; audits in README https://github.com/wasmi-labs/wasmi ; CHANGELOG https://github.com/wasmi-labs/wasmi/blob/main/CHANGELOG.md
- Plonky3 advisories: https://github.com/Plonky3/Plonky3/security/advisories
- curve25519-dalek advisories (none): https://github.com/dalek-cryptography/curve25519-dalek/security/advisories ; Lizard PR #826: https://github.com/dalek-cryptography/curve25519-dalek/pull/826 ; 5.0.0 source: https://static.crates.io/crates/curve25519-dalek/curve25519-dalek-5.0.0.crate ; API: https://docs.rs/curve25519-dalek/5.0.0/curve25519_dalek/ristretto/struct.RistrettoPoint.html
- RustCrypto advisories: AEADs https://github.com/RustCrypto/AEADs/security/advisories (GHSA-423w-p2w9-r7vq) ; KEMs https://github.com/RustCrypto/KEMs/security/advisories ; hashes https://github.com/RustCrypto/hashes/security/advisories ; password-hashes https://github.com/RustCrypto/password-hashes/security/advisories
- RustCrypto sources read: aes 0.9.3 https://static.crates.io/crates/aes/aes-0.9.3.crate (CHANGELOG #560, #575, #580, #586: https://github.com/RustCrypto/block-ciphers) ; aes-gcm 0.11.1 https://static.crates.io/crates/aes-gcm/aes-gcm-0.11.1.crate ; ml-kem https://crates.io/crates/ml-kem
- getrandom: 0.3.4 / 0.4.3 sources https://static.crates.io/crates/getrandom/ ; CHANGELOG https://github.com/rust-random/getrandom/blob/master/CHANGELOG.md ; issues #314, #414 https://github.com/rust-random/getrandom/issues/314 , https://github.com/rust-random/getrandom/issues/414
- rustc_apfloat: https://github.com/rust-lang/rustc_apfloat ; https://docs.rs/rustc_apfloat
- proptest 1.11.0: https://github.com/proptest-rs/proptest ; https://crates.io/crates/proptest
- bip39 CHANGELOG: https://github.com/rust-bitcoin/rust-bip39/blob/master/CHANGELOG.md
- monero-oxide: https://github.com/monero-oxide/monero-oxide ; audits dir https://github.com/monero-oxide/monero-oxide/tree/main/audits ; CCS audit proposal https://ccs.getmonero.org/proposals/monero-serai-wallet-audit.html
- cargo-deny: bans https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html ; advisories https://embarkstudios.github.io/cargo-deny/checks/advisories/cfg.html ; sources https://embarkstudios.github.io/cargo-deny/checks/sources/cfg.html ; repo https://github.com/EmbarkStudios/cargo-deny
- cargo-vet: importing audits https://mozilla.github.io/cargo-vet/importing-audits.html ; registry https://raw.githubusercontent.com/mozilla/cargo-vet/main/registry.toml ; audit sets: https://raw.githubusercontent.com/google/supply-chain/main/audits.toml , https://raw.githubusercontent.com/mozilla/supply-chain/main/audits.toml , https://raw.githubusercontent.com/zcash/rust-ecosystem/main/supply-chain/audits.toml , https://raw.githubusercontent.com/divviup/libprio-rs/main/supply-chain/audits.toml , https://raw.githubusercontent.com/bytecodealliance/wasmtime/main/supply-chain/audits.toml
- cargo-geiger (optional unsafe inventory): https://github.com/geiger-rs/cargo-geiger
- Rust std file locking (stable 1.89): https://doc.rust-lang.org/std/fs/struct.File.html
- M. Tibouchi, Elligator Squared, FC 2014, ePrint 2014/043: https://eprint.iacr.org/2014/043 ; RFC 9496 (ristretto255) §4.3.4: https://www.rfc-editor.org/rfc/rfc9496
- FIPS 203 (ML-KEM) §7.2 input checks: https://csrc.nist.gov/pubs/fips/203/final
- RFC 9106 (Argon2) test vectors §5.3: https://www.rfc-editor.org/rfc/rfc9106
- crates.io API and sparse index (versions, yanked flags, dates): https://crates.io/api/v1/crates/<name> ; https://index.crates.io/
