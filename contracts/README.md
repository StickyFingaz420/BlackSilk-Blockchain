# blacksilk-contracts: frozen Wasm contract research

**Not consensus, not integrated, not built by CI.** PX is the only consensus contract
platform (ADR-28-1, owner decision D22): private contracts are PX functions, specified
in [docs/contracts.md](../docs/contracts.md) ("Private contracts on PX") and
[docs/px.md](../docs/px.md). This crate is the engine of the earlier Wasm
confidential-contract design, whose specification is kept as history in
[docs/research/wasm-contracts.md](../docs/research/wasm-contracts.md). References to
`docs/contracts.md` in older text about Wasm mean that file.

## What "frozen" means (decision D22, "D-freeze")

- The crate is **excluded from the root workspace** (root `Cargo.toml`) and has its
  own workspace and `Cargo.lock`, like `fuzz/`. wasmi and the crates only it needs are
  in no lockfile or binary of the node, wallet or miner. The CI `doc-lint` job fails if
  wasmi reappears in the root or fuzz `Cargo.lock`.
- No workspace crate may depend on it. Transaction kinds 0 to 3 keep their meaning
  (kinds 2 and 3 are PX); no kind number is reserved for Wasm.
- The code is kept buildable and tested, not deleted: its sparse Merkle tree and
  per-block undo model are reusable research. It is not maintained for production.
- Any future public-state "finalize" step for PX contracts would run on the BVM-1
  interpreter (safe Rust), never on wasmi (dossier 29 §3.2; P3, only with evidence of
  demand).

## Build and test

From this directory, with the same Rust toolchain as the rest of the project:

```sh
cargo test --locked      # 30 tests: engine, profile, state, SMT, mutation fuzzing
```

The coverage-guided fuzz targets `wasm_module` and `contract_sequence` moved here
from `fuzz/` and are their own workspace (`fuzz/Cargo.toml` in this directory; nightly
toolchain and cargo-fuzz, as for the main fuzz targets). Their results are not testnet
evidence: the engine is not integrated, and the harnesses cannot see cross-call memory
growth (dossier 29 W-8).

## Known limits: preconditions for any revival

The findings below are recorded, not fixed. They are **preconditions for any
revival**, not open testnet work (dossier 29 §3.4 and §4;
[docs/reviews/contracts-completion-assessment.md](../docs/reviews/contracts-completion-assessment.md)):

- **C-1:** per-transaction instantiation memory (every nested call instantiates into
  one store: about 3.9 GiB of zeroed memory within one call's fuel limit, by
  arithmetic from the constants, not measured).
- **C-2 and W-2:** the module cache is unbounded, and wasmi never frees compiled code,
  so a bounded cache alone does not bound memory.
- **C-3 and W-3:** wasmi 0.38's `EnforcedLimits::strict()` rejects modules the
  profile accepts, so acceptance is "profile and wasmi 0.38 compiles", not the profile
  alone (`src/profile.rs`).
- **C-4 and W-7:** encoders do not check lengths; `Note::encode`'s `u8` length prefix
  makes the leaf encoding non-injective above 255 bytes of policy.
- **C-5:** `commit` panics on an inconsistent diff.
- **W-4:** the fuel schedule is wasmi's internal IR schedule (with truncating
  division), not a function of Wasm semantics; one golden fuel value pins it.
- **W-5:** wasmi 0.38 is an unpatched line. **W-1:** 0.38.0 is not itself an audited
  release (the Runtime Verification report covers 0.36.0 and its fixes; see the
  comment in `Cargo.toml`).
- **W-6:** the profile enables reference types and multi-value, which the most
  reviewed production configuration of wasmi (Soroban) disables.

The Wasm-only cryptography in `crypto` (`schnorr`, `membership`, `claims`) is still
compiled into the `crypto` crate; gating it behind an off-by-default feature is a
separate `crypto` work item (dossier 29 W29-5). Its hash tags stay registered.
