# BVM-1 guest programs and their reproducible build

This workspace builds the programs that run inside the zkVM
(`riscv32i-unknown-none-elf` with Zmmul, docs/zkvm.md §4). Two are pinned by id:

| Guest | Pinned binary | Pinned id | Role |
|---|---|---|---|
| `kernel` | `px/kernel.elf` | `px/kernel.id` | **Consensus.** Every PX transaction proves this program (docs/px.md §4.3) |
| `vault` | `px/vault.elf` | `px/vault.id` | The reference contract (demonstration only), registered by a deploy |
| `sum`, `arith` | `zkvm/tests/fixtures/` | — | Test fixtures |

A **program id** (docs/zkvm.md §3) commits to the entry point, the code and the
data segments. It does not cover the ELF's symbol table, which records
path-dependent crate hashes. So two builds can differ as files and still have the
same id; the id is what consensus pins.

## Build environment (verified 2026-09-27)

- **rustc 1.98.1** (`48a229cea 2026-09-01`) with the `riscv32i-unknown-none-elf`
  target. `rust-toolchain.toml` in this directory selects it, and CI pins the same
  version for the host build.
  - The id does not depend on the host flavour of that rustc: both
    `1.98.1-x86_64-pc-windows-gnu` and `stable-x86_64-pc-windows-msvc` (1.98.1)
    reproduced the pinned ids.
  - There is deliberately no `rust-toolchain.toml` at the repository root. It
    would resolve to rustup's default host, which on a machine with a GNU default
    host cannot build the workspace (the `dlltool` failure).
- Profile and flags: `Cargo.toml` here (`opt-level` 2 for the kernel, the vault
  and `px-core`, `lto`, one codegen unit, `panic = "abort"`, `strip`). Also
  `.cargo/config.toml` (static relocation, `+zmmul`).
- `Cargo.lock` here is tracked. The guests have no external dependencies.
- **A Windows host with Git Bash.**
  - The pinned binaries embed one absolute source path: the panic messages of
    `px-core/src/hash.rs` carry `C:\Users\Home 01\Desktop\BlackSilk\BlackSilk-Blockchain\px-core\src\hash.rs`.
    It is part of the data segment, and so of the id.
  - The build scripts remap the checkout's path to that canonical path
    (`--remap-path-prefix`), so a checkout anywhere gives the same bytes there.
  - On Linux or macOS the path separators differ (`/` instead of `\`), and the
    rebuilt id would differ.

## Procedure

```sh
cd zkvm/guests
bash reproduce.sh  # rebuild the kernel and the vault; compare with the pinned ids
bash build.sh      # rebuild every guest and copy it over the pinned binaries
```

- `reproduce.sh` exits non-zero if either id differs. CI runs it on a Windows
  runner for every push (`.github/workflows/ci.yml`, job `guests`).
- **Verified:** a separate checkout at `C:\bszkeval\repro` reproduced both pinned
  ids. A one-character change to a `px-core` panic message made both ids mismatch,
  and the script failed.

## Known limitation and the planned fix (owner decision pending)

- The consensus-pinned kernel carries a developer's local path. Reproduction
  therefore needs a Windows host and the path remapping.
- A platform-neutral kernel would remove the embedded path, either with a neutral
  remapping or by removing the panic messages from `px-core`. That changes the
  kernel's data segment, and so its id, which is a **consensus change** needing a
  new testnet identity.
- It is deferred to the owner's decision. It would best be bundled with any other
  kernel change (PX-F4, PX-F5), so the network identity changes only once.
