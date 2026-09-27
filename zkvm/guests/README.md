# BVM-1 guest programs and their reproducible build

This workspace builds the programs that run inside the zkVM
(`riscv32i-unknown-none-elf` with Zmmul, docs/zkvm.md §4). Two are pinned by id:

| Guest | Pinned binary | Pinned id | Role |
|---|---|---|---|
| `kernel` | `px/kernel.elf` | `px/kernel.id` | **Consensus.** Every PX transaction proves this program (docs/px.md §4.3) |
| `vault` | `px/vault.elf` | `px/vault.id` | The reference contract (demonstration only), registered by a deploy |
| `sum`, `arith` | `zkvm/tests/fixtures/` | — | Test fixtures |

A **program id** (docs/zkvm.md §3) commits to the entry point, the code and the
file-backed bytes of every loadable data segment. For these binaries the first
loadable segment starts at file offset 0, so it contains the **ELF header**.
The header holds the section header table's offset and count
(`e_shoff`, `e_shnum`, `e_shstrndx`), so the id also depends on the size of the
sections placed before that table. See "Path independence".

## Build environment (verified 2026-09-27)

- **rustc 1.98.1** (`48a229cea 2026-09-01`) with the `riscv32i-unknown-none-elf`
  target. `rust-toolchain.toml` in this directory selects it. The scripts print
  `rustc -vV` and stop on any other version.
  - The host flavour of that rustc does not matter:
    `1.98.1-x86_64-pc-windows-gnu` and `stable-x86_64-pc-windows-msvc` (1.98.1)
    gave byte-identical kernels.
  - There is deliberately no `rust-toolchain.toml` at the repository root. It
    would resolve to rustup's default host, which on a machine with a GNU default
    host cannot build the workspace (the `dlltool` failure).
- Profile: `Cargo.toml` here (`opt-level` 2 for the kernel, the vault and
  `px-core`, `lto`, one codegen unit, `panic = "abort"`, `strip`).
- Target flags: static relocation, `+zmmul` and **`-Clink-arg=--strip-all`**.
  **`build.sh` is the single source** (`GUEST_FLAGS`). `.cargo/config.toml`
  repeats them for ad-hoc `cargo build` runs here, and the scripts fail if the
  two differ.
- `Cargo.lock` here is tracked, and the build uses `--locked`. The guests have
  no external dependencies. The id tool is also built with `--locked`.
- The scripts refuse to run when any of these is set: `RUSTC`, `RUSTC_WRAPPER`,
  `RUSTC_WORKSPACE_WRAPPER`, `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`,
  `CARGO_BUILD_RUSTFLAGS`, `CARGO_BUILD_TARGET`, `CARGO_BUILD_RUSTC*`,
  `CARGO_PROFILE_*`, `CARGO_TARGET_RISCV32I_UNKNOWN_NONE_ELF_*`.
- **Any host with bash, at any checkout path.** The build runs in place. There is
  no longer a canonical build path (testnet v3; the v2 kernel needed one).

## Path independence (testnet v3, R15-6)

Until testnet v2 the pinned binaries depended on the absolute path they were
built at, in two ways:

1. **Panic locations.** The `assert!`s in `px-core/src/hash.rs` (and an array
   bounds check there) recorded their source location,
   `C:\Users\Home 01\Desktop\BlackSilk\BlackSilk-Blockchain\px-core\src\hash.rs`,
   in `.rodata`, so in the id. The guest panic handler ignores it, but the data
   was still linked in.
2. **Crate hashes.** `px-core` and `zkvm/sdk` are path dependencies outside this
   workspace, so cargo hashes their absolute path into `-C metadata`. The crate
   disambiguators appeared in the v0-mangled names in `.symtab`/`.strtab`; their
   length moved `e_shoff` in the ELF header, which is in the first loaded
   segment. So the id changed with the path. `--remap-path-prefix` does not reach
   these hashes, and a neutral prefix would still leave OS-native separators.

**The v3 build removes both:**

1. `px-core` has no located panic on the guest paths. Invalid `Hk` inputs go to
   `Permutation::invalid_input`, which hosts implement as a panic (the default)
   and the kernel and vault guests as `sdk::halt(1)` (the exit code a panic had).
   Index bounds are checked explicitly before indexing, so the compiler emits no
   bounds-check panic.
2. The guests are linked with `--strip-all`: no symbol table, so no crate hashes.

A test pins it: `px/tests/elf_paths.rs` fails if `px/kernel.elf` or
`px/vault.elf` contains a path-like string (`.rs`, `/src/`, `:\`, a home
directory) or a symbol table. Array-index bounds checks and any future `assert!`
would bring a path back; the test catches that.

**Verified (2026-09-27, V3-B), all with rustc 1.98.1 on Windows:**

| Build tree | kernel.elf sha256 | vault.elf sha256 |
|---|---|---|
| the repository checkout (`.claude\worktrees\…`) | `587e0a4f…b100294e` | `1b949884…5b625034aecf` |
| a copy at `…\scratchpad\buildA` | identical | identical |
| a copy at `…\scratchpad\build B with spaces\deeper` | identical | identical |

- kernel sha256 `587e0a4f059c593891054759f530bf13302cc4f62f8ee28eba48b972b100294e`,
  id `0577e667c09a8007871d3fda04af01520877db63d9a3a40391a6c8b0598e143a`;
- vault sha256 `1b9498843209beceafccc146627cde5a133cce1b89bbb3e80c0d5b625034aecf`,
  id `666f7aab9350c9c67c3b68b5a5a92cf14e7808e10074723f36ff16dd2ea12f98`.
- The fixtures `sum` and `arith` are byte-identical to the committed ones
  (they were already stripped).
- `reproduce.sh` passed in the checkout.
- **Not yet verified here:** a Linux build. CI's `guests` job now runs on
  `windows-latest` and `ubuntu-latest`; the first run is the cross-OS evidence.

Previous ids (testnet v2): kernel `e55c1d2a…`, vault `be646844…`.

## Procedure

```sh
bash zkvm/guests/reproduce.sh  # rebuild kernel and vault; compare ids and bytes
bash zkvm/guests/build.sh      # rebuild every guest and copy it over the pinned binaries
```

- `reproduce.sh` checks, for the kernel and the vault:
  - the rebuilt id equals `px/*.id`;
  - the committed `px/*.elf` has that id too;
  - the rebuilt ELF is byte-identical (sha256) to the committed one.

  It exits non-zero on any mismatch. CI runs it on Windows and Linux for every
  push (`.github/workflows/ci.yml`, job `guests`).
- `.gitattributes` marks `*.elf` binary and `*.id` `-text`, so no checkout
  converts them.
- A changed kernel id is a consensus change: it needs the owner's approval and a
  new testnet identity.
