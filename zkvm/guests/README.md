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
sections placed before that table, including the symbol table. See
"Why a fixed build path".

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
- Target flags: static relocation and `+zmmul`. **`build.sh` is the single
  source** (`GUEST_FLAGS`). `.cargo/config.toml` repeats them for ad-hoc
  `cargo build` runs here, and the scripts fail if the two differ.
- `Cargo.lock` here is tracked, and the build uses `--locked`. The guests have
  no external dependencies. The id tool is also built with `--locked`.
- The scripts refuse to run when any of these is set: `RUSTC`, `RUSTC_WRAPPER`,
  `RUSTC_WORKSPACE_WRAPPER`, `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`,
  `CARGO_BUILD_RUSTFLAGS`, `CARGO_BUILD_TARGET`, `CARGO_BUILD_RUSTC*`,
  `CARGO_PROFILE_*`, `CARGO_TARGET_RISCV32I_UNKNOWN_NONE_ELF_*`.
- **A Windows host with Git Bash (MSYS).** The scripts use `pwd -W` and stop
  with a clear message in any other bash (WSL, Cygwin, Linux, macOS).
- **The build runs at the canonical path**
  `C:\Users\Home 01\Desktop\BlackSilk\BlackSilk-Blockchain`, see below.

## Why a fixed build path

The pinned binaries depend on the absolute path they were built at, in two ways:

1. **Panic messages.** `px-core/src/hash.rs` panic locations embed
   `C:\Users\Home 01\Desktop\BlackSilk\BlackSilk-Blockchain\px-core\src\hash.rs`.
   They are in `.rodata`, so in the id.
2. **Crate hashes.** `px-core` and `zkvm/sdk` are path dependencies outside this
   workspace. Cargo therefore hashes their absolute path into `-C metadata`. The
   resulting crate disambiguators appear in the v0-mangled names in `.symtab` and
   `.strtab`, and their base-62 length varies. A different checkout path changes
   the size of `.strtab`, which moves `e_shoff` in the ELF header, which is in
   the first loaded segment. So **the id changes, not just the file.**
   - `--remap-path-prefix` does not reach these hashes.
   - The previous script remapped the source path and built in place. It
     reproduced the kernel id only when the new crate hashes happened to have
     the same total length. From a git worktree under `.claude\worktrees\...`
     it gave kernel id `d8d32b76…` instead of `e55c1d2a…`, with the code and
     data sections byte-identical and only `.symtab`/`.strtab` differing. Two
     other checkout paths happened to match.

So `build.sh` always compiles at the canonical path, spelled exactly as
`GUEST_CANONICAL`:

- If this checkout is at that path, it builds in place.
- If the path does not exist (a CI runner), it copies `px-core`, `zkvm/sdk` and
  `zkvm/guests` (without `target`) there and builds the copy.
- If the path exists and is not this checkout, it stops. It never deletes or
  overwrites anything. On the development machine that path is the main
  checkout, so a worktree cannot run the scripts. A stale copy from an earlier
  run must be removed by hand.

The target directory stays in the checkout; it does not affect the output.

**Verified (2026-09-27):**

- A build at the canonical path is byte-identical to the committed files:
  - `px/kernel.elf` sha256 `95c728847f6e116a9dd492c6186d3ab7550235c96aaa5c23c1cd54cbb806a019`
  - `px/vault.elf` sha256 `bea7db998828f3f60ef82d27174d66f59196a9a63bc00671fb75d75627892f14`
- Staging was tested from three different checkouts: two `git archive` copies
  and one CRLF working copy whose path contains spaces. `GUEST_CANONICAL` was
  pointed at a scratch path. All three gave the same bytes (kernel `4c65aa61…`,
  vault `996c5e61…`); built in place, the three give three different files.
- `reproduce.sh` passed end to end on a full copy. It failed as intended when
  one byte was appended to the committed vault ELF.

## Procedure

```sh
bash zkvm/guests/reproduce.sh  # rebuild kernel and vault; compare ids and bytes
bash zkvm/guests/build.sh      # rebuild every guest and copy it over the pinned binaries
```

- `reproduce.sh` checks, for the kernel and the vault:
  - the rebuilt id equals `px/*.id`;
  - the committed `px/*.elf` has that id too;
  - the rebuilt ELF is byte-identical (sha256) to the committed one.

  It exits non-zero on any mismatch. CI runs it on a Windows runner for every
  push (`.github/workflows/ci.yml`, job `guests`), where it stages the sources
  at the canonical path.
- `.gitattributes` marks `*.elf` binary and `*.id` `-text`, so no checkout
  converts them.

## Stripping: not possible without a new kernel id

The kernel and vault keep their `.symtab`/`.strtab` despite `strip = true` in
the profile. The fixtures, built with the same profile, are stripped; the cause
is not established. Stripping the kernel and vault (tested with
`-Clink-arg=--strip-all`) removes the path-dependent crate hashes and makes
builds byte-identical from any path. It also shrinks the file and moves
`e_shoff`, so it **changes both program ids**:

| | id now | stripped |
|---|---|---|
| kernel | `e55c1d2a…` | `ecd0808f…` |
| vault | `be646844…` | `3c071c5c…` |

That is a consensus change, so it was not done. The fixtures `sum` and `arith`
are stripped already, and a rebuild left them byte-identical.

## Known limitation and the planned fix (owner decision pending)

- The consensus-pinned kernel carries a developer's local path, and its id
  depends on the symbol table's size. Reproduction therefore needs a Windows
  host and the canonical path (staged on CI).
- A platform-neutral kernel would take one consensus change, bundled with any
  other kernel change (PX-F4, PX-F5) so the network identity changes only once:
  - strip the symbol table (`-Clink-arg=--strip-all`);
  - remove the panic paths (neutral remapping, or no panic messages in `px-core`);
  - ideally keep the ELF header out of the id: a linker script, or an id rule
    that ignores bytes outside the sections.
- That changes the kernel's id, which needs a new testnet identity and the
  owner's decision.
