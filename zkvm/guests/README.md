# BVM-1 guest programs and their reproducible build

This workspace builds the programs that run inside the zkVM
(`riscv32i-unknown-none-elf` with Zmmul, docs/zkvm.md §4). Two are pinned by id:

| Guest | Pinned binary | Pinned id | Role |
|---|---|---|---|
| `kernel` | `px/kernel.elf` | `px/kernel.id` | **Consensus.** Every PX transaction proves this program (docs/px.md §4.3) |
| `vault` | `px/vault.elf` | `px/vault.id` | The reference contract (demonstration only), registered by a deploy |
| `sum`, `arith` | `zkvm/tests/fixtures/` | — | Test fixtures |

A **program id** (docs/zkvm.md §3) commits to the entry point, the code and the
file-backed bytes of every loadable data segment. Since the testnet v3 rebuild the
guests are linked with **`guest.ld`**: the sections start at `0x10000`, so no
loadable segment covers the ELF header or the program headers (the first `PT_LOAD`
is at file offset `0x1000`), and `.comment` is discarded. The id therefore covers
only loaded code and data, and no byte of the file depends on the host (CI-1, "Header
bytes in the id"). `px/tests/elf_paths.rs` pins both properties.

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
- Target flags: static relocation, `+zmmul`, **`-Clink-arg=--strip-all`** and
  **`-Clink-arg=-Tguest.ld`** (the link layout; cargo runs rustc, and rustc runs
  LLD, in this directory, so the relative path resolves here and no absolute path
  enters the ELF). **`build.sh` is the single source** (`GUEST_FLAGS`).
  `.cargo/config.toml` repeats them for ad-hoc `cargo build` runs here, and the
  scripts fail if the two differ.
- `Cargo.lock` here is tracked, and the build uses `--locked`. The guests have
  no external dependencies. The id tool is also built with `--locked`.
- The scripts refuse to run when any of these is set: `RUSTC`, `RUSTC_WRAPPER`,
  `RUSTC_WORKSPACE_WRAPPER`, `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`,
  `CARGO_BUILD_RUSTFLAGS`, `CARGO_BUILD_TARGET`, `CARGO_BUILD_RUSTC*`,
  `CARGO_PROFILE_*`, `CARGO_TARGET_RISCV32I_UNKNOWN_NONE_ELF_*`.
- They also refuse cargo configuration files that would change the build
  (CI-6). Cargo merges every `.cargo/config[.toml]` from this directory up to
  the filesystem root, then `$CARGO_HOME/config[.toml]`. Except for this
  directory's own `.cargo/config.toml`, none of them may contain:
  - `[profile.*]` tables or `profile.*` keys (config profiles override
    `Cargo.toml`);
  - `build.rustc`, `build.rustc-wrapper` or `build.rustc-workspace-wrapper`
    (for example sccache);
  - `[target.riscv32i-unknown-none-elf]` or `[target.'cfg(...)']` tables;
  - `[patch.*]` tables or path overrides (`paths = [...]`).

  `rustflags` elsewhere are harmless: the flags the scripts pass take
  precedence over every config `rustflags`. The check reads lines, so a file
  that only mentions such a key can be refused too; move it aside for the
  build. CI runs a self-test of this check
  (`.github/scripts/guests-config-selftest.sh`).
- **The toolchain manifest is pinned** in `toolchain.sha256` (CI-13). rustup
  checks each download only against the channel manifest from the same
  server, so the repository records:
  - the sha256 of the published `channel-rust-1.98.1.toml`;
  - the riscv32i `rust-std` archive hashes it lists (the precompiled `core`
    and `compiler_builtins` in every guest).

  Source (2026-09-27): `https://static.rust-lang.org/dist/channel-rust-1.98.1.toml`,
  whose `.sha256` file and a local `sha256sum` agree. The dated
  `2026-09-03/channel-rust-stable.toml` has the same hash. The rust-std lines
  are identical in that manifest and in rustup's own copy.
  - On every build, the scripts check rustup's copy of the manifest
    (`<sysroot>/lib/rustlib/multirust-channel-manifest.toml`) against the
    pinned rustc release and rust-std hashes. rustup rewrites that copy, so
    its own sha256 is not the published one.
  - With `GUEST_VERIFY_MANIFEST_ONLINE=1` (CI), they also download the
    published manifest, check its sha256, and check that rustup recorded the
    same rustc package hash for this host.
  - A rustc not installed by rustup has no manifest. The scripts then warn, or
    stop when `GUEST_REQUIRE_MANIFEST=1` (CI).
- `sha256sum`, `shasum -a 256` or `openssl dgst -sha256`: whichever the host
  has (CI-17; stock macOS has no `sha256sum`).
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
   (Since the v3 rebuild the ELF header is not loaded at all, see CI-1.)

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

**Verified (2026-09-27, V3-B, the pre-rebuild layout), all with rustc 1.98.1 on
Windows:**

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
- **Linux did not reproduce these ids (CI-1).** CI rebuilt both guests on
  `ubuntu-latest`. The loaded sections matched, but the files did not: the
  Linux `.comment` differs, and through the ELF header that changed the id.
  Fixed by the link layout of the single v3 rebuild (below).

**The single v3 rebuild (2026-09-28, W1-CB-B2).** One rebuild of the kernel and the
vault carries every guest-affecting v3 item: `ApprovalConflict` in the kernel
(F-20-1), the call ABI and validity-window prefix and the vault's timeout, refund and
contract-bound locks (F-28-1, PX6, W28-4), and the `guest.ld` layout (CI-1). The
pinned ids are in `px/kernel.id` and `px/vault.id`; the record, with the ids and the
ELF hashes, is docs/reviews/v3-consensus-changes.md, section `guest-rebuild`.
`reproduce.sh` ends with one `SUMMARY` line per guest (host, id, sha256, size), and
CI turns them into a notice annotation on each of the windows, ubuntu and
ubuntu-arm legs, so the three hosts can be compared without the job logs.
- Reproduced on Windows (rustc 1.98.1, `x86_64-pc-windows-gnu`) from a fresh target
  directory, byte-identical to the committed ELFs.
- Not yet shown here: the Linux x86_64 and arm64 legs (CI, after the push) and an
  operator build.

Previous ids: testnet v2 kernel `e55c1d2a…`, vault `be646844…`; the pre-rebuild
neutral build kernel `0577e667…`, vault `666f7aab…`.

## Procedure

```sh
bash zkvm/guests/reproduce.sh  # rebuild kernel and vault; compare ids and bytes
bash zkvm/guests/build.sh      # rebuild every guest and copy it over the pinned binaries
```

- `reproduce.sh` checks, for the kernel and the vault:
  - the rebuilt id equals `px/*.id`;
  - the committed `px/*.elf` has that id too;
  - the rebuilt ELF is byte-identical (sha256) to the committed one.

  It exits non-zero on any mismatch, and prints a `SUMMARY` line per guest. CI runs
  it on Windows, Linux x86_64 and Linux arm64 for every push
  (`.github/workflows/ci.yml`, job `guests`).
- `.gitattributes` marks `*.elf` binary and `*.id` `-text`, so no checkout
  converts them.
- A changed kernel id is a consensus change: it needs the owner's approval and a
  new testnet identity.

## The toolchain is part of the identity (CI-7, accepted limitation)

The pinned ELFs are the output of one exact toolchain: rustc 1.98.1
(`48a229cea`), its LLVM and LLD, and its precompiled riscv32i `core` and
`compiler_builtins` (pinned in `toolchain.sha256`). Any other compiler
release, even with identical source, may emit other code, and so another id.
Therefore:

- **The guest toolchain never changes within a program identity.** A new
  rustc for the guests means a rebuild, new ids and a new testnet identity,
  like any other kernel change.
- Before the v3 rebuild the id also bound the toolchain in a way that was not
  about code at all: the ELF header was loaded, so the toolchain's identification
  strings in `.comment` reached the id (next section). The `guest.ld` layout
  removes that effect. It does not remove the first point.
- The host toolchain (the node, the prover) may change freely. It only reads
  the pinned ELF.

## Header bytes in the id (CI-1): fixed by the v3 rebuild

**Problem.** A program id covers the file-backed bytes of every `PT_LOAD`
segment. LLD's default layout starts the first `PT_LOAD` at file offset 0, so
the ELF header and the program headers are part of the id. The ELF header
holds `e_shoff`, the offset of the section header table, which lies after the
non-loaded sections. So every non-loaded byte before that table moves the id.

`.comment` is such a section. It holds rustc's and LLD's identification
strings, and they differ by host distribution:
- The Windows build (committed): `rustc version 1.98.1 (48a229cea 2026-09-01)`,
  then `Linker: LLD 22.1.8 (https://github.com/rust-lang/llvm-project.git 52ed14fc…)`.
- The Linux build (CI): the LLD string first, with the source path
  `/checkout/src/llvm-project/llvm` instead of the URL. That is 14 bytes
  shorter, so `e_shoff` moves.

So the same rustc release, producing the same code, gives a different id on
Linux.

**Decision (coordinator, CI-1):** make the id independent of every non-loaded
byte before the single v3 rebuild. Two ways were tested with rust-lld 22.1.8
(rustc 1.98.1). The tests used a scratch copy of the repository, and no ELF
was committed. Method: build the kernel and the vault; then rewrite the
`.comment` of each result exactly as Linux differs (the same strings, 14
bytes shorter, every later offset shifted); then compare the ids from
`cargo run -p blacksilk-zkvm --example program_id`.

| Layout | Headers in a `PT_LOAD` | `.comment` | Id after the Linux-style `.comment` rewrite |
|---|---|---|---|
| current (LLD default) | yes, offset 0 | kept | **changes** (reproduces CI-1) |
| (a1) `-Clink-arg=--nmagic` | no (first `PT_LOAD` at offset `0xb4`) | kept | unchanged |
| (a2) linker script, see below | no (first `PT_LOAD` at offset `0x1000`) | kept | unchanged |
| (a2) plus `/DISCARD/ : { *(.comment) }` | no | **removed** (rustc's and LLD's) | not applicable; the id equals (a2) without the discard |

**(a) Keep the headers out of every `PT_LOAD`.** This works, in two variants:
- **(a1) `--nmagic`**, a single flag. LLD then stops page-aligning segments,
  and the headers are not loaded. The file still contains `.comment`, so the
  files still differ between hosts while the ids agree. `reproduce.sh` would
  have to compare ids and loaded bytes instead of whole files.
- **(a2) a linker script** (`-Clink-arg=-T<file>`, a new tracked file here). It
  places the sections from `0x10000`, a page boundary. The headers then do not
  fit below the first section, and LLD leaves them out of the first `PT_LOAD`
  (observed in the builds above; without `PHDRS`, LLD loads the headers only
  when they fit below the first section in the same page).

  ```
  SECTIONS
  {
    . = 0x10000;
    .rodata : { *(.rodata .rodata.* .srodata .srodata.*) }
    .eh_frame : { KEEP(*(.eh_frame)) }
    .text : { *(.text .text.*) }
    .data : { *(.data .data.* .sdata .sdata.*) }
    .bss : { *(.sbss .sbss.* .bss .bss.*) }
    /DISCARD/ : { *(.comment) }
  }
  ```

  Cargo runs rustc from this directory, and rustc runs LLD there, so a path
  relative to this directory works in `GUEST_FLAGS` and
  `.cargo/config.toml`. The absolute path never enters the ELF.

**(b) Remove `.comment`.** There is no stable rustc option for this, and
rust-lld 22.1.8 has no flag for it (checked with `rust-lld -flavor gnu
--help`). It works through the linker script's `/DISCARD/` rule, which drops
rustc's string and LLD's own. `rust-objcopy --remove-section .comment` (shipped
with rustc) would also work, but as a post-link rewrite. Removing `.comment`
while the headers are still loaded would make the id depend on the remaining
non-loaded sections instead: fragile, and not a fix on its own.

**Recommendation: (a2) with the `/DISCARD/` rule.** The ids no longer depend on
any non-loaded byte. There are no toolchain strings left, so the whole file is
expected to be byte-identical on every host, and `reproduce.sh` keeps its
byte comparison. The id definition in zkvm (docs/zkvm.md §3) does not change.
The ids change once, with the single v3 rebuild that is already planned.

Evidence (scratch builds, Windows):
- (a2) kernel and vault pass `px/tests/kernel.rs` (6 tests, native = guest),
  `px/tests/elf_paths.rs` (2) and, with the relinked fixtures,
  `zkvm/tests/guest.rs` (5).
- `Program::from_elf` accepts all four relinked guests.
- Not yet shown: the cross-host byte identity of (a2). That needs the CI legs
  at the rebuild commit.

**Done at the rebuild (W1-CB-B2):** the test that no pinned ELF has a `PT_LOAD`
covering the headers and that none has a `.comment`
(`px/tests/elf_paths.rs::pinned_guests_load_no_header_and_carry_no_comment`); the
flag in `GUEST_FLAGS` and `.cargo/config.toml` and the script file `guest.ld`; the
kernel budgets re-measured (unchanged, still within 95%); the test fixtures `sum`
and `arith` relinked with the same layout. **Still owed:** CI green on the two
Linux hosts [coordinator, after the push] and one operator build [owner].

**Fallback.** If a later toolchain cannot be made to keep headers out of
`PT_LOAD`, change the program-id definition itself: hash each `PT_LOAD`'s
bytes minus any part that overlaps the ELF header or the program header
table. That is a consensus change to zkvm's id rule. It would be recorded in
`docs/reviews/v3-consensus-changes.md`, and the coordinator has said it would
approve it for the v3 rebuild. It is not needed with (a2).
