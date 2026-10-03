# Windows release build: reproducibility and build paths (W4-GUARD)

Internal engineering evidence, not an audit. One Windows 10 machine, one user,
rustc 1.98.1, x86_64-pc-windows-msvc, commit `6760831` (branch w4-guard). It shows
that two release builds of one commit on this machine give the same bytes, and that
`tools/release-build.sh` keeps the build user's home directory out of the binaries.
It does not show reproducibility across machines, users, toolchain installs or
operating systems (docs/STATUS.md).

## Before

Two plain `cargo build --release` runs of one commit differed in 24 bytes, all
written by the MSVC linker: the COFF time stamp, the time stamps of three
debug-directory entries and the PDB GUID
([labnet-w4 README](../labnet-w4-2026-09-30/README.md) §1.1). The node, miner and
wallet also embedded the build user's home directory in the panic locations of
registry crates (`C:\Users\<user>\.cargo\registry\src\...`); the genesis tool has
no registry dependency with such a string.

## Builds

Four builds of `6760831`, each from a clean checkout into an empty target directory,
`CARGO_BUILD_JOBS=2`, `CARGO_INCREMENTAL=0`, no `RUSTFLAGS` or `BLACKSILK_*`
variable, packages `-p blacksilk-node -p blacksilk-miner -p blacksilk-wallet -p
blacksilk-genesis`:

| Build | Checkout | Command |
|---|---|---|
| A | `C:/bszkeval/wt-w4-guard` | `bash tools/release-build.sh <packages>` |
| B | `C:/bszkeval/wt-w4-guard-repro` (a second worktree) | `bash tools/release-build.sh <packages>` |
| C | `C:/bszkeval/wt-w4-guard` | `cargo build --release --locked <packages>` |
| D | `C:/bszkeval/wt-w4-guard-repro` | `cargo build --release --locked <packages>` |

SHA-256 (`sha256sum`):

| Binary | A and B (release-build.sh) | C and D (plain, `-Brepro` from `.cargo/config.toml`) |
|---|---|---|
| `blacksilk-node.exe` | `f0ef057d973aa60340d578019e6636036a112cca3fac94361e93414b75ba5346` | `d64a52161c41f9fe9632a845c0ade5ac32edf64eef339fb3f530d89d8a86283d` |
| `blacksilk-miner.exe` | `10860730e5880b775110c70835a767cb80bf5caf0815b8d7ca7429a40dd6dbfa` | `bdb30534e8906a756978676d3833111a94761b1bc0eab03ae4838c0790673568` |
| `blacksilk-wallet.exe` | `94cac10ef02414ad4f72714a4c15763ee2be03ca6d4c9c2fa9de2af91ad8ffb8` | `ead8a0e81d663d796fd4e8fcf9900576d12526b6070b408ab5e2bc942d80c841` |
| `blacksilk-genesis.exe` | `628d690cd8d8d6fc1c7a749a3409146cf0814feaf8b9a8c1d49131a2dfac999c` | `628d690cd8d8d6fc1c7a749a3409146cf0814feaf8b9a8c1d49131a2dfac999c` |

- A equals B and C equals D for every binary: the same commit gives the same bytes,
  whatever the checkout path and target directory.
- A differs from C for the node, miner and wallet: the release build remaps the
  paths (not analysed byte by byte). The genesis tool is the same in all four
  builds.

## Paths

String scan of build A (`grep -aoE '[ -~]{4,}' <binary>`): no string contains the
user name or `C:\Users` in any of the four binaries. The registry panic locations
read `/cargo\registry\src\...` (230 in the node), the standard library's
`/rustc/<commit-hash>/library\...` (as shipped by rustup).

## Fingerprints

`--print-manifest` of build A for testnet, regtest and mainnet, compared with a
plain build of the base commit `11cb583`: only the header line (the build commit)
differs and the `# build flags: none` line is added; every rules, identity and
consensus digest and both encodings are identical. `--version` likewise differs
only in the commit line and the added `build flags: none` line. Linker flags and
path remapping change no digest: the digests are computed from the rules at run
time.

## Limits

- One machine and one user: the remapped build should not depend on either, but
  that is not shown here. The plain build (C, D) depends on the user name.
- Linux and macOS builds are not covered (no `-Brepro` there; their linkers write
  no time stamp by default, unverified here).
- Paths other than CARGO_HOME, the sysroot and the checkout (a different
  CARGO_TARGET_DIR is shown harmless above) are not remapped.
