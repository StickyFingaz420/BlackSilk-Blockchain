# Testnet v3 genesis: procedure and rationale

**No v3 genesis exists.** The v3 work is on `rebuild/core` (the former
`v3/candidate` branch was merged in `9e422d8` and deleted); current status:
[STATUS.md](STATUS.md). The genesis is generated at launch, after the protocol
freeze, with the owner, by the procedure below. The tool (`tools/genesis`) and its
tests exist; the constants in `consensus/src/params.rs` are still those of the
retired v2 identity, and no beacon is committed (`ChainParams::genesis_is_final` is
false), so `--network testnet` refuses to start.

This is internal engineering work, not an audit. Source: the R15 review §4 (the
procedure), R15-3 and R15-4, and the SX1 cross-review.

## 1. Why a v3 identity exists

1. **No pre-mining.** Under v2 the genesis was fixed in the source ahead of
   launch, so anyone with the source could mine before the launch. The v3
   genesis nonce is derived from a Bitcoin block hash that does not exist when
   every other field is announced. Nobody, the maintainer included, knows the
   genesis id, and so the first RandomX key, before that block is mined.
2. **A clean launch point.** The testnet starts from an empty chain with every
   rule of this tree active from height 0. No v2 block, transaction or wallet
   file carries over (the reset plan applies).
3. **One identity for every identity-changing change.** Each of these changes the
   chain's identity (the genesis id, the consensus fingerprint, the PX kernel id,
   or every signature):
   - the upgrade mechanism and the branch id in every signature message;
   - the deploy rules;
   - the PX kernel change (PX-F5);
   - the canonical FRI schedule and the circuit tag in the proof transcript;
   - the platform-neutral kernel build (new kernel and vault ids).

   They are bundled so that the network changes identity once. After v3, rule
   changes arrive by activation height (docs/consensus.md §11), not by a new
   genesis.
4. **Deterministic, reproducible construction.** The genesis is a pure function
   of announced inputs and one public beacon. Anyone can recompute it with any
   Blake2b implementation; nothing depends on trusting the maintainer.

## 2. Construction

Every field except the nonce is fixed and announced before the beacon:

| Field | Value |
|---|---|
| `version` | the header version of the first epoch (1) |
| `height` | 0 |
| `prev_id` | 32 zero bytes |
| `timestamp` | `T_g`, announced (§4) |
| `difficulty` | `D0`, announced (§5) |
| `tx_root` | 32 zero bytes (the empty body; docs/blocks.md §3) |
| `nonce` | derived from the beacon (below) |

```text
beacon = the 32 bytes of Bitcoin block H's hash in DISPLAY order
         (the hex printed by `bitcoin-cli getblockhash H`, decoded left to right)
d      = Blake2b-256("BlackSilk/genesis-nonce/v1" ‖ LE32(network_id) ‖ LE64(H) ‖ beacon)
nonce  = LE64(d[0..8])
id     = Blake2b-256("BlackSilk/block-id" ‖ LE32(network_id) ‖ header bytes)
```

- The domain string, the network id and the height make the derivation
  single-purpose.
- **Display order** is the hex people see. Bitcoin stores the hash reversed
  internally. Using the reversed bytes gives a different nonce; a test pins that
  (`tools/genesis/tests/genesis.rs`).
- The genesis is never validated (docs/blocks.md §3), so any nonce is legal.
  64 bits of beacon-derived entropy mean a guess succeeds with probability 2⁻⁶⁴.
- Biasing the beacon costs a Bitcoin block reward (withholding a found block).

## 3. The network id

The testnet v3 id is **`0x0001D673`**, final (decision "Agent 40"; committed with
fingerprint v3, reviews/v3-consensus-changes.md#fingerprint-v3): it is
`ChainParams::testnet().network_id` and `TESTNET_V3_NETWORK_ID` in `tools/genesis`.
The genesis on it is generated at launch; the id is registered afterwards (step 7).
The known-answer tests use `TEST_VECTOR_NETWORK_ID = 0xFFFFFF00`, reserved for
test vectors and never a network's id. Rehearsal ids are reserved at
`0x0001D6E0`–`0x0001D6EF`.

The tool enforces the reserved ids (`RESERVED_IDS` in `tools/genesis`, RT-FP3):

| Id | Use | `generate` accepts it with |
|---|---|---|
| `0x0001D673` | testnet v3, final | `--final` only |
| `0x0001D6E0`–`0x0001D6EF` | rehearsals | `--rehearsal` only |
| `0xFFFFFF00` | test vectors | never |

`--final` accepts no other id and `--rehearsal` none outside the range; without
either flag, `generate` refuses every reserved id.

- It must not be any id already used (`NETWORK_ID_REGISTRY`: testnet v1
  `0x0001D670`, the 2026-09-25 rehearsal `0x0001D671`, testnet v2 `0x0001D672`,
  mainnet `0x000B1A6C`, regtest `0x00DEB06E`). `generate` refuses them, with any
  flag. `verify` recomputes an unregistered id as given, and accepts a registered
  id only when the recomputed genesis is that built-in network's compiled
  genesis, so after step 7 the testnet genesis still verifies from its announced
  inputs and a retired id's genesis does not.
- A release candidate or rehearsal must use its own id, recorded in the registry
  afterwards. Since R15-3, the genesis id is also bound into the P2P session key
  and the wallet file, so a node or wallet on another genesis with the same id
  still cannot join or reconcile.

## 4. Timing rules (R15-4)

The FTL does not prevent pre-mining with future timestamps: a miner who knows the
genesis at time `t_r` can mine a private chain with timestamps up to the launch
plus 360 s and release it at launch. Its advantage is its hash rate × (launch −
`t_r`). An unpredictable nonce removes knowledge before `t_r`; after `t_r`
everyone is equal. Hence:

1. **`T_g` is fixed before the beacon**: about 2 h before block `H`'s expected
   time (current Bitcoin height plus the remaining blocks, × 600 s). The genesis
   is then already in the past when anyone can compute it. `generate` refuses a
   `T_g` later than the current time.
2. **Never `T_g` after the beacon.** That opens a window in which anyone who
   knows the beacon mines future-timestamped blocks until `T_g`.
3. **Keep reveal → start short.** Target: all operators mining within 1 h of
   `H + 6`.
4. If `H` arrives unusually early (before `T_g`), wait: the window is then at
   most about 2 h of equal-access mining, acceptable for a trusted trial.
5. The Bitcoin block's own timestamp plays no role (it may be 2 h off).
6. **Cost:** block 1 comes ≥ 7 200 s after `T_g`. LWMA caps the solve time at
   6T = 720 s, so block 2's difficulty is ⌊D0·120·2 / (2·720)⌋ = 16 for D0 = 100,
   and it rises again within the window. A test covers this gap
   (`genesis_to_launch_gap_is_absorbed_by_lwma`).

## 5. Starting difficulty `D0` (SX1)

`D0` is set from the **measured** honest hash rate, erring low:

```text
D0 = max(1, floor(honest_hash_rate × T / 2))
```

(`blacksilk-genesis difficulty --hashrate-mhs <milli-hashes/s>`). A block at
difficulty `D` takes `D` hashes on average, so honest miners find block 1 in
about T/2. A `D0` that is too high stalls block 1, because LWMA cannot lower it
until blocks arrive; one that is too low only makes the first blocks fast. The
rate must be measured on the trial machines with real RandomX (R15 §3 C) before
the announcement; it is an input, not a constant of the tool.

## 6. Steps

1. **Freeze** every non-beacon field (release candidate, signed tag): network id,
   `T_g`, `D0`, `H`, the derivation (this document), with `GENESIS_NONCE` a
   placeholder and `--network testnet` refusing to start.
2. **Announce** ≥ 48 h before `H`'s expected time: this document, the values, the
   confirmation rule (block `H` once it has 6 confirmations) and the fallback (if a
   reorganization replaces `H` before 6 confirmations, use the new block at
   height `H`; nothing else moves).
3. **Wait for `H + 6`.** Two people, the owner and one operator, independently
   obtain `H`'s hash from at least two sources and compare.
4. **Compute,** with a binary from a plain release build of a clean checkout of
   the release-candidate tag (never one written by `cargo test`, docs/testnet.md
   §2), whose `--version` prints `build flags: none`:
   ```sh
   bash tools/release-build.sh -p blacksilk-genesis
   bash tools/check-build-flags.sh --strings target/release/blacksilk-genesis
   target/release/blacksilk-genesis generate --final \
     --network-id 0x0001D673 --timestamp <T_g> --difficulty <D0> \
     --btc-height <H> --btc-hash <hash, display order>
   ```
   The tool refuses to run when it was built with test-only code (exit status
   2), and its build refuses `--cfg fuzzing`.
   (A rehearsal uses `--rehearsal` and an id of `0x0001D6E0`–`0x0001D6EF`.)
   It prints the nonce derivation, the header, its 100 bytes, the full id and the
   constants to paste. Both people compare the full id.
5. **Commit** the final values only: the nonce, the beacon hash (for provenance),
   the pinned genesis id and fingerprint (the committed beacon makes
   `ChainParams::genesis_is_final` true), and docs/testnet.md §1 (the network id
   and time; ids and fingerprints are referenced there, never copied).
   `git diff <rc-tag> HEAD` must show only these.
6. **Operators** verify the tag and the diff, re-run
   `blacksilk-genesis verify ... --expected-id <id>` from the announced inputs,
   build the node with a plain `cargo build --release` from the tag and check
   that `blacksilk-node --version` prints `build flags: none`, start the node,
   check that `/info` shows the full announced `genesis_id`, then
   start miners.
7. **Retire** the id in the registry. Never reuse it, the release candidate's or
   any rehearsal's. `verify` keeps accepting the launched testnet's genesis
   (a registered id whose genesis is the compiled one); `generate` refuses the id
   from then on.

**Anyone, later:** `verify` needs only the announced inputs and a public Bitcoin
hash. Without the tool:
`printf 'BlackSilk/genesis-nonce/v1' ; <LE32 id> ; <LE64 H> ; <32 hash bytes>`
into `b2sum -l 256`, then the first 8 bytes little-endian.

## 7. Bugs this procedure avoids (R15 §4.3)

- Byte order: display order, tested against Bitcoin block 0 and its reversal.
- Hex versus bytes: the 32 decoded bytes are hashed, not the ASCII.
- Nonce extraction: little-endian `d[0..8]`, tested.
- Grinding after the reveal: every field but the nonce is announced; any change
  after the reveal voids the procedure. The tests assert every genesis field.
- Showing only an 8-byte prefix: operators compare the full id.
- Time zones: `T_g` is Unix seconds.

## 8. Tests (`tools/genesis`)

- Known-answer vector: Bitcoin block 0 (`000000000019d668…8ce26f`), `H = 0`, the
  test-vector id; the nonce is pinned.
- The reversed byte order gives a different nonce.
- Every genesis field asserted (version 1, height 0, zero parent and root, the
  given timestamp and difficulty, the derived nonce).
- Registry: the testnet v3 id is not a used id; every used id is refused by
  `generate` with any flag (`used_network_ids_are_refused`).
- Reserved ids: `--final` only for `0x0001D673`, `--rehearsal` only for the
  range, the test-vector id never (`reserved_ids_need_their_purpose`).
- Build guard: a binary with test-only code refuses to run, and `--version`
  names it (`a_marked_genesis_tool_refuses_to_run`, `src/main.rs`).
- `verify` accepts a registered id only for a built-in network's compiled genesis
  (`verify_accepts_a_registered_built_in_genesis`, simulated on the test-vector id).
- `generate` refuses a future timestamp; `verify` refuses a wrong id.
- The starting difficulty from a measured rate (err low), and the genesis gap.
