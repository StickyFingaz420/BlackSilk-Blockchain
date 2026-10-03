# TM2-X: cross-challenge of threat-model round 2

Agent TM2-X, phase 2, 2026-10-02. This is an internal engineering review, not an audit. It
does not claim that BlackSilk is secure, private, production-ready or audited. Zero
knowledge is described only as statistical and conditional (computational in practice).

## 0. Scope, method, limits

- **Code:** local `rebuild/core` at **a144d94** (clean tree), read-only. The three reports
  were written at 3c21afe. The only commit since then is a docs commit (decisions), so
  every code reference below holds for both.
- **Nothing was modified, and nothing was built or run.** No worktree was created. Every
  claim is tagged:
  - **[src]**: read in the source;
  - **[test: name]**: a test exists (not run by me);
  - **[ev]**: committed evidence;
  - **[r]**: reasoning.
- **Read:**
  - `brief.md`;
  - `decisions.md` (the sections cited below, including "Threat model round 2", lines
    1100-1123);
  - round 1 (`48-threat-model-adversarial.md`, via the reports and decisions);
  - `tm2-privacy.md`, `tm2-consensus.md` and `tm2-network-ops.md`, in full.
- **Code re-read for this cross-check:**
  - `p2p/src/net/{relay,stem,admission,maintenance,headers,blocks,state,conn,peers}.rs`
  - `p2p/src/{limits,dandelion,originated,message}.rs`
  - `chain/src/{mempool.rs,sync_policy.rs,manager/replay.rs}`
  - `tx/src/params.rs`
  - `zkvm/src/prove.rs` and `zkvm/tests/vm.rs`
  - `wallet/src/{main.rs,file.rs,wallet/px_flows.rs}`
  - `miner/src/{main.rs,lib.rs}`
  - `node/src/config.rs` and the node's logging sites
  - `rpc/src/lib.rs` (`Info`)
  - `tools/supply-audit/src/lib.rs`
  - `deploy/systemd/blacksilk-node.service`
  - `docs/testnet.md` (§7.1 and the PSK row) and `docs/testnet-incident-response.md` §5
  - `docs/evidence/daa-sim-2026-09-27/{redteam,results}.md`
- **Naming.** The consensus report and the network report both use `TM2-1` to `TM2-10` for
  different findings. To avoid collisions this document uses:
  - **C-n** for the consensus report (C-1 = its TM2-1, the AIR census);
  - **N-n** for the network report (N-1 = its TM2-1, signing; the DoS items keep their
    own names D1 to D5);
  - **P-Pn** for the privacy report.

  The task's "TM2-1 / TM2-4 / TM2-5" are C-1, C-4 and C-5.

---

## 1. Verification of the top findings

Verdicts:
- **Confirmed:** the code does what the report says.
- **Adjusted:** the mechanism is right, but the severity, scope or fix changes.
- **Refuted:** the mechanism does not hold.

### 1.1 P-P1: the origin re-announces one block early. CONFIRMED, and WIDER than reported (the proposed fix is incomplete)

**Evidence [src]:**
- `p2p/src/net/relay.rs:117-121`: `anchor = originated.relayed(id).map_or(admitted, |r| r.min(admitted))`.
- `p2p/src/net/stem.rs:234-242`: `relayed = c.height() + 1` is recorded *before* the stem.
- Every other node's `admitted` is the next height when it pools the transaction at the
  fluff (`chain/src/mempool.rs:185-187`, `admitted_at` `:596`).
- The schedule runs once per new height (`p2p/src/net/maintenance.rs:283-287`), only for
  transactions in the next template (`relay.rs:94-108`).

The block-during-stem case is exactly as the report states.

**Narrower than stated:**
- `reannounce_pool` only re-announces transactions *in the node's next template*
  (`relay.rs:99-106`). A PX transaction kept out of templates by congestion (3 per block)
  is re-announced by **no** node.
- The leak therefore needs a transaction that is in the templates but still unmined at
  age 10. This happens when the actual miners lack it, or when a miner excludes it.
- In the 7-device trial, with consistent pools, that is rare. So the report's "PX
  congestion" trigger is wrong; a censoring miner is the realistic one.

**Wider than stated (new, X6): reorg readmission.**
- A transaction returned by a disconnected block is readmitted with `admitted = next` at
  the *reorg* height on every node [test:
  `chain/src/mempool.rs::returned_transactions_are_readmitted_without_verification`,
  line 2545 asserts `admitted_at == next`].
- The origin keeps its old `relayed` in the originated set. That entry lives until
  `relayed + 2190` (`p2p/src/originated.rs:98-105, 138-145`), and the anchor takes the
  min, so the origin anchors on its old relay height while everyone else anchors on the
  reorg height.
- **Examples:**
  - Relayed for R, mined at R+1, reorged out by a branch that reaches R+12: the origin's
    age range at the next tick covers 10, so it re-announces **immediately after the
    reorg**, and no other node does.
  - A shallower reorg moves the origin's point ahead of everyone else's by
    (reorg height − R).
- **Who can trigger it:**
  - an attacker with majority hash rate (K1, accepted on the testnet: "any depth, at
    will") can reorg out a target's block and then keep excluding it;
  - a natural 1-2 block reorg leaks only if the transaction then stays unmined for about
    10 blocks.
- This is a consensus or liveness event that deanonymizes. No single-lens reviewer
  covered it.

**The proposed fix is incomplete.**
- P-P1 proposes anchoring on "the height at which the origin first saw its transaction
  in fluff, persisted", combined with the min.
- After a reorg, `min(fluff_seen, admitted)` is still the old `fluff_seen`, so the reorg
  variant survives that fix.
- **Correct rule:**
  - the origin uses `admitted`, exactly like every other node;
  - **except** when its pool entry came from the `Verdict::Held` path after a restart
    (`stem.rs:209-223`). Only there does it use the persisted fluff-seen height, which is
    what the `relayed` term was protecting.
  - A readmission after a reorg must always use the readmission height.

**Tests (both must fail first):**
- `a_block_found_during_the_stem_does_not_make_the_origin_reannounce_first`;
- `a_reorg_that_returns_an_originated_transaction_does_not_make_the_origin_reannounce_first`.

**Severity:**
- trial: Medium (an insider with most of the trial's hash rate can trigger it);
- public: **High**, L4 × I4 under K1.

P0-genesis, S, already in TM2-P2P (the reorg variant must be added to that task).

### 1.2 P-P4: black-holing PX stems. CONFIRMED; cost model added; a v1 analogue exists (X1)

**Evidence [src]:**
- The node-wide PX token is taken only after the cheap checks (`admission.rs:206-219`):
  structure, balance, proof decode, `revalidate_after_extension` (anchor, nullifiers,
  registry, pool) and proof shape.
- A per-peer budget excess on a `StemTx` is dropped unscored and not fluffed
  (`admission.rs:134-144`; `limits.rs:90-116`).
- The node-wide bucket holds 2/s with a burst of 10 [test:
  `the_node_wide_px_bucket_has_burst_10_and_rate_2`]. A zero-v1-input PX transaction
  with fresh random nullifiers, a public anchor and a well-shaped junk proof passes every
  pre-token check.

**Cost, which the report omits:**
- Each fake fails full verification as a stateless `PxProof` and is scored
  `INVALID_TX = 20` (`limits.rs:16`). A clearnet identity therefore lasts 5 fakes before
  a 24 h ban.
- Keeping one relayer drained needs 2 fakes/s, which is 0.4 new IPv4 identities per
  second per relayer, or free over Tor inbound (proxied peers are never banned,
  `peers.rs:68-73`).
- Each fake also costs the victim a full PX verification (about 0.2 s), so the attack
  doubles as CPU DoS.
- To hit an unknown first hop the attacker must drain the victim's outbound peers, or all
  reachable nodes. That is cheap on a small public testnet and expensive on a large one.

**Severity:**
- trial: Low (the PSK keeps attackers out);
- public: **High**, provided the network is small. Kept.

**X1 (new, cross-lens): the same black hole for v1 through the Tx lane.**
- Relayed transactions are verified with `try_call` on the chain actor's Tx lane
  (capacity 64), and **dropped when the lane is full** (`admission.rs:411-425`).
- An honest `StemTx` dropped there is neither stemmed nor fluffed, so the origin's
  embargo fires first.
- The network report's D5 is exactly a Tx-lane flood: young-ring invalid CLSAGs, unscored
  (`admission.rs:341-355`), bypassing `ctx_rejects` by re-randomization (`:61-73`), about
  50 verifications/s per peer.
- So D5 is not only "relay liveness": it is a **PoW-free, fee-free origin-deanonymization
  lever for v1**. P-P4's fixes (local re-stem on the first expiry, 33 W3) bound both
  variants; the D5 budget alone does not.
- **Severity (P):** High. P1-public.

### 1.3 P-P5: Tor mode. CONFIRMED in code; impact ADJUSTED

**Confirmed [src]:**
- With a proxy, every outbound dial goes through SOCKS (`peers.rs:343-353`).
- Onions are skipped only when there is *no* proxy (`peers.rs:440`), so there is no
  onion-only outbound, contrary to decisions "Agent 32".
- `--proxy` alone listens on 0.0.0.0 and resolves seeds with system DNS
  (`node/src/config.rs:292-308, 405-416`).

**Adjusted impact:**
- An exit node that MITMs a clearnet-over-Tor link reads the Tor node's `StemTx`, but it
  does **not** learn the Tor client's IP.
- What it gets:
  - **pseudonymous clustering:** every transaction the node originates, linked together,
    made worse by the missing stream isolation (several links can share one exit);
  - **eclipse** of those links (the Biryukov-Pustogarov pattern).
- The report's "first-hop origin information about a Tor client" is true but should not
  read as IP deanonymization.
- The dual-homed findings are real IP-linking findings: `--proxy` without `--proxy-only`
  (F33-7), GetAddr mixing, and the new X4 below.
- **Severity (P):** Medium. P1-public.

### 1.4 D4 (N-17), GetTx over 64 ids disconnects honest peers. CONFIRMED (high confidence); also an attacker lever (X3)

**Evidence [src]:**
- `on_inv_tx` requests every unknown id of an `InvTx` (up to 500) in one `GetTx`
  (`relay.rs:151-172`).
- `on_get_tx` pushes one `Tx` per id into the 64-slot control outbox (`conn.rs:49`) in a
  synchronous loop under the state lock (`relay.rs:201-204`).
- `Inner::send` disconnects on the first `try_send` failure (`state.rs:481-494`).
- The writer task drains concurrently, but the loop holds a std mutex and does no I/O, so
  it fills the 64 slots in microseconds.
- **The trigger is common:**
  - more than 64 new transactions inside one trickle interval (mean 2 s outbound, 5 s
    inbound);
  - or one re-announcement of a full template (`relay.rs:126-128`).

**New angle (X3, cross-lens):**
- An attacker connected to honest node H floods H with more than 64 *valid* transactions
  (cheap with testnet coins). H announces them to its peers, and H then disconnects each
  honest peer V that asks for them all.
- If H was V's Dandelion stem peer, V re-draws a stem peer mid-epoch
  (`dandelion.rs:97-128, 150-154`).
- Repeated, this gives an attacker who holds one of V's outbound slots many extra chances
  to become V's stem peer, which defeats the per-epoch route stability Dandelion++
  relies on.

Severity: Medium (trial, evidence integrity); Medium-High (P). P0-genesis, S,
TM2-P2P. "Reproduce first" (decisions) stands; the test should also assert that no
stem-peer change follows.

### 1.5 D1 (junk-PoW header batches). CONFIRMED

**Evidence [src]:**
- An extension of our best chain always reaches the work gate
  (`chain/src/sync_policy.rs:69-71`).
- The first chunk, `pow_chunk = clamp(pow_threads, 1, seed_lag)`
  (`sync_policy.rs:143-146`; the default `pow_threads` is the logical CPU count,
  decisions W4-POWPOOL), is hashed in full (`headers.rs:574-580, 667-674`). Only then
  does the first junk header fail with `InsufficientWork`.
- There is a single header worker. Proxied and onion peers are never banned.

**Precision:** the wall-time cost per batch is about one light hash (about 0.45 s)
however many threads there are; the CPU cost scales with the thread count.
- At about 2 batches/s the single header worker stays saturated whatever the core count,
  and honest tip headers queue behind it.
- The per-origin queue room (2 batches per IP or onion address, `headers.rs:49-59`) does
  not help against many origins.

**Severity:** High (P); closed in the trial **only if the PSK is in force** (see N-2).
P1-public, M.

### 1.6 D2 (no staller detection). CONFIRMED

**Evidence [src]:**
- `schedule_downloads` picks uniformly among peers with `p.height >= height`
  (`blocks.rs:251-262`).
- `p.height` is only ever lowered to our *header* height (`headers.rs:226, 421-440`;
  `maintenance.rs:151`), so a withholding peer stays a candidate.
- A timeout releases the slot and logs at debug only (`maintenance.rs:154-165, 187-192`).
- Decisions "Agent 31" ("Staller disconnects: enforced") is not implemented.

**Severity:** High (P). P1-public, M.

A trial note: honest but slow home links get the same behaviour (random re-pick of a slow
peer), so a mild version affects the trial without any attacker.

### 1.7 C-4: the DAA raising race and park-on-deep-reorg. Mechanism CONFIRMED; the remedy is REFUTED as stated

**Confirmed:** no park code exists. A grep for `park` and `max_reorg` finds only
`DEEP_REORG_WARN_DEPTH = 10` (`chain/src/manager.rs:126`; `fork_choice.rs:314`, warn
only).

**Refuted remedy:**
- The RT-3 figures (+3.5% at q = 0.4, +27.4% at q = 0.45) are measured at **z = 100
  confirmations** (`docs/evidence/daa-sim-2026-09-27/results.md`: "Effect at q = 0.4,
  z = 100").
- The decided park depth is **720** for a public testnet and **OFF** for the trial
  (decisions "Agent 02" W-7).
- A park at 720 never fires on a 100-deep race. The statement "residual to
  park-on-deep-reorg" (redteam.md RT-3; v3-consensus-changes.md §8 line 736; decisions
  lines 208, 599) is therefore **a misattribution in the consensus record**.
- RT-4 (hash-and-leave, up to 18× equilibrium difficulty) happens *after* the attacker's
  chain is accepted, so park does not touch it either.

**Correct framing:**
- The q ≥ 0.4 race residual is accepted under K1 (q = 0.45 is effectively a majority
  attacker on a testnet whose honest hash rate is tiny).
- RT-4 needs an incident-runbook entry (the stall time measured in daa-sim, and the
  response on the testnet: wait, or reset).
- Park stays useful for its own purpose (deep rewrites) as P1-public.

**Actions:**
1. Correct the freeze record now: P0-freeze docs, S. A frozen rule must not rest on a
   remedy that cannot apply.
2. Park itself: P1-public, M.
3. Measure the RT-4 stall: P1-public, S.

### 1.8 C-1: the AIR census. CONFIRMED as a gap; its gate is OVERSTATED

**Confirmed [src]:** `CIRCUIT_DIGEST` is recomputed by evaluating every table's
constraints (`zkvm/src/prove.rs:61-74`; `zkvm/tests/circuit_fingerprint.rs`). A naive
cargo-mutants run would therefore be killed by the pin. W4-MUTAIR excludes it (decisions
line 1104).

**Challenge:**
- A mutation census measures whether **existing** constraints are tested. It cannot find
  a constraint that was **never written**, and that is the RISC Zero CVE-2025-52484 class
  the report cites.
- The repository already has the right kind of probe:
  `every_single_cell_mutation_of_real_cpu_and_memory_rows_is_caught`
  (`zkvm/tests/vm.rs:172-208`) and its ALU twin (`zkvm/tests/alu.rs:249`). But they cover:
  - only the CPU, memory and ALU tables, not Poseidon, byte or program;
  - only real rows, not padding;
  - only single cells with ±1 deltas, so an unconstrained *relation* that needs two
    coordinated cells (for example result and carry) survives.
- **The freeze gate should be "census plus free-witness search", not the census alone:**
  1. extend the single-cell census to every table, padding rows included;
  2. a **lying-generator test**: patch the trace generator to emit a wrong result for one
     opcode or one Poseidon round, regenerate every dependent column honestly, and assert
     that `air::check` fails;
  3. a spec-to-constraint traceability table (RV32 semantics → constraint ids).

Severity High (evidence gap; likelihood unknown). P0-freeze, L, W4-MUTAIR (items 1-3 to
be added).

### 1.9 C-5: `recent_rejects` and the vacuous fee guard. CONFIRMED; scope clarified

**Evidence [src]:**
- `recent_rejects` is keyed by the transaction id only and only FIFO-evicted
  (`admission.rs:18-30`).
- `TxRules::at_height` hard-codes `fee_per_weight: FEE_PER_WEIGHT`
  (`tx/src/params.rs:193-202`).
- The guard test skips every epoch whose fee rule equals the first
  (`tx/tests/upgrade.rs:389-395`), so it can never fail today.

**Realistic failure:** one block of height skew between peers around a fee-changing
activation.
1. Peer A (next = a, new rules) relays a transaction made for the new rules.
2. Peer B (next = a−1) finds it stateless `FeeNotExact`, scores A by 20, and blacklists the
   id.
3. B keeps refusing it after the activation.

This needs byte-identical transactions, which only arise in that skew window (the branch
id in the signature domain differs per epoch). It is a one-epoch-boundary hazard, not a
v3 hazard.

P1, before the first rule-changing activation. S.

### 1.10 Other top findings, briefly

| Finding | Verdict | Note |
|---|---|---|
| P-P2 / N-3 `originated.json` | **Confirmed** (`originated.rs:224-232` plain `File::create`; `docs/testnet-incident-response.md:183-184` asks for "the node's data directory" and logs "at their original level") | N-3's fix (c) (keyed hashes with the key in a 0600 file) protects only against the file leaking **alone**. Backups, seized devices, incident bundles and copied data dirs carry the key too. The docs must say so, and must not claim "a copied file alone reveals nothing" as protection |
| P-P3 decoy distribution from the node | **Confirmed** (`wallet/src/wallet/px_flows.rs:221-231`: the node's `cumulative` drives `usable_outputs` and coinbase maturity; only total and monotonicity are checked) | P0-public (decided) |
| P-P6 slow-lane oracle | Not re-verified beyond the report's citations | P1 |
| N-1 signing / second channel "High (T), blocks launch" | **Adjusted** | What the trial needs is an *authenticated release reference*. A signed tag is one way. A full commit id plus the fingerprints confirmed over two independent channels is another. P0-genesis for the reference; signing itself P1-public (owner) |
| N-2 PSK not required by the trial procedure | **Confirmed** (`docs/testnet.md:260` is the only mention; §12.3, the v3 genesis steps and the checklist do not require it) | Raised: this is the **linchpin**. D1, D2, D3, D5, X1 and T1 are "not trial blockers" only because of the PSK |
| N-4 systemd crash loop (P0) | **Adjusted to P1** | `RestartPreventExitStatus=2 65` confirmed. But the trial devices are "mostly Windows desktops", where the unit does not apply. P0 is only the incident-runbook text for exits 70 and 101 |
| N-5 replay trusts stored PoW (P0) | **Adjusted** (`replay.rs:293` preloads the stored hash) | P0-genesis as a docs rule ("never copy a data directory; resync, the chain is small"); the 48-sample check P1-public. Copying also moves `originated.json` (origin list) and the addrman key to another operator (X8) |
| N-7 overrides not in `/info` (P0) | **Adjusted to P1-public** | Decided P1 (F48-9). The P0 part is the docs rule "no flag or binary from chat without the authenticated reference" |
| C-2 golden PX fixture | Confirmed | P0-freeze |
| C-3 RandomX start-up self-test | Confirmed absent (grep for `self_test` and `randomx-self-test`: none) | Kept at **P0-genesis** (C), against N's P1: the trial runs on heterogeneous Windows devices, and a divergent device splits at genesis |
| C-10 D0 / T_g | Confirmed | P0-genesis |

---

## 2. Cross-lens interactions the single-lens reviews missed

| # | Interaction | Lenses | Mechanism (evidence) | Severity | Fix |
|---|---|---|---|---|---|
| **X1** | Tx-lane flood → v1 stem black hole → origin exposed | DoS → privacy | §1.2 (`admission.rs:411-425`, `:341-355`) | High (P), Low (T with PSK) | local re-stem on the first embargo expiry (33 W3) for v1 and PX; a per-peer unscored-failure budget (N's P1-16); test: lane saturated ⇒ origin is not the first announcer |
| **X2** | PX bucket drain → PX black hole (P-P4) | DoS → privacy | §1.2 | High (P) | as P-P4, plus a per-source share of the node-wide token |
| **X3** | Valid-transaction flood → honest `GetTx` disconnects → stem-peer churn | DoS → privacy | §1.4 | Medium-High (P) | the D4 fix; on a stem-peer loss, keep the epoch's routes for the remaining stem peer instead of re-drawing to a fresh one (33 review) |
| **X4** | **Header tagging links dual-homed identities.** `Version.tip` is the *best header* id and `height` the header height (`conn.rs:161-176`); the `GetHeaders` locator carries the same. One PoW-valid header at tip+1 with its body withheld (D2 keeps it pending; header-first relay does not exist, so it is not propagated) becomes the target's unique best header. Read it back over the target's onion identity | consensus/sync → privacy | [src] | Medium (P, Tor dual-homed); about one block of PoW per tag, cheap under K1 | `Version` carries the body-complete tip (or its parent) and no header height; locators over onion links from the connected chain; test: a withheld-body header never appears in our `Version` |
| **X5** | Induced lag (D1/D2) → the node and its wallets stand out: `Version` height and tip; PX anchor `round_down16(synced − 3)`; no decoys newer than the node's view | DoS → privacy | [src] `wallet/src/px.rs` anchor; `plans_for` uses `synced_height` | Low-Medium (P) | the D1 and D2 fixes; the wallet refuses or warns when the node lags the best header (`--allow-stale-tip` exists, so extend it to header lag) |
| **X6** | Reorg readmission → the origin re-announces early (P-P1 variant) | consensus → privacy | §1.1 | High (P) under K1 | §1.1 rule |
| **X7** | Deep reorg (K1) → orphaned decoys replaced → ring intersection on the rebuilt transaction | consensus → privacy | W-5 reuses rings "as far as members still exist" (`px_flows.rs:211-213`) | Medium (P), accepted (k4-reorg-policy.md) | quantify it in the privacy regression suite; state it in transactions.md §11 |
| **X8** | Operational aggregation: the owner receives incident data dirs (with `originated.json` and debug stem logs), runs the central supply audit (every wallet and password, F48-2), and builds third-party crates on the same workstation (F48-4) | ops → privacy | incident-response §5; testnet.md:498-500; N SC1 | **High (T)**: one compromise deanonymizes the whole trial and exposes every seed | incident bundle = `blocks.dat` plus info logs only; the supply-audit custody as decided (local mid-trial runs, the central run at the end); a separate machine for custody |
| **X9** | Evidence published in a **public** repository: trial logs at INFO carry peer IPs (`conn.rs:366, 519`); the supply-audit JSON has per-wallet rows (name, balances, pending; `tools/supply-audit/src/lib.rs:170-193, 221`) | ops → privacy | [src] | Medium (T) | evidence redaction rule: no IPs, totals only, no debug logs; a CI grep for IP literals in `docs/evidence/` |
| **X10** | Economics of a tiny network: 7 miners own almost every output, so colluding operators eliminate decoys (black marbles by mining); a PX anonymity set of a handful of deposits makes bridge-in to bridge-out matching trivial | econ → privacy | P-report §6 (coinbase-dominated rings, documented in part) | High for privacy claims (T) | docs: the trial demonstrates function, not anonymity; no privacy figures from trial data |
| **X11** | Miner fingerprints: `timestamp = now.max(min_timestamp)` (`miner/src/lib.rs:62`) exposes each miner's clock offset. Together with the block-origin IP (A5, documented) and coinbase ownership, this clusters a miner's blocks | mining → privacy | [src] | Low-Medium | docs (NTP); optional: round stamps to the MTP floor (policy, no rule change). Nonce starts are already random (`miner/src/main.rs:319-323`) |
| X12 | Crash, restart, held transactions | ops → privacy | checked: the originated set is saved before sending (`stem.rs:240-243`); held local transactions wait for a stem peer | **No leak found** | — |

---

## 3. Gaps none of the three reports covered

1. **Wallet keys and seed on disk.**
   - **Good [src]:** Argon2id (64 MiB, t = 3), AES-256-GCM, atomic writes, 0600 on Unix
     (`wallet/src/file.rs:1-44`).
   - **Gap:** any password is accepted, the empty one included (`wallet/src/main.rs:295-309`:
     no length check). The wallet path is user-chosen, and on Windows 11 Desktop and
     Documents are OneDrive-synced by default (Known Folder Move). A weak password plus a
     cloud-synced wallet file gives the seed to an offline attacker.
   - **Fix:**
     - refuse an empty password, and warn below about 12 characters (P1-public, S);
     - add "never in a synced folder" to the F48-7 endpoint checklist (P0-genesis docs).
   - The node data dir defaults to roaming `%APPDATA%` (`node/src/config.rs:264-268`).
     Roaming profiles on domain machines copy `originated.json` and the cookie off-device.
     P2 (prefer `%LOCALAPPDATA%`; docs now).
2. **The RPC as a privacy surface.**
   - **Covered by the reports:** remote-node trust (`/distribution` and `/tx/status`,
     P-report §5) and plaintext on non-loopback binds (N R2).
   - **Not covered:**
     - `submit_local` returns at once when a transaction is already in the stempool
       (`stem.rs:201-205`): a stempool-membership oracle for any cookie holder. Low,
       because the caller needs the transaction's bytes.
     - There is no per-client separation on a shared node. Every cookie holder can submit
       and probe, so a remote-node operator sees all its users' origins (inherent; the
       restricted RPC is P3).
   - **Good [src]:** no transaction id is logged at INFO by the node; `/info` has no
     stempool field.
3. **Miner privacy.**
   - **Good:** the payout address never reaches the node; nonce starts are random.
   - **Gaps:**
     - the timestamp offset fingerprint (X11);
     - the miner and node on one host, so the block-origin IP is the payout owner (A5);
     - `miner.env` is 0644 (N D4);
     - the `--address` argument is visible in process lists on shared hosts.

     Low; docs.
4. **Contract and vault metadata.** Covered well in P-report §6. Addition: the vault
   `--secret` on the command line also lands in shell history (`.bash_history`, PowerShell
   `ConsoleHost_history.txt`). Docs, Low.
5. **Long-term (quantum).** These are owner-decided or documented items: v1 retroactive
   deanonymization (key-image test after a DL break), transport harvest-now-decrypt-later
   (ML-KEM in transport v2 "targeted"), hybrid PX delivery (good). No new action. **One
   decision is due before the freeze:** the PX ciphertext `R` canonical-point rule that
   P-report item 22 defers "to a future reset". **This reset is that reset.** Adding it
   later needs an activation. It needs a Lead decision (in or out of v3) before the freeze:
   consensus-visible, S.
6. **Legal and compliance exposure of operators (mention only; no legal advice).**
   Operators should be aware that:
   - INFO logs hold peer IP addresses (personal data in many jurisdictions; retention and
     sharing);
   - the central supply audit puts other people's wallets and passwords in one person's
     custody;
   - hosting onion services or relays, and privacy-coin software generally, may carry
     jurisdiction-specific obligations;
   - export rules on cryptography may apply to binary distribution.

   The owner should obtain their own advice before a public testnet.

---

## 4. Merged, deduplicated ranked list

**Columns:**
- **Area:** consensus, p2p, wallet, node-ops, docs, ci, owner.
- **CV:** consensus-visible.
- **Size:** S, M or L.
- **Tag** (already being worked on):
  - W4-MUTE: mutation run E;
  - W4-MUTAIR: the AIR census;
  - TM2-P2P: P-P1 and the GetTx outbox;
  - TM2-DOCS: docs, claims, procedures and STATUS.

### P0-genesis (blocks genesis or the trial)

| # | Item (sources) | One-line fix or measurement | Area | CV | Size | Tag |
|---|---|---|---|---|---|---|
| G1 | Origin re-announces early: block during the stem **and reorg readmission** (P-P1, X6) | The origin anchors on `admitted` like every node, except on the Held-after-restart path (persisted fluff height); readmission always uses its own height; two failing-first tests | p2p | no | S | TM2-P2P (**add the reorg case**) |
| G2 | PSK required by the trial procedure (N-2, F48-1) | testnet.md §12.3 and v3-genesis §6 require `network_psk_file`; generation, E2E distribution, 0600, rotation on device loss; `/info` says "psk loaded" | docs, node-ops | no | S | TM2-DOCS (docs part) |
| G3 | RandomX start-up self-test (C-3, decision 08) | KAT 1a-1f in light mode at node and miner start; refuse on mismatch; `--skip-randomx-self-test` visible in `/info` | node-ops | no | S | — |
| G4 | D0 and T_g (C-10, N G1, F40-12) | Measure every trial device's hash rate with the release build; D0 with the tool; two-stage T_g | owner, node-ops | yes (genesis parameters) | S | — |
| G5 | Origin data at rest and operational procedures (P-P2, N-3, N-5 docs, X8, X9) | 0700 data dir and 0600 node files on Unix; incident bundle = `blocks.dat` plus info logs only; "never copy a data dir"; evidence redaction (no IPs, supply-audit totals only); state the keyed-hash limitation | node-ops, docs | no | S | TM2-DOCS (docs); perms not tagged |
| G6 | `GetTx` over 64 ids disconnects honest peers (D4, X3) | Reproduce; then the requester splits requests to at most 32 ids and the server serves through a byte-bounded queue that yields; assert no `slow_disconnects` and no stem-peer change | p2p | no | S | TM2-P2P |
| G7 | Authenticated release reference (N-1, N G2) | A signed tag, or a full commit id plus fingerprints confirmed over two independent channels; every operator recomputes the genesis | owner | no | S | — |
| G8 | Docs and claims (P-P7 C-1 to C-15, F48-2 custody, F48-7 endpoint checklist with OneDrive and password, N-11 STATUS, the exit 70/101 runbook, N-4 docs) | Land the listed corrections; supply-audit §7.1 aligned with the decision; custody banner in the tool | docs | no | M | TM2-DOCS |
| G9 | Privacy regression suite (P-P10, 33 W1, decided trial P0) | `p2p/tests/privacy.rs`: G1 (both variants), held local transactions, InvTx uniformity, GetAddr inbound-only, the slow-lane oracle and the X1 lane black hole (`#[ignore]` with a reason until fixed) | p2p, ci | no | M | — |
| G10 | Supply-audit PX test (C-8 / F40-9, decided P0) | Regtest bridge-in, PX transfers and bridge-out audited exactly; an injected PX record alarms | ci, node-ops | no | M | — |

### P0-freeze (blocks the consensus freeze)

| # | Item | One-line fix or measurement | Area | CV | Size | Tag |
|---|---|---|---|---|---|---|
| F1 | AIR soundness evidence (C-1) | Census without the digest pin **plus** a cell census of all tables and padding rows, a lying-generator test per opcode and Poseidon round, and a spec-to-constraint table; any real survivor is reported and leads to a new CIRCUIT_ID | consensus (zkvm) | yes if a defect is found | L | W4-MUTAIR (add the last three) |
| F2 | Golden PX fixtures (C-2) | Transfer and two-function vault proofs on the frozen kernel, pinned; tamper sweep over the transcript fields; then PX5, PX6, pool and B8 verdict samples in the fingerprint (part of C-6) | consensus (zk, px), ci | no (fingerprint coverage only) | M | — |
| F3 | Mutation run E, then run F scope (C-9) | Finish E; run F: `replay.rs`, `store.rs`, zk verify/config/params, `randomx/`, both fingerprint modules, supply-audit | ci | no | L | W4-MUTE (E only) |
| F4 | P-5 re-run and widest proof on the frozen kernel (C §7 P0-7, ZP-2) | n_fn = 0, 1 and 2; confirm the 4 MiB and 6,000-column envelopes with margin | consensus (zk) | no (evidence) | M | — |
| F5 | Freeze-record correction: the DAA residual is not covered by park (C-4, §1.7) | Rewrite the redteam RT-3/RT-4 action, v3-consensus-changes §8 and decisions lines 208/599: "accepted under K1"; RT-4 to the runbook | docs | no | S | TM2-DOCS (should take it) |
| F6 | PX ciphertext `R` canonical-point rule: in or out of v3 (P-report item 22) | A Lead decision before the freeze; if in, it goes through the full consensus record | consensus, owner | yes | S | — |
| F7 | Compile-time guards BPP-10 and F11-10 (C §6.2) | Const asserts | consensus (crypto, tx) | no | S | — |

### P1-public-testnet

| # | Item | One-line fix or measurement | Area | CV | Size | Tag |
|---|---|---|---|---|---|---|
| P1 | D1 junk-PoW headers (N-14) | Per-peer slow start (one header until work is delivered); a node-wide budget for unproven peers; Tor sessions share it | p2p | no | M | — |
| P2 | D2 staller detection (N-15, decision 31) | Disconnect (no ban) the holder of the lowest timed-out body; never re-pick it; lower `p.height` after a timeout | p2p | no | M | — |
| P3 | Stem black holes: PX bucket and Tx lane (P-P4, X1, X2, D5) | Local re-stem on the first embargo expiry (33 W3); a kind-aware PX embargo (W4); per-source fair share; an unscored-failure budget; measure P(first announcer = origin) in labnet | p2p | no | M | — |
| P4 | Decoy distribution from the local index (P-P3, F38-1/F38-6) | Compute `cumulative` from `IndexedOutput.height`; drop the spend-time `/distribution` | wallet | no | M | — |
| P5 | Tor mode (P-P5, F33-7, 33 W6) | Onion-only outbound under `--proxy-only`; random SOCKS credentials per connection; a dual-homed warning; per-network GetAddr cache; `testnet-tor.toml` on `onion_inbound` | p2p, node-ops | no | M | — |
| P6 | Header tagging and lag fingerprints (X4, X5) | `Version` carries the body-complete tip, with no header height; onion locators from the connected chain; the wallet refuses on header lag | p2p, wallet | no (wire semantics) | S-M | — |
| P7 | Park-on-deep-reorg, decoupled from the DAA (C-4) | Implement W-7 (OFF in the trial, 720 public); measure the RT-4 stall | consensus-adjacent (fork-choice policy) | no | M | — |
| P8 | D3 outbox byte bound, D6 read buffer (N-16) | Byte-counted outboxes; pause request processing while queued bytes exceed 2 × `MAX_BLOCK_BYTES` | p2p | no | M | — |
| P9 | Replay PoW sampling (N-5) | 48 samples at start-up plus `--verify-store-pow` (decision 01) | node-ops (chain) | no | S-M | — |
| P10 | Overrides and verdicts in `/info` (N-7, F48-9) | `operator_verdicts`, `overrides`, `psk`; `check-node.sh` fails on any | node-ops | no | S | — |
| P11 | F48-5 quarantine marker; crash-loop unit change (N-4) | Write 0x82 before validation; `StartLimitBurst`/`IntervalSec` in both units | node-ops | no | M | — |
| P12 | Wallet: SOCKS5 (W5), hedged decoy RNG (F38-5), password minimum (gap 1), young-spend warning | As named | wallet | no | M | — |
| P13 | Slow-lane timing oracle (P-P6) | Verification off the per-peer lane (34 Stage 4) | p2p | no | M | — |
| P14 | Download starvation, failed-reorg re-validation (02 F-1/F-2), outbound chain-work eviction (E8) | As decided | p2p, chain | no | M | — |
| P15 | Live network tests (N-13: NS-1 to NS-7) | netns harness in CI or on a VM | ci | no | L | — |
| P16 | Logs: rate limit, IPs at debug only, stem lines off info (F48-8, L1-L4, 33 W12) | Per-category token buckets; a `--log-peer-ips` opt-in | node-ops | no | S-M | — |
| P17 | Build channel (P-P8, N B1, N-9) | Home-path string check (**P0 if any binary is published**); cross-host reproducible builds; `install-linux.sh --tag` verification | ci, owner | no | M | — |
| P18 | Stored invalid bodies (N-6) | Origin-1 verdict markers; bodies out of RAM | chain | no | M | — |
| P19 | Determinism: soft-AES leg (part of C-7) | A CI leg with `aes_force_soft` on the RandomX vectors | ci | no | S | — |
| P20 | Docs: X7, X10, X11 statements, the RT-4 runbook | — | docs | no | S | TM2-DOCS (if in scope) |

### P1-mainnet

| # | Item | Fix | Area | CV | Size |
|---|---|---|---|---|---|
| M1 | `recent_rejects` keyed by rules domain; a non-vacuous fee guard; `verifier_id` in the domain (C-5, RT-3) | Clear on `enter_rules` or key by (id, domain); a synthetic two-epoch test covering `PxFeeNotStandard` | p2p, consensus (tx tests) | no | S |
| M2 | Transport v2 with ML-KEM, padding and rekeying (P-P9, N T4) | Per decision 30 | p2p | no (protocol version) | L |
| M3 | v1 verifier assurance (C-8): CLSAG/BP+ verifier fuzzing, an independent BP+ verifier, Monero CLSAG conformance | As decided | consensus (crypto) | no | L |
| M4 | Build identity and fingerprint coverage (C-6) | Dirty check for untracked files; the independent manifest recompute | ci | no | M |
| M5 | Determinism legs: aarch64, target-cpu, Plonky3 backend differential (C-7) | As decided (27 W2-W4) | ci | no | M |
| M6 | K1/K4 finality, hopper criterion, private broadcast, `--tx-proxy`, F38-9 parity | Owner and design | owner | maybe | L |

### P2

| Item | Notes |
|---|---|
| `CachedPow` bound | F07-5, D8 |
| fsync of `peers.json`, `bans.json`, `anchors.json` | N-12 |
| Ban-list cap | E11 |
| RPC pre-auth slots | N-10 |
| Miner unit hardening; `miner.env` 0600 | N D4, D5 |
| Docker STOPSIGNAL and release build | N-8, D3 |
| Store sampling extras; checked adds | — |
| BPP-1/BPP-6 | — |
| F23-9 | — |
| Denomination helper; deploy merge avoidance | — |
| View-only audit; payment proofs | — |
| Data dir under `%LOCALAPPDATA%` | — |
| Miner timestamp rounding (X11) | — |

---

## 5. Severity adjustments, summary

| Item | Report | This review | Why |
|---|---|---|---|
| P-P1 | Medium/Medium, P0 | Medium (T) / **High (P)**, P0 | The reorg variant (X6) is triggerable at will under K1; the proposed fix misses it |
| P-P4 | High (P) | High (P), plus a v1 variant | Costed; X1 extends it to v1 through the Tx lane |
| P-P5 | Medium-High | Medium (P) | Exit MITM clusters a Tor node's transactions; it does not reveal the IP |
| D4 | Medium | Medium (T) / Medium-High (P) | Attacker-triggerable stem-peer churn (X3) |
| D5 | Medium (P), liveness | **High (P), privacy** | Tx-lane black hole (X1) |
| C-1 | High, census as the gate | High; the gate needs a free-witness search | A census cannot find a missing constraint |
| C-4 | Medium; "park fixes it" | Medium; the park remedy is refuted (z = 100 vs 720) | The freeze record must be corrected |
| N-1 | High (T), blocks launch | P0 for an authenticated reference; signing P1 | Two-channel commit ids are sufficient for 7 operators |
| N-4 | P0 | P1 (docs P0) | The trial is on Windows; the systemd unit does not apply |
| N-5 | P0 | Docs P0, code P1 | Resyncing a small chain is the simpler control |
| N-7 | P0 | P1 (docs P0) | Decided P1 (F48-9) |
| C-3 | P0 (C) vs P1 (N) | P0-genesis | Heterogeneous trial devices |
| N-2 | Medium | Medium, **linchpin** | Every PoW-free DoS and T1 depends on it in the trial |

## 6. Open questions for the Lead

1. **G1 fix scope:** confirm that TM2-P2P takes the reorg-readmission case (§1.1).
2. **F6:** is the PX `R` canonical-point rule in v3 or out? It must be decided before the
   freeze.
3. **F5:** who rewrites the DAA freeze record (TM2-DOCS or the DAA owner)?
4. **G7:** does the owner accept a two-channel commit id plus fingerprints as the trial's
   authenticated reference if signing is not ready?
5. **X8:** can the custody machine for the central supply audit be other than the
   build/agent workstation?

No web content was fetched in this round. No repository content was sent anywhere. No
injected instructions were met.
