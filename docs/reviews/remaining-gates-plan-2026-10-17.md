# Plans: the remaining freeze, genesis and trial gates

Planning memo, 2026-10-17, at `rebuild/core` db12c0c. Internal engineering work, not
an audit. **Plans only:** nothing here starts a run, changes a consensus or genesis
value, generates a key, or closes a gate. Every gate below stays in the state
[STATUS.md](../STATUS.md) gives it until its own evidence is merged.

Labels: **[V]** checked by reading code, docs or logs for this memo; **[I]** inferred
or estimated, to be confirmed by the first step that measures it; **[O]** needs an
owner decision.

Gate ids used here: G1 `D0`, G2 the multi-machine supply audit, G3 labnet run C,
G4 the genesis rehearsal and second operator, G5 release signing, G6 `zkvm-stress`
on the freeze candidate, G7 the other freeze-commit gates, G8 Defender and Windows
Update, G9 the trial authorization. They map to [STATUS.md](../STATUS.md) §5 rows and
§5.1 items 1, 3–8 and 10–13.

Common rules for every run below (from the labnet v3 record and the owner's
standing rules):

- Bounds are fixed in the evidence README **before** the run starts, with a UTC time.
  A changed bound is recorded as superseded with its reason, before the run (the §0.1
  pattern of [labnet-v3](../evidence/labnet-v3-2026-10-15/README.md)).
- A run is never repeated to make it pass. An environmental failure (a port bind
  before any process starts; outside load shown by the load samples) may be rerun
  once, with a new output directory, recorded and labelled.
- Every binary that is evidence is built by `bash tools/release-build.sh` from a clean
  checkout ([testnet.md](../testnet.md) §2, lines 47-51) and passes
  `bash tools/check-build-flags.sh --strings`; its SHA-256 and `--version` text are
  recorded.
- Processes are stopped by PID only. No run starts while another heavy job (cargo,
  mutation, fuzz, another labnet) runs on the same machine.
- Nothing from a trial-like run enters the repository unredacted
  ([testnet.md](../testnet.md) §7, "Redact before anything enters the repository").

---

## Findings from preparing these plans [V]

These affect the plans; none is fixed here (this memo changes no other file).

1. **The §7 multi-machine procedure cannot run on testnet before the genesis.**
   `deploy/config/lab-testnet.toml` sets `network = "testnet"`, and
   `check_network_enabled` (node/src/config.rs:230-245) refuses testnet until
   `TESTNET_BEACON` is committed (consensus/src/params.rs:53). Before the final
   genesis it can run only on regtest (G2, option A) or inside the trial
   (option B). Decision O-2.
2. **No node can start a rehearsal genesis.** The node knows three networks
   (node/src/config.rs `parse_network`). `blacksilk-genesis generate --rehearsal`
   computes a rehearsal genesis, but no node can run it without a code change. A
   rehearsal therefore covers the procedure and the tool, not a node launch (G4).
3. **The genesis document and the decisions differ on `T_g` and the fallback.**
   Decisions "Agent 40" (decisions.md:350): a two-stage announcement (stage 1 at
   least 48 h ahead fixes everything except `T_g`; stage 2 at H−12) and a fallback at
   H' = H+36. [testnet-v3-genesis.md](../testnet-v3-genesis.md) §6 steps 1-2 freeze
   `T_g` with the other fields at the release candidate, and its fallback is the new
   block at height `H` after a reorganization. STATUS §1 says "`T_g` by the two-stage
   announcement". If `T_g` comes at stage 2, the release-candidate commit cannot
   contain it, and step 5's rule ("`git diff <rc-commit> HEAD` must show only" the
   beacon, the pinned ids and testnet.md §1) would also need `TESTNET_GENESIS_TIME`.
   This must be settled before G4. Decision O-4c.
4. **Labnet `checks_passed` does not need any PX activity.** The pass logic
   (tools/labnet/src/main.rs:1646-1657) never reads `px_submitted` or
   `px_failures`. A run C with no PX transaction at all would pass, so G3 adds its
   own PX bounds.
5. **The supply audit's PX limitation sentence is out of date.** testnet.md:822-823
   says the automated test "does no PX proving" and that the PX part is tested only
   with an empty pool. `tools/supply-audit/tests/px_audit.rs` (G8 T7) now tests a
   non-empty pool with hand-built PX transactions without proofs. Both statements
   agree that no real proof has gone through the tool. A B7 item (G7c).
6. **STATUS and the caller differ on two facts.** STATUS §5.1 item 6 (at db12c0c)
   says the branch-protection ruleset is approved but not applied; this plan's
   brief says rebuild/core is now protected. STATUS §5.1 item 1 says 742:24 stage 2
   (E3) is not started; the brief says E3 is in progress. STATUS stays the source
   until it is updated by a commit; these plans name both.

---

## G1. `D0` on the trial hardware

**Type:** technical measurement plus owner inputs (the device list). A genesis gate
(F40-12; decisions "Labnet deep reorgs (INV-REORG)"); STATUS §5 row "`D0` measured on
the trial hardware", §5.1 item 3.

**What `D0` is.** [testnet-v3-genesis.md](../testnet-v3-genesis.md) §5 (lines
144-164): `D0 = max(1, floor(honest_hash_rate × T / 2))` with T = 120 s, computed by
`blacksilk-genesis difficulty --hashrate-mhs <milli-hashes/s>`
(tools/genesis/src/main.rs:35, :154-162; `starting_difficulty`,
tools/genesis/src/lib.rs:252-255, divides by `STARTING_DIFFICULTY_MARGIN = 2`,
lib.rs:127). It must be measured on the actual trial devices with real RandomX, and
it **must not be inferred**: not from the i7-6700 figures of testnet.md §12.1, not
from CI runners, not from the light-mode `randomx/examples/bench.rs`, and not
extrapolated from another device of the same model.

**Prerequisites.**
- [O] The list of trial devices that will mine **from block 1**, each with its trial
  mining configuration: full or light mode, `--threads`, `--prebuild`. A device whose
  participation at launch is uncertain is left out (errs low).
- The binary revision: the freeze-candidate commit, or an earlier commit with
  `git diff <measured> <candidate> -- randomx miner consensus chain/src/pow*` empty
  (otherwise remeasure). Built per device with `tools/release-build.sh -p
  blacksilk-node -p blacksilk-miner -p blacksilk-genesis`.
- Each device passes `blacksilk-node --randomx-self-test` and
  `blacksilk-miner --randomx-self-test` (full mode unless it mines light;
  testnet.md:120-127).
- Each device quiet: no other heavy load, sleep off, power plan recorded, clock
  synchronized (testnet.md §12.2).

**Procedure (per device, 3 repeats on separate occasions).**
1. Start a local regtest node with its own empty data directory and P2P off, and
   `--mine-from-stale-tip` (the regtest genesis is old, so the template gate would
   answer `503 syncing`; testnet.md §9, the `503 syncing` row) [I: confirm the flag
   combination at the measured commit].
2. Start the miner with exactly the trial configuration, `RUST_LOG=info`, paying an
   address of a throwaway regtest wallet.
3. Discard the first 10 minutes (dataset build, regtest difficulty ramp). Then record
   30 consecutive `hash rate X H/s (search), Y H/s (effective: ...)` lines; the miner
   prints one per 60 s window (`HASHRATE_EVERY`, miner/src/main.rs:164; format
   :488-501).
4. Exclude a window that contains a RandomX key switch or a dataset build (its log
   lines), and record that it was excluded.
5. The run's rate is the **median effective rate** of its valid windows. The effective
   rate includes template, submission and retry overhead; regtest's 10 s blocks
   refresh templates more often than testnet's 120 s blocks, so it errs low [I]. The
   search rate is recorded too, not used.
6. The device rate is the **minimum** of its three run rates.

**Aggregation.** `R = Σ device rates` (H/s) over the listed devices;
`mhs = floor(1000 × R)`; `D0 = max(1, floor(mhs × 120 / 1000 / 2))`, i.e. the tool's
output for `--hashrate-mhs <mhs>`. Arithmetic illustration only, not an estimate:
R = 100.0 H/s gives mhs = 100000 and D0 = 6000.

**Independent recomputation.** A second person recomputes every device rate from the
raw logs (not from the summary table), the sum and `D0`, by hand and with the tool
built on their own machine. The two `D0` values must be equal.

**Evidence:** `docs/evidence/d0-trial-hardware-<date>/`: README (bounds first), per
device a label (no host name, user name or IP), CPU model, cores and threads, RAM,
OS build, mode, threads, prebuild, binary commit and SHA-256, `--version`, self-test
output; `rates.csv` (device, run, UTC start and end, window, search H/s, effective
H/s, excluded flag and reason); the raw miner logs with paths redacted; the
aggregation; the tool's output; the second person's recomputation.

**PASS (fixed now, before any run):** every listed device has 3 runs with at least 25
valid windows each; within a run, the valid windows' effective rates have a
coefficient of variation ≤ 10 %; the three run rates of a device are within 15 % of
their maximum; both computations give the same `D0`. **FAIL or investigate:** a
self-test failure (the device does not join; testnet.md:120-127), a run outside the
spread bounds (a finding; the cause is recorded, the run is not silently replaced).

**Resources [I, basis testnet.md §12.1]:** per device about 3 × 45 min wall (10 min
discard, 30 min measured, start and stop); full mode 2 GiB dataset plus about 0.3 GB,
about 4.4 GiB peak with prebuild; light mode 256 MiB; CPU-h = mining threads × about
2.3 h; disk under 1 GB. Devices run in parallel with each other.

**Re-pin consequences.** `D0` is an identity value since cf2414e (decisions
"Fingerprint sample inputs and D0 as identity", decisions.md:1858-1890): it is in the
genesis header and the identity manifest, not the rules manifest. Committing it
(the testnet `initial_difficulty`, consensus/src/params.rs:76, today the placeholder
100) changes the testnet genesis id, the identity fingerprint and the consensus
fingerprint; the rules fingerprint stays the same. It is a consensus-path commit
(trailer and record in [v3-consensus-changes.md](v3-consensus-changes.md)) with the
testnet pins of `node/tests/deploy_configs.rs` re-pinned; the PX pin
(`px/tests/consensus_fingerprint.rs`) is expected unchanged [I]. Because
testnet-v3-genesis.md §6 step 1 freezes `D0` at the release candidate, **G1 lands
before the freeze candidate**, and G6 and G7 run after it. A change of the device set
after G1 means remeasuring; a `D0` change after the freeze means a new candidate and
G6/G7 again.

**Abort and recovery:** a device that cannot finish (crash, thermal throttling seen in
the rate) is recorded; it is either remeasured or left out of `R` (errs low), an owner
choice recorded in the README.

**Parallel:** with G3 (if not on the same machine), G4 preparation, G5, G7e, G7f.

**Never claim:** a `D0` "measured on the trial hardware" from fewer than the listed
devices, from another binary revision, or from a model or bench figure; hash-rate
figures as performance claims beyond these devices and configurations.

---

## G2. Multi-machine 72-hour supply audit with a PX pool

**Type:** operational (machines, people, custody), owner-dependent. STATUS §5 row
"Supply audit with a PX pool, a multi-machine 72-hour run"; §5.1 item 4;
[testnet.md](../testnet.md) §7 (lines 642-700) and §7.1 (lines 702-825).

**[O] O-2, where it runs** (Finding 1):
- **Option A (recommended as the pre-trial gate):** regtest, on at least 3 machines
  in 2 networks, before the freeze or the trial. Regtest rules equal testnet rules
  except the network id, `D0 = 1` and 10 s blocks (consensus/src/params.rs regtest).
  72 h is about 25,900 blocks and about 12 RandomX key switches [I], more than the
  trial reaches. Evidence is "regtest, multi-machine", never "testnet".
- **Option B:** the first 72 h of the seven-device trial on the final testnet, with
  procedures A and B as written. Then it is a trial result, not a freeze gate, and
  G9 comes before it.
- Option A then option B (the procedure rehearsed, then run on the real network) is
  the stronger evidence.

**Prerequisites.**
- At least 3 machines (A, B, C) in at least 2 different networks (two cloud regions
  and one home connection, testnet.md:645-646); a fresh node D for step 6 (a separate
  data directory, on any machine); the custodian machine for procedure B: a
  **separate machine, never the project's build or development (agent) workstation**
  (testnet.md:765-772; owner decision 2026-10-02). It may be one of A–C only if that
  machine is not the development workstation and runs nothing but its node and the
  audit tool during the audit.
- At least two machines able to prove PX: about 3.6 GB free for a transfer, 4.3 GB
  for a one-function and 6.4 GB for a two-function vault call (testnet.md §12.1
  Wallet row); 8 GB machines prove transfers, single calls and the vault pair (STATUS
  §2, px-deploy-row-caps row).
- Every machine: the same commit, built by `tools/release-build.sh`, values compared
  as in testnet.md §2.1; clock offset under 10 s (§12.2); a fresh network pre-shared
  key (§12.3) for this run only; the endpoint checklist (§12.8).
- Trial-only seeds for every wallet, miner payout wallets included; a backup of every
  wallet file and password at the start (testnet.md:713-725).
- The operators' end-to-end encrypted channel exists
  ([testnet-incident-response.md](../testnet-incident-response.md) §1a).

**Procedure: the seven pass steps** (testnet.md:648-684; option A uses regtest
configurations with the same peers, `allow_private` as needed, and the key):
1. Set up: build, start nodes; give the key.
2. Automatic joining: B and C get only A as a peer. Pass: within 5 minutes both show
   `peers ≥ 2` in `deploy/scripts/check-node.sh`.
3. Mining across machines: a miner on A and on C. Pass: every node reports the same
   `tip`; each miner's wallet receives rewards for its own blocks.
4. Transaction propagation: after 60 blocks, A → C through B's RPC. Pass: C's wallet
   shows it after the next block; B's log does not show B announcing it before the
   embargo.
5. Reorganization: block {A} against {B, C} for 20 minutes with both sides mining
   (`iptables -A INPUT -s <A> -j DROP` on B and C; on Windows
   `New-NetFirewallRule -Direction Inbound -RemoteAddress <A> -Action Block`), then
   remove the rule. Pass: all tips equal within 5 minutes; the minority side logs
   `reorganization: disconnecting …`; transactions of the orphaned side return to the
   mempool and confirm. On regtest 20 minutes is about 120 blocks per side, so the
   deep-reorganization warning (10 blocks or more) is expected and recorded.
6. Wallet sync from a fresh node D: restore each wallet from its 27 words against D
   (`blacksilk-wallet -w fresh.wallet restore --network <net>`, then `balance`). Pass:
   identical balances, v1 and PX.
7. Stability: at least 72 hours. Pass: no crash; all nodes on the same tip; RSS
   against height recorded, growth explained by the chain (about 7 KB per v1 block,
   up to about 8 MiB per full PX block, PX-F1/PX-F2).

**PX pool traffic (this plan's addition, fixed in advance):** from hour 1 on, each
PX-capable machine does one PX operation every 2 hours, cycling `px-deposit`,
`px-send` (to another machine's wallet), `px-send`, `px-withdraw` (testnet.md §10);
at least one PX transaction is submitted during step 5's partition; optionally one
`px-deploy --vault`, lock and claim on a machine with 8 GB or more [O]. Passwords are
typed at the prompt (§12.8), so an operator drives each operation [I: about 36 per
machine over 72 h].

**Custody and audit.**
- **Procedure A (mid-run, local, per operator)** at about 24 h and 48 h: the owner
  announces a height H that every node has passed by 10 blocks; each operator runs
  `blacksilk-supply-audit --node <own RPC> --height <H> --wallet ... --password-file
  ... --json` **without** `--expect-complete` (testnet.md:735-760) and sends only
  `height`, `tip`, `chain.generated` and `totals`; the owner checks by hand that the
  heights, tips and `chain.generated` agree and that Σ(`totals.v1 + totals.px`)
  equals `chain.generated`.
- **Procedure B (end, central, once)** (testnet.md:762-790): stop all miners, wait for
  one `tip`; wallets and password files travel only over the encrypted channel or by
  hand; the custodian builds the tool from the run's commit
  (`bash tools/release-build.sh -p blacksilk-supply-audit`) and runs it with every
  wallet listed and `--expect-complete --json`, then again without `--json`; then
  deletes every wallet copy and password file and tells the operators, who retire the
  seeds.

**Redaction:** commit only the chain figures, `totals` and the differences, never
per-wallet rows; info-level logs with every IPv4, IPv6, `.onion` address and host
name replaced by placeholders; never `debug` logs, `originated.json`, `peers.json`,
`anchors.json`, `bans.json`, wallet files, passwords, seeds or the key
(testnet.md:686-700).

**Evidence:** `docs/evidence/supply-audit-multimachine-<date>/`: README (bounds and
the option first), per machine the commit, binary SHA-256, `--version`, self-test;
a step table with times and pass lines; redacted info logs; `rss-height.csv` per
node; procedure A sums; procedure B's chain figures, `totals` and differences, the
exit code; the custodian's deletion statement (date, by whom).

**PASS (fixed now):** all seven step pass lines; procedure A exit codes 0 (never 2)
and the owner's sums equal `chain.generated`; procedure B exit code 0,
`total_difference` 0 (so `v1_difference` and `px_difference` 0), `px_pool > 0` at
the audited height, PX records held by wallets on at least two machines, at least 20
PX transactions confirmed over the run, no unexplained duplicate. **FAIL:** any exit
code 2 (halt and follow testnet-incident-response.md §4.3), a crash, tips not equal 5
minutes after a heal, a lost wallet (the check becomes impossible; the run fails and
restarts with new seeds).

**Recovery:** exit 1 (wrong password, node syncing, wallets on different blocks, a
reorganization during the run): fix the cause and rerun the tool (testnet.md:818-820);
a node crash: preserve its data directory and log off the repository, record it,
step 7 fails and the 72 h restart after the fix; exit 3: find the missing wallet or
the payment outside the set (testnet.md:812-816), never "clean up" a wallet.

**Resources [I]:** 3–5 machines for 72 h plus about a day of set-up and an hour for
procedure B; per node about 300 MB at start plus growth (regtest about 180 MB of v1
bodies over 72 h, plus about 2.4 MB per PX transaction kept in memory, about 0.3 GB
for 100 PX transactions); PX proving 3.6–6.4 GB peaks; miners 256 MiB (light) or
2.3–4.4 GiB (full); disk about 2 GB per node; CPU-h = miner threads × 72 per mining
machine (basis testnet.md §12.1).

**Parallel:** independent of G1, G3 (other machines), G5, G7e, G7f. Not on the
development workstation while that runs G3 or G7a.

**Never claim:** a single-machine or loopback result as multi-machine; a regtest run
as a testnet run; 3 machines as the seven-device trial; that the supply is sound in
general (testnet.md:822-825); any privacy property (small anonymity sets,
testnet.md §12.7).

---

## G3. Labnet run C: PX traffic  **[O] owner approval needed (scope and window)**

**Type:** technical, single machine. STATUS §5 rows "Labnet campaign" and "Labnet
reruns on the current tree"; §5.1 item 12.

**Proposed scope (a proposal; nothing is fixed until the owner approves and the
README records it before the run):**

| Parameter | Proposal | Reason |
|---|---|---|
| Nodes | 8 (12 if at least 12,000 MB are available) | memory: 12 nodes plus a prover is close to the guard (below) |
| Topology | `ring-chords`, default partition split (4 / 4, one miner each) | PX across reorganizations; comparable with run B's bounds |
| Partitions | `--partition-every-mins 30 --partition-mins 4` (3 partitions) | PX transactions in orphaned blocks return and confirm |
| Duration | `--duration-mins 120` after warm-up | about 27 PX attempts (below) |
| PX | `--px-every-mins 4` | first attempt 12 min after the measured phase starts (main.rs:1298), then every 4 min; proving pauses the harness about a minute (main.rs:86-90) |
| v1 traffic | `--tx-every-secs 20` | as runs A and B |
| Miners | light, `--miner-threads 1`, `--evidence` (prebuild on) | as runs A and B |
| Other | `--relay-joiners 3`, `--latency-ms 20 --jitter-ms 10`, own `--base-port`, `RUST_LOG="info,blacksilk_p2p::net=debug"`, `BLACKSILK_REQUIRE_CLEAN_BUILD=1` | as runs A and B |

**PX mix:** fixed by the tool (main.rs:1401-1450): a wallet with less than
0.5 BLK + fee spendable in PX and more than 2 BLK unlocked deposits 1 BLK; otherwise
one attempt in three withdraws 0.1 BLK and two in three send 0.2 BLK privately to
another lab wallet. No deploy and no vault call: run C does not exercise the 4.3 GB
or 6.4 GB proofs or the 10.6 GB memory-widest pair.

**Command (proposal):**
```
RUST_LOG="info,blacksilk_p2p::net=debug" BLACKSILK_REQUIRE_CLEAN_BUILD=1 \
bin/blacksilk-labnet.exe --bin-dir <bin> --out runs/C-px8 \
  --nodes 8 --topology ring-chords --duration-mins 120 \
  --partition-every-mins 30 --partition-mins 4 --px-every-mins 4 \
  --relay-joiners 3 --base-port <port> --latency-ms 20 --jitter-ms 10 \
  --tx-every-secs 20 --miner-threads 1 --evidence
```
Preceded by a smoke run (not evidence; 15 min, `--px-every-mins 3`, no `--evidence`)
to measure the memory baseline with a prover active, as the run A/B smoke did.

**Pass bounds (proposed, in run A/B style; recorded before run C starts):**
- labnet exit 0 with `--evidence`; `summary.json`: `checks_passed`, `evidence: true`,
  `evidence_notes: []`, `crashes: []`, `stuck_incidents: 0`,
  `misbehavior_disconnects: 0`, `converged_at_end`, `mempools_drained_at_end`,
  `late_joiner_synced`, `late_joiner_peers >= late_joiner_required_peers`,
  `late_joiner_secs_to_required <= 120`, `relay_discovery.all_reached`,
  `fresh_wallet_balances_match`, `fresh_wallet_px_balances_match`,
  `supply_conserved`, `warmup.reached`;
- **PX (Finding 4):** `px_submitted >= 20`; `px_failures` empty; the journal shows at
  least one `px deposit`, one `px send` and one `px withdraw`; `wallet_px_total > 0`;
- binaries: the run commit without `-dirty`, `build flags: none`, SHA-256 equal to the
  recorded `SHA256SUMS`;
- `report.json`: every final-chain block reached all lab nodes;
- log greps: `RandomX self-test passed` in every node log; zero honest-block or
  honest-transaction `is invalid`, zero `misbehaved (+` (the PX relay penalty must
  not hit honest peers), zero `inbound limit reached`, zero panic / `ERROR` / halt;
- connected-phase reorganization depth ≤ 2 (as run B); every heal one tip within
  120 s of the partition ending (measured from the journal's heal mark, since a
  proving pause can delay the harness loop); every switch to strictly more work;
- resources: no node's peak RSS above 600 MB; the memory guard not triggered.

**Resources [I; basis runs A/B and testnet.md §12.1]:** nodes about 280 MB each
(8 × 0.28 = 2.2 GB; 12 × 0.28 = 3.4 GB), miners about 0.27 GB each, the harness's
prover about 3.6 GB per transfer proof (one at a time, in the labnet process), PX
bodies in every node (about 27 × 2.4 MB = 65 MB per node), fresh-wallet PX scans at
the end. Peak about 7 GB with 8 nodes, about 8.5 GB with 12, against the run A/B
prerequisite of 10,000 MB available and the 2 GB guard. Proving uses all 8 threads
for about a minute, so expect more stale blocks during proving. Wall time about
2 h 45 min: build about 6 min, prerequisites 2 min, warm-up about 11 min, 120 min
measured, end checks about 15 min. Disk under 2 GB.

**Window:** an owner-confirmed quiet window of about 3.5 hours on the 16 GB
workstation: no Chrome, no cargo, no other agent; the prerequisite table of the
labnet-v3 record §5 repeated before the run.

**Evidence:** `docs/evidence/labnet-runC-<date>/`, laid out as labnet-v3 §10 (build,
smoke, run, acceptance table, files; no node data directories).

**Abort and recovery:** the load sampler's 2 GB guard stops processes by PID; an
environmental failure may be rerun once (new `--out` and base port, labelled); a
bound miss is a finding, not a rerun.

**Parallel:** nothing heavy on the same machine. G1 (other devices), G2 (other
machines), G5, G7e, G7f can proceed.

**Never claim:** multi-machine behaviour; privacy (decisions "RTW1B-2"); the PX
memory envelope (no vault calls); seeds are not settable, so a rerun repeats the
configuration, not the events.

---

## G4. Genesis rehearsal plus the second operator

**Type:** operational plus owner decisions. STATUS §5 row "Genesis rehearsal"; §5.1
items 5 and 13. **The second operator is currently unidentified** [O]: who it is and
on which machine. Decisions "Agent 40" require the second computer to be an
operator's machine, not the owner's.

**Prerequisites:** O-4c settled (Finding 3); a rehearsal id from `0x0001D6E0`–`EF`
not yet used ([testnet-v3-genesis.md](../testnet-v3-genesis.md) §3); the second
operator identified, with a machine identified independently of the owner's (its own
OS install, network and Bitcoin data sources); both channels set up (G5 / §1a); a
real future Bitcoin height H about 48 h or more ahead.

**Checklist (each line: the value, its source of truth, who checks):**

| Value | Source of truth | Check |
|---|---|---|
| Release-candidate commit | the full 40-hex id on both channels | both people build it; `git status --porcelain` empty |
| `blacksilk-genesis` binary | `tools/release-build.sh -p blacksilk-genesis` on each machine; `check-build-flags.sh --strings` | SHA-256 compared; a cross-machine difference is a reason to compare the full output, not a failure (§6 step 4) |
| Network id | `--rehearsal` id from the reserved range (final: consensus/src/params.rs:75, `TESTNET_V3_NETWORK_ID` tools/genesis/src/lib.rs:46) | the tool refuses ids outside the range |
| `T_g` | the announcement (stage 1 or stage 2 per O-4c); Unix seconds | not later than now at `generate`; about 2 h before H's expected time (§4) |
| `D0` | the G1 evidence (a rehearsal may use any value, labelled) | equal on both channels |
| H | the announcement | equal on both channels |
| Beacon | H's hash in display order, after 6 confirmations | each person from at least two sources (an own Bitcoin node's `bitcoin-cli getblockhash H`, and at least one independent explorer), compared |
| Nonce, header bytes, genesis id | `generate --rehearsal --network-id <id> --timestamp <T_g> --difficulty <D0> --btc-height <H> --btc-hash <hash>` (§6 step 4, lines 199-203) | both compare the full 64-hex id, never a prefix |
| Verification | `blacksilk-genesis verify ... --expected-id <id>` | exit 0 on both machines |
| Fingerprints | `blacksilk-node --version` / `--print-manifest testnet` at the candidate; pins in `node/tests/deploy_configs.rs` | the rules fingerprint equals the candidate's announced value (a rehearsal id changes nothing in the node) |

**Who publishes what:** the owner publishes the candidate id, `T_g`, `D0`, H and the
fingerprints on both channels; the second operator publishes, on the encrypted
channel, the H hash they obtained (with sources) and their computed full genesis id;
until a signing key exists (G5), "signed" means "published identically on both
channels".

**Not covered:** a node start on the rehearsal genesis (Finding 2). [O] optional
R2: a throwaway local build with the rehearsal genesis compiled in, never pushed or
distributed, to rehearse steps 5-6 (the diff shape, `/info` showing the full id).

**Evidence:** `docs/evidence/genesis-rehearsal-<date>/`: the announcement texts as
published, both people's tool outputs, binary hashes, the H sources and times, the
comparison, a timeline against §4's timing rules. No personal data of the operator
beyond a role name.

**PASS:** both full ids equal and equal to `verify`; every value equal on both
channels; the timing rules of §4 held. **FAIL:** any difference, which is then traced
before any final genesis. After the rehearsal the id is recorded in the registry and
never reused (§3, §6 step 7).

**Resources:** two machines, about 1 h of work each around H + 6, plus the 48 h
announcement lead; negligible CPU.

**Parallel:** with G1, G3, G5, G7; before the final genesis. Uses no freeze value
except as labelled.

**Never claim:** the rehearsal as a launch; a rehearsal id's genesis as the testnet
genesis; a node-level rehearsal unless R2 ran.

---

## G5. Release signing  **[O] owner decisions only; no key is generated by this plan**

**Type:** owner decision and owner task. STATUS §1 row "Release signing", §5.1 item 7.

**Requirements (decisions "Agent 43" and "Agent 48", decisions.md:403-481; "Threat
model round 2", decisions.md:1130-1137):**
- **The trial:** the two-channel commit id: the owner publishes the full commit id and
  the consensus fingerprints on two separate channels; every operator compares both,
  builds that commit with `tools/release-build.sh` and recomputes the genesis
  ([testnet.md](../testnet.md) §2.1). Signed tags are **not** required for the trial.
- **Before a public testnet:** SSH-signed annotated tags (an `ed25519-sk` FIDO2 key
  preferred; gitsign rejected because it would publish the e-mail address), and a
  second announcement channel. CI runs on `testnet-*` tags (.github/workflows/ci.yml:7-9).

**Owner decisions:** the two channels (the operators' end-to-end encrypted group and
an independent public one; tools and member list,
[testnet-incident-response.md](../testnet-incident-response.md) §1a); the signing
key type; where its public key and fingerprint are published (both channels and an
`allowed_signers` file in the repository); a backup key and a revocation statement.

**Key custody (F48-4):** generated offline on a machine that never builds third-party
crates, preferably on a hardware key; never on the development (agent)
workstation; the private key never enters the repository, CI or a synced folder.

**Operator verification (once tags exist):** fetch the tag; check it with
`git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=<file> verify-tag <tag>`
against the owner's public key from both channels; check that the tag's commit equals
the commit id on both channels; then the §2.1 checks.

**PASS:** the trial: both channels exist and are named in the README of the launch;
before a public testnet: a signed tag verifies on two operators' machines. **Never
claim:** signed releases for the trial; a channel as independent if one account or
device controls both.

---

## G6. `zkvm-stress` on the freeze candidate

**Type:** technical action (STATUS §5.1 item 11; §5 row "CI on the release commit").

**Why it needs its own run:** the job runs only when
`github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`
(ci.yml:248-249); every push and pull request skips it. A scheduled run tests the
default branch's head at a time unrelated to the candidate and runs only `audit`,
`deny`, `randomx-full` and `zkvm-stress` (ci.yml:11-17). A skipped job is not a pass.
Its last success is the scheduled run 38239177329 at bfb5d0d (2026-10-12).

**Procedure:**
1. The candidate lands on rebuild/core through a pull request (branch protection;
   Finding 6) and is the branch head. No other merge until step 4.
2. `gh workflow run ci.yml --ref rebuild/core`
3. `gh run list --workflow ci.yml --event workflow_dispatch --branch rebuild/core
   --limit 1 --json databaseId,headSha,status,conclusion`; record the run id and
   check that `headSha` equals the candidate's full commit id.
4. After completion: `gh run view <id> --json jobs` and record every job's name and
   conclusion.

**PASS:** `headSha` equals the candidate; `zkvm-stress` concluded `success` (not
`skipped`), within its 20-minute stress limit (ci.yml:261-272; 3 rounds, 24 proofs).
**FAIL:** exit 124 (a hang: ZK-F11/ZK-F21 regression) or any failure: no freeze;
investigate. A different `headSha` voids the run (dispatch again).

**Evidence:** the run id, the commit, the job table, recorded in STATUS §5 (CI
results live on GitHub, not in the repository).

**Resources:** one GitHub ubuntu-24.04 runner for the job (timeout 60 min,
ci.yml:251); the whole dispatched run lasts up to the `test` job's 330 min
(ci.yml:84). A dispatch run also runs every job without the schedule-only
condition, so it can serve G7d too.

**Never claim:** a scheduled run or an earlier commit's run for the candidate.

---

## G7. Other freeze-commit gates

All run on the exact freeze commit (after G1 lands).

**G7a. The full test suite, including the PX-proving tests** (STATUS §5 first row).
Procedure: the dispatched CI run of G6 at the candidate, jobs `test` (the non-PX
suite in parallel and the PX-proving tests one at a time, ci.yml:81-150), `overflow`,
`px-tamper`, `guests`, `arm64`, `randomx-full`, `fuzz-smoke`, all `success`; and a
local Windows run mirroring ci.yml:91-150 (the non-PX tests in parallel, then each
PX-proving test with `--test-threads=1`, nothing else running; PX tests use 4–6 GB
each). PASS: every job and every local test passes; zero failures, no test skipped
beyond the lists in ci.yml. Resources: local about 4–6 h [I] on the 16 GB
workstation in a quiet window. Evidence: `docs/evidence/freeze-suite-<date>/` (local
log summary, commit, toolchain) and the CI run id.

**G7b. `tools/fingerprint-mutations.sh` on the freeze commit** (FX-RTFP3).
`bash tools/fingerprint-mutations.sh <empty scratch dir>` from a clean checkout of
the freeze commit (tools/fingerprint-mutations.sh:15-20). PASS: exit 0, every
mutation changes the rules fingerprint, the count equals the script's list at that
commit (16 at b0a6b4a). Resources: one release build of the node per mutation,
minutes each, several GB of disk [I: about 2–3 h]. Evidence: the output, in the
freeze-suite directory.

**G7c. B7: doc reconciliation at the freeze commit** (STATUS §5 B7 row): STATUS
reconciled at the freeze commit; RT-FREEZE-V follow-ups closed or recorded; doc-lint
and the Unicode scan clean; Findings 3 and 5 of this memo resolved. PASS: an internal
reviewer finds no doc statement contradicting the code at that commit.

**G7d. CI on the release commit, all jobs green** (STATUS §5 last row): the G6 run
(or a push run of the same commit plus the G6 run) with every job `success`.

**G7e. Threat-model round 2** (STATUS §5 row "Second threat-model round"): the four
internal reports are written; its P0 items are the open rows of STATUS. PASS: each
P0-freeze and P0-genesis item of decisions "Threat model round 2" is done or has an
owner decision.

**G7f. 742:24** (STATUS §5.1 item 1; [plans-g8-742](plans-g8-742-2026-10-15.md)
Plan 2; [stage 1b](rx742-stage1b-2026-10-16.md)): OPEN. The mutation gate criterion
("zero unexplained survivors") is not met until a proof of unreachability or a
reaching key closes it, or the owner formally accepts it as a documented
test-adequacy residual [O]. E3 (the descent closure): in progress per the brief, not
started per STATUS (Finding 6).

**Never claim:** the freeze before every G7 item and G6 pass; a per-merge suite as
the freeze-commit suite.

---

## G8. Windows Defender and Windows Update

**Type:** owner action; no automation, and this plan proposes none. STATUS §5.1 item
10: both were found disabled on 2026-10-15
([labnet-v3](../evidence/labnet-v3-2026-10-15/README.md) §1, the Windows Update and
Defender rows); the owner said on 2026-10-16 not to re-enable them for now.

**Reminder:** they must be restored, and the machine fully updated and rebooted,
before any network-exposed trial or multi-machine run that uses this machine (G2,
G9). STATUS calls it "an operational item, not a gate"; this plan recommends the
owner make it a precondition of G2 and G9 [O]. A record of the restored state (the
service states as in the labnet-v3 §1 table) goes in the trial README.

---

## G9. Trial authorization

**Type:** owner decision, after every gate (STATUS §1 row "Seven-device trial", §5.1
item 8). Preconditions: the protocol freeze (G6, G7), `D0` (G1), the rehearsal (G4),
the two channels (G5), G8, a fresh pre-shared key (testnet.md §12.3), the endpoint
checklist on every device (§12.8), and then the final genesis by
[testnet-v3-genesis.md](../testnet-v3-genesis.md) §6. G2 before it under option A,
inside it under option B.

---

## Dependency-ordered timeline

| Phase | Gates | Depends on |
|---|---|---|
| 0 | Owner decisions (list below) | none |
| 1 (parallel) | G1 measurement; G3 run C (window); G2 option A (other machines); G5 channels and key decisions; G4 preparation (second operator, O-4c); G7e; G7f | phase 0 for each item's decision |
| 2 | `D0` committed with the re-pin (consensus record, a PR) | G1 |
| 3 | Freeze candidate at the head of rebuild/core via a PR; G6 dispatch run (also G7a CI and G7d); G7a local; G7b; G7c | phase 2; G7e, G7f decided |
| 4 | Protocol freeze declared by the owner | phase 3 all PASS |
| 5 | G4 rehearsal (may run in phase 1–3 with a labelled `D0`; must precede the final genesis) | O-4c; second operator |
| 6 | G8 restored; PSK; endpoint checklist | owner |
| 7 | G9 authorization, then the final genesis (§6) and the trial; G2 option B within it | all above |

## Owner decisions needed

1. O-1: the trial device list and each device's mining configuration (G1).
2. O-2: G2 on regtest before the trial (A), inside the trial (B), or both; the
   machines, networks and the custodian; whether a vault call is included.
3. O-3: approve G3's scope (8 or 12 nodes, the bounds) and a quiet window.
4. O-4a: the second operator and their machine; O-4b: the rehearsal id and H;
   O-4c: one-stage or two-stage `T_g`, and the fallback rule (Finding 3); O-4d:
   whether to do the throwaway node rehearsal R2.
5. O-5: the two channels; later the signing key, its custody and publication.
6. O-6: confirm branch protection is applied (Finding 6) before G6.
7. O-7: 742:24: fund the remaining research or accept the residual.
8. O-8: Defender and Windows Update restored, and whether that is a precondition.
9. O-9: the trial authorization.

## Not authorized by this document

No run of any gate, no campaign, no trial, no deployment, no real payouts, no
genesis (rehearsal or final), no key generation, no consensus or genesis value
change, and no protocol freeze. Each needs its own owner approval.
