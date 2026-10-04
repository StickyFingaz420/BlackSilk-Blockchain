# Autonomous work session, 2026-09-27: report to the owner

> Historical record (2026-09-27). Superseded where it conflicts with the code: the v3 candidate was merged into `rebuild/core` in 9e422d8; RandomX uses BlackSilk's Argon2 salt "BlackSilk/RandomX/v1", not Monero's rx/0 salt (RX-SALT, 3e3e9ca); the header is 172 bytes (output-root commitments, f5daa0e) and the PoW input is the 47-byte mining blob with the nonce at byte 39 (921fdd5). Current: [docs/consensus.md](../consensus.md), [docs/STATUS.md](../STATUS.md).

**Internal work, not an audit.** Nothing here claims that BlackSilk is secure, audited,
production-ready or fully proven. Zero knowledge remains **statistical and
conditional** (docs/reviews/zk-coverage.md §3).

**Scope.** The owner granted full autonomy for about seven hours. Work was split across
parallel agents, each with its own scope and git worktree. The coordinator reviewed
every branch, merged it, re-ran the tests on the merged tree and pushed.

**Where things stand.**

| Branch | Commit | Status |
|---|---|---|
| `rebuild/core` | `1c07316` (pushed) | Policy and engineering changes only. It holds no consensus change beyond the canonical-proof decode rule in `4b277cd` (see §5). |
| `v3/candidate` | `a9edbf3` (pushed; 17 commits ahead of rebuild/core when pushed) | Consensus changes for the future testnet v3 identity. **Not merged.** It waits for the owner's decisions (§8). |

The full review is in [full-review-2026-09-27.md](full-review-2026-09-27.md): findings
register, recommendations, innovation, what must never change. Its source reports are in
[full-review-2026-09-27/](full-review-2026-09-27/).

## 1. What was discovered

The work had two waves:
- **16 subsystem reviews (R1–R16) and 4 innovation studies (I1–I4)**;
- **2 senior cross-reviews (SX1, SX2)**, which re-checked about 90 major findings
  against the code: about 50 were confirmed, 14 corrected, 3 overstated, 1 partly
  wrong. None was fabricated.

### No rule bug found in the reviewed code
The reviewers found:
- no consensus-rule bug that accepts an invalid block or rejects a valid one (64-bit);
- no BVM-1 soundness defect;
- no PX inflation, theft or double-spend path.

### The main issues found
- **Proof of work and the honest-majority assumption.** The PoW is exactly Monero's
  RandomX, and stock JIT miners are about 50–100× faster than the safe-Rust miner. So
  the honest-majority assumption (K1) cannot hold against outsiders (R1-C2, R15-2).
- **Free low-work headers.** A fork reaches difficulty 1 cheaply, then produces
  unlimited valid headers that cost every node hashing work (R1-C1).
- **A global chain lock held during expensive verification.** Held on async threads,
  it can freeze a node (R8-1, R16-7).
- **P2P and addrman weaknesses** (R8):
  - unsolicited blocks were hashed under the lock;
  - outbound peer-group diversity was not enforced (a bug);
  - an unknown message type got a peer banned, which would block later protocol
    upgrades;
  - block-download timeouts falsely banned slow peers.
- **Privacy** (R3, I3):
  - the miner's nonce pattern clustered coinbases by miner;
  - coinbase maturity made the real input the newest ring member about 90 % of the
    time;
  - the Dandelion++ parameters were a mismatched pair;
  - an `InvTx` reply revealed stem membership (an oracle);
  - an onion address leaked to clearnet peers;
  - the size of a PX transaction reveals its origin to link-level observers.
- **Randomness hedging.** Several randomness sources were unhedged or bound too little
  of their statement: PX delivery, the transfer context, PX witness values (R2).
- **Transactions and deploys** (R6, R12-2, R5):
  - output-key front-running is cheap;
  - deploys are underpriced;
  - the zero-weight v1 inputs of deploy and PX transactions allow about 12,000 CLSAG
    verifications in one block.
- **Hash-construction documentation.** The tree node of the Poseidon2 hash Hk has no
  feed-forward, so its documented collision claim was false. The tree stays binding by
  a separate argument (R2-C6, SX1).
- **Build and testing:**
  - the kernel id depended on the checkout path;
  - the fuzz campaign ran without overflow checks;
  - there were no consensus golden vectors, and a 1.6 % difficulty mutation survived
    every test (R13, A15b).
- **The v2 identity was unsafe.** The tree already enforced a rule under the v2
  identity that v2 builds lack (R15-1).
- **There was no upgrade mechanism.** Every rule change needed a new genesis (R16-1,
  I4).

## 2. What was fixed (rebuild/core)

Each item names its commit; the tests are listed in §7.

### Consensus-adjacent node policy
- **Fork choice** (`9d689f0`). The node now follows the most-work *body-complete*
  chain, so a withheld body can no longer stall block production. Ties keep the
  current tip. This was approved as A10-H1. The same commit adds a low-work body policy
  and a header on `blocks.dat` naming the network and genesis.
- **P2P, round 2** (`12ce4cb`, `b12b024`, `54c4827`):
  - the header queue is bounded;
  - the work gate applies to header batches;
  - concurrent handshakes count against the inbound limits;
  - admission charges a per-peer input budget, caches contextual rejects and penalizes
    invalid signatures over rings buried 60 blocks deep;
  - PX tokens are charged only after cheap checks, so replays cannot drain the budget;
  - local transactions wait for a stem peer;
  - Dandelion++ uses the 0.2 / 39 s pair;
  - the /16 outbound diversity bug is fixed;
  - seeds are used as a fallback;
  - there is no oracle on `InvTx`;
  - the onion listen address is advertised only to peers of the same kind;
  - timeouts are no longer misbehaviour.
- **P2P, round 3** (`7d72b37`, `1c07316`):
  - chain work runs off the async workers;
  - block connection proceeds in bounded steps, with a fairness pause between them;
  - protocol 2: unknown message types are ignored, and `Version` may carry trailing
    bytes;
  - a per-peer in-flight window of 32 MiB;
  - control messages go ahead of block frames;
  - a mempool conflict query.
- **A poisoned chain lock stops the node** (`35b7cb9`, `7d72b37`).
- **The testnet refuses to start** until the v3 genesis is final (`f6a52ca`).

### Transactions and mempool
- Output one-time keys are conflict keys (F1, `16659ee`).
- Stateless checks run before contextual ones, and the new error variants are
  classified (`b33a1ce`).
- `/px/commitments` is paginated and no longer clones the record log (`d374ef3`).

### Cryptography and randomness (wallet-side; no consensus change)
- **Hedging:**
  - the CLSAG nonce binds the full transcript (F2, `f677e55`);
  - PX delivery, and the transfer, coinbase and PX contexts, are hedged (`b7d0d3a`);
  - PX witness randomness is hedged (`36c250e`).
- Secrets are redacted in `Debug` output, and more intermediate values are zeroized.

### ZK
- Rewritten proofs are rejected: unbound FRI witnesses and empty optional openings
  (`4b277cd`).
- Verification uses a fresh setup configuration (`f36b909`).
- The build refuses `panic = abort` (`5888d4c`).

### Wallet
- **Round 1** (`22ad441`):
  - gap limits and a growing scan window;
  - the vault secret is stored before sending (R11-W1), and the vault trust boundary
    is enforced (P-1, P-2);
  - response caps on the RPC client;
  - secret input from a file or a prompt.
- **Round 2** (`2b0f75a`):
  - decoy eligibility is applied inside the draw;
  - ring members come from a local output index, with no `/outputs` query that
    singles out the real input;
  - outputs of one transaction are not spent together unless needed;
  - PX key derivation 2: ranges, range views and incoming views.

### Storage and node
- Fail-safe load; a failed store stops the node; the PoW cache is keyed by seed
  (`9578517`).
- Consensus fingerprint and build commit in `--version`, the start-up log and `/info`
  (`f440c4b`).

### Mining
- A fresh random nonce start per template (`f331642`).

### Build, CI and supply chain
- **Guest build** (`9ddaddd`): at a fixed path, which was later made path-independent
  on the candidate.
- **CI** (`9ddaddd`, `5872621`):
  - `--locked`;
  - an overflow/debug-assertion job;
  - weekly audit;
  - fuzz `-O -a` with pipefail;
  - failed tests reported as annotations.
- **Dependencies** (`249d4f0`): exact pins for the crates that define consensus bytes.
- **Target guards** (`8097f66`): refuse non-64-bit and x86 non-SSE2 targets.
- **Docker:** pinned toolchain, `.dockerignore`, and the build commit forwarded.

### Tools and tests
- **Supply-audit tool** (`f25f007`): a closed-set supply check for the trial.
- **Tests** (`f6c98c3`):
  - consensus golden vectors, derived from the specs by an independent script;
  - non-malleability tests for tx, block, CLSAG and BP+ (including batch against
    single verification) and ZK field mutation.

### Documentation
- **Honesty corrections** (`6ed731f`, `e5dc2bd`, `42320ac`, `58f25ec`):
  - "audited" wording removed;
  - 3 PX transactions per block, not 4;
  - the PoW limitation is stated;
  - Neptune Cash is named as prior art;
  - a privacy-safe bug template.
- **Operator section:** testnet.md §12.

## 3. What was improved (beyond fixes)

- **Evidence infrastructure:**
  - golden vectors, mutation-checked: all 15 non-equivalent mutants were caught;
  - byte-level malleability sweeps;
  - a consensus fingerprint pinned per network;
  - a build commit visible to operators.
- **Operability:**
  - supply-audit procedure (testnet.md §7.1);
  - operator requirements (§12);
  - `--repair-store`;
  - fail-stop behaviour on store failure or a poisoned lock.
- **Wallet privacy:**
  - guess-newest for a real input spent at about 12 blocks: from about 90 % to 52 %
    (measured in `young_decoys_survive_coinbase_maturity`). The ideal gamma target is
    62 %, so this is **reduced, not solved**.

## 4. What was redesigned

- **Fork choice:** body-complete most-work. The target depends only on storage order,
  so live processing and replay agree.
- **Chain-lock access pattern:**
  - blocking threads;
  - one block worker;
  - bounded sync steps.

  This is not yet the single-writer actor with snapshots that R16-7 recommends.
- **Transaction admission:** checks now run cheapest first, with budgets charged before
  verification and a reject cache.
- **Randomness:** every wallet-side secret draw now goes through a hedged, fully bound
  derivation, apart from three items listed in docs/transactions.md §10.
- **On the candidate only:** a height-scheduled rule-set mechanism (§8).

## 5. Major architectural decisions made under autonomy

1. **Consensus changes go on `v3/candidate` only.**
   - Nothing that changes block or transaction validity was merged to rebuild/core.
   - The exception: `4b277cd` (a decode rule refusing rewritten proofs). That is why
     the v2 identity is retired and the testnet refuses to start (`f6a52ca`).
2. **The PX-F4 "option B" fix is deferred.** It is documented as a limitation. SX1 and
   I2 support the deferral: option B must keep `rcm` prover-chosen.
3. **Standard RandomX is kept for the testnet.** The limitation is documented; the
   mainnet PoW is an owner decision.
4. **Invalid-signature penalty only over rings buried 60 blocks deep**, not 10.
   Reorganizations of 10 blocks only warn.
5. **The Wasm contract system stays out of consensus.** R7, R16 and SX1 agree on
   PX-only contracts.
6. **Other v3 items left unimplemented.** R6's (output key, commitment) uniqueness
   (needs your choice between C and B), R12-2 (v1 weight of deploy and PX inputs) and
   R2-C6 feed-forward (measured: +2,631 cycles; `n_fn = 1` would cross 2^15 rows with
   the usual margin) are left for your decision.

## 6. What remains incomplete

### Before the seven-device trial
- **Your v3 decisions (§8), then:**
  - finish and freeze the candidate;
  - re-measure the widest two-function proof against `MAX_PROOF_BYTES`;
  - re-run P-5, since every proof changed;
  - Linux reproduction of the new kernel ids (the CI matrix has not yet run for the
    candidate).
- **Wallet side of the upgrade mechanism:** `at_height`, and refusing to broadcast
  across an activation.
- **Evidence still missing:**
  - a fuzz campaign re-run with overflow checks;
  - the seed switch at 2113 with real RandomX (the 4-node run is in progress, see §7);
  - a full-mode miner across the switch;
  - a full suite on the release tag.
- **Release procedure:** signed tags, the fingerprint published in two channels, a
  licence decision.
- **Remaining doc and consensus-adjacent items** in the consolidated report §5 (P0
  list).

### Open engineering (P1/P2)
- A single-writer chain actor with snapshots.
- Verification fully outside the lock: relayed transactions are still verified under
  it.
- A headers presync with `MIN_CHAIN_WORK`.
- RandomX: the seed cache built outside the lock, and next-seed prebuild in the miner.
- The addrman v2 and eclipse work (R8-3, R8-5).
- Persistent state with restart snapshots.
- Compact blocks, a wallet compact feed, and parallel verification.
- A seed phrase with version and birthday.
- The PX view-key CLI.
- Wallet SOCKS5 support.
- The remaining hedging items: contract-output `rcm` and function blinds in the vault
  flows, and the membership nonce.

## 7. Tests performed and results

All test runs were in release mode on Windows unless stated otherwise. After each merge
wave the coordinator ran the affected suites on the merged tree.

### Final state of rebuild/core
- **PX proving suites, all passing:**
  - `tx px_consensus` 3/3 (431 s);
  - wallet PX end-to-end 4/4 (771 s), including the vault-secret recovery;
  - chain `restart_rebuilds_the_px_state_exactly` 1/1;
  - p2p PX network tests 2/2;
  - `tx fuzz_decode` 1/1;
  - `px` 49 tests (`unified` 7, `proof` 3);
  - `zk` 13 (proofs 10, field_mutations 1, pins 1, lib 1).
- **Non-proving suites, all passing:**
  - p2p: lib 31, fuzz_message 1, network 42 (+2 PX), withheld_body 1;
  - chain: lib 39, fork_choice 9, manager 20 (+1 PX), mempool_conflicts 10,
    revalidation 4, storage_recovery 8, golden 3, block_malleability 1, fuzz_block 1;
  - node: 5 + 6 + build_id 11 + deploy_configs 9 + info_identity 1 +
    px_commitments 7;
  - wallet: lib 30, e2e 16 (+4 PX);
  - tx: lib 22, adversarial 20, transfers 8, privacy 6, malleability 3,
    validation_order 10, revalidate_after_extension 10;
  - crypto: 96 + malleability 9;
  - consensus: 30 + golden 17 + randomx_end_to_end 2;
  - supply-audit: 6.
- **Checks:** `cargo clippy --locked --workspace --all-targets -D warnings` is clean,
  and `cargo fmt --check` is clean.
- **A flaky test that exposed a real problem.**
  - `pings_are_answered_while_a_long_batch_of_blocks_connects` failed 1 run in 3. The
    cause was that the standard mutex is not fair.
  - Fixed with a 1 ms pause between sync steps; the test then passed 6 of 6.

### CI on GitHub
- Runs 75–77 failed on:
  - lint: a constant assertion (mine);
  - fuzz-smoke: the fuzz lockfile and a missing seed field;
  - intermittent test/overflow failures.
- Runs **78 and 79 passed every job**, including:
  - `guests`: the kernel reproduces on the runner;
  - `overflow`: debug assertions and overflow checks on;
  - `randomx-full`: official vectors on Linux.
- Run 80 (`1c07316`) failed one test on Linux in both test jobs,
  `announcing_a_stem_transaction_neither_reveals_nor_fluffs_it`. It was a test race: the
  stem peer had no stem route, so it fluffed honestly, and its announcement raced the one
  under test. The tests were fixed in `197855b`; the new annotations named the test.
- Failed tests are now reported as annotations, because job logs need admin access.

### v3 candidate (V3-B's runs)
- Non-PX suites: 495 passed in dev mode.
- Wallet: lib 27, e2e 15.
- Proving: `px_consensus` 3/3, `px` 53/53, `zk` 17/17.
- Path independence: identical ELF sha256 from three different directories.
- The coordinator then ran the remaining PX suites on the candidate at `602e07b`: chain
  restart 1/1, p2p PX 2/2, wallet PX e2e 4/4.
- V3-C then added the wallet side of the upgrade mechanism: builds per height, and no
  rebroadcast across an activation. `a9edbf3` also opens the node with base rules
  instead of `for_chain`. Results at `a9edbf3`: wallet lib 33, e2e 18 (+4 PX), and the
  wallet PX e2e 4/4 again.

### Labnet with real RandomX (in progress)
- 4 nodes, light-mode miners, binaries at `83fceee`, 450 minutes, with partitions
  every 25 minutes.
- About 2 h in: height 1,091, all nodes agreeing.
- The seed switch at 2,113 is expected about 5 h into the run.
- The summary lands in `C:/bszkeval/seedrun2/` and must be added to docs/evidence
  when the run finishes.

## 8. v3 decisions for you (the candidate branch)

**Implemented on `v3/candidate`. Please accept or drop each item:**
1. **Height-scheduled rule sets and a branch id** in the signature message and the PX
   `h_tx`. There is one epoch at v3, so behaviour is unchanged. Later changes can
   activate by height with no reset.
2. **Deploy rules:**
   - reject duplicate programs;
   - reject budgets above the proving limits;
   - an exact deploy fee;
   - a 1 MiB deploy budget per block.
3. **PX-F5:** the kernel refuses contract outputs that carry an owner.
4. **Proof rules:**
   - the canonical FRI folding schedule is required;
   - `CIRCUIT_ID` enters the transcript.
5. **Platform-neutral kernel and vault ELFs,** giving new ids:
   - kernel `0577e667…`;
   - vault `666f7aab…`.
6. **Genesis-id binding** in P2P sessions and wallet files (not consensus).
7. **The genesis tool and procedure** (`tools/genesis`, docs/testnet-v3-genesis.md):
   - the nonce comes from a Bitcoin block hash, so no one can know it in advance;
   - the network id is a placeholder, `0x0001D673`.

**Not implemented; your decision:**
- **R6 uniqueness.** Option C: key uniqueness on the (output key, commitment) pair,
  with within-transaction key uniqueness kept. Option B: drop C4. Or keep the current
  rule.
- **R12-2.** Count the v1 inputs of deploy and PX transactions in block weight.
- **R2-C6.** Feed-forward in the Hk node. The measured data is in
  docs/reviews/v3-upgrade-mechanism.md §9 (on the candidate).
- **Shielded coinbase into PX** (R3, I4). Recommended: later, by activation height.
- **Mainnet PoW** (R1-C2, I4). Stock RandomX, a BlackSilk-specific configuration, or a
  reviewed optional JIT miner.
- **Licence.**

## 9. Risks that remain

These are open, whatever is decided about v3:
- **PoW:** there is no honest-majority guarantee against anyone running a stock
  RandomX miner.
- **Small anonymity sets:**
  - v1 rings are coinbase-dominated early on;
  - guess-newest is only reduced;
  - Dandelion++ sets are small.
- **PX origin:** the 2.2 MB PX upload reveals its origin to the ISP, even over Tor.
- **Memory and restarts:** all state lives in RAM, and a restart revalidates every
  block.
- **Sync attacks:** there is no minimum chain work during early sync. The work gate
  helps only once 144 or more blocks exist.
- **Chain lock:**
  - one block's validation, up to about 3.4 s with 3 PX proofs, still holds the lock;
  - relayed transactions are still verified under it.
- **Zero knowledge:** statistical and conditional only.
- **Hash margin:** the Poseidon2 partial-round margin is thin (R2-C7).
- **Dependencies:** there are no external test vectors for Ristretto-based CLSAG or
  BP+, and ml-kem is unaudited.
- **Operator evidence:** the platform-neutral kernel ids have been reproduced on
  Windows only. The trial needs a second operator to reproduce them.

## 10. What to do next (recommended order)

1. Read this report and the consolidated report's §1 and §6. Decide the items in §8.
2. Let the coordinator finish the candidate:
   - wallet `at_height`;
   - your choices on R6, R12-2 and R2-C6;
   - re-measure the proof sizes and re-run P-5;
   - CI on Linux.
   Then review the candidate as one diff.
3. Collect the evidence:
   - the finished labnet run past 2,113;
   - a full-mode miner across a key switch;
   - a fuzz re-run with overflow checks;
   - a full suite on the tag.
4. Release steps:
   - a signed release-candidate tag in which the testnet refuses to start;
   - the genesis ceremony per docs/testnet-v3-genesis.md, with you;
   - a constants-only final tag;
   - the fingerprint published in two channels.
5. The seven-device trial: at least 96 h, beyond height 2,113 + 720, with every wallet
   kept, and the supply audit at the end.
