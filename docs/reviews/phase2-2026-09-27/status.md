# Phase 2 status (coordinator log)

## Git
- **v3/candidate** merged into rebuild/core as 9e422d8 (merge commit). Every item had been reviewed by SX1.
- **Removed:** all agent worktrees and temporary branches, local v3/candidate, and the old worktrees repro and wt-v1.
  - All work had been merged into rebuild/core or v3/candidate first.
  - Four stale branches were patch-equivalent (checked with `git cherry`).
- **Pending:**
  - full test suite on 9e422d8;
  - push rebuild/core;
  - delete origin/v3/candidate.

## Disk
- Cleaned from 8.9 GB to 91.4 GB free: removed the repo `target`, `fuzz/target`, `C:\bstarget*` (30 cargo caches) and old scratch copies.
- Kept: `fuzz/corpus`, `seedrun2` and `bin-83fceee` (the labnet is running).

## Evidence
- **Labnet seedrun2** (binaries at 83fceee, 4 nodes, light-mode miners): passed height 2113. All 4 nodes agreed at 2123.
- **Full-mode miner across a switch:** still TODO.

## Research phase (read-only dossiers in C:/bszkeval/p2/research)
- **Harness limit:** 20 concurrent subagents.
- **Running:** 01–20.
- **Queue:** 21–50, launched as slots free.

## 2026-09-27: after RT-DAA
- **rt-daa** (3d80ca6, tools and evidence only) merged into rebuild/core and pushed. daa-sim tests: 34 passed, 0 failed.
- **Decisions:** warm-up 11 (RT-1) adopted; hopper ±5 points for the testnet (option a).
- **Running builders (3/3):**
  - w1-zk (CB-B3)
  - w1-tx-a (CB-B1a)
  - w1-cb-a (CB-A: DAA, ChainParams::check, F-05, BE guard, genesis.rs, RT-1)
- **Next when a slot frees:** CB-B1b, then CB-B2, then the 43 rebuild.

## Wave 1 merges
- **w1-tx-a (CB-B1a):** D8-B, CLSAG D≠identity, early PX decode and RT-14, merged as f1fc15a. Non-PX suites: 570 passed, 0 failed, 6 ignored.
- **w1-zk (CB-B3):** 8 codewords, canonical form, COLLISION_BITS 122, deterministic grinding, AIR digest, advisories and docs, merged as 03e9bd3. The consensus record was merged by concatenation; headings are unchanged so trailer anchors stay valid.
- **OPEN (owner):** after the merges, the fingerprint pins fail as expected: px `consensus_fingerprint` (now 1673ae51…) and node `deploy_configs` (testnet now 3f865a23…).
  - The coordinator's re-pin was blocked by the auto-mode permission classifier (it counts as a security-test change).
  - The pins say "update only with a new network id". Options:
    - (1) the owner authorizes re-pinning at each reviewed merge;
    - (2) leave them red until the fingerprint v3 commit (40), which also sets the new network id.
  - Until then CI's test job is red on these two tests.
- **Running:** CB-A (w1-cb-a), CB-B1b (w1-tx-b), and the coordinator's PX-proving suite run.
