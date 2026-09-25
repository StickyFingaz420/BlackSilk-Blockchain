# K4: reorganization-depth policy (provisional, testnet only)

Status: **provisionally accepted by the owner for the experimental testnet
(2026-09-25). Not a mainnet decision. Included in the internal review (review-status.md §3, components 7 and 11) and in the scope kept for a possible future external review.**

## 1. The policy

| Item | Testnet policy |
|---|---|
| Depth limit | None: the valid chain with the most cumulative work wins, at any depth |
| Checkpoints | None |
| Monitoring | Reorganizations of `DEEP_REORG_WARN_DEPTH` = 10 blocks or more are logged at WARN; `ChainManager::deepest_reorg` records the deepest seen since start |
| Chain selection | Unchanged by this policy |
| Code | `chain/src/manager.rs` (`sync_state`); documented in docs/consensus.md §8 |

## 2. Security implications

| Threat | With no limit (this policy) | With a hard limit N | With checkpoints |
|---|---|---|---|
| **Majority-hash-power rewrite** (K1): double spends, censorship | Possible at any depth for an attacker who out-mines the network. The cost grows with depth, but on a small testnet it is cheap | Rewrites deeper than N are refused by nodes online at the time | Refused below the last checkpoint |
| **Partition or eclipse** | Nodes converge on the heaviest chain once connected | Nodes that followed different branches for more than N blocks **never** converge without manual action. An attacker can split the network on purpose by releasing a secret chain to part of it | As without a limit, above the last checkpoint |
| **Nodes that were offline** (new, restarting or syncing) | Follow the most work, as the online nodes do | They may follow a chain the online nodes refuse (the Bitcoin Cash criticism): a split | Follow the checkpoints |
| **Trust** | None beyond proof-of-work | None, but behaviour depends on each node's history | Trust in whoever publishes the releases |

**Privacy consequences of deep reorganizations**, whatever the policy:
- Transactions whose ring members or PX anchors fall into the disconnected blocks
  become invalid.
- Wallets then spend those inputs again. The reference wallet reuses the stored rings
  (wallet-review.md W-5), so the two spends are linkable but do not reveal the real
  input.
- Decoys younger than the reorganization depth may vanish; the wallet verifies ring
  members by key before reuse.

**Resource consequences:**
- Undo data for every block is kept in memory, so a reorganization of any depth can be
  carried out. Memory grows with the chain (a storage-work item).
- The wallet keeps 720 block ids. A deeper reorganization makes it rescan from its
  restore height: correct, but slow.

## 3. Operational implications for the testnet

- **Confirmations.** With no limit, finality is probabilistic. Testnet guidance: treat
  a payment as final only after 10 blocks (about 20 minutes at 120-second blocks), and
  more for anything that matters.
- **Monitoring.** Operators watch for `reorganization: disconnecting` at WARN level.
  One such warning triggers the incident-response procedure
  (docs/testnet-incident-response.md, "deep reorganization").
- **Expected depth.** Labnet runs with simulated 3-minute partitions produced
  reorganizations up to 17 blocks at 10-second blocks. At the testnet's 120-second
  blocks the same partitions give about 2 blocks. Anything of 10 or more on the
  testnet means a partition of 20 minutes or more, or a hash-power attack.

## 4. Why not a limit or checkpoints now

- A limit trades deep rewrites for permanent splits. On a small testnet, splits cost
  more, and the testnet's purpose is to observe real behaviour.
- Checkpoints add a trust point, and they need a release process that does not exist
  yet.

## 5. Open for mainnet

To be decided with testnet data and the internal review's findings:
- whether finality needs protection beyond proof-of-work (a limit, checkpoints, or
  none);
- a bound on in-memory undo data;
- the wallet's reorganization window.

## 6. Questions for the internal review passes (and any future external reviewer)

1. Is "no limit, warn at 10" acceptable for an experimental testnet with little hash
   power, given its purpose?
2. Are there interactions between deep reorganizations and PX state (anchors, the
   nullifier set, the contract registry, the contract log) that the undo path does
   not handle? The code: `tx/src/state.rs::undo_block`; tests:
   `chain/tests/manager.rs`, `wallet/tests/e2e.rs::px_records_follow_a_reorganization`.
3. What finality mechanism, if any, should mainnet adopt?

## 7. Limitations of this policy (stated plainly)

- **No protection against a hash-power majority.** On a small testnet, anyone renting
  more CPU than all honest miners combined can rewrite history at will. That is
  accepted for an experiment with valueless coins; it is not acceptable for mainnet
  as is.
- **Monitoring only.** The warning and the counter detect deep reorganizations; they
  prevent nothing. The response is manual (docs/testnet-incident-response.md).
- **The counter resets on restart.** `deepest_reorg` covers the time since the node
  started; logs are the durable record.
- **Deep reorganizations are tested only on one machine** (labnet, up to 17 blocks;
  the unit and integration tests). They have not been tested between real machines.
- **PX state under very deep reorganizations** (many PX blocks disconnected at once) is
  covered by the undo code and tests with shallow depths only.
