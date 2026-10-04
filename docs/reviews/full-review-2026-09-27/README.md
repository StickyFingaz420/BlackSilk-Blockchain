# Full-project internal review, 2026-09-27: source reports

Internal review, not an audit. The consolidated report is
[../full-review-2026-09-27.md](../full-review-2026-09-27.md); it takes precedence where the
senior cross-reviews (SX1, SX2) correct a wave-1 report.

| File | Scope |
|---|---|
| R1-consensus.md | consensus and chain |
| R2-crypto.md | cryptography |
| R3-privacy.md | end-to-end privacy |
| R4-zk.md | ZK and the zkVM |
| R5-px.md | the PX protocol |
| R6-tx-mempool.md | transactions, mempool, economics |
| R7-contracts.md | contracts strategy |
| R8-p2p.md | P2P, sync, network |
| R9-randomx.md | RandomX |
| R10-storage-node.md | storage, node, RPC |
| R11-wallet.md | wallet and UX |
| R12-performance.md | performance and scalability |
| R13-testing-supplychain.md | testing and supply chain |
| R14-docs-dx.md | documentation and operators |
| R15-testnet-decentralization.md | testnet readiness and decentralization |
| R16-architecture.md | whole-system architecture |
| I1–I4 | innovation research |
| SX1, SX2 | senior cross-reviews |
| v3-plan.md | the coordinator's v3 candidate plan, with the SX1 corrections |

Reviewers read a moving tree (commits between `f677e55` and `f6a52ca`). Line numbers refer
to the commit each report names. Many findings were fixed afterwards; the consolidated
register records the status.

These reports are historical records. Where they state a fact in the present tense, it
held for the tree they read, not for the current code. Superseded since then, among
others: the header is 172 bytes and the PoW input is the 47-byte mining blob with the
nonce at byte 39 (not the 100-byte header with the nonce at 92); RandomX uses the salt
"BlackSilk/RandomX/v1" (not Monero's rx/0 salt); the ZK parameter set is BS-ZK-3
(BS-ZK-4 pending); the v3 candidate was merged in 9e422d8. Current:
[docs/consensus.md](../../consensus.md), [docs/STATUS.md](../../STATUS.md).
