# legacy/: pre-rebuild code (reference only)

Everything here is **excluded from the Cargo workspace and does not build**. It is kept
only as a reference while its functionality is redesigned on the rebuilt core:
- `consensus/`, `randomx/`
- `crypto/`, `tx/`
- `chain/`, `node/`, `miner/`, `wallet/`

Do not deploy anything from this directory. The findings in `AUDIT.md` Phase 2 describe
why each component was replaced.

| Path | What it was | Status |
|---|---|---|
| `node/` | Old node. Fake RandomX, stub P2P, forgeable ring signatures, no balance check. | Replaced by `node/` + `chain/`. |
| `wallet/` | Old CLI wallet. Ring size 1, no stealth outputs, hard-coded seed. | Replaced by `wallet/`. |
| `primitives/` | Old shared types. The broken ring signatures and "quantum ring" were **deleted**. | Superseded by `crypto/` and `tx/`. |
| `smart-contracts/` | WASM contracts (escrow, marketplace) and a fourth RandomX copy. | Deferred: contracts on a chain with hidden amounts and recipients need their own design and spec. |
| `marketplace/`, `gui-wallet/`, `web-wallet/`, `testnet-faucet/`, `block-explorer/` | Applications against the old node's HTTP API. | Deferred: to be ported to the new node RPC. |
| `i2p/` | I2P client used by the old node. | Revisited in the P2P rebuild. |
| `scripts/` | Log comparison tool and a deploy script for the old binaries. | Stale. |
| `deploy/` | Docker, config, monitoring for the old binaries. | Stale; to be replaced for the new binaries. |
| `tests/` | Integration tests against the old node. | Stale. |

Deleted outright rather than parked:
- the C/FFI post-quantum crates (`pqcrypto_native`, `ml-dsa-44`, `ml-dsa-44-c`,
  `ml-dsa44-standalone`);
- the root `build.rs`, which cloned and executed remote code at build time;
- the old ring-signature code;
- stray files.

The pure-Rust `pqsignatures` crate lives in `research/` for the post-quantum research
track.
