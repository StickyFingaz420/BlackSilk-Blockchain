# xmrig compatibility for BlackSilk (2026-10-04)

> Historical record (2026-10-04). Superseded where it conflicts with the code: Option C (the 47-byte mining blob, nonce at byte 39) was implemented in 921fdd5, with the normative text in docs/consensus.md §3; the 172-byte header is committed; no pool or stratum server is part of the project, and `blacksilk-miner` mines solo through `/template`. Current: [docs/consensus.md](../consensus.md), [docs/STATUS.md](../STATUS.md).

xmrig sources: master @ b2ca72480c58d197e18c885d9fc1a0c8d517e60a, copies in ./src/.

## Facts (primary sources)
- Nonce offset: Job::nonceOffset() returns 39 for every RandomX algo except rx/yada (147).
  Nonce size is 4 (8 only for KawPow). Source: src/base/net/stratum/Job.cpp nonceOffset(); Job.h nonceSize().
- Blob size: hex, even length, min nonceOffset+nonceSize (43), max < kMaxBlobSize=408 (so 407 bytes). Job.cpp setBlob().
- If nonce bytes in a received blob are non-zero, xmrig switches to nicehash mode (iterates only the low 24 bits).
- The nonce is written as u32 LE at the offset (Nonce::next, WorkerJob.h). The bytes after it are untouched.
- The whole blob (job.size()) is the RandomX input (CpuWorker.cpp randomx_calculate_hash_first/next).
- Share filter: u64 LE of hash bytes 24..32 < target (CpuWorker.cpp). target: 8 hex chars = compact u32,
  16 hex = u64 LE (Job::setTarget). The full check is the server's job.
- seed_hash: required for RandomX in pool mode, exactly 64 hex chars (Client::parseJob code 7; Job::setSeedHash).
  next_seed_hash is not read by the miner's Client.cpp.
- Submit: {id, job_id, nonce: 8 hex (4 bytes LE), result: 64 hex}.
- Salt: RandomX_ConfigurationSafex only changes ArgonSalt; saltlen = strlen(ArgonSalt) (dataset.cpp 81-82).
- Daemon mode: DaemonClient::parseJob parses blocktemplate_blob as a Monero block (BlockTemplate::parse: varint
  versions, timestamp, prev_id, nonce, miner tx...) and splices the nonce into it at nonceOffset on submit
  (submitblock). Not usable with a non-CryptoNote block.
- OpenCL: blobs <= 128 bytes use a kernel with the nonce hard-wired at byte 39 (blake2b.cl lines 123-125);
  larger blobs use the "big" kernel with a nonce_offset argument.
- Precedents: Yada PR #2411 (+44/-9, 9 files; opened 2021-05-26, merged 2024-08-02). PCoin PR #3843 (open,
  nonce offset 76 + no-seed key) — maintainers slow to merge custom-offset algos.
- Tari RandomXT: 76-byte mining blob = 3 zero bytes | mining_hash(32) | nonce u64 BE (35..43; low 4 bytes at 39) |
  pow_algo | pow_data padded to 32. Zero padding made equal-work variants -> later consensus rule
  check_randomxt_pow_data. (tari base_layer/core/src/proof_of_work/monero_rx/helpers.rs)
- BlackSilk: seed_height identical to Monero rx_seedheight (epoch 2048, lag 64); key = 32-byte BlackSilk block id.
- omr header (uncommitted, read-only): 172 bytes, nonce u64 LE at 164..172 (last field).

## Recommendation
Option C: PoW input = 47-byte mining blob:
  [0..7]  constant tag b"BSilk/1"
  [7..39] mining_hash = H32("mining-hash", network_id u32 LE || header_bytes[0..164])
          (implemented: Blake2b-256 over u8(24) || "BlackSilk/v1/mining-hash" || network_id ||
          header[0..164], the project's tag encoding; the normative text is docs/consensus.md §3)
  [39..47] header.nonce.to_le_bytes()   (xmrig iterates 39..43; server extranonce in 43..47)
A pool rebuilds the header's nonce from a share as `nonce = (extranonce << 32) | xmrig_nonce`
(both little-endian u32 halves: bytes 39..43 are the low half, 43..47 the high half).
Header layout: keep omr's (nonce last). Stratum only (no Monero daemon RPC emulation).
