# 36 rpc-security: research dossier (phase 2, research and briefing)

> Historical record (2026-09-27). Superseded where it conflicts with the code: the wallet derives the decoy distribution from its own output index and makes no spend-time `/distribution` request (1902761). Current: [docs/consensus.md](../../../consensus.md), [docs/STATUS.md](../../../STATUS.md).

Agent 36, 2026-09-27. Repository `rebuild/core` at **`9e422d8`**. This was read-only work: no builds and no tests were run. This is internal engineering work, not an audit.

Evidence classes used below: **[math]** mathematically established, **[test: name]** proven by the named test, **[src]** read in the source, **[ext]** a primary external source (cited in §8), **[assumed]**, **[unknown]**.

---

## 1. Scope and what I read

**Code in scope (read in full):**
- `node/src/lib.rs` (554 lines): the router, the 9 handlers, `with_chain`, `lock`, and `PxPage`.
- `node/src/main.rs` (201 lines): bind, the non-loopback warning, `axum::serve`, the runtime.
- `node/src/config.rs` (416 lines): `rpc_bind`, the defaults, and the TOML file.
- `rpc/src/lib.rs` (769 lines): the wire types, the request/response caps, and the blocking `Client`.

**Code read for context:**
- `p2p/src/net.rs`: `submit_tx` :483-492, `stats` :513-528, `Inner::with_chain` :562-572, `stem_or_fluff` :2501-2542.
- `chain/src/manager.rs`: `submit_block_in_steps` :266-289, `block_at` :544-553, `template` :1247-1281, `check_tx`/`submit_tx` :1200-1215.
- `tx/src/state.rs`: `cumulative_outputs` :88-97.
- `tx/src/params.rs`: the size constants.
- `wallet/src/node.rs`.
- `wallet/src/wallet.rs`: `complete_index` :1800-1865, `plans_for` :1878-1890, the sync and submit call sites.
- `miner/src/main.rs`: the `--node` flag.
- `tools/labnet/src/main.rs`: `wait_rpc`, `node_args`.
- The `deploy/` configs, the systemd units, `check-node.sh` and the Dockerfile comment.

**Dependency sources (local cargo registry, versions from `Cargo.lock`):**
- axum 0.7.9: `src/serve.rs`, `src/json.rs`.
- hyper 1.11.1: `src/server/conn/http1.rs`, `src/common/time.rs`.
- hyper-util 0.1.20: `server/conn/auto`.
- `tower-http` 0.6.11 is already in the lock, pulled in by reqwest.
- `subtle` 2.6.1 is already in the lock.

**Tests read:**
- `node/tests/info_identity.rs`
- `node/tests/px_commitments.rs` (`http_parameters`, over the real router)
- `node/tests/deploy_configs.rs`
- `node/src/config.rs` tests
- `rpc/src/lib.rs` tests (`https_and_unknown_schemes_are_refused`, `an_oversized_body_with_a_length_is_refused_before_reading`, `an_endless_body_without_a_length_is_cut_at_the_cap`, `error_bodies_are_capped_too`, `a_body_within_the_cap_is_parsed_and_redirects_are_not_followed`, `caps_cover_the_largest_honest_responses`, `info_identity_fields_are_optional`)
- how `wallet/tests/e2e.rs` and `tools/supply-audit/tests/regtest.rs` start the router (`router(shared)` plus `axum::serve`)

**Docs and reports:**
- `docs/reviews/full-review-2026-09-27.md` (§3.9, §3.10, the register rows for R10-4, R10-5, R10-11, R3-9 and I3 §3.9, P1-7, P1-10, P2-13, never-change items 27–28, risks 12 and 16).
- `docs/reviews/autonomous-session-2026-09-27.md` (wallet round 2: local output index).
- `full-review-2026-09-27/R10-storage-node.md` (R10-4, R10-5, R10-11, §2.5, §3 target model, §4).
- `SX2-systems-crossreview.md` (R10 rows, P0-7, P0-13).
- `R3-privacy.md` (R3-9, §4.4).
- `I3-network-privacy.md` §3.9.
- `R11-wallet.md` §3.7.
- `R16-architecture.md` R16-7.
- `R13` (rpc has 0 direct tests).
- `docs/blocks.md` §9.
- `docs/testnet.md` §11–§12.

**Phase 2 inputs:**
- `C:/bszkeval/p2/brief.md`
- `roster.md` (entries 30–39)
- `decisions.md` (W2 shared `worth_verifying`; `/template` 503)
- the dossiers of 07 (F07-3, W2) and 09 (M9-8, `/template` 503, `/tip`), for the overlap

---

## 2. Current state

### 2.1 What exists and is correct

| Property | Evidence |
|---|---|
| The RPC binds to `127.0.0.1:<port>` by default, and all deploy configs use loopback. The Dockerfile does not publish 29333. | [src] `config.rs:207-209`; [test: `config::tests::defaults`, `deploy_configs::every_deploy_config_parses_and_is_set_up_as_named`] |
| A non-loopback bind logs a warning, but nothing more. | [src] `main.rs:126-130` |
| The global body limit is `MAX_REQUEST_BYTES` ≈ 18.9 MB, and a compile-time assert ties it to `MAX_BLOCK_BYTES`. | [src] `lib.rs:153,166`, `rpc/src/lib.rs:14` |
| **Cross-site "simple" POSTs cannot reach `/tx`, `/block` or `/outputs`.** axum's `Json` extractor requires `Content-Type: application/json` (or a `+json` suffix), and a cross-origin JSON POST needs a CORS preflight. The router answers the preflight (`OPTIONS`) with 405 and sends no `Access-Control-*` headers, so the browser never sends the real request. **This does NOT hold under DNS rebinding**, where the page is same-origin. | [src] `axum-0.7.9/src/json.rs:117-140`; [ext] Fetch standard (CORS-safelisted content types) |
| CPU-heavy submits and every chain read run on `spawn_blocking`. `/block` connects in bounded steps of `SYNC_STEP_BLOCKS = 8`. | [src] `lib.rs:135-142, 239-244`; `manager.rs:266-289` |
| `/blocks` returns at most 100 blocks and at most 64 MiB of hex. `/outputs` takes at most 1,024 indices. `/px/commitments` is paginated (a slice, not a clone). `/px/contracts` returns at most 1,024 entries. | [src] and [test: `px_commitments::*`] |
| **The PX endpoints are bulk-only:** there is no per-record or per-contract lookup. | [src]; never-change item 27 |
| **Client:** plain HTTP only (`https://` refused), `no_proxy()`, no redirects, a 120 s timeout, and per-endpoint response caps enforced while reading. | [test: the `rpc` tests listed in §1] |
| **`/tx` is not a stempool oracle.** `Network::submit_tx` runs `check_tx` against the mempool and chain, then `stem_or_fluff`. A transaction whose key images are already in the stem returns silently (`net.rs:2505-2508`), and the RPC still answers `accepted: true` with the id. The reply therefore does not depend on stempool membership. This resolves the `[unknown]` in R10 §3. It does not rule out a timing side channel (a stem hit skips a map insert, which is negligible). | [src] `net.rs:483-492, 2501-2542` |
| **The wallet no longer asks for rings.** Ring members come from the local output index. `/outputs` is used only once, for a backfill of the whole missing range in fixed pages (`wallet.rs:1800-1865`). | [src]; `2b0f75a` |

### 2.2 What is missing

These points are confirmed from source, not assumed:

- **No Host-header check, no Origin/Fetch-Metadata check, and no authentication** of any kind. The router has only `DefaultBodyLimit` (`lib.rs:155-168`). [src]
- **No header-read timeout.** `axum::serve` in 0.7.9 builds `hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())` with no timer (`axum-0.7.9/src/serve.rs:423`). hyper's default 30 s `header_read_timeout` is `Dur::Default`, and without a timer `Time::check` returns `None` (it only logs "has default, but no timer set") (`hyper-1.11.1/src/common/time.rs:70-77`). R10-11 had this as [assumed]; it is now [src]. The upstream fix, axum PR #3478, is merged but **unreleased** and marked breaking [ext].
- **No connection cap, no request timeout, and no per-endpoint concurrency limit.** [src]
- **One body limit for every route.** `/tx` accepts 18.9 MB, although the largest transaction is `max(MAX_TX_SIZE, MAX_PX_TX_SIZE, MAX_DEPLOY_TX_SIZE)`. [src] `tx/src/params.rs:17-19,56`
- **The RPC and P2P share one blocking pool.** The RPC `spawn_blocking` tasks and the P2P `Inner::with_chain` tasks share the same tokio blocking pool (default 512 threads) on the single `Runtime::new()` (`main.rs:132`), and all of them contend for one unfair `std::sync::Mutex`. [src]

### 2.3 What the tests prove

- The only HTTP-level node tests are `info_identity` (field names) and `px_commitments::http_parameters` (400s on bad parameters). **No test exercises any security property of the server:** Host, Origin, auth, timeouts, limits under concurrency, or body limits per route.
- The client caps are well tested.
- R13 counts 0 direct tests for `rpc`. That is out of date: 7 client tests exist now. The server side is still untested for security.

---

## 3. Problems in scope

### P1. DNS rebinding and browser-originated requests (R10-4, refined)

**What the problem is, and why it exists.** The RPC trusts whoever can open a TCP connection to loopback. Browsers can do exactly that, by two routes.

1. **DNS rebinding.** The attacker's page at `http://evil.example:29333` rebinds `evil.example` to 127.0.0.1. The page is then *same-origin* with the node. It can read every response and POST JSON. That includes `/block`, which is F07-3's unguarded PoW and seed path, and `/tx`.
2. **Plain cross-site requests to `http://127.0.0.1:29333`.** The page cannot read the responses, but the node still does the work: `<img src>` or `fetch(..., {mode:"no-cors"})` GETs of `/blocks?from=0&count=100`, `/distribution?to=18446744073709551615` or `/template`.
   - `/blocks` clones up to 100 bodies and hex-encodes up to 64 MiB **inside the chain-lock closure** (`lib.rs:312-331`).
   - `/distribution` clones the O(height) vector under the lock (`state.rs:88-97`).
   - This route needs no rebinding. It is the more practical variant, and R10 mentions it only in passing.

**Where browsers stand in 2026 [ext]:**
- **Chrome.** Chrome ≥ 142 prompts for Local Network Access (public page to loopback), and Chrome 145 split this into a separate "loopback-network" permission. The check is made on the resolved address, so it also covers rebinding and no-cors subresource loads.
- **Firefox and Safari.** They have no equivalent shipped protection [assumed from the absence of any such claim in the Chrome and WICG material; not verified per browser version].
- **The "0.0.0.0 day" (Oligo, 2024).** A request to `0.0.0.0:port` reached loopback services on Linux and macOS. It is patched in current browsers, but it shows why a naive "allow any IP literal" Host rule (geth's original behaviour) is wrong.

**Security consequences:**
- **Privacy.** A page can fingerprint that the visitor runs a BlackSilk node, and learn its network, height, peers, commit and version. This links a web identity to node operation.
- **Integrity and DoS:**
  - arbitrary `/tx` and `/block` submissions;
  - F07-3 (deep free-fork headers and bodies stored, attacker-chosen seeds forcing RandomX cache builds under the chain lock);
  - lock-held CPU and memory work from any page the user visits.
- **Not** consensus-critical. Privacy-relevant, and liveness-relevant.

**Prior art [ext]:**
- **Transmission, CVE-2018-5702 (Ormandy).** A session-id header that the attacker could *read* was not a defence. The fix was a Host allowlist.
- **go-ethereum PR #15962.** Added `--rpcvhosts`, a Host allowlist defaulting to `localhost`. It exempted IP literals, which issue #16507 later questioned.
- **Dorsey (2018).** Showed DNS-rebinding attacks against many local devices and APIs.
- **Bitcoin Core** relies on mandatory HTTP auth (cookie or rpcauth), which a browser does not have. It has no Host check.
- **monerod** has optional `--rpc-login` (digest auth) and `--rpc-access-control-origins` (CORS off by default).
- **The W3C Fetch Metadata spec.** `Sec-Fetch-*` headers are sent only to *potentially trustworthy* URLs. `http://127.0.0.1` and `http://localhost` are potentially trustworthy (Secure Contexts), so direct cross-site requests to the node carry `Sec-Fetch-Site: cross-site`. A rebinding request to `http://evil.example` carries **no** Sec-Fetch headers, so the Host check is still needed.

**Proposed design:** three independent layers, all enforced before any handler runs.

1. **Host allowlist.** Parse `Host` (a missing header is rejected with 400 or 403). Allow only:
   - IPv4 `127.0.0.0/8` literals and `[::1]`;
   - `localhost`, compared case-insensitively, with no trailing dot;
   - the exact bound IP when the bind is non-loopback;
   - names listed in a new `rpc_allow_hosts` setting (for example an onion hostname).

   Any port is accepted. Anything else gets 403, including `0.0.0.0`, `[::]`, other IP literals and any DNS name. A rebinding request always carries the attacker's hostname, so this blocks rebinding completely.
2. **Browser rejection.** Answer 403 if the request carries `Origin`, or any `Sec-Fetch-Site`/`Sec-Fetch-Mode`/`Sec-Fetch-Dest` header. None of our clients (reqwest, curl) sends these, and every modern browser sends at least one of them on requests to loopback. There is no CORS support, and `OPTIONS` returns 405 or 403.
3. **Authentication** (P2 below). This is what finally closes the gap for old browsers and non-browser local attackers.

**Trade-offs and what could go wrong:**
- A reverse proxy or onion service forwarding with a different `Host` breaks until `rpc_allow_hosts` lists that name. It must be documented.
- A developer's browser-based tool cannot use the RPC. That is intended (monerod also defaults CORS off).
- Rejecting on `Origin` alone would also break a same-origin browser page, but no such page exists.
- **Invariant:** the guard must wrap *every* route, including routes added later (39's compact feed, 09's `/tip`). It must be applied as a `Router::layer` after all routes, and a test must enumerate the routes.

**Tests that prove the fix** (in a new `node/tests/rpc_security.rs`). For every route:
- `Host: evil.example:29333` gives 403;
- `Host: 0.0.0.0:29333` and `Host: [::]:1` give 403;
- `Host: 127.0.0.1:N`, `127.1.2.3:N`, `[::1]:N` and `LOCALHOST:N` pass;
- a missing `Host` is rejected;
- `Origin: https://evil.example` gives 403;
- `Sec-Fetch-Site: cross-site` (and `same-origin`, `none`) gives 403;
- `OPTIONS` never returns `Access-Control-Allow-*`;
- a `text/plain` POST to `/tx` gives 415, which locks in the current axum behaviour;
- a route-enumeration test fails if a new route bypasses the guard.

These tests prove server behaviour only. Browser behaviour is cited, not tested.

### P2. No authentication (R10-4, auth part; R10 §3 target model)

**What the problem is.** Any local process or user, or any client reaching a non-loopback bind, has full access. On a multi-user host, or with a careless `--rpc-bind 0.0.0.0`, anyone can submit and poll. The warning at `main.rs:126-130` is the only barrier.

**Prior art [ext]:**
- **Bitcoin Core:**
  - `<datadir>/.cookie` holds `__cookie__:<hex of 32 random bytes>`;
  - it is regenerated at every start, written to a `.tmp` file and renamed, with owner-only permissions (`-rpccookieperms` is configurable), and deleted at shutdown;
  - it is sent as HTTP Basic auth;
  - static credentials use `rpcauth`, a salted HMAC-SHA256 so the config never holds the password;
  - the comparison is `TimingResistantEqual`;
  - a failed auth sleeps 250 ms;
  - the docs say "do not enable RPC connections over the public Internet", and `rpcwhitelist` is "not a robust security boundary".
- **monero-wallet-rpc** generates a random login in `monero-wallet-rpc.<port>.login` when no `--rpc-login` is given.
- **monerod** requires `--confirm-external-bind` for a non-local bind.

**Proposed design:**
- **Cookie.** At start the node writes `<data_dir>/rpc.cookie`: 32 bytes from `getrandom`, hex-encoded. It writes a temporary file (`create_new`, mode 0600 on Unix) and renames it into place, and removes the file on clean shutdown.
- **Header.** Clients send `Authorization: Bearer <hex>` (RFC 6750). Bearer is simpler than Basic and needs no username.
- **Check.** Compare in constant time with `subtle::ConstantTimeEq`. subtle is already in the tree and is pure Rust. It must be verified that `subtle` has no `unsafe` issue for node use (agent 44).
- **Failure.** On failure return 401 after an **async** 250 ms delay (`tokio::time::sleep`, not a blocked thread). Do not add `WWW-Authenticate: Basic`, because it would trigger a browser prompt.
- **Scope: every route, including `/info`** (Bitcoin parity). One rule is simpler to reason about than per-route exemptions.
- **Clients:**
  - `rpc::Client::with_token()` and `with_cookie_file(path)`.
  - The miner, wallet, labnet and supply-audit get `--rpc-cookie <path>`. The default is the default data directory of the network implied by the port (29333 testnet, 39333 regtest), and `BLACKSILK_RPC_TOKEN` is an alternative.
  - `check-node.sh` gets `-H "Authorization: Bearer $(cat …)"`.
  - The systemd miner already runs as user `blacksilk` and can read `/var/lib/blacksilk/...` under `ProtectSystem=strict`, which is read-only but readable [src].
- **Static token for remote wallets (P1, with P4).** Configure `rpc_auth = "<salt>$<hmac-sha256 hex>"`, like Bitcoin's `rpcauth`, so the config holds no secret. This needs an HMAC-SHA256 implementation. Check whether `sha2`/`hmac` are already in the tree (agent 44). Otherwise use a SHA-256 of salt‖token, with a domain tag registered by 19.

**Trade-offs:**
- On **Windows**, file permissions cannot be restricted without ACL APIs, which would mean `windows-sys` and `unsafe`, and that is rejected. The cookie relies on the per-user ACL of `%APPDATA%`. This is an accepted limitation, documented; Bitcoin Core applies `rpccookieperms` on non-Windows systems only [assumed from its docs]. If `--data-dir` points outside the user profile on Windows, warn.
- The cookie does not protect against malware running as the same user. No design does.
- **Test harness impact.** `router(shared)` (tests, e2e, supply-audit) stays unauthenticated **but still host-guarded**. Auth is carried in `App` as `Option<Token>`, and `main.rs` always sets it. A test asserts that the binary's path always passes a token.

**Tests:**
- no header gives 401;
- a wrong token of the same length gives 401;
- a malformed header gives 401;
- the right token gives 200;
- the cookie file exists after start, has mode 0600 (Unix), is different on every start, and is gone after a graceful shutdown;
- a stale cookie from a crashed run is overwritten;
- the client reads a cookie file;
- the miner and wallet e2e run against an authenticated router.

### P3. Connection and resource controls (R10-11, now source-verified)

**Problems:**
- **(a) No header timeout:** slowloris (§2.2).
- **(b) No connection cap:** `axum::serve` spawns one task per accepted connection, without bound.
- **(c) No admission control on chain work.** Each request spawns a blocking task that waits on the unfair std mutex. A local flood, or a browser before the P1 fix, can queue up to 512 blocking tasks. `Inner::with_chain` tasks for P2P headers, bodies and transactions then wait behind them. P0-7/R16-7 fixed the async-worker side; **this is the blocking-pool side, and it is not reported anywhere.**
- **(d) Oversized `/tx`.** An 18.9 MB `/tx` body is allowed, and `hex::decode` plus `Transaction::decode`/`Block::decode` run on the **async worker** (`lib.rs:234-235, 274-275`), not on a blocking thread.

**Prior art [ext]:**
- Bitcoin Core: `-rpcthreads=4`, `-rpcworkqueue=16` (excess requests are rejected with "Work queue depth exceeded", HTTP 503), `-rpcservertimeout=30`.
- monerod restricted mode: `RESTRICTED_BLOCK_COUNT` and similar caps.
- axum PR #3478: sets a timer so that hyper's 30 s header timeout applies.

**Proposed design:**
- **A serve loop in `node/src/serve.rs`.** Use `hyper_util::server::conn::auto::Builder` (or the http1 builder) with `.timer(TokioTimer::new())` and `header_read_timeout(10 s)`, a connection `Semaphore` (64 by default), and graceful shutdown.
  - hyper and hyper-util are already transitive dependencies. They become direct ones (agent 44 to confirm).
  - `axum::serve` stays compatible, because the router is a `tower::Service`.
- **Request deadline.** A per-request deadline (60 s) applies to reading the body and running the handler. Aborting a handler cannot stop a running `spawn_blocking` job, so the real bound is admission (below) plus bounded per-call work.
- **Per-class admission** with `try_acquire`, answering an immediate 503 `busy` like Bitcoin's work queue:

  | Class | Endpoints | Concurrent |
  |---|---|---|
  | reads | `/info`, `/px/*`, `/outputs`, `/distribution` | 4 |
  | bulk | `/blocks`, `/template` | 2 |
  | submits | `/tx` | 2 |
  | blocks | `/block` | 1 |

  This bounds RPC occupancy of the blocking pool to 9 threads.
- **Per-route body limits.** `/tx` gets `2·max_tx + 4 KiB`; `/outputs` gets `1,024 × 21 + 1 KiB` (for 1,024 indices); `/block` keeps its current limit; GET routes get 0.
- **Decoding off the async worker.** Move hex and struct decoding into the blocking closure.

**Trade-offs:**
- A miner or wallet that sees 503 must retry with backoff. 09 already plans retry on 503 for `/template`.
- Limits that are too tight could throttle labnet, so they are configurable, with defaults sized for one miner and a few wallets.

**Tests:**
- a slow-header client is closed within the timeout (configure 200 ms in the test);
- connection N+1 is refused or queued;
- a saturated class answers 503;
- **a liveness test:** while 200 concurrent RPC reads hammer the node, a P2P-style `with_chain` probe completes within X ms (bounded, not measured on today's code);
- `/tx` over its limit gives 413;
- `/block` at the maximum size still passes.

### P4. Non-loopback binds only warn (R10-4 last bullet)

**Design:**
- Refuse to start when `rpc_bind` is not loopback unless both of these hold:
  - `rpc_allow_remote = true`, the equivalent of Monero's `--confirm-external-bind`;
  - authentication is active (it always is once P2 exists; a static `rpc_auth` is recommended for remote use).
- Log an explicit **"plaintext HTTP"** warning: the token and every request are cleartext. Recommend SSH, a VPN or a Tor onion service.

**Scope:** policy only, with no identity impact.

**Tests:** config tests covering refusal, acceptance, and the deploy configs.

### P5. `/block` admission gate (F07-3; decision W2)

The endpoint side belongs to me; 07 and 31 supply the shared `worth_verifying` predicate in `chain`.

- The handler must call the predicate **before** `submit_block_in_steps`.
- **My recommendation for the RPC:** additionally require that the block's parent is the connected tip, or a known header within N blocks of it, and that its seed equals the tip's seed or the next scheduled seed. This is Monero's PR #11238 rule, cited by 07. Only the local miner legitimately uses `/block`.
- **Tests** (in `node/tests/rpc_security.rs`):
  - a block extending a deep low-work fork gets a clean rejection, with no store write and no PoW call (use a counting `PowFunction`);
  - a block on the tip passes.

### P6. `/distribution` cost (R10-5 residual)

**Problem:** every call clones the full cumulative vector under the lock (`state.rs:88-97`) and then truncates it. The cost is O(height) per call. The wallet calls it once per send, with `to = synced_height` (`wallet.rs:1887-1889`).

**Design:**
- Add `MemoryChain::cumulative_outputs_range(from, to)`, which copies only the slice.
- Add an optional `from` parameter (default 0, for compatibility) and a maximum span, `MAX_DISTRIBUTION_SPAN = 100_000` (about 2 MB of JSON).
- Give the client a `distribution_range` method.
- **Better long term (38/39):** the wallet computes the distribution from its own complete output index, which already holds the heights. That removes the call, and with it the "about to send" timing signal to a remote node (P8).

**Tests:**
- the pages reassemble the full vector;
- a span over the limit gives 400;
- the lock is held for O(span) (structural, by code review).

### P7. `/info` information exposure

**Current fields:** network, id, height, tip, difficulty, generated, mempool transactions and bytes, outputs, peers, header height, deepest reorg, misbehaving disconnects, genesis id, fingerprint, build commit and version.

For an authenticated local admin this is appropriate and useful: R15-8 requires the identity fields.

For any future **restricted or public** surface, follow Monero's `on_get_info` [ext], which in restricted mode zeroes the connection counts, peer-list sizes, alt-block count, start time and version, and rounds the database size. For BlackSilk that means hiding `peers`, `misbehaving_disconnects`, `deepest_reorg`, `build_commit` and `version`, and keeping the identity fields (genesis id, fingerprint). The P2P `NetStats` (stempool size, bans, addrman sizes) must **never** be exposed on any surface: the stempool size is a Dandelion signal.

### P8. Remote-node privacy for wallets (R3-9, I3 §3.9)

**What a remote node, or anyone on the path, learns today** (plaintext HTTP, no SOCKS) [src]:
- the wallet's IP address;
- its scan start (the birthday), from the first `/blocks?from=`;
- the fact that a send is imminent (a `/distribution` call followed by `/tx`);
- the transaction itself, together with the IP address. The node then treats it as `Source::Local` and stems it, so the network does not learn the origin, but the operator does.

`/outputs` no longer reveals rings (§2.1). `docs/blocks.md` §9 still says it does (finding F36-10).

**Prior art:** Monero recommends your own node or a remote node over Tor, and provides restricted RPC with `--public-node`. Bitcoin Core says never to expose the RPC publicly.

**Recommendation:**
- **Agent 38 owns** wallet SOCKS5, with separate circuits for queries and submits.
- **Agent 36 provides:**
  - (a) the documentation;
  - (b) P4, the remote bind with auth;
  - (c) a P2/P3 **restricted mode** design: a separate listener, an endpoint whitelist `{/info (reduced), /blocks, /distribution, /px/*, /tx}`, never `/template`, `/block` or the `/outputs` per-index API, per-IP token buckets, stable error codes, bulk-only, and served as an onion service.
- **Invariant:** no endpoint that looks up an individual record, contract or ring.

### P9. Robustness of handlers under the lock

**Problem.** `lock()` exits the process (code 70) on a poisoned mutex (`lib.rs:63-75`). Any panic inside an RPC closure that holds the lock therefore becomes a node kill switch that any RPC client can trigger.

**Current exposure.** The `expect`s at `lib.rs:317,326` (`block_at`, `first_output_at` for `h ≤ height` under the same lock) and in `manager.rs:1250` are unreachable by argument [src]. There is no test.

**Recommendation.** Replace the `expect`s with errors that answer 500, and add a property test: random `(from, count, to, limit)` values never panic.

**Severity:** Low.

### P10. Stringly-typed errors

`SubmitResult.error` is `format!("{e:?}")`, and the client's `already_pooled` matches on `Debug` names (`rpc/src/lib.rs:106-112`). R10 §2.5 noted this.

**Recommendation:** add an optional `code: Option<String>` field with a stable enum mapping (serde default for compatibility) and keep `error`. P2.

---

## 4. New findings

The existing reports cover R10-4, R10-5, R10-11 and R3-9. The IDs below refine them or add to them.

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F36-1** (R10-4 refined) | **Medium** (privacy + integrity; the trial runs on browsing desktops) | Not implemented | `node/src/lib.rs:155-168` | DNS rebinding makes a web page same-origin with the RPC. It can read `/info` and POST `/tx` and `/block` (F07-3 path: deep-fork headers and bodies stored, attacker seeds forcing RandomX cache builds under the chain lock). Chrome ≥ 142 mitigates this with the LNA prompt; Firefox and Safari do not. | high [src]; exploit class [ext]; not demonstrated against this node |
| **F36-2** (new) | **Medium** (liveness) | Not implemented | `lib.rs:302-334` (`/blocks` encodes under the lock), `lib.rs:485-496` + `state.rs:88-97` (`/distribution`), `lib.rs:199-219` | **No rebinding needed.** Any visited page fires no-cors GETs at `http://127.0.0.1:29333/blocks?from=0&count=100` in a loop. Each call clones up to 100 bodies and builds up to 64 MiB of hex while holding the chain mutex. P2P body and header processing stalls, and memory grows with concurrency. The page cannot read the replies, and it does not need to. | high [src]; browser behaviour [ext]/[assumed] per browser |
| **F36-3** (new) | **Medium** (liveness) | Not implemented | `lib.rs:135-142`, `p2p/src/net.rs:562-572`, `main.rs:132` | RPC and P2P chain tasks share one tokio blocking pool (default 512) and one unfair std mutex. Without admission control, a burst of cheap RPC reads queues hundreds of blocking tasks ahead of the P2P `with_chain` jobs. Not measured. | medium [src] |
| **F36-4** (R10-11 confirmed) | Low (loopback); Medium if bound non-loopback | Not implemented | `main.rs:181`; `axum-0.7.9/src/serve.rs:423`; `hyper-1.11.1/src/common/time.rs:70-77` | Slowloris: hyper's default header timeout is disabled because axum 0.7.9 sets no timer. Unbounded connections, no request deadline. The upstream fix (#3478) is unreleased. | high [src] |
| **F36-5** (R10-4, auth) | Low (loopback); **High** if non-loopback | Not implemented | `main.rs:126-130` | Any local user or process, or anyone who can reach a mistaken non-loopback bind, gets full RPC. The only barrier is a log warning. | high [src] |
| **F36-6** (new) | Low | Partially implemented | `lib.rs:166, 234-235, 274-275` | `/tx` accepts 18.9 MB (the block limit), and hex and struct decoding run on the async worker, not on a blocking thread: tens of ms of async-thread stall per large request [assumed magnitude]. | high [src] |
| **F36-7** (R10-5 residual) | Low | Not implemented | `lib.rs:485-496`, `tx/src/state.rs:88-97` | `/distribution` clones O(height) under the lock whatever `to` is. Unpaginated. | high [src] |
| **F36-8** (F07-3 endpoint side) | Low (loopback) / Medium (after F36-1 or F36-5) | Not implemented | `lib.rs:230-244` | `/block` bypasses the shared work gate. | high [src] (07) |
| **F36-9** | Informational | — | `lib.rs:175-197` | `/info` exposes operational data. That is acceptable for an authenticated local admin, but it must be reduced on any restricted or public surface (Monero parity). `NetStats` must never be exposed. | high |
| **F36-10** (new, docs) | Low | Not implemented | `docs/blocks.md` §9 | The spec table omits `/px/commitments` and `/px/contracts`. It says a remote node learns "which ring members it fetches", which has been false since `2b0f75a`. It does not mention the send-timing signal of `/distribution`. It gives no auth or limit semantics. | high |
| **F36-11** (resolves an R10 unknown) | Informational (positive) | Complete (source-read; no test) | `p2p/src/net.rs:483-492, 2505-2508` | `/tx` replies do not depend on stempool membership, so there is no stem oracle through the reply. Side effect: a conflicting stem transaction is reported `accepted:true` and silently dropped, which is acceptable because it avoids the oracle. Needs a regression test. | high [src] |
| **F36-12** (new) | Low | Not implemented | `lib.rs:63-75, 317, 326`; `manager.rs:1250` | A panic inside any RPC lock closure poisons the mutex, and the next `lock()` exits the node. Unreachable today by argument, but untested. A future bug would be a remote kill switch. | medium |
| **F36-13** (R10 §2.5) | Low | Not implemented | `rpc/src/lib.rs:106-112`; `lib.rs:221-267` | Stringly-typed error API. `already_pooled` depends on `Debug` names. | high |
| **F36-14** (R3-9 restated) | Medium (for remote-node users) | Partially implemented | `rpc/src/lib.rs:357-364`, `wallet.rs:1887` | A remote node or on-path observer sees the IP↔transaction link, the birthday and the send timing. Owner 38; 36 documents it and supplies P4 and the restricted mode. | high |

**I challenge one existing claim.** R10-4 rates the risk mainly through rebinding. F36-2 shows that the cheaper, rebinding-free cross-site GET route already causes lock-held work today. The Host check alone does **not** fix it, because the Host is `127.0.0.1`. The Origin/Fetch-Metadata rejection, or auth, is required.

**R13 correction.** It says "rpc: 0 tests". 7 client tests exist now; the server-side security tests are still 0.

---

## 5. Implementation plan for phase 2

**Proposed ownership split of `node/src/lib.rs`:**
- **36:** the router composition (`router_with`) and the new modules `node/src/guard.rs` and `node/src/serve.rs`.
- **09:** the `/template` and `/tip` handler bodies.
- **36:** the `/block` handler wiring (07 and 31 provide the predicate).
- **34:** later, the replacement of `with_chain` by snapshots.

All items are **policy only**: no consensus change and **no identity impact**.

| # | Item | Files (owner 36 unless noted) | Tests | Docs | Size | Priority |
|---|---|---|---|---|---|---|
| **W1** | **Host allowlist and browser rejection** (P1): a middleware layer covering all routes; `rpc_allow_hosts` config | new `node/src/guard.rs`; `node/src/lib.rs` (`router_with` only); `node/src/config.rs` | new `node/tests/rpc_security.rs`: the Host, Origin, Sec-Fetch, OPTIONS and text/plain cases; route-enumeration guard (adversarial and regression) | `docs/blocks.md` §9, `docs/testnet.md` §11 | S | **P0** (cheap; trial on browsing desktops; closes F36-1, F36-2 and the browser path of F36-8) |
| **W2** | **Connection and admission controls** (P3): a serve loop with `TokioTimer` + `header_read_timeout`, a connection semaphore, per-class `try_acquire` returning 503, a request deadline, per-route body limits, and decoding moved into the blocking closure | new `node/src/serve.rs`; `node/src/main.rs`; `node/src/lib.rs` (handlers `submit_block` and `submit_tx`: decode placement only); `node/Cargo.toml` (direct `hyper`, `hyper-util`; 44 confirms) | slow-header close; connection cap; 503 when saturated; 413 on oversized `/tx`; a max-size `/block` still accepted; **a liveness test**: a P2P-style chain probe stays within a bound during an RPC flood | `docs/blocks.md` §9 (503 and limits) | M | **P0** (F36-3; the trial is exposed to F36-2 until W1 lands) |
| **W3** | **Cookie auth** (P2): generate, write, delete; Bearer check with `subtle`; async 250 ms delay on failure; `Client::with_token`/`with_cookie_file` | `node/src/main.rs`, `node/src/guard.rs`, `node/Cargo.toml` (`subtle`), `rpc/src/lib.rs`, `tools/supply-audit`, `deploy/scripts/check-node.sh`. **Via owners:** `miner/src/main.rs` (09: add the `--rpc-cookie` flag), `wallet/src/main.rs` (wallet owner 37 or 38: `--rpc-cookie`), `tools/labnet` (09/45: read each node's cookie) | 401 and 200 cases; cookie mode 0600 (Unix, `#[cfg(unix)]`); different on every start; deleted on shutdown; the e2e miner and wallet run authenticated; the client reads the cookie | `docs/blocks.md` §9, `docs/testnet.md` (how the miner and wallet find the cookie), `SECURITY.md` | M | **P1** (P0 if the coordinator wants auth before the trial; it touches 5 crates) |
| **W4** | **Refuse non-loopback binds** unless `rpc_allow_remote` is set and auth is on; a static `rpc_auth` salted hash for remote wallets | `node/src/config.rs`, `node/src/main.rs`, `deploy/config/*.toml` (with 40), `node/tests/deploy_configs.rs` | config refusal and acceptance tests; the deploy configs still parse | `docs/testnet.md` §11–12 | S | **P1** |
| **W5** | **`/block` admission** (P5): call the shared `worth_verifying` predicate; pinned-seed or tip-proximity rule for the RPC | `node/src/lib.rs` (`submit_block`). The predicate is in `chain/src/manager.rs` (07/31). | deep-fork submission rejected with no PoW call and no store write (counting pow); a tip block passes | `docs/blocks.md` §9, `docs/p2p.md` §12 (07) | S | **P0** (decisions: W2 is P0) |
| **W6** | **`/distribution` range** (P6) | `node/src/lib.rs` (handler), `rpc/src/lib.rs` (`from`, `distribution_range`), `tx/src/state.rs` `cumulative_outputs_range` (**owner 35 or 11**; a few lines) | pages reassemble; span limit gives 400; old clients (no `from`) still work | `docs/blocks.md` §9 | S | **P1** |
| **W7** | **Non-panicking handlers** (P9) and **error codes** (P10) | `node/src/lib.rs`, `rpc/src/lib.rs` (a `code` field with serde default; `already_pooled` checks `code` first) | a proptest of random query parameters (no panic, no poisoning; proptest is approved in principle, 41 owns adoption); code round-trip; a `/tx` stem-no-oracle regression test (F36-11) using the approved `#[doc(hidden)]` stempool accessor | `docs/blocks.md` §9 | S–M | **P2** |
| **W8** | **Restricted/public mode** (P7, P8): a second listener, an endpoint whitelist, reduced `/info`, per-IP token buckets, onion guidance | `node/src/serve.rs`, `node/src/guard.rs`, `node/src/lib.rs`, `node/src/config.rs` | whitelist enforcement; reduced `/info` fields; rate limiting | `docs/blocks.md`, `docs/testnet.md` | M–L | **P3** (a design note now; implement after the key and SOCKS work of 37/38) |
| **W9** | **Docs:** rewrite blocks.md §9 (all 9+ endpoints, limits, auth, 503, the remote-node leakage inventory from P8, the removal of the "ring members" claim); testnet.md §11–12; P0-14 trial procedure: keep the RPC firewalled until W1–W3 land | `docs/blocks.md` §9 (36 writes the content, 47 coordinates), `docs/testnet.md` (40/47) | none | — | S | **P0** (the docs claim nothing false at the freeze) |

**Benchmarks:** none needed for correctness. One optional `#[ignore]` timing test for W2: P2P-probe latency under an RPC flood, before and after, as evidence for F36-3.

**Dependencies to vet (agent 44):**
- `hyper` and `hyper-util` as direct dependencies of `node`, with the features `server`, `http1`, `tokio`. They are already in the graph through axum.
- `subtle` as a direct dependency of `node`. It is already in the graph.

No new third-party crate enters the build, and `tower-http` is not needed.

---

## 6. Dependencies and conflicts

- **07 randomx-cache-seed / 31 p2p-sync:** the shared `worth_verifying` predicate (decision W2). 36 wires it into `/block` (W5). The severity of F07-3 depends on W1 and W3.
- **09 mining-templates:**
  - `/template` 503 while syncing, and `/tip` (09 owns both handlers);
  - any new route must sit behind the W1 guard;
  - the miner's `--rpc-cookie` flag in `miner/src/main.rs` (09 owns the file);
  - W2's 503 on saturation needs the same retry and backoff as 09's 503 handling.
- **34 chain-actor-concurrency:** snapshots remove the lock from RPC reads. W2's admission semaphores stay useful (bounded CPU and memory) and must not assume the chain lock. `with_chain` is 34's to replace.
- **35 storage-recovery:** `tx/src/state.rs` (W6 range accessor).
- **37/38 wallet:** `wallet/src/main.rs` cookie flag; SOCKS5 (R3-9); computing the distribution locally (removes the send-timing signal); remote-node documentation.
- **39 wallet-sync-scanning:** any compact-feed endpoint goes behind the W1 guard, with the W2 bulk class, and stays bulk-only.
- **40 testnet-genesis:** `deploy/config/*.toml` (W4), `docs/testnet.md`, P0-14 procedure.
- **41 / 44:** proptest adoption; dependency vetting (hyper-util, subtle).
- **45 (labnet/CI):** `tools/labnet` reads the cookies. The labnet evidence runs must keep working.
- **47 docs; 50 red-team:** review of W1 and W3 (rebinding cases, constant-time comparison, cookie lifecycle).

---

## 7. Open questions for the coordinator

1. **Cookie auth before the trial (W3 as P0)?** It touches `node`, `rpc`, the miner, the wallet, labnet, supply-audit and `check-node.sh`. W1 alone blocks the browser paths; W3 adds protection against local users and processes. I recommend W1, W2, W5 and W9 as P0 and W3 as P1, unless trial devices are shared or multi-user.
2. **Auth on `/info` too?** I recommend yes (Bitcoin parity, one rule). The cost is that `check-node.sh` and labnet readiness polling must read the cookie.
3. **Windows cookie permissions:** accept the `%APPDATA%` ACL inheritance limitation, with a warning for custom data directories outside the profile? (The alternative needs `unsafe` Windows ACL calls, which are rejected.)
4. **Ownership of `node/src/lib.rs`:** confirm the split in §5 (36: router, guard, serve and the `/block` wiring; 09: `/template` and `/tip`; 34: `with_chain`).
5. **Restricted/public RPC mode for the public testnet (W8):** P3 as proposed, or P2? It matters only if community remote nodes are expected.
6. **Default admission limits** (4/2/2/1, 64 connections, 10 s header timeout, 60 s deadline): acceptable for labnet with 7 miners polling? 09's `/tip` long-poll will hold connections for up to 30 s, so it needs its own class or a higher connection cap.

---

## 8. Sources

**DNS rebinding and browser behaviour:**
- Transmission CVE-2018-5702 (Ormandy); the Host-allowlist fix, PR #468: https://github.com/transmission/transmission/pull/468 ; https://www.cvedetails.com/cve/CVE-2018-5702/ ; https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-5702
- go-ethereum "RPC: DNS rebind protection" (`--rpcvhosts`), PR #15962: https://github.com/ethereum/go-ethereum/pull/15962 ; the IP-literal exemption questioned in issue #16507: https://github.com/ethereum/go-ethereum/issues/16507
- B. Dorsey, "Attacking Private Networks from the Internet with DNS Rebinding" (2018): https://medium.com/@brannondorsey/attacking-private-networks-from-the-internet-with-dns-rebinding-ea7098a2d325
- Oligo Security, "0.0.0.0 Day: Exploiting Localhost APIs From the Browser" (2024): https://www.oligo.security/blog/0-0-0-0-day-exploiting-localhost-apis-from-the-browser
- Chrome, "New permission prompt for Local Network Access" (Chrome 142; the loopback-network split in 145): https://developer.chrome.com/blog/local-network-access ; Intent to Ship: https://groups.google.com/a/chromium.org/g/blink-dev/c/cwu_RUmBpzY
- W3C Fetch Metadata Request Headers (headers only for potentially trustworthy URLs): https://www.w3.org/TR/fetch-metadata/
- W3C Secure Contexts (loopback is potentially trustworthy): https://www.w3.org/TR/secure-contexts/
- WHATWG Fetch standard (CORS preflight, CORS-safelisted request headers): https://fetch.spec.whatwg.org/

**Bitcoin Core:**
- JSON-RPC interface doc (cookie, rpcauth, no public exposure, rpcwhitelist caveat): https://github.com/bitcoin/bitcoin/blob/master/doc/JSON-RPC-interface.md
- `src/httprpc.cpp` (`TimingResistantEqual`, HMAC-SHA256 rpcauth, 250 ms sleep on failure): https://github.com/bitcoin/bitcoin/blob/master/src/httprpc.cpp
- `src/rpc/request.cpp` (`__cookie__`, 32 random bytes, tmp and rename, `cookie_perms`, `DeleteAuthCookie`): https://github.com/bitcoin/bitcoin/blob/master/src/rpc/request.cpp
- `-rpcworkqueue`/`-rpcthreads`/`-rpcservertimeout` behaviour: https://github.com/bitcoin/bitcoin/issues/10436 ; https://github.com/bitcoin/bitcoin/issues/11574

**Monero:**
- monerod reference (`--restricted-rpc`, `--rpc-login`, `--confirm-external-bind`, `--rpc-restricted-bind-port`, `--rpc-access-control-origins`, `--public-node`, `--rpc-ssl`): https://docs.getmonero.org/interacting/monerod-reference/
- `src/rpc/core_rpc_server.cpp` (restricted `on_get_info` field hiding; the `RESTRICTED_*` limits): https://github.com/monero-project/monero/blob/master/src/rpc/core_rpc_server.cpp
- Monero PR #11238, "rpc: reject deep block submissions on restricted RPC" (via 07): https://github.com/monero-project/monero/pull/11238
- monero-wallet-rpc random login file: https://docs.getmonero.org/interacting/monero-wallet-rpc-reference/

**axum, hyper, tower:**
- axum PR #3478, "axum::serve: Enable Hyper request header timeout" (merged 2025-09-16; unreleased and breaking in the CHANGELOG): https://github.com/tokio-rs/axum/pull/3478 ; https://github.com/tokio-rs/axum/blob/main/axum/CHANGELOG.md
- axum issue #2741 / discussion #2716 (slowloris): https://github.com/tokio-rs/axum/issues/2741
- hyper issue #3756 (header timeout semantics): https://github.com/hyperium/hyper/issues/3756
- tower-http `ValidateRequestHeaderLayer::bearer` (deprecated since 0.6.7): https://docs.rs/tower-http/latest/tower_http/validate_request/struct.ValidateRequestHeaderLayer.html
- Local sources: `axum-0.7.9/src/serve.rs:423`, `axum-0.7.9/src/json.rs:117-140`, `hyper-1.11.1/src/server/conn/http1.rs:250,346-353,478-483`, `hyper-1.11.1/src/common/time.rs:70-85`.

**Standards:**
- RFC 6750 (Bearer token usage): https://www.rfc-editor.org/rfc/rfc6750
- RFC 9110 (HTTP semantics, Host): https://www.rfc-editor.org/rfc/rfc9110
