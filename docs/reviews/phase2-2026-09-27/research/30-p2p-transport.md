# 30 p2p-transport: research dossier (phase 2, phase 1)

Author: specialist agent 30. Date: 2026-09-27. Repository commit: `9e422d8` (branch `rebuild/core`).
This is internal engineering research. It is not an audit, and nothing in it establishes that the transport is secure.

---

## 1. Scope and what I read

**Code in scope (read in full):**
- `p2p/src/transport.rs` (319 lines): the handshake, KDF, AES-256-GCM framing, and its 6 unit tests.
- `p2p/src/message.rs` (427 lines): the codec, `PROTOCOL_VERSION = 2`, `is_known_type`, and its 5 unit tests.

**Code read for integration:**
- `p2p/src/net.rs`: constants (`:60-104`), `accept_loop` / `HandshakeSlot` (`:803-890`), `recv_msg` (`:942-950`), `run_connection` including the Version/Verack exchange (`:952-1045`), the read loop (`:1124-1200`), `write_loop` (`:1226-1244`), `misbehave` / `penalize` / `ban_addr` (`:611-654`), and the unit tests (`:2860-2934`).
- `p2p/src/addr.rs` (`NetAddr::decode`, `:155-181`); `p2p/src/limits.rs` (scores and ban constants); `tx/src/codec.rs` (`Reader::varint`, `count`, `skip`, `finish`).
- `crypto/src/hash.rs` (`h64` = tagged Blake2b-512; the tag registry).
- `chain/src/block.rs:10` and `tx/src/params.rs:17-22`: `MAX_BLOCK_BYTES` = 1,000,000 + 8 MiB + 64 KiB, so `MAX_FRAME` = `MAX_BLOCK_BYTES` + 64 KiB ≈ 9.45 MB.
- `p2p/Cargo.toml`, `Cargo.lock` (the `aes` entry), and the registry sources of `aes-0.8.4` and `aes-gcm-0.10.3`, to check the zeroize features.

**Tests read:**
- `p2p/tests/fuzz_message.rs` (the seeded mutation fuzzer).
- `fuzz/fuzz_targets/p2p_message.rs` (the libFuzzer target).
- `p2p/tests/network.rs`:
  - the helpers `raw_peer*` and `try_raw_handshake`;
  - `malformed_messages_and_floods_are_cut_off`;
  - `wrong_network_and_self_connections_are_refused`;
  - `concurrent_handshakes_respect_the_inbound_limits`;
  - `unknown_message_types_are_ignored_but_charged`;
  - `an_extended_version_and_unknown_handshake_messages_are_accepted`.
- `net.rs` unit tests: `control_messages_overtake_queued_block_frames`, and the others listed at `:2860-2934`.

**Docs and reports read:**
- `docs/p2p.md` §1-§5 (and §10-§11 by grep).
- `docs/reviews/full-review-2026-09-27.md`: the register rows for R8-6, R8-10, R8-11, R8-14, R8-20, R8-21, I4-7 and N-4/N-6/N-9; P0-6, P1-2, P1-3, P2-19 and P3-10; decision D18.
- `docs/reviews/autonomous-session-2026-09-27.md` (by grep).
- `R8-p2p.md` §2.6, §2.10, §2.11, §2.14, §2.20, §2.21 and §3.5.
- `SX2-systems-crossreview.md` (the R8-10 and R15-3 corrections).
- `SX1-core-crossreview.md` (the ML-KEM decision).
- `I3-network-privacy.md` §3.7.
- `I4-sustainability-scaling-pq.md` §0.1 (F5) and §3.4 (I4-7).
- The roster entries for 30 through 34.

**Rules followed:** No build or test was run. No repository file was modified. No repository content was sent to any web service.

---

## 2. Current state

### 2.1 What exists

**The handshake (`transport.rs:122-195`):**
- One unauthenticated round trip of ephemeral Ristretto255 keys: the initiator writes `A`, then the responder writes `B`.
- The shared secret is `S = a·B`.
- The key is `k = H64("p2p/session", LE32(network_id) ‖ genesis_id ‖ A ‖ B ‖ S)`, with `k[0..32]` for initiator→responder and `k[32..64]` for responder→initiator.

**Frames:**
- `AES-256-GCM(k_dir, n, LE32(len)) ‖ AES-256-GCM(k_dir, n+1, payload)`.
- The counter starts at 0 and rises by 2 per frame.
- `len ≤ MAX_FRAME` is checked after the length decrypts and before the payload is read.

**The codec (`message.rs`):**
- 15 message types (0-14).
- Strict decoding with bounded counts.
- An ignored `Version` extension area (P0-8).
- `is_known_type` lets `net.rs` skip unknown types; they are charged to the message and byte budgets.
- Up to 8 unknown frames are tolerated between `Version` and `Verack`.

### 2.2 What is correct and well designed

| Claim | Evidence class |
|---|---|
| No plaintext magic, version or user agent on the wire | source-read (`transport.rs:138-150`, `net.rs:983-995`) |
| Different `network_id`s cannot talk | tested (`different_networks_cannot_talk`, `wrong_network_and_self_connections_are_refused`) |
| Different `genesis_id`s cannot talk (R15-3) | tested (`different_genesis_ids_cannot_talk`, network.rs `wrong_network...`) |
| Directional keys; a reflected frame cannot decrypt, because `k[..32] ≠ k[32..]` except with negligible probability | source-read (`:178-181`), mathematically established under the Blake2b PRF assumption; **not tested** |
| Identity and non-canonical peer keys are rejected. A shared secret equal to the identity is rejected. The group has prime order, so there is no small-subgroup confinement | tested (`bad_keys_and_silence_are_rejected`); mathematically established (Ristretto255 has prime order, RFC 9496) |
| The KDF input is unambiguous: every field has a fixed length | source-read |
| The length is authenticated separately, so a tampered length is detected before allocation or payload read. This is stricter than BIP324, whose 3-byte length is unauthenticated until the packet tag | source-read; tested (`oversized_length_is_rejected_before_reading_payload`, `ciphertext_hides_content_and_tampering_is_detected`) |
| Nonces never repeat under one key: the counter is `u64`, is incremented before `write_all`, and 2^64 is unreachable | source-read |
| AES and GHASH are constant-time in the `aes 0.8.4` / `polyval` backends (AES-NI/CLMUL, or fixsliced software) | assumed (upstream documentation); not measured |
| aes-gcm 0.10.3 is not affected by CVE-2023-42811 (the `decrypt_in_place_detached` plaintext exposure), and the code uses only the allocating `decrypt` anyway | source-read plus the advisory |
| Decoding never panics, and every decoded message except `Version` re-encodes identically | tested (`random_bytes_never_panic`, `fuzz_message.rs`, libFuzzer `p2p_message`) |
| Every list is bounded before allocation | tested (`limits_are_enforced_before_allocation`) |
| Forward compatibility: unknown types are ignored but charged; `Version` extensions are ignored; unknown pre-`Verack` frames are skipped | tested (`unknown_message_types_are_ignored_but_charged`, `an_extended_version_and_unknown_handshake_messages_are_accepted`, `version_extensions_are_ignored_but_known_fields_stay_strict`) |
| `FrameReader::recv` is cancelled only where the connection is then dropped: in the read loop, `select!` breaks on kill and on timeout | source-read (`net.rs:1126-1133`, `:1017-1022`); not documented as an invariant |

### 2.3 What the tests do not prove

- No known-answer vector for the KDF or the first frame. A change to the tag, the field order or the nonce layout would still pass every test, because both ends change together.
- No test of reflection, frame replay or reordering, truncation mid-frame, or a random byte stream after the handshake. `recv` is never fuzzed.
- No test that the whole handshake finishes within a deadline. Only per-step timeouts are exercised.
- No test of the memory behaviour of pre-registration frames.
- Nothing measures distinguishability or flow shape.

---

## 3. Problems in scope

### P-1. Fingerprintability: the key encoding and the flow shape (R8-20; refines it)

**What and why:**
- The canonical Ristretto255 encoding is injective from about 2^252 group elements into 2^256 strings. A random 32-byte string therefore decodes with probability about 2^-4. The two fixed bits R8 cites (the "non-negative" LSB and bit 255) are only part of that.
- A passive observer runs `decode` on the first 32 bytes of each direction. Every BlackSilk handshake passes; random traffic passes about 2^-8 of the time per connection. That is **about 8 bits of distinguisher per connection** (R8 said 4).
- The flow shape adds more:
  - exactly 32 bytes each way;
  - then two Version frames of size 36 + 51..110 bytes;
  - then 37-byte Veracks;
  - every frame has a constant 36-byte overhead.
- The Version frame length also reveals the advertised-listen kind (none / IPv4 / IPv6 / onion) and the height varint width. (Over Tor, the cell padding hides this.)

**Consequences:** Privacy and censorship. An ISP learns that a host runs BlackSilk, which for a privacy coin can itself be sensitive. Content stays confidential.

**Classification:** Privacy (network metadata). Not consensus.

**Literature and practice:**
- **BIP324** encodes its 64-byte key with ElligatorSwift (SwiftEC, Chávez-Saab, Rodríguez-Henríquez and Tibouchi, ePrint 2022/759), adds 0-4095 bytes of garbage with a 16-byte derived terminator, and supports decoy packets with an ignore bit. It explicitly does *not* target censorship resistance: "a pseudorandom bytestream", shapable.
- **Noise rev. 34** recommends Elligator for "indistinguishable from random" handshakes.
- **Elligator 2** (Bernstein, Hamburg, Krasnova and Lange, CCS 2013) covers about half the points of Curve25519.
- **Elligator Squared** (Tibouchi, FC 2014, ePrint 2014/043) encodes *any* point of a prime-order curve as a uniform 2-element string, P = f(u1)+f(u2). **Ristretto255's `from_uniform_bytes` is exactly f(u1)+f(u2)** (RFC 9496 §4.3.4), and BlackSilk already uses it for `Hp`.
- **curve25519-dalek 5.0.0** (released 2026-07-06) exposes `RistrettoPoint::map_to_curve_inverse(&self) -> [CtOption<[u8;32]>; 16]` behind the `lizard` feature. That makes an Elligator-Squared encoder for Ristretto possible in pure Rust with no fork. BlackSilk pins dalek `=4.1.3`, which has no such API.
- **Pitfalls:**
  - obfs4's Elligator2 use was "trivially distinguishable with simple math" until obfs4proxy 0.0.12 (2021-12-31). The cause was cofactor and representative bugs.
  - The Tor Project's Rust `curve25519-elligator2` is still `0.1.0-alpha.2` (2024).
  - A naive Elligator-Squared encoder that always takes the first preimage is distinguishable. Tibouchi's algorithm samples the preimage index uniformly in `[0, d)` and retries when that index is empty.
- **Limits of "looks random":** Wu et al. (USENIX Security 2023) show the GFW blocks *fully encrypted* traffic with popcount and printable-prefix exemption heuristics. Random-looking bytes are themselves a fingerprint to such a censor. BIP324 and obfs4 are both in that class.

**Trade-offs:**
- A uniform encoding costs 32 more bytes and an inverse map (a few field inversions, a retry loop).
- It adds dalek 5 as a second dalek version in the tree, or a crate upgrade that touches consensus crypto. The p2p crate could use 5.0 alone while `crypto/` stays on 4.1.3.
- Garbage and decoys cost bandwidth.
- None of this gives censorship resistance. Tor with pluggable transports, through `--proxy`, remains the answer for censored users (I3 §3.7 agrees).

**Tests that would prove a fix:**
- A statistical indistinguishability test: 2^16 encodings, per-bit chi-square/frequency, and the decode-rate test must match uniform, e.g. `decode()` success ≈ 1/16 on the halves.
- A round trip `from_uniform_bytes(encode(P)) == P`.
- Known-answer vectors.

**Invariants:** no cleartext marker; `network_id` and `genesis_id` stay bound into the key schedule.

### P-2. "Probe resistance" is not attainable for public listeners (R8-20 correction)

- R8-20 says the responder "answers any 32 bytes" and that a censor confirms a listener with one probe. True, but no design for a *public, permissionless* listener can avoid it: a censor can simply run the protocol as a client.
- BIP324 has the same property: any 64 bytes get a 64-byte reply.
- Probe resistance requires a secret the prober lacks:
  - obfs4 uses a bridge line with the server's static key and a node ID;
  - I3 §3.7's "bridge mode" uses a responder static key;
  - Monero PR #8996 uses certificate fingerprints, and is still unmerged in 2026.
- Frolov, Wampler and Wustrow (NDSS 2020) show that even secret-gated servers are identifiable by their close thresholds and timeouts.

**Conclusion:** For public nodes, drop "probe resistance" as a goal. Offer it only in an opt-in bridge mode (P3). What *can* be removed cheaply is the unconditional immediate reply to non-protocol bytes, and only once keys are uniform (P-1): with v1 the reply itself is the 2^-4 test.

### P-3. No transport versioning path: the transport is a flag day (new, architectural)

**What:**
- The transport has no cleartext marker, by design, and no version inside the handshake.
- BIP324 detects v1 peers by matching the 16-byte `magic ‖ "version"` prefix and falls back with a v1 reconnect. BlackSilk v1 has no such prefix.
- So a v2 responder cannot tell a v1 Ristretto key from the first half of a v2 uniform key: 1/16 of v2 prefixes also decode as valid Ristretto.
- An initiator could fall back by reconnecting, but that needs a signal that a peer supports v2. `NetAddr` carries no service bits, and BIP324 needs `NODE_P2P_V2`.
- The reconnect-downgrade is itself a fingerprint, and a downgrade vector.

**Consequence:** Any transport change after launch needs dual-stack detection heuristics, an addr-format change and a downgrade policy. Before launch it costs nothing: the testnet reset is authorized, and mainnet has its own genesis.

**Classification:** Architectural and liveness (upgrade path). Not consensus. It is a network-wide protocol flag day, like the genesis binding (R15-3).

**Recommendation:** Decide now. Either ship transport v2 (P-1, P-5, P-6, P-7) at the v3 testnet genesis, or record explicitly that v1 is frozen for the v3 testnet and that v2 is a reset or mainnet-genesis item. In either case, reserve an in-band version:
- the KDF input should include a transport-version constant (`LE32(2)`);
- a future v3 can then only be a new flag day or an additive in-band negotiation after the key exchange, never a fallback.

**Invariant to add:** a transport never falls back silently to a weaker transport.

### P-4. Pre-registration frames: size, budget and deadline (new; extends R8-10 and N-4)

**What:**
- Before `Verack`, a peer is not in `st.peers`, so no message or byte budget applies (`net.rs:998-1031`).
- Each pre-`Verack` frame may still claim `MAX_FRAME` ≈ 9.45 MB. `FrameReader::recv` allocates `len + 16` (`transport.rs:108`), and `decrypt` then allocates a second `len`-byte plaintext (`:110-113`). The peak is about 2 × 9.45 MB per connection.
- Up to `1 + HANDSHAKE_UNKNOWN_FRAMES` = 9 such frames are accepted (`net.rs:96`, `:1017-1031`). Each has its own 10 s timeout.
- The handshake can therefore last about 10 s (key exchange) + 10 s (Version) + 9 × 10 s ≈ **110 s**. docs/p2p.md:102 says "must complete within 10 s".
- All 64 inbound slots can be held in this state. With the attacker streaming data, the transient memory is about 64 × 18.9 MB ≈ 1.2 GB. RSS is attacker-bandwidth-bound, since SX2 notes the allocation is lazy until written.

**Why it exists:** The P0-8 negotiation window was added without a size class for pre-`Verack` frames.

**Consequences:** Memory and bandwidth DoS on listeners by unregistered peers. Moderate, because it is bandwidth-bound and not an amplification. The documentation is also wrong about the deadline.

**Classification:** Security (DoS) and liveness. Policy only.

**Prior art:**
- Bitcoin Core grows the receive buffer incrementally with data received, with a 4 MB message limit.
- BIP324 limits garbage to 4095 bytes.
- Noise caps every message at 65535 bytes.

**Fix:**
- Specify `MAX_HANDSHAKE_FRAME = 4096` bytes for every frame before `Verack`: Version plus extensions, and negotiation messages. Enforce it through a `recv_limited(max)` on `FrameReader`.
- Enforce one overall handshake deadline, `HANDSHAKE_TIMEOUT` from TCP accept to `Verack`, with a single `timeout` around the whole exchange.
- Grow the receive buffer incrementally, in 64 KiB steps as bytes arrive, and decrypt in place. This is R8-10 on the receive side.

**Specify before launch:** Deployed nodes will enforce the cap, so a future protocol must fit its negotiation messages in 4 KiB. That is cheap to state now and impossible to relax later without a flag day.

**Tests:**
- An adversarial test: a pre-`Verack` frame of 4097 bytes → disconnect without ban.
- A test that the handshake is closed at about 10 s under drip-fed unknown frames.
- An allocation-counting test: a global counting allocator in a dedicated test binary, or a `recv_limited` unit test showing the buffer never exceeds the bytes received plus one step.

### P-5. A transport decryption failure bans the peer's IP for 24 h (new)

**What:**
- In the read loop, `Ok(Err(e))` for any non-I/O transport error calls `misbehave(PROTOCOL = 100)` (`net.rs:1133`), which bans the IP for 24 h (`limits.rs:6-12`, `ban_addr`).
- A `Decrypt` failure is **not attributable**: an on-path party that flips one bit on a clearnet link causes it.
- The attacker needs only momentary on-path access. The ban then persists: it is saved to disk and survives restarts. Both ends may ban each other, and honest peers drop out of each other's candidate sets for a day. This helps an eclipse attempt.
- Proxied peers are exempt (`ban_addr` returns if proxied), so a malicious Tor exit (R8-6) cannot do this.
- An inbound hidden-service peer arrives from loopback. Without `allow_private`, a `Decrypt` failure from any onion peer bans 127.0.0.1, which is the known N-6. Any misbehaviour does the same.
- Under the same unauthenticated model, a full MITM can also *inject* authenticated junk (invalid headers) to frame an honest peer. That is inherent to unauthenticated transports and is fixed only by authentication (P-7) or by not scoring what cannot be attributed.

**Prior art:** Bitcoin Core disconnects on a V2Transport failure, without a misbehaviour score.

**Fix:**
- `Decrypt` → disconnect, no score and no ban. Count it in a `transport_failures` statistic.
- `FrameTooLarge` is authenticated, and therefore attributable to the key holder. It can keep its ban.

**Classification:** Security (ban amplification) and liveness. Policy only.

**Tests:** A MITM relay flips one bit after registration → the victim disconnects, `bans` stays empty, and a reconnection succeeds.

### P-6. Hybrid post-quantum key exchange (I4-7)

**What:**
- An adversary who records links today and breaks Ristretto DH later learns which IP sent which `StemTx` first: the Dandelion++ stem origin, retroactively.
- PX's on-chain layer is hash-based and plausibly post-quantum, so for PX users the transport becomes the weakest link for origin privacy. That argues for more than I4's "Low"; I keep Low severity but raise the priority to P1 *if* transport v2 is built at all.

**Prior art:**
- OpenSSH 10.0 (April 2025) defaults to `mlkem768x25519-sha256`, a hybrid.
- PQNoise (Angel, Dowling, Hülsing, Schwabe and Weber, CCS 2022, ePrint 2022/539) replaces DH with KEMs in Noise patterns.
- Kemeleon (Günther, Stebila and Veitch, CCS 2024, ePrint 2024/1086; draft-veitch-kemeleon) gives uniform encodings of ML-KEM keys and ciphertexts for *obfuscated* exchanges. The Rust crate `kemeleon` is `0.1.0-rc.1` (2024), too immature.

**Design choice:** Run the ML-KEM-768 exchange *inside* the classical encrypted channel:
1. The initiator sends `ek` (1184 B) as its first encrypted frame.
2. The responder replies with `ct` (1088 B).
3. Both switch to `k' = H64("p2p/session-pq", k ‖ ss_pq ‖ H(transcript))`.

**Why this construction:**
- It keeps the bytestream uniform with no Kemeleon.
- It resists harvest-now-decrypt-later: a later ECDH break reveals `ek` and `ct` but not `ss_pq`.
- It is hybrid: a bug in the unaudited `ml-kem 0.3.2` (R2-C12) degrades only to classical security. Panics on hostile input remain the risk, so fuzz them.

**Costs:** About 2.3 KB and half a round trip per connection, plus tens of µs of CPU.

**What could go wrong:**
- `ek` must pass the FIPS 203 encapsulation-key check before `encapsulate`.
- The switch must be atomic in both directions: define the exact frame at which `k'` begins.
- Timing is irrelevant here: the keys are ephemeral.

**Classification:** Privacy (long-term). Not consensus.

### P-7. No session id and no optional authentication (R8-21)

**Agreed with R8-21:**
- Expose a session id, `sid = H32("p2p/session-id", k-transcript)`, in `PeerInfo` and RPC `/peers`, as BIP324 does, so operators can compare manual links out of band. Difficulty S.
- Authentication through a responder static key: a Noise NK-like `es` token, `--peer addr#pubkey`, and bridge mode. This is P3.
  - A static key links a listener across IP changes.
  - It must never be used by initiators.
- This can be added inside v2 as an in-band extension, provided P-3's no-fallback rule holds.

### P-8. Forward secrecy is overclaimed (docs/p2p.md:66-67; new)

**What:** The spec says "recorded traffic cannot be decrypted later, even if a node is compromised". Three facts contradict that:
- **No rekey.** A key captured during a session decrypts all earlier traffic of that session. Sessions last days. BIP324 rekeys every 224 packets, and Noise provides `Rekey()`.
- **Key schedules outlive the session.** `aes` and `aes-gcm` are built without their `zeroize` features: `p2p/Cargo.toml:16`, and the `aes` entry in `Cargo.lock` has no `zeroize` dependency. The expanded AES round keys and the GHASH key are not wiped on drop. `shared` (the DH point) is not zeroized either (`transport.rs:158`).
- **HNDL (P-6).**

**Classification:** Documentation and claims policy. Low security.

**Fix:**
- Enable `aes-gcm/zeroize` and `aes/zeroize`. This is a Cargo feature change, and it unifies with `randomx`'s `aes` (hazmat functions only; no semantic change).
- Zeroize `shared`.
- Rekey in v2, every 224 frames per direction, as in BIP324: `k_dir ← H32("p2p/rekey", k_dir)`.
- Correct the docs text.

### P-9. Frame copies (performance and memory; new, Low)

- On send, `msg.encode()` makes one copy, `encrypt` returns a new Vec, and `frame.extend_from_slice(&body)` copies again. That is 3 × 9.45 MB transiently per block frame.
- On receive, the buffer plus the `decrypt` output is 2×.
- **Fix:** encode into a buffer with 20 bytes of headroom, then use `encrypt_in_place_detached` and `decrypt_in_place_detached`.
  - aes-gcm ≥ 0.10.3 is required (CVE-2023-42811).
  - The buffer must be discarded, never read, on a failed decrypt.

### P-10. Codec forward-compatibility gaps (new, Informational to Low)

- **`Addr` (type 5):** an unknown `NetAddr` kind is a decode error, a 100-point ban (`addr.rs:178`). A future address type such as I2P therefore **must** use a new message type (an addrv2 pattern like BIP155). This is not written in docs/p2p.md §4.1. Alternatively, before launch, give each `NetAddr` a length prefix so that unknown kinds are skipped, as BIP155 does.
- **`Version.listen`:** an unknown kind fails the handshake. A new listen kind must go in the extension area, and that is not documented either.
- **`MIN_PROTOCOL_VERSION = 1`** is dead compatibility. Every binary able to connect (genesis binding, R15-3) already speaks protocol 2. Raising it to 2 at the v3 genesis removes an untested branch. v1 would ban peers for unknown frames.
- **The `Version` extension area** is bounded only by the frame. That is fine once P-4's 4 KiB cap exists.

### P-11. Cancellation safety of `FrameReader::recv` (Informational)

- `recv` is not cancellation-safe: a cancelled future leaves the stream mid-frame and the counter unadvanced.
- Every current call site drops the connection on cancellation.
- Future edits to the read loop (for example a third `select!` branch, as roster 34 or 31 might add) could silently desynchronize the stream.
- **Fix:** document it on the type, or make recv cancel-safe with an internal state machine. The state machine is also what incremental receive (P-4) needs.

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| T-1 (P-4) | **Medium** | Not implemented | `net.rs:96, 998-1031`; `transport.rs:104-113`; docs/p2p.md:102 | An unregistered inbound peer sends up to 9 frames of about 9.45 MB before `Verack`, unbudgeted; the handshake lasts up to about 110 s instead of 10 s; 64 slots give about 1.2 GB transient | High (source-read) |
| T-2 (P-5) | **Medium** | Not implemented | `net.rs:1133`, `limits.rs:12`, `ban_addr :641` | A momentary on-path bit flip → a 24 h persistent ban of an honest peer, on both sides; aids an eclipse | High |
| T-3 (P-3) | **Medium** (architectural) | Not implemented | `transport.rs:122-195` (no version); `addr.rs` (no service bits) | Any post-launch transport change needs a dual-stack, fingerprinting, downgradable fallback | High |
| T-4 (P-1) | Low-Medium (privacy) | Partially implemented (content is encrypted) | `transport.rs:138-150` | A passive decode test gives about 8 bits per connection (R8 said 4), plus a fixed flow shape; the Version size reveals the listen kind | High (mathematically established count) |
| T-5 (P-8) | Low | Not implemented | `p2p/Cargo.toml:16`; `transport.rs:158`; docs/p2p.md:66-67 | Memory disclosure or a swap image after a session yields AES round keys; no rekey; the FS claim is overstated | High for the features (lock and registry read); Medium for exploitability |
| T-6 (P-6, I4-7) | Low | Not implemented | `transport.rs` | A recorded transcript plus a future DLP break → retroactive stem origin | Medium |
| T-7 (P-7, R8-21) | Low | Not implemented | `net.rs:169` `PeerInfo` | No way to detect a MITM on manual links | High |
| T-8 (P-9) | Low | Not implemented | `transport.rs:76-90, 108-113` | 2-3× the frame size in transient copies per large frame | High |
| T-9 (P-10) | Low | Partially implemented | `addr.rs:178`; `message.rs:21`; docs/p2p.md §4.1 | A future I2P address in `Addr` → old nodes ban the sender for 24 h | High |
| T-10 (P-2) | Informational (correction to R8-20) | Accepted limitation | — | Public listeners cannot be probe-resistant; only bridge mode can | High (literature) |
| T-11 (P-11) | Informational | Not implemented | `transport.rs:96-117` | A future `select!` edit desynchronizes the stream | High |
| T-12 | Informational | Not implemented | tests | No KAT for the KDF or first frame; no reflection, replay or reorder tests; `recv` not fuzzed | High |

---

## 5. Implementation plan for phase 2

Every item below is P2P policy. None changes consensus or the chain identity (genesis, rules, fingerprint). Items W5-W7 change the P2P wire protocol: they are a network flag day, cheap only before the v3 testnet launch.

### W1 (P0). Pre-`Verack` frame cap and one handshake deadline (T-1)

- **Files:**
  - `p2p/src/transport.rs`: add `recv_limited(max)`.
  - `p2p/src/message.rs`: add a `MAX_HANDSHAKE_FRAME = 4096` constant.
  - `p2p/src/net.rs`: `run_connection` at about `:952-1045` only. Coordinate with 34 and 31.
  - `docs/p2p.md` §3-§4.
- **Visibility:** policy, externally visible as a rule (future negotiation must fit in 4 KiB).
- **Tests:**
  - adversarial: a 4097-byte Version → closed, no ban;
  - drip-fed unknown frames → closed at about 10 s;
  - 8 unknown frames of 4 KiB still pass (the P0-8 regression).
- **Difficulty:** S.

### W2 (P0). Transport failures do not ban (T-2)

- **Files:** `p2p/src/net.rs`, the read-loop transport arm at about `:1130-1134`, plus a statistic.
- **Visibility:** policy.
- **Tests:** a relay flips a bit after registration → disconnect, no ban, a reconnection succeeds; `FrameTooLarge` is still scored.
- **Difficulty:** S.

### W3 (P0). Transport known-answer vectors and adversarial tests (T-12)

- **Files:**
  - `p2p/src/transport.rs`: a test module with fixed-secret constructors behind `#[cfg(test)]`.
  - A new `p2p/tests/transport_adversarial.rs`.
  - A new `fuzz/fuzz_targets/p2p_transport.rs`, plus its Cargo entry, shared with 41.
- **Tests:**
  - a golden vector: fixed `a`, `b`, `network_id` and `genesis_id` → `k` and the first frame bytes;
  - reflection of our own key → first frame fails;
  - replay, reorder and truncation of frames;
  - random bytes after the handshake → `Decrypt`, no panic, no allocation beyond the cap;
  - a fuzz of `recv` over arbitrary streams.
- **Difficulty:** S-M.
- **Note:** Pin the vector only after W5/W6 decide the final transport.

### W4 (P0). Documentation and claims corrections (T-5 text, T-9, T-10)

- **Files:** `docs/p2p.md`:
  - §3 forward-secrecy text;
  - §4 the actual deadline;
  - §4.1 rules for new address kinds and listen kinds, and the pre-`Verack` cap;
  - §1 "probe resistance" is not a goal for public nodes.
- **Difficulty:** S.

### W5 (P0 decision; P1 build). Transport flag-day decision and version constant (T-3)

- **Decision for the coordinator:** v2 at the v3 genesis, or v1 frozen for v3.
- In both cases:
  - add `LE32(TRANSPORT_VERSION)` to the KDF input (`transport.rs`);
  - raise `MIN_PROTOCOL_VERSION` to 2 (`message.rs:21`) at the v3 genesis;
  - state the no-fallback invariant in docs/p2p.md §3.
- **Difficulty:** S.

### W6 (P1). Transport v2

Built only if W5 chooses to build it. Owner: 30.

- **Files:**
  - `p2p/src/transport.rs`, restructured into a state machine, or split into `transport/{handshake,frame}.rs`;
  - `p2p/Cargo.toml` (add `curve25519-dalek = "=5.0.0"` with `lizard`, p2p only; add `ml-kem = "=0.3.2"`; enable the zeroize features);
  - `crypto/src/hash.rs` (new tags `P2P_REKEY`, `P2P_SESSION_ID`, `P2P_SESSION_PQ`, `P2P_GARBAGE`), owned by 19;
  - `docs/p2p.md` §3.
- **Design:**
  1. **Keys.** Ephemeral Ristretto255 keys are encoded as 64-byte Elligator-Squared representatives and decoded with `RistrettoPoint::from_uniform_bytes`. The encoder follows Tibouchi's sampling (uniform preimage index with retries, random top bits).
  2. **Garbage.** 0-4095 bytes of garbage, then a derived 16-byte terminator; the garbage is authenticated as AAD of the first frame.
  3. **Key schedule.** `k = H64("p2p/session", LE32(net) ‖ genesis ‖ LE32(2) ‖ enc_A ‖ enc_B ‖ S)` is taken over the exact encodings, as in BIP324.
  4. **Hybrid PQ.** The ML-KEM-768 hybrid step runs inside the channel (P-6), then the switch to `k'`.
  5. **Length block.** Each frame keeps a separately authenticated 20-byte length block, now carrying `len` (3 bytes) plus a flags byte:
     - a decoy bit;
     - a size class (control ≤ 64 KiB; tx ≤ `MAX_ANY_TX_SIZE`; block ≤ `MAX_FRAME`, accepted only while a block request to the peer is outstanding; the class must match the decoded type).

     This closes the R8-10 receive side structurally.
  6. **Rekey.** Every 224 frames per direction.
  7. **Session id.** Exposed as `sid`.
  8. **Decoys.** Decoy frames are defined; sending policy (padding buckets) goes to 33 (P2-19).
- **Visibility:** P2P wire flag day. No consensus effect.
- **Tests:**
  - uniformity statistics on 2^16 encodings (frequency, per-bit, and the Ristretto-decode rate ≈ 1/16 per half);
  - round trip `from_uniform_bytes(encode(P)) == P` over 10^5 random points;
  - KATs;
  - a garbage-terminator search bound;
  - a size-class violation → ban; an unsolicited block-class frame → rejected before allocation;
  - a PQ switch-point desync test;
  - an ML-KEM `ek` validation failure → disconnect;
  - a fuzz target for ML-KEM decapsulation and encapsulation-key parsing (no panic);
  - differential tests against a small independent reference of the handshake (a test-only straight-line implementation);
  - cross-version: a v1 node and a v2 node fail cleanly, with no fallback.
- **Benchmarks:** handshake latency and CPU (the encoder retry loop, ML-KEM), frame throughput on a non-AES-NI host, and memory per connection.
- **Difficulty:** L.

### W7 (P1). Zeroization and copy reduction (T-5, T-8)

- **Files:** `p2p/Cargo.toml` (features; coordinate with 44 and with 05/06 for the shared `aes` build), and `p2p/src/transport.rs`: in-place AEAD, incremental receive (the W1 buffer logic), and zeroizing `shared`.
- **Tests:**
  - the existing round trips;
  - an allocation bound test;
  - a failed decrypt never exposes the buffer: a unit test asserts `recv` returns `Err` and the buffer is dropped.
- **Benchmark:** 9 MB frame send/receive throughput and peak RSS, before and after.
- **Difficulty:** S-M.

### W8 (P2). Session id in `PeerInfo` and RPC `/peers` (T-7)

This can be done on v1 if W6 is deferred.

- **Files:** `p2p/src/transport.rs` (return `sid`), `p2p/src/net.rs` (`PeerInfo`), and `rpc/` peer output (owned by 36).
- **Difficulty:** S.

### W9 (P2). Cancellation-safety invariant (T-11)

- A doc comment, or a cancel-safe receive state machine folded into W7.
- **Test:** a `select!` in which the timer branch fires mid-frame, then the stream is dropped (no reuse).
- **Difficulty:** S.

### W10 (P3). Responder static key and bridge mode (R8-21 authentication, P-2)

- A Noise NK-like `es` token.
- `--peer addr#key`.
- Silent refusal without a MAC, as obfs4 does. Frolov et al. show the close thresholds must mimic a plain TCP server.
- Needs an addrv2 carrying keys (with 32).
- **Difficulty:** M-L.

---

## 6. Dependencies and conflicts

- **31 p2p-sync and 34 chain-actor:** `net.rs` ownership. W1 and W2 touch `run_connection` and the read-loop error arm only. The W6 size classes need 31's "block request outstanding" state (`block_requests`). Agree on the `requested_by_us` interface.
- **32 eclipse-addrman:** P-10 (the length-prefixed or new-type `NetAddr`), and W10 static keys in addr records. T-2 interacts with ban policy. N-6 (onion inbound loopback bans) is theirs, but W2 removes one trigger.
- **33 dandelion-network-privacy:** decoy and padding policy (P2-19) and the PX 2.2 MB origin leak (R8-18: the transport cannot fix it). SOCKS stream isolation (R8-6) complements the transport's lack of authentication. HNDL on stem origin (P-6) is a shared rationale.
- **19 hash-domain-separation:** new tags in `crypto/src/hash.rs`.
- **44 supply-chain:** dalek 5.0.0 (with `lizard`) beside the pinned 4.1.3; the `ml-kem` pin; the `aes`/`aes-gcm` `zeroize` features. Needs its review, especially of `map_to_curve_inverse`.
- **15/16/17 crypto:** dalek stays `=4.1.3` in consensus crates. The transport must not force an upgrade there.
- **05/06/08 randomx:** the shared `aes` crate build. Enabling `zeroize` adds `ZeroizeOnDrop` to key-schedule types only; `randomx` uses `hazmat` round functions. No semantic change, but they should confirm.
- **36 rpc-security:** `sid` in `/peers`.
- **41 fuzzing:** the new `p2p_transport` and ML-KEM decapsulation targets.
- **47 docs** and **48 threat-model:** the forward-secrecy and probe-resistance wording, and a censorship non-goal statement.
- **40 testnet-genesis:** the W5 flag-day timing.

---

## 7. Open questions for the coordinator

1. **W5.** Should transport v2 ship at the v3 testnet genesis (L effort, one flag day, no fallback ever), or should v1 be frozen for v3, with v2 at the next reset or at mainnet genesis?
2. **A second dalek version.** Is dalek 5.0.0 (`lizard`) acceptable in `p2p` only, for a uniform key encoding? The alternatives:
   - keep raw Ristretto (fingerprintable, T-4 accepted);
   - switch the transport to X25519 with the alpha `curve25519-elligator2` (not recommended: alpha maturity, obfs4's history).
3. **Hybrid ML-KEM.** Should it be in v2 (my recommendation, P1 given PX's post-quantum posture), or deferred as D18 said?
4. **AEAD choice for v2.** Keep AES-256-GCM (no new code, constant-time software fallback but slow without AES-NI), or move to ChaCha20-Poly1305 (already in the tree via `px`; faster on ARM hosts)? I lean towards keeping AES-GCM, for minimal change.
5. **Censorship resistance.** Is it a stated project goal? If not, W10 stays P3 and docs/p2p.md should say "Tor with pluggable transports" explicitly.

---

## 8. Sources

- BIP324, *Version 2 P2P Encrypted Transport Protocol* (Dettman, Wuille, Kaur et al.): https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki. Used for: ElligatorSwift 64-byte keys, 4095-byte garbage, 16-byte terminators, `REKEY_INTERVAL = 224`, session id, the V1_PREFIX detection, `NODE_P2P_V2` with v1 retry, and its non-goals.
- BIP155, *addrv2*: https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki
- T. Perrin, *The Noise Protocol Framework*, revision 34 (2018-07-11): https://noiseprotocol.org/noise.html. Used for the NN/NK/XK/IK patterns, the prologue, `GetHandshakeHash` channel binding, `Rekey()`, the 65535-byte message limit, and the Elligator recommendation.
- J. Chávez-Saab, F. Rodríguez-Henríquez, M. Tibouchi, *SwiftEC: Shallue–van de Woestijne Indifferentiable Function to Elliptic Curves* (ElligatorSwift), ASIACRYPT 2022; J. Cryptology 2025. ePrint 2022/759: https://eprint.iacr.org/2022/759
- M. Tibouchi, *Elligator Squared: Uniform Points on Elliptic Curves of Prime Order as Uniform Random Strings*, FC 2014. ePrint 2014/043: https://eprint.iacr.org/2014/043
- D. J. Bernstein, M. Hamburg, A. Krasnova, T. Lange, *Elligator: Elliptic-curve points indistinguishable from uniform random strings*, CCS 2013. ePrint 2013/325: https://eprint.iacr.org/2013/325
- RFC 9496, *The ristretto255 and decaf448 Groups*: https://www.rfc-editor.org/rfc/rfc9496
- curve25519-dalek 5.0.0 `RistrettoPoint` API (`map_to_curve_inverse`, `lizard` feature): https://docs.rs/curve25519-dalek/5.0.0/curve25519_dalek/ristretto/struct.RistrettoPoint.html. Version dates from https://crates.io/crates/curve25519-dalek
- Tor anti-censorship team, *obfs4proxy-0.0.12 fixes the Elligator2 bug* (2022-01): https://archive.torproject.org/websites/lists.torproject.org/pipermail/anti-censorship-team/2022-January/000213.html; obfs4 x25519ell2: https://github.com/Yawning/obfs4/tree/master/internal
- `curve25519-elligator2` (Tor Project fork, 0.1.0-alpha.2): https://crates.io/crates/curve25519-elligator2; https://docs.rs/curve25519-elligator2/latest/curve25519_elligator2/elligator2/struct.Randomized.html
- Monero PR #8996, *Add SSL support to P2P* (vtnerd; open as of 2026-09): https://github.com/monero-project/monero/pull/8996. Monero PR #5793, *I2P/Tor White Noise*: https://github.com/monero-project/monero/pull/5793
- Y. Angel, B. Dowling, A. Hülsing, P. Schwabe, F. Weber, *Post Quantum Noise*, CCS 2022. ePrint 2022/539: https://eprint.iacr.org/2022/539
- F. Günther, D. Stebila, S. Veitch, *Obfuscated Key Exchange* (Kemeleon), CCS 2024. ePrint 2024/1086: https://eprint.iacr.org/2024/1086. draft-veitch-kemeleon: https://www.ietf.org/archive/id/draft-veitch-kemeleon-00.html. *Hybrid Obfuscated Key Exchange and KEMs*, ePrint 2025/408: https://eprint.iacr.org/2025/408.pdf
- OpenSSH, *Post-Quantum Cryptography* (mlkem768x25519-sha256 default since 10.0): https://www.openssh.org/pq.html
- M. Wu et al., *How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic*, USENIX Security 2023: https://gfw.report/publications/usenixsecurity23/en/ ; https://www.usenix.org/conference/usenixsecurity23/presentation/wu-mingshi
- S. Frolov, J. Wampler, E. Wustrow, *Detecting Probe-resistant Proxies*, NDSS 2020: https://www.ndss-symposium.org/ndss-paper/detecting-probe-resistant-proxies/
- RustCrypto advisory GHSA-423w-p2w9-r7vq / CVE-2023-42811 (aes-gcm `decrypt_in_place_detached`): https://github.com/RustCrypto/AEADs/security/advisories/GHSA-423w-p2w9-r7vq
- NIST FIPS 203, *ML-KEM* (the encapsulation-key check): https://csrc.nist.gov/pubs/fips/203/final
- Crate metadata (versions and dates) from the crates.io API: `ml-kem` 0.3.2, `kemeleon` 0.1.0-rc.1, `elligator2` 0.1.0, `snow` 0.10.0, `x25519-dalek` 3.0.0.
