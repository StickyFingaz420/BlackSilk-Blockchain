# BlackSilk Blockchain

## Overview
BlackSilk is a professional, privacy-first, open-source blockchain platform designed for real-world utility, robust privacy, and modern developer experience. It features:
- **Automatic, production-ready privacy networking** (Tor, I2P, clearnet, auto-fallback)
- **RandomX proof-of-work mining** (ASIC-resistant, CPU-friendly)
- **Transparent, fair tokenomics** (no premine, no tail emission)
- **Modern Rust codebase** with modular architecture
- **Comprehensive CLI, HTTP API, and integration tests**

---

## Tokenomics
- **Ticker:** BLK
- **Initial Block Reward:** 5 BLK
- **Block Time:** 120 seconds (2 minutes)
- **Halving Interval:** 1,051,200 blocks (~4 years)
- **Supply Cap:** 21,000,000 BLK
- **No Premine, No ICO, No Tail Emission:** All coins are mined; after cap, miners receive only transaction fees.
- **Block Reward Schedule:**
  - Block reward halves every 1,051,200 blocks
  - After 21M BLK, block reward is 0 (fees only)

---

## Network Ports
| Network    | P2P Port | HTTP API | Tor Hidden | I2P SAM (default) |
|------------|----------|----------|------------|-------------------|
| Mainnet    | 9334     | 9333     | 19334      | 7656              |
| Testnet    | 19334    | 19333    | 29334      | 17656             |

- All ports are configurable via CLI arguments.

---

## Privacy Networking
BlackSilk provides a seamless, user-friendly privacy experience. Select your preferred mode at startup:

- `--net-privacy clearnet` — Use direct clearnet connections only.
- `--net-privacy tor` — Require Tor for all connections. Node will exit if Tor is unavailable.
- `--net-privacy i2p` — Require I2P for all connections (via I2P SAM bridge).
- `--net-privacy auto` (default) — Try Tor first, then I2P, then clearnet. Fallbacks are automatic and clearly logged.

**Tor and I2P are managed automatically:**
- Tor process is auto-started, health-checked, and shut down as needed.
- I2P connections use a real I2P SAM client (local or remote).
- Privacy status and fallbacks are clearly logged at startup and runtime.

### Example Usage
```sh
# Start node in auto privacy mode (default)
cargo run --bin blacksilk-node -- --net-privacy auto

# Start node in Tor-only mode (Tor must be running)
cargo run --bin blacksilk-node -- --net-privacy tor

# Start node in I2P-only mode (I2P SAM must be running)
cargo run --bin blacksilk-node -- --net-privacy i2p

# Start node in clearnet mode
cargo run --bin blacksilk-node -- --net-privacy clearnet
```

### Fallback Behavior
- In `auto` mode, the node will attempt to use Tor. If Tor is unavailable, it will fallback to I2P, and finally to clearnet if neither privacy network is available. Each fallback is logged to the console.
- In `tor` or `i2p` mode, the node will exit if the required privacy network is unavailable.

---

## Features
- **Privacy-First Networking:** Tor, I2P, clearnet, and auto-fallback modes
- **RandomX Mining:** ASIC-resistant, CPU-friendly mining
- **Professional CLI:** Full-featured, with advanced privacy, mining, and network options
- **HTTP API:** REST endpoints for wallets, explorers, and apps
- **Advanced Peer Management:** Auto-discovery, banning, DNS, and privacy-aware connections
- **Marketplace-Ready:** Support for encrypted memos, metadata, and future smart contracts
- **Integration Tests:** End-to-end privacy fallback and connection logic
- **Comprehensive Logging:** Startup banner, privacy status, and error feedback

---

## CLI Reference (Key Options)
- `--net-privacy [clearnet|tor|i2p|auto]` — Select privacy mode
- `--data-dir <DIR>` — Blockchain and node state directory
- `--network [mainnet|testnet]` — Network type
- `--bind <ADDR>` — HTTP API bind address
- `--p2p-bind <ADDR>` — P2P network bind address
- `--connect <ADDR>` — Connect to peer(s)
- `--mining` — Enable internal miner
- `--mining-threads <N>` — Mining threads
- `--mining-address <ADDR>` — Mining payout address
- `--tor-hidden-service` — Enable Tor hidden service
- `--tor-proxy <ADDR>` — Tor SOCKS proxy address
- `--i2p-enabled` — Enable I2P support
- `--i2p-sam <ADDR>` — I2P SAM bridge address
- `--log-level [error|warn|info|debug|trace]` — Logging verbosity
- `--help` — Show all options

---

## Project Structure
```
BlackSilk-Blockchain/
├── node/           # Core node implementation (Rust)
│   ├── src/
│   │   ├── main.rs           # CLI entry point, privacy manager, Tor/I2P integration
│   │   ├── lib.rs            # Consensus, chain, emission, config
│   │   ├── network/
│   │   │   ├── privacy.rs    # Privacy manager, fallback logic
│   │   │   └── tor_process.rs# Tor process management
│   │   └── ...
├── i2p/            # Local I2P SAM client crate
├── miner/          # Standalone RandomX miner (Rust CLI)
├── wallet/         # Privacy wallet (Rust CLI)
├── block-explorer/ # Modern web explorer (Next.js, TypeScript)
├── tests/          # Integration and e2e tests
├── Cargo.toml      # Workspace manifest
└── README.md       # This file
```

---

## Roadmap
### Accomplished
- Modernized workspace and dependencies
- Integrated real I2P protocol (SAM client)
- Refactored privacy manager for auto/fallback
- Professional Tor process management
- CLI privacy mode and config refactor
- Integration and fallback tests
- Enhanced user feedback and logging
- Updated documentation and CLI help

### Pending / Future
- Smart contracts and programmable privacy
- Marketplace and confidential assets
- Mobile and light wallet support
- Advanced analytics and explorer features
- Further privacy protocol research

---

## Development & Testing
- **Build:** `cargo build --release`
- **Test:** `cargo test`
- **Integration tests:** See `tests/integration/e2e/`
- **Run node:** See CLI examples above

---

## License
MIT License. See [LICENSE](LICENSE).

---

## Contact & Community
- [GitHub](https://github.com/blacksilk-org/BlackSilk-Blockchain)
- [Discord](https://discord.gg/blacksilk)
- [docs.blacksilk.io](https://docs.blacksilk.io)

---

**BlackSilk: Professional, privacy-first blockchain for the real world.**
