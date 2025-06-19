# BlackSilk Blockchain: Comprehensive Technical Documentation

---

<p align="center">
  <img src="blacksilklogos/main_1024x512.png" alt="BlackSilk Logo" width="400"/>
</p>

<p align="center">
  <a href="#protocol-parameters"><img src="https://img.shields.io/badge/Protocol-Privacy--First-blueviolet?style=for-the-badge"/></a>
  <a href="#build"><img src="https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge"/></a>
  <a href="#license"><img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/></a>
  <a href="#monitoring--devops"><img src="https://img.shields.io/badge/Monitoring-Prometheus%20%7C%20Grafana-orange?style=for-the-badge"/></a>
</p>

---

## Table of Contents
- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [Component Breakdown](#component-breakdown)
  - [Rust Workspace Crates](#rust-workspace-crates)
  - [Web Frontends](#web-frontends)
  - [Smart Contracts](#smart-contracts)
  - [Infrastructure & Monitoring](#infrastructure--monitoring)
- [Setup & Installation](#setup--installation)
  - [Prerequisites](#prerequisites)
  - [Manual Build](#manual-build)
  - [Dockerized Deployment](#dockerized-deployment)
- [Configuration](#configuration)
- [CLI/API Usage](#cliapi-usage)
- [Integration & Dependencies](#integration--dependencies)
- [Monitoring & DevOps](#monitoring--devops)
- [Known Limitations & Future Enhancements](#known-limitations--future-enhancements)
- [Contributing](#contributing)
- [License](#license)

---

## Project Overview

BlackSilk is a privacy-first, modular blockchain platform with a focus on advanced cryptography, decentralized marketplace, and professional-grade infrastructure. The project is organized as a multi-language monorepo, supporting Rust, TypeScript, Next.js, and Dockerized deployments.

## Architecture

BlackSilk is composed of several tightly integrated components:
- **Core blockchain node** (Rust)
- **CLI wallet** (Rust)
- **Standalone miner** (Rust)
- **Decentralized marketplace backend** (Rust)
- **Web-based block explorer** (Next.js/TypeScript)
- **Web wallet** (Next.js/React)
- **Testnet faucet** (Next.js + Express.js)
- **Smart contracts** (Rust, WASM)
- **Monitoring stack** (Prometheus, Grafana, AlertManager)

All components are containerized for production and development.

---

## Architecture and Design Rationale

BlackSilk is a modular, privacy-first blockchain platform designed for extensibility, security, and real-world usability. The architecture is split into several core domains:

- **Consensus and Node Layer:** Implements Proof-of-Work (RandomX), advanced privacy networking (Tor/I2P), and a modular smart contract VM (WASM).
- **Wallet Layer:** CLI and web wallets with full privacy, stealth addresses, ring signatures, and hardware wallet support.
- **Marketplace Layer:** Fully decentralized marketplace backend, escrow, and on-chain data storage.
- **Web Layer:** Modern, responsive web apps for block exploration, wallet management, and testnet token distribution.
- **Infrastructure:** Dockerized deployment, monitoring, and alerting for all services.
- **Smart Contracts:** WASM-based contracts for escrow, marketplace, and mining logic.

The design prioritizes:
- **Privacy:** All networking supports Tor/I2P, stealth addresses, ring signatures, and ZKPs.
- **Security:** No premine, no ICO, all coins mined, strong cryptography, and hardware wallet support.
- **Extensibility:** Modular Rust workspace, WASM contracts, and pluggable web frontends.
- **Production-Readiness:** Health checks, monitoring, Docker orchestration, and CI/CD support.

---

## Rust Core Modules

### node/
- Implements the full blockchain node: consensus, networking, mining, RPC, and smart contract VM.
- Features:
  - RandomX mining and verification (CPU-only, ASIC/GPU detection)
  - Advanced privacy networking (Tor, I2P, clearnet, auto)
  - Modular WASM VM for smart contracts
  - Full emission schedule, halving, and supply cap enforcement
  - HTTP/RPC server for API access
  - Health checks and metrics endpoints

### wallet/
- CLI wallet with full privacy and cryptography features.
- Features:
  - Stealth address generation
  - Ring signature creation and verification
  - BIP39 mnemonic support
  - Hardware wallet (Ledger/Trezor) integration
  - Transaction creation, signing, and broadcasting

### miner/
- Standalone miner with pure Rust RandomX implementation (no FFI, no C dependencies).
- Features:
  - Multi-threaded mining
  - Hashrate and performance tracking
  - Configurable node connection and mining address

### marketplace/
- Decentralized marketplace backend using Axum (Rust web framework).
- Features:
  - On-chain product listings and purchases
  - Escrow integration for secure transactions
  - IPFS client for decentralized file storage
  - No centralized database or authentication

### primitives/
- Core types and cryptographic primitives for the entire platform.
- Features:
  - Canonical CryptoNote-style ring signatures
  - zk-SNARKs and advanced ZKP integration
  - Stealth address types and serialization
  - Escrow contract logic

### i2p/
- I2P SAM client for privacy networking.
- Features:
  - Session management
  - Destination/key generation
  - Streaming and datagram support

## Component Breakdown

### Rust Workspace Crates
- **node**: Main blockchain node, privacy networking (Tor/I2P), mining, smart contract VM, HTTP/RPC server.
- **wallet**: CLI wallet, stealth addresses, ring signatures, BIP39, hardware wallet support.
- **miner**: Standalone miner, pure Rust RandomX, multi-threaded, portable.
- **marketplace**: Decentralized backend, Axum web API, IPFS, escrow, on-chain data.
- **primitives**: Core types, cryptography, serialization, ZKPs.
- **smart-contracts**: On-chain logic for escrow, marketplace, RandomX (WASM).

### Web Frontends
- **block-explorer**: Next.js/TypeScript, real-time stats, privacy features, analytics, responsive UI.
- **web-wallet**: Next.js/React, privacy-first wallet, QR/BIP39, browser-based crypto.
- **testnet-faucet**: Next.js + Express.js, token distribution, admin dashboard, SQLite, Docker/Nginx.

### Smart Contracts
- **escrow_contract**: On-chain escrow logic (Rust/WASM).
- **marketplace_contract**: Marketplace logic (Rust/WASM).
- **randomx**: RandomX mining logic (Rust/WASM).

### Infrastructure & Monitoring
- **Docker**: Multi-service orchestration, health checks, persistent volumes.
- **Prometheus/Grafana/AlertManager**: Metrics, dashboards, alerting.
- **Config**: TOML files for node, miner, wallet, network specs.

## Setup & Installation

### Prerequisites
- Rust (1.70+), Cargo
- Node.js (18+), npm/yarn
- Docker & Docker Compose
- Git

### Manual Build
#### Rust Components
```sh
# Build all Rust workspace crates
cargo build --release
```

#### Web Frontends
```sh
# Block Explorer
cd block-explorer
npm install && npm run build

# Web Wallet
cd ../web-wallet
npm install && npm run build

# Testnet Faucet
cd ../testnet-faucet
npm install && npm run build
```

### Dockerized Deployment
```sh
git clone <repo-url>
cd BlackSilk-Blockchain
docker-compose up --build
```
- For monitoring: `cd monitoring && docker-compose up --build`
- For testnet faucet: `cd testnet-faucet && docker-compose up --build`

## Configuration
- All services are configurable via environment variables and TOML files in the `config/` directory.
- Example: `config/mainnet/node_config.toml`, `config/testnet/chain_spec.json`, etc.
- Sensitive data (secrets, admin credentials) should be set via environment variables or Docker secrets.

## CLI/API Usage

### Node CLI
```
blacksilk-node --data-dir ./data --network testnet --bind 127.0.0.1:9333 --p2p-bind 0.0.0.0:9334 --net-privacy auto
```
- Supports Tor/I2P/clearnet, peer management, custom configs.

### Wallet CLI
```
wallet --generate-address
wallet --send --to <address> --amount <amt>
```
- Supports stealth addresses, ring signatures, BIP39 mnemonics.

### Miner CLI
```
blacksilk-miner --node-url http://localhost:9334 --threads 4
```
- Pure Rust RandomX, multi-threaded.

### Marketplace API
- RESTful endpoints via Axum (see `marketplace/src/main.rs` for routes).
- Supports product listing, escrow, decentralized storage.

### Block Explorer & Web Wallet
- Next.js apps, run via `npm run dev` or Docker.
- Connect to running node via `.env.local` config.

### Testnet Faucet
- REST API for requesting testnet tokens.
- Admin dashboard at `/admin` (see `testnet-faucet/README.md`).

## Advanced CLI, API, and Integration Details

### Node CLI Commands
- `blacksilk-node --data-dir <path> --network <mainnet|testnet> --bind <addr> --p2p-bind <addr> --net-privacy <auto|tor|i2p|clearnet>`
  - Full support for Tor/I2P/clearnet, peer management, custom configs
  - Mining address, RPC, and advanced privacy flags

### Wallet CLI Commands
- `wallet --generate-address` — Generate new stealth address
- `wallet --send --to <address> --amount <amt>` — Send transaction
- `wallet --import-mnemonic <mnemonic>` — Import wallet
- `wallet --hardware` — Use hardware wallet (Ledger/Trezor)
- Supports ring signatures, range proofs, key images, and BIP39

### Miner CLI Commands
- `blacksilk-miner --node-url <url> --threads <n>` — Start mining
- Pure Rust RandomX, multi-threaded, performance stats

### Marketplace API
- RESTful endpoints (Axum): product listing, escrow, decentralized storage
- IPFS integration for file storage
- Escrow contract integration for secure transactions

### Smart Contract APIs
- WASM VM: `deploy_contract`, `invoke_contract_with_gas`, `save_contract_state`, `load_contract_state`
- Privacy primitives: `privacy_ring_sign`, `privacy_stealth_address`, `privacy_encrypt`, `privacy_decrypt`

### Cryptography & Privacy APIs
- Ring signature: `generate_ring_signature`, `verify_ring_signature`
- Stealth address: `generate_stealth_address`
- zk-SNARKs: `generate_zk_proof`, `verify_zk_proof`, `batch_verify_zk_proofs`
- Escrow contract: `fund`, `release`, `refund`, `dispute`, `voting`

### Web Frontend Utilities
- Block explorer: formatting, validation, QR code, difficulty, privacy level, analytics
- Web wallet: BIP39, QR, address validation, transaction creation
- Testnet faucet: REST API, admin dashboard, rate limiting, JWT auth

### Configuration & Environment Variables
- All services support `.env` files and environment variables for secrets, ports, node URLs, credentials, and feature flags
- Example: `BLACKSILK_NODE_URL`, `MINER_REWARD_ADDRESS`, `JWT_SECRET`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, etc.

### Monitoring & DevOps
- Prometheus metrics endpoints on node, miner, faucet
- Grafana dashboards for blockchain, mining, faucet, and system health
- AlertManager for critical alerts
- Health checks for all Docker services

### Error Handling & Security
- All critical operations have error handling and logging
- Peer scoring and blacklisting for suspicious mining activity
- Full memory and timing enforcement for RandomX (ASIC/GPU detection)
- Secure admin authentication (JWT) for faucet and web admin
- No private key handling in web explorer (read-only)

### Extensibility & Integration
- Modular Rust workspace for adding new crates
- WASM smart contract support for new on-chain logic
- Pluggable web frontends and API integrations
- Dockerized for easy deployment and scaling

## Integration & Dependencies
- Rust: `clap`, `serde`, `tokio`, `ed25519-dalek`, `curve25519-dalek`, `axum`, `askama`, `reqwest`, `bip39`, `wasmer`, `i2p`, etc.
- Web: `next`, `react`, `tailwindcss`, `axios`, `sqlite3`, `express`, `helmet`, `rate-limiter-flexible`, etc.
- Monitoring: `prom/prometheus`, `grafana/grafana`, `prom/alertmanager`.

## Monitoring & DevOps
- Prometheus scrapes node/miner/faucet metrics.
- Grafana dashboards for blockchain health, mining, faucet usage.
- AlertManager for system alerts.
- All services support health checks and logging.

## Known Limitations & Future Enhancements
- Ongoing: Smart contract language improvements, more ZKP schemes, mobile wallet, advanced privacy features.
- Known: WASM contract sandboxing, further decentralization of marketplace, UI/UX polish.

## Future Enhancements & TODOs

- Chain reorganization and fork resolution logic
- Bulletproofs and advanced range proof validation
- Privacy-aware client handling and advanced Tor/I2P features
- Hardware wallet import/export and multisig
- Resource metering and performance optimizations for WASM VM
- Admin features and configuration validation
- UI/UX polish and accessibility improvements
- Mobile wallet and light client support
- Additional smart contract templates and language support
- More comprehensive test coverage and fuzzing

## Contributing
- See `CONTRIBUTING.md` (to be created).
- PRs, issues, and feature requests welcome.

## License
MIT License. See `LICENSE` file.

## Protocol Parameters

- **Block Reward:**
  - Initial: 5 BLK (5,000,000 atomic units)
  - Halving every 1,051,200 blocks (~4 years at 2 min/block)
  - No tail emission: after cap, miners receive only transaction fees
  - Maximum supply: 21,000,000 BLK
- **Block Time:** 120 seconds (2 minutes)
- **Difficulty Adjustment:** Every 60 blocks (~2 hours)
- **Genesis Timestamp:** October 5, 1986
- **Consensus:** Proof-of-Work (RandomX), emission and reward schedule enforced by consensus layer

---

<h2 align="center" style="color:#00bcd4;">🚀 <span style="color:#00bcd4;">BlackSilk Technical Roadmap</span> 🚀</h2>

<table align="center" width="100%">
  <tr>
    <th width="30%" style="color:#43a047;">Milestone</th>
    <th width="20%" style="color:#ff9800;">Status</th>
    <th width="50%" style="color:#6c63ff;">Details</th>
  </tr>
  <tr>
    <td>🟢 <b>Core Protocol</b></td>
    <td><span style="color:#43a047;">Complete</span></td>
    <td>Consensus, mining, emission, privacy, and networking fully implemented and tested.</td>
  </tr>
  <tr>
    <td>🟢 <b>Wallet Suite</b></td>
    <td><span style="color:#43a047;">Complete</span></td>
    <td>CLI wallet, stealth addresses, ring signatures, hardware wallet integration, BIP39, and ZKPs.</td>
  </tr>
  <tr>
    <td>🟢 <b>Web Frontends</b></td>
    <td><span style="color:#43a047;">Complete</span></td>
    <td>Block explorer, web wallet, and testnet faucet (Next.js, React, Express, Dockerized).</td>
  </tr>
  <tr>
    <td>🟡 <b>Smart Contracts</b></td>
    <td><span style="color:#ffeb3b;">Beta</span></td>
    <td>WASM VM, escrow, marketplace contracts. Resource metering and sandboxing in progress.</td>
  </tr>
  <tr>
    <td>🟡 <b>Marketplace Backend</b></td>
    <td><span style="color:#ffeb3b;">Beta</span></td>
    <td>Decentralized listings, escrow, IPFS, Axum API. UI/UX and admin features in progress.</td>
  </tr>
  <tr>
    <td>🟢 <b>Monitoring & DevOps</b></td>
    <td><span style="color:#43a047;">Complete</span></td>
    <td>Prometheus, Grafana, AlertManager, health checks, Docker Compose orchestration.</td>
  </tr>
  <tr>
    <td>🔵 <b>Advanced Privacy</b></td>
    <td><span style="color:#2196f3;">Planned</span></td>
    <td>Enhanced Tor/I2P, privacy-aware clients, advanced ZKPs, and mobile wallet support.</td>
  </tr>
  <tr>
    <td>🔵 <b>Extensibility</b></td>
    <td><span style="color:#2196f3;">Planned</span></td>
    <td>Additional smart contract templates, language support, and plugin APIs.</td>
  </tr>
  <tr>
    <td>🔴 <b>Chain Reorg & Fork Handling</b></td>
    <td><span style="color:#f44336;">In Progress</span></td>
    <td>Robust fork resolution, chain reorganization, and consensus edge cases.</td>
  </tr>
  <tr>
    <td>🟣 <b>Mobile & Light Clients</b></td>
    <td><span style="color:#9c27b0;">Planned</span></td>
    <td>Mobile wallet, light client, and browser extension support.</td>
  </tr>
</table>

---

> <p align="center" style="color:#00bcd4; font-size:1.2em;">✨ <b>Every milestone is tracked, tested, and reviewed for security, privacy, and performance. For the latest status, see the <a href="#future-enhancements--todos">Future Enhancements</a> section below.</b> ✨</p>

---

## 🚀 Testnet Deployment & Onboarding Guide

### 1. Running a Node
```sh
git clone <repo-url>
cd BlackSilk-Blockchain
docker-compose up -d blacksilk-node
```
- Edit `config/testnet/node_config.toml` for custom settings.
- Ensure ports 9333 (RPC), 9334 (P2P), and 9090 (metrics) are open.

### 2. Mining on Testnet
```sh
docker-compose up -d blacksilk-miner
```
- Set your mining address in `config/miner_config.toml`.
- Monitor hashrate and blocks found via logs or Prometheus.

### 3. Using the CLI Wallet
```sh
cd wallet
cargo run --release -- --generate-address
cargo run --release -- --send --to <address> --amount <amt>
```
- Import or generate a mnemonic for your testnet wallet.
- All transactions are privacy-preserving by default.

### 4. Accessing the Web Wallet & Block Explorer
- Web Wallet: http://localhost:3001
- Block Explorer: http://localhost:3002
- Testnet Faucet: http://localhost:3003

### 5. Listing & Buying Products on the Marketplace
- Marketplace: http://localhost:3000
- List products, place orders, and use escrow—all on-chain and decentralized.
- All actions require cryptographic authentication (no admin, no centralization).

### 6. Getting Testnet Coins
- Visit the faucet and request coins to your testnet address.
- Faucet is rate-limited to prevent abuse.

### 7. Monitoring & Support
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3001 (monitoring dashboards)
- Logs: Check Docker logs for each service

---

## 📢 Testnet Launch Announcement (Template)

> **BlackSilk Testnet is Live!**
>
> We invite the community to join, mine, transact, and build on the BlackSilk privacy blockchain testnet. All core features are decentralized, privacy-first, and open for real-world testing. No admin, no centralization—just pure cryptography and community.
>
> - Run a node, mine, and earn testnet coins
> - Use the CLI and web wallets
> - Explore the chain and participate in the decentralized marketplace
> - Report bugs, suggest features, and help us build the future of privacy tech
>
> **Docs, guides, and support:** [GitHub](https://github.com/StickyFingaz420/BlackSilk-Blockchain) | [[Discord link](https://discord.gg/5jtxPkwp)]
>
> Let’s build the next generation of privacy together!

---

## 📊 Monitoring, Logging, and Support

### Monitoring
- **Prometheus** scrapes metrics from all core services (node, miner, marketplace, faucet) at `/metrics` endpoints.
- **Grafana** dashboards visualize chain health, mining, marketplace activity, and faucet usage.
- **AlertManager** notifies of critical failures or abnormal activity.

**To start monitoring stack:**
```sh
cd monitoring
docker-compose up -d
```
- Prometheus: [http://localhost:9090](http://localhost:9090)
- Grafana: [http://localhost:3001](http://localhost:3001)

### Logging
- All services log to stdout (view with `docker logs <service>`)
- For persistent logs, mount volumes or configure log rotation in Docker Compose
- Review logs for errors, warnings, and user-reported issues

### Support & Troubleshooting
- **Support Channel:** Join our [Discord](https://discord.gg/5jtxPkwp)
- **FAQ:**
  - _Node won’t sync?_ Check ports, config, and peer list.
  - _Wallet not connecting?_ Ensure node is running and RPC is reachable.
  - _Faucet not working?_ Check faucet logs and rate limits.
  - _Marketplace issues?_ Ensure all services are up and check logs for errors.
- For more help, open an issue on [GitHub](https://github.com/StickyFingaz420/BlackSilk-Blockchain) or ask in the support channel.

---
