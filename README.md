# BlackSilk Blockchain

A privacy-first, modular blockchain platform with advanced cryptography, decentralized marketplace, block explorer, testnet faucet, and full ecosystem tooling. Built in Rust and TypeScript, BlackSilk is designed for developers, privacy advocates, and next-generation decentralized applications.

---

## Table of Contents
- [Overview](#overview)
- [Tokenomics](#tokenomics)
- [Architecture](#architecture)
- [Monorepo Structure](#monorepo-structure)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Subprojects](#subprojects)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

---

## Overview
BlackSilk is a professional, privacy-focused blockchain with:
- No premine, no ICO. All coins are mined.
- Advanced privacy (RingCT, stealth addresses, zk-SNARKs ready)
- Modular node, miner, wallet, explorer, marketplace, and faucet
- Full TypeScript/Rust stack for web and backend
- Dockerized, production-ready infrastructure

## Tokenomics
- **Token Symbol:** BLK (mainnet), tBLK (testnet)
- **Initial Block Reward:** 5 BLK
- **Block Time:** 120 seconds
- **Halving:** Every 1,051,200 blocks (~4 years)
- **Supply Cap:** 21,000,000 BLK
- **No tail emission:** After cap, miners receive only transaction fees

## Architecture
- **Node:** Rust, privacy-by-default, RandomX PoW, Tor/I2P support
- **Miner:** Standalone RandomX miner (Rust)
- **Wallet:** CLI and web wallet (Rust/TypeScript)
- **Marketplace:** Decentralized, smart contract-powered (Rust/TS)
- **Block Explorer:** Next.js, TypeScript, Tailwind CSS
- **Testnet Faucet:** Next.js/Express, SQLite, Docker
- **Monitoring:** Prometheus, Grafana, Alertmanager

## Monorepo Structure
```
- node/           # Core blockchain node (Rust)
- miner/          # Standalone RandomX miner (Rust)
- wallet/         # CLI wallet (Rust)
- web-wallet/     # Web wallet (Next.js/TS)
- block-explorer/ # Block explorer (Next.js/TS)
- marketplace/    # Decentralized marketplace (Rust/TS)
- testnet-faucet/ # Testnet faucet (Next.js/Express/TS)
- smart-contracts/# WASM smart contracts (Rust)
- monitoring/     # Monitoring stack (Prometheus, Grafana)
- config/         # Chain specs, bootnodes, configs
- tests/          # Integration and e2e tests
```

## Quick Start
### Prerequisites
- Rust (latest stable)
- Node.js 18+
- Docker & Docker Compose
- Git

### Build All (Rust)
```powershell
cargo build --release
```

### Run Node
```powershell
cd node
cargo run --release -- start
```

### Run Miner
```powershell
cd miner
cargo run --release -- --address <YOUR_BLK_ADDRESS>
```

### Run Wallet
```powershell
cd wallet
cargo run --release
```

### Block Explorer (Web)
```powershell
cd block-explorer
npm install
npm run dev
```

### Testnet Faucet (Web)
```powershell
cd testnet-faucet
npm install
npm run dev
```

### Marketplace (Backend)
```powershell
cd marketplace
cargo run --release
```

### Monitoring
```powershell
cd monitoring
# Start Prometheus, Grafana, exporters
docker-compose up -d
```

## Configuration
- See `config/` for chain specs, node and wallet configs
- Each subproject has its own `.env` or TOML config
- Example: `config/testnet/node_config.toml`, `testnet-faucet/.env.example`, `block-explorer/.env.example`

## Subprojects
- **node/**: Core blockchain node (Rust, RandomX, privacy, Tor/I2P)
- **miner/**: Standalone RandomX miner (Rust)
- **wallet/**: CLI wallet (Rust, RingCT, mnemonic, address gen)
- **web-wallet/**: Web wallet (Next.js, TypeScript)
- **block-explorer/**: Modern explorer (Next.js, TypeScript, privacy indicators)
- **marketplace/**: Decentralized marketplace (Rust backend, Next.js frontend, smart contracts)
- **testnet-faucet/**: Testnet faucet (Next.js, Express, SQLite, Docker)
- **smart-contracts/**: WASM smart contracts (Rust, marketplace, escrow, RandomX)
- **monitoring/**: Prometheus, Grafana, exporters
- **tests/**: Integration, e2e, performance, and security tests

## Testing
- Rust: `cargo test --workspace`
- JS/TS: `npm test` (in web subprojects)
- Integration: See `tests/integration/README.md`

## Contributing
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit and push your changes
4. Open a Pull Request

### Guidelines
- Follow Rust and TypeScript best practices
- Add/maintain tests for new features
- Use conventional commit messages
- Ensure Docker builds pass

## License
MIT License - see the [LICENSE](LICENSE) file for details.

## Support
- **GitHub Issues:** [Report bugs or request features](https://github.com/BlackSilk-Blockchain/BlackSilk-Blockchain/issues)
- **Discord:** [Join our Discord community](https://discord.gg/blacksilk)
- **Docs:** [Official documentation](https://docs.blacksilk.com)

---

## Roadmap

### Near Term (Next Release)
- [ ] CAPTCHA integration
- [ ] Multi-language support
- [ ] Advanced analytics dashboard
- [ ] WebSocket real-time updates

### Medium Term
- [ ] Multiple token support
- [ ] Social media verification
- [ ] API key management
- [ ] Webhook notifications

### Long Term
- [ ] Kubernetes deployment
- [ ] Multi-chain support
- [ ] Advanced fraud detection
- [ ] Machine learning abuse detection

---

**BlackSilk Blockchain** – Privacy, performance, and modularity for the next generation of decentralized applications.
