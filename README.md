# BlackSilk Blockchain

<div align="center">

![BlackSilk Logo](https://img.shields.io/badge/BlackSilk-Blockchain-000000?style=for-the-badge&logo=blockchain&logoColor=white)

**A Privacy-First, CPU-Only Blockchain with Complete Ecosystem**

[![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Next.js](https://img.shields.io/badge/Next.js-000000?style=for-the-badge&logo=nextdotjs&logoColor=white)](https://nextjs.org/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-success?style=for-the-badge)](https://github.com/StickyFingaz420/BlackSilk-Blockchain)

</div>

## 🚀 Overview

BlackSilk is a next-generation privacy-focused blockchain ecosystem featuring CPU-only mining, decentralized marketplace, comprehensive monitoring infrastructure, and developer tools. Built from scratch with Rust for maximum performance and security, it provides a complete blockchain solution with integrated services including testnet faucet, block explorer, monitoring stack, and privacy-enhanced transactions using the RandomX proof-of-work algorithm.

## 📚 Table of Contents

- [🚀 Overview](#-overview)
- [📊 Network Specifications](#-network-specifications)
- [🏗️ Complete Architecture](#️-complete-architecture)
- [🚀 Quick Start](#-quick-start)
- [🔧 Usage](#-usage)
- [🛡️ Privacy Features](#️-privacy-features)
- [🛒 Marketplace Features](#-marketplace-features)
- [📈 Roadmap](#-roadmap)
- [🧪 Testing & Development](#-testing--development)
- [🤝 Contributing](#-contributing)
- [🔗 Links & Resources](#-links--resources)
- [📞 Support & Documentation](#-support--documentation)
- [🔐 Security & Privacy](#-security--privacy)
- [🌐 Network Information](#-network-information)
- [📊 Performance & Scalability](#-performance--scalability)
- [🏭 Production Deployment](#-production-deployment)
- [📋 License & Legal](#-license--legal)
- [⚠️ Important Disclaimers](#️-important-disclaimers)
- [🙏 Acknowledgments](#-acknowledgments)


### Key Features

- 🔒 **Privacy-First**: Ring signatures, stealth addresses, and Tor/I2P integration
- ⚡ **CPU-Only Mining**: RandomX algorithm prevents ASIC domination
- 🛒 **Built-in Marketplace**: Decentralized commerce with escrow contracts
- 🔐 **Smart Contracts**: 2-of-3 multisig escrow with ZKP verification
- 🌐 **Anonymous Networks**: Native Tor and I2P support
- 💎 **Fixed Supply**: 21,000,000 BLK with Bitcoin-style halving
- 🚰 **Testnet Faucet**: Automated tBLK token distribution for developers
- 🔍 **Block Explorer**: Modern web-based blockchain explorer with privacy features
- 📊 **Monitoring Stack**: Comprehensive Prometheus/Grafana monitoring infrastructure
- 🏗️ **Developer Tools**: Complete development and testing environment

## 📊 Network Specifications

| Parameter | Value |
|-----------|-------|
| **Total Supply** | 21,000,000 BLK |
| **Block Time** | 120 seconds (2 minutes) |
| **Initial Block Reward** | 5 BLK |
| **Halving Interval** | 1,051,200 blocks (~4 years) |
| **Difficulty Adjustment** | Every 60 blocks (~2 hours) |
| **Mining Algorithm** | RandomX (CPU-only) |
| **Genesis Date** | October 5, 1986 |
| **Mainnet Difficulty** | 100,000,000 (starting) |

### Network Ports

| Service | Network | P2P Port | HTTP Port | Special Port |
|---------|---------|----------|-----------|--------------|
| **Node** | Mainnet | 9334 | 9333 | 9999 (Tor) |
| **Node** | Testnet | 19334 | 19333 | 19999 (Tor) |
| **Testnet Faucet** | - | - | 3000 (Frontend) | 3003 (Backend) |
| **Block Explorer** | - | - | 3002 | - |
| **Monitoring** | - | - | 9090 (Prometheus) | 3001 (Grafana) |

## 🏗️ Complete Architecture

BlackSilk is built as a comprehensive blockchain ecosystem with nine core components:

```
BlackSilk-Blockchain/
├── node/              # Core blockchain node
├── wallet/            # Privacy-enhanced wallet
├── miner/             # Standalone RandomX miner
├── marketplace/       # Decentralized marketplace
├── primitives/        # Shared cryptographic primitives
├── testnet-faucet/    # Automated testnet token distribution
├── block-explorer/    # Web-based blockchain explorer
├── monitoring/        # Prometheus/Grafana monitoring stack
└── config/            # Network and service configurations
```

### Core Components

#### 🔧 Node (`node/`)
- **Full blockchain validation** and consensus
- **RandomX mining** with CPU-only verification
- **HTTP API server** for block submission and queries
- **Privacy network integration** (Tor/I2P)
- **Escrow contract management**

#### 💼 Wallet (`wallet/`)
- **Privacy-enhanced transactions** with ring signatures
- **Stealth address generation**
- **Hardware wallet support**
- **Blockchain synchronization**
- **Privacy command interface**

#### ⛏️ Miner (`miner/`)
- **Standalone RandomX implementation**
- **Pure Rust mining** without external dependencies
- **Multi-threaded CPU mining**
- **Network difficulty adjustment**

#### 🛒 Marketplace (`marketplace/`)
- **Decentralized storage** on blockchain
- **Escrow smart contracts** with dispute resolution
- **Next.js frontend** with modern UI
- **Product catalog** and order management
- **IPFS integration** for large data storage

#### 🔐 Primitives (`primitives/`)
- **Cryptographic types** and utilities
- **Ring signature implementation**
- **zk-SNARKs integration** (Groth16, BLS12-381)
- **Escrow contract primitives**

### Infrastructure & Services

#### 🚰 Testnet Faucet (`testnet-faucet/`)
- **Automated tBLK token distribution** for developers and testers
- **Next.js 14 frontend** with responsive design
- **Express.js backend** with SQLite database
- **Rate limiting** (24-hour cooldown per address/IP)
- **Admin dashboard** with real-time statistics
- **Docker containerization** with production deployment
- **JWT authentication** and security features
- **Request tracking** and transaction lifecycle monitoring

#### 🔍 Block Explorer (`block-explorer/`)
- **Real-time network statistics** (block height, difficulty, hashrate)
- **Block and transaction browser** with detailed information
- **Address lookup** with balance and transaction history
- **Privacy transaction support** (ring signatures, stealth addresses)
- **Modern responsive UI** with dark/light theme
- **Advanced search** by block, transaction, or address
- **Mempool monitoring** and pending transaction viewer
- **Network analytics** with charts and statistics

#### 📊 Monitoring Stack (`monitoring/`)
- **Prometheus metrics collection** with 30-day retention
- **Grafana dashboards** with custom BlackSilk metrics
- **AlertManager** for automated alerts and notifications
- **Node Exporter** for system metrics
- **Custom BlackSilk exporter** for blockchain-specific metrics
- **Loki log aggregation** with Promtail collection
- **Jaeger distributed tracing** for performance analysis
- **Docker Compose deployment** with persistent storage

## 🚀 Quick Start

### Prerequisites

- **Rust 1.70+** with Cargo
- **Node.js 18+** (for frontend services)
- **Docker & Docker Compose** (for monitoring and services)
- **Git** for version control

### Complete Installation

1. **Clone the repository:**
```bash
git clone https://github.com/StickyFingaz420/BlackSilk-Blockchain.git
cd BlackSilk-Blockchain
```

2. **Build all core components:**
```bash
cargo build --release
```

3. **Set up monitoring infrastructure:**
```bash
chmod +x scripts/setup-monitoring.sh
./scripts/setup-monitoring.sh
```

4. **Start the blockchain node:**
```bash
# Mainnet
./target/release/blacksilk-node --mainnet

# Testnet
./target/release/blacksilk-node --testnet
```

5. **Launch testnet faucet (for development):**
```bash
cd testnet-faucet
npm install
npm run dev:server &  # Backend on port 3003
npm run dev &         # Frontend on port 3000
```

6. **Start block explorer:**
```bash
cd block-explorer
npm install
npm run dev  # Explorer on port 3002
```

7. **Access monitoring dashboards:**
```bash
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3001 (admin/blacksilk123)
# AlertManager: http://localhost:9093
```

## 🔧 Usage

### Node Operations

```bash
# Start mainnet node
blacksilk-node --mainnet

# Start testnet node
blacksilk-node --testnet

# Enable Tor privacy
blacksilk-node --mainnet --privacy tor

# Enable I2P privacy
blacksilk-node --mainnet --privacy i2p
```

### Wallet Commands

```bash
# Create new wallet
blacksilk-wallet create

# Generate stealth address
blacksilk-wallet address --stealth

# Send private transaction
blacksilk-wallet send --to <address> --amount <BLK> --privacy

# Sync with blockchain
blacksilk-wallet sync
```

### Mining Operations

```bash
# Start mining to address
blacksilk-miner --address <your-address> --threads 8

# Mine on testnet
blacksilk-miner --testnet --address <address>

# Check mining status
blacksilk-miner --status
```

### Service Management

```bash
# Testnet Faucet
cd testnet-faucet
npm run dev:server &  # Backend API
npm run dev           # Frontend UI

# Block Explorer
cd block-explorer
npm run dev           # Explorer interface

# Marketplace
cd marketplace/frontend
npm run dev           # Marketplace frontend

# Monitoring Stack
cd monitoring
docker-compose up -d  # All monitoring services
```

### API Endpoints

#### Node API (Port 9333/19333)
```bash
# Get blockchain info
curl http://localhost:9333/info

# Get latest block
curl http://localhost:9333/block/latest

# Submit transaction
curl -X POST http://localhost:9333/submit -d '{"tx": "..."}'
```

#### Testnet Faucet API (Port 3003)
```bash
# Request testnet tokens
curl -X POST http://localhost:3003/api/faucet \
  -H "Content-Type: application/json" \
  -d '{"address": "tBLK..."}'

# Check faucet stats
curl http://localhost:3003/api/stats

# Check request status
curl http://localhost:3003/api/status/request-id
```

#### Block Explorer API (Port 3002)
```bash
# Get network statistics
curl http://localhost:3002/api/stats

# Get block information
curl http://localhost:3002/api/block/12345

# Search blockchain
curl http://localhost:3002/api/search?q=block-hash
```

## 🛡️ Privacy Features

### Ring Signatures
- **Anonymous transactions** hiding sender identity
- **Configurable ring size** for enhanced privacy
- **Linkable ring signatures** preventing double-spending

### Stealth Addresses
- **One-time addresses** for each transaction
- **Recipient privacy** protection
- **Address unlinkability**

### Network Privacy
- **Tor integration** for IP address anonymity
- **I2P support** for additional network privacy
- **Clearnet operation** for standard usage

### Zero-Knowledge Proofs
- **zk-SNARKs implementation** using Groth16
- **BLS12-381 elliptic curve** for efficiency
- **Private transaction verification**

## 🛒 Marketplace Features

### Decentralized Commerce
- **On-chain product listings**
- **Blockchain-based inventory**
- **Decentralized reputation system**

### Escrow Smart Contracts
- **2-of-3 multisig escrow** with buyer, seller, and arbiter
- **Automatic dispute resolution**
- **Funds protection** for all parties
- **Time-locked releases**

### Storage Solutions
- **IPFS integration** for large files
- **On-chain metadata** for critical data
- **Distributed content delivery**

## 📈 Roadmap

### ✅ Completed Features

- [x] **Core Blockchain**: Full implementation with RandomX mining
- [x] **Privacy Layer**: Ring signatures and stealth addresses
- [x] **Network Privacy**: Tor and I2P integration
- [x] **Mining Infrastructure**: CPU-only RandomX implementation
- [x] **Wallet Foundation**: Privacy-enhanced wallet with CLI interface
- [x] **Escrow Contracts**: 2-of-3 multisig implementation
- [x] **ZKP Integration**: zk-SNARKs with Groth16
- [x] **Marketplace Backend**: Decentralized storage and APIs
- [x] **Marketplace Frontend**: Next.js interface framework
- [x] **Testnet Faucet**: Complete automated token distribution system
- [x] **Block Explorer**: Full-featured web-based blockchain explorer
- [x] **Monitoring Infrastructure**: Prometheus/Grafana stack with alerts
- [x] **Developer Tools**: Comprehensive testing and deployment scripts

### 🚧 In Development

- [ ] **Advanced Privacy**: Enhanced ring signature algorithms
- [ ] **Marketplace Completion**: Full UI/UX implementation and testing
- [ ] **Mobile Wallet**: iOS and Android applications
- [ ] **Hardware Integration**: Ledger and Trezor support
- [ ] **Smart Contract VM**: General-purpose contract execution
- [ ] **Cross-chain Bridges**: Interoperability protocols
- [ ] **API Documentation**: OpenAPI/Swagger documentation

### 🔮 Future Plans

- [ ] **Layer 2 Solutions**: Payment channels and sidechains
- [ ] **Governance System**: Decentralized decision making
- [ ] **DeFi Protocols**: Lending, staking, and yield farming
- [ ] **Enterprise Solutions**: Business-grade privacy tools
- [ ] **Research Initiatives**: Post-quantum cryptography
- [ ] **Mainnet Launch**: Production network deployment

## 🧪 Testing & Development

### Test Environment Setup

```bash
# Set up complete test environment
chmod +x scripts/setup-test-environment.sh
./scripts/setup-test-environment.sh

# Run all component tests
cargo test

# Test specific component
cargo test --package blacksilk-node
cargo test --package blacksilk-wallet
cargo test --package blacksilk-miner
```

### Integration Testing

```bash
# Test privacy features
cargo test --package blacksilk-wallet --test privacy_commands

# Test marketplace integration
cargo test --package blacksilk-marketplace

# Test faucet system
cd testnet-faucet
npm test

# Test block explorer
cd block-explorer
npm test
```

### Testnet Operations

```bash
# Connect to testnet
blacksilk-node --testnet

# Mine on testnet (difficulty: 1)
blacksilk-miner --testnet --address <test-address>

# Request testnet tokens
curl -X POST http://localhost:3003/api/faucet \
  -H "Content-Type: application/json" \
  -d '{"address": "tBLK_your_testnet_address"}'
```

### Development Tools

```bash
# Format code
cargo fmt

# Run linting
cargo clippy

# Build documentation
cargo doc --open

# Monitor logs
docker logs -f blacksilk-prometheus
docker logs -f blacksilk-grafana
```

## 🤝 Contributing

We welcome contributions from the community! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

1. **Fork the repository**
2. **Create feature branch**: `git checkout -b feature/amazing-feature`
3. **Install dependencies**: `cargo build && npm install` (in service directories)
4. **Set up test environment**: `./scripts/setup-test-environment.sh`
5. **Run tests**: `cargo test && npm test` (in applicable directories)
6. **Commit changes**: `git commit -m 'Add amazing feature'`
7. **Push to branch**: `git push origin feature/amazing-feature`
8. **Open Pull Request**

### Code Standards

- **Rust formatting**: Use `cargo fmt`
- **Linting**: Run `cargo clippy`
- **TypeScript**: Use `npm run lint` in frontend projects
- **Documentation**: Add doc comments for public APIs
- **Testing**: Include unit tests for new features
- **Security**: Follow secure coding practices

### Project Structure

```
BlackSilk-Blockchain/
├── node/              # Core blockchain (Rust)
├── wallet/            # CLI wallet (Rust) 
├── miner/             # RandomX miner (Rust)
├── marketplace/       # Decentralized marketplace (Rust + Next.js)
├── primitives/        # Cryptographic primitives (Rust)
├── testnet-faucet/    # Token distribution service (Next.js + Express)
├── block-explorer/    # Blockchain explorer (Next.js + TypeScript)
├── monitoring/        # Prometheus/Grafana stack (Docker)
├── config/            # Network configurations
├── scripts/           # Setup and deployment scripts
└── tests/             # Integration tests
```

## 📋 License & Legal

### MIT License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for complete details.

```
Copyright (c) 2025-2026 BlackSilk Community

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

### Third-Party Licenses
- **RandomX Algorithm**: BSD 3-Clause License
- **Ring Signatures**: MIT License (Monero Research Lab)
- **BLS12-381 Curve**: Apache 2.0 License
- **Prometheus**: Apache 2.0 License
- **Grafana**: AGPL v3 License

## ⚠️ Important Disclaimers

### Experimental Software Notice
BlackSilk is experimental blockchain software currently in active development. Users should be aware of the following:

- **Pre-Production**: This software is not yet ready for production mainnet use
- **Testnet Only**: Current deployment is limited to testnet operations
- **Active Development**: Features and APIs may change without notice
- **No Warranties**: Software provided "as is" without warranties of any kind

### Financial Disclaimers
- **Not Financial Advice**: This project does not constitute financial or investment advice
- **Risk Warning**: Cryptocurrency investments carry significant financial risk
- **Loss of Funds**: Users may lose funds due to software bugs or user error
- **Regulatory Compliance**: Users are responsible for compliance with local laws

### Privacy & Security Notices
- **Privacy Features**: Privacy features are experimental and not guaranteed
- **Security Audits**: Professional security audit pending
- **Key Management**: Users are solely responsible for private key security
- **Network Risks**: Testnet may be reset without notice

## 🙏 Acknowledgments

### Core Contributors
- **StickyFingaz420**: Lead Developer & Project Founder
- **BlackSilk Community**: Contributors, testers, and supporters

### Technology Stack
- **Rust Programming Language**: Systems programming foundation
- **RandomX Algorithm**: Monero Research Lab's CPU-mining innovation
- **Next.js Framework**: React-based frontend development
- **Prometheus & Grafana**: Monitoring and observability infrastructure
- **Docker**: Containerization and deployment platform

### Research & Inspiration
- **Monero Project**: Privacy technology inspiration
- **Bitcoin**: Blockchain fundamentals and proof-of-work consensus
- **Ethereum**: Smart contract concepts and development patterns
- **Zcash**: Zero-knowledge proof implementations

### Open Source Libraries
- **Tokio**: Asynchronous runtime for Rust
- **Serde**: Serialization framework
- **SQLite**: Embedded database engine
- **Tailwind CSS**: Utility-first CSS framework
- **TypeScript**: Type-safe JavaScript development

---

<div align="center">

## 🚀 Join the BlackSilk Revolution

**Building the Future of Private, Decentralized Commerce**

[![GitHub Stars](https://img.shields.io/github/stars/StickyFingaz420/BlackSilk-Blockchain?style=social)](https://github.com/StickyFingaz420/BlackSilk-Blockchain/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/StickyFingaz420/BlackSilk-Blockchain?style=social)](https://github.com/StickyFingaz420/BlackSilk-Blockchain/network/members)
[![GitHub Issues](https://img.shields.io/github/issues/StickyFingaz420/BlackSilk-Blockchain)](https://github.com/StickyFingaz420/BlackSilk-Blockchain/issues)
[![GitHub Pull Requests](https://img.shields.io/github/issues-pr/StickyFingaz420/BlackSilk-Blockchain)](https://github.com/StickyFingaz420/BlackSilk-Blockchain/pulls)

**Built with ❤️ by the BlackSilk Community**

*Empowering Privacy • Enabling Commerce • Securing Freedom*

</div>