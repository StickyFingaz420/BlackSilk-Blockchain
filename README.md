# BlackSilk Blockchain

<div align="center">

![BlackSilk Logo](https://img.shields.io/badge/BlackSilk-Blockchain-000000?style=for-the-badge&logo=blockchain&logoColor=white)

**A Privacy-First, CPU-Only Blockchain with Decentralized Marketplace**

[![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-success?style=for-the-badge)](https://github.com/BlackSilkCoin/BlackSilk-Blockchain)

</div>

## 🚀 Overview

BlackSilk is a next-generation blockchain focused on privacy, decentralization, and CPU-only mining. Built from scratch with Rust for maximum performance and security, it features an integrated decentralized marketplace with escrow smart contracts, privacy-enhanced transactions, and the RandomX proof-of-work algorithm.


### Key Features

- 🔒 **Privacy-First**: Ring signatures, stealth addresses, and Tor/I2P integration
- ⚡ **CPU-Only Mining**: RandomX algorithm prevents ASIC domination
- 🛒 **Built-in Marketplace**: Decentralized commerce with escrow contracts
- 🔐 **Smart Contracts**: 2-of-3 multisig escrow with ZKP verification
- 🌐 **Anonymous Networks**: Native Tor and I2P support
- 💎 **Fixed Supply**: 21,000,000 BLK with Bitcoin-style halving

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

| Network | P2P Port | HTTP Port | Tor Port |
|---------|----------|-----------|----------|
| **Mainnet** | 9334 | 9333 | 9999 |
| **Testnet** | 19334 | 19333 | 19999 |

## 🏗️ Architecture

BlackSilk is built as a modular Rust workspace with five core components:

```
BlackSilk-Blockchain/
├── node/          # Core blockchain node
├── wallet/        # Privacy-enhanced wallet
├── miner/         # Standalone RandomX miner
├── marketplace/   # Decentralized marketplace
└── primitives/    # Shared cryptographic primitives
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

## 🚀 Quick Start

### Prerequisites

- **Rust 1.70+** with Cargo
- **Node.js 18+** (for marketplace frontend)
- **Git** for version control

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/BlackSilkCoin/BlackSilk-Blockchain.git
cd BlackSilk-Blockchain
```

2. **Build all components:**
```bash
cargo build --release
```

3. **Run the node:**
```bash
./target/release/blacksilk-node --mainnet
```

4. **Start mining:**
```bash
./target/release/blacksilk-miner --node-url http://localhost:9333
```

5. **Launch marketplace frontend:**
```bash
cd marketplace/frontend
npm install
npm run dev
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

### Mining

```bash
# Start mining to address
blacksilk-miner --address <your-address> --threads 8

# Mine on testnet
blacksilk-miner --testnet --address <address>

# Check mining status
blacksilk-miner --status
```

### Marketplace

```bash
# Start marketplace backend
blacksilk-marketplace

# Run frontend development server
cd marketplace/frontend && npm run dev

# Build production frontend
npm run build && npm start
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
- [x] **Wallet Foundation**: Basic privacy-enhanced wallet
- [x] **Escrow Contracts**: 2-of-3 multisig implementation
- [x] **ZKP Integration**: zk-SNARKs with Groth16
- [x] **Marketplace Backend**: Decentralized storage and APIs
- [x] **Frontend Framework**: Next.js marketplace interface

### 🚧 In Development

- [ ] **Advanced Privacy**: Enhanced ring signature algorithms
- [ ] **Marketplace Frontend**: Complete UI/UX implementation
- [ ] **Mobile Wallet**: iOS and Android applications
- [ ] **Hardware Integration**: Ledger and Trezor support
- [ ] **Smart Contract VM**: General-purpose contract execution
- [ ] **Cross-chain Bridges**: Interoperability protocols

### 🔮 Future Plans

- [ ] **Layer 2 Solutions**: Payment channels and sidechains
- [ ] **Governance System**: Decentralized decision making
- [ ] **DeFi Protocols**: Lending, staking, and yield farming
- [ ] **Enterprise Solutions**: Business-grade privacy tools
- [ ] **Research Initiatives**: Post-quantum cryptography

## 🧪 Testing

### Unit Tests
```bash
# Run all tests
cargo test

# Test specific component
cargo test --package blacksilk-node

# Run with output
cargo test -- --nocapture
```

### Integration Tests
```bash
# Test privacy commands
cargo test --package blacksilk-wallet --test privacy_commands

# Test marketplace integration
cargo test --package blacksilk-marketplace
```

### Testnet
```bash
# Connect to testnet
blacksilk-node --testnet

# Mine on testnet (difficulty: 1)
blacksilk-miner --testnet --address <test-address>
```

## 🤝 Contributing

We welcome contributions from the community! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

1. **Fork the repository**
2. **Create feature branch**: `git checkout -b feature/amazing-feature`
3. **Install dependencies**: `cargo build`
4. **Run tests**: `cargo test`
5. **Commit changes**: `git commit -m 'Add amazing feature'`
6. **Push to branch**: `git push origin feature/amazing-feature`
7. **Open Pull Request**

### Code Standards

- **Rust formatting**: Use `cargo fmt`
- **Linting**: Run `cargo clippy`
- **Documentation**: Add doc comments for public APIs
- **Testing**: Include unit tests for new features

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Website**: [https://blacksilkcoin.org](https://blacksilkcoin.org)
- **Documentation**: [https://docs.blacksilkcoin.org](https://docs.blacksilkcoin.org)
- **Explorer**: [https://explorer.blacksilkcoin.org](https://explorer.blacksilkcoin.org)
- **Discord**: [https://discord.gg/blacksilk](https://discord.gg/blacksilk)
- **Telegram**: [https://t.me/blacksilkcoin](https://t.me/blacksilkcoin)
- **Reddit**: [https://reddit.com/r/blacksilkcoin](https://reddit.com/r/blacksilkcoin)

## 📞 Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/BlackSilkCoin/BlackSilk-Blockchain/issues)
- **Community Forum**: [Join discussions](https://forum.blacksilkcoin.org)
- **Email**: support@blacksilkcoin.org

## ⚠️ Disclaimer

BlackSilk is experimental software. Use at your own risk. The developers are not responsible for any loss of funds or other damages that may occur from using this software.

---

<div align="center">

**Built with ❤️ by the BlackSilk Community**

</div>