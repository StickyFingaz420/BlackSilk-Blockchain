# BlackSilk Blockchain

![BlackSilk Logo](https://img.shields.io/badge/BlackSilk-Privacy%20Blockchain-black?style=for-the-badge&logo=blockchain&logoColor=white)

A **privacy-focused, CPU-only blockchain** built entirely in Rust with advanced cryptographic features, zero-knowledge proofs, and professional mining infrastructure.

## 🚀 Key Features

### 🔒 **Advanced Privacy Technology**
- **CryptoNote Protocol**: Full implementation with ring signatures and stealth addresses
- **Zero-Knowledge Proofs**: Real zk-SNARKs integration using arkworks library
- **Bulletproofs**: Range proofs for confidential transactions
- **Ring Signatures**: CryptoNote-style unlinkable signatures with variable ring sizes
- **Stealth Addresses**: Complete transaction unlinkability

### ⛏️ **Professional Mining Infrastructure**
- **Pure Rust RandomX**: CPU-only mining with ASIC/GPU resistance
- **Professional Miner**: Standalone mining software with advanced features
- **Mining Statistics**: Real-time hashrate monitoring and performance tracking
- **Cross-Platform**: Works on Linux, macOS, and Windows without external dependencies

### 🌐 **Privacy-First Networking**
- **Tor Integration**: Native Tor hidden service support
- **I2P Support**: Advanced privacy routing capabilities
- **Privacy Modes**: Configurable privacy enforcement levels
- **Connection Filtering**: Automatic privacy-based connection management

### 💰 **Smart Contracts & DeFi**
- **Escrow Contracts**: Trustless escrow with dispute resolution
- **Multisig Support**: 2-of-3 signature schemes
- **DAO Voting**: Community-driven dispute resolution
- **Hardware Wallet Support**: Ledger and Trezor integration

---

## 📊 Tokenomics

| Parameter | Value |
|-----------|-------|
| **Total Supply** | 21,000,000 BLK |
| **Block Time** | 120 seconds (2 minutes) |
| **Initial Reward** | 5 BLK |
| **Halving Interval** | 1,051,200 blocks (~4 years) |
| **Atomic Units** | 1 BLK = 1,000,000 atomic units |
| **Tail Emission** | None (fees only after cap) |
| **Premine** | 0 BLK (100% mined) |

### Emission Schedule
- **Genesis**: 5 BLK per block
- **First Halving** (~2029): 2.5 BLK per block
- **Second Halving** (~2033): 1.25 BLK per block
- **Final Emission** (~2045): Only transaction fees

---

## 🏗️ Architecture

### Core Components

```
BlackSilk-Blockchain/
├── node/               # Core blockchain node
├── wallet/             # Privacy wallet with hardware support
├── miner/              # Professional standalone miner
├── primitives/         # Blockchain primitives and cryptography
└── src/                # Main entry point and CLI
```

### Network Configuration

#### Mainnet
- **P2P Port**: 1776
- **HTTP API Port**: 2776
- **Tor Hidden Service**: 3776
- **Network Magic**: 0xB1A6C
- **Genesis**: May 24, 2025

#### Testnet
- **P2P Port**: 8333
- **HTTP API Port**: 9333
- **Tor Hidden Service**: 10333
- **Network Magic**: 0x1D670
- **Genesis**: July 26, 1953

---

## 🔧 Installation & Setup

### Prerequisites
- Rust 1.70+ with Cargo
- Git
- Build essentials (gcc, make)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/blacksilk/BlackSilk-Blockchain.git
cd BlackSilk-Blockchain

# Build the project
cargo build --release

# Run a node
./target/release/BlackSilk --network testnet

# Start mining
./target/release/blacksilk-miner --threads 4 --pool solo
```

### Advanced Configuration

```bash
# Start with custom network settings
BLACKSILK_NETWORK=mainnet ./target/release/BlackSilk --port 1776

# Enable Tor-only mode
./target/release/BlackSilk --tor-only --hidden-service

# Professional mining with statistics
./target/release/blacksilk-miner --threads 8 --stats-interval 30 --log-level info
```

---

## ⛏️ Mining

### CPU-Only RandomX Mining

BlackSilk uses a **pure Rust RandomX implementation** ensuring:
- ✅ ASIC resistance
- ✅ GPU resistance 
- ✅ Fair CPU-only mining
- ✅ Cross-platform compatibility
- ✅ No external dependencies

### Mining Commands

```bash
# Solo mining
./target/release/blacksilk-miner --threads 4 --pool solo --node http://localhost:9333

# Pool mining (when pools are available)
./target/release/blacksilk-miner --threads 8 --pool stratum+tcp://pool.blacksilk.io:4444

# Benchmark mode
./target/release/blacksilk-miner --benchmark --threads auto

# Mining statistics
./target/release/blacksilk-miner --status
```

### Mining Statistics Dashboard

The miner provides comprehensive statistics:
- Real-time hashrate (10s, 60s, 15min averages)
- Total hashes computed
- Blocks found and shares accepted/rejected
- Hardware utilization and temperature monitoring
- Profit calculations and power consumption estimates

---

## 💳 Privacy Wallet

### Features
- **Stealth Addresses**: Complete transaction privacy
- **Ring Signatures**: Unlinkable transaction signing
- **Hardware Wallet Support**: Ledger and Trezor integration
- **Multisig Wallets**: 2-of-3 and custom threshold signatures
- **BIP39 Mnemonic**: Industry-standard seed phrases
- **Encrypted Storage**: AES-256 wallet encryption

### Wallet Commands

```bash
# Create new wallet
./target/release/blacksilk-wallet new --name my-wallet

# Generate stealth address
./target/release/blacksilk-wallet generate-address --wallet my-wallet

# Send private transaction
./target/release/blacksilk-wallet send --to ADDRESS --amount 1.5 --ring-size 11

# Check balance
./target/release/blacksilk-wallet balance --wallet my-wallet

# Hardware wallet integration
./target/release/blacksilk-wallet hardware --connect ledger
```

### Privacy Features

- **Ring Signatures**: Variable ring sizes (3-64 decoys)
- **Stealth Addresses**: One-time addresses for each transaction
- **Range Proofs**: Bulletproofs for amount confidentiality
- **View Keys**: Optional transaction visibility for auditing
- **Subaddresses**: Multiple addresses from single wallet

---

## 🤝 Smart Contracts

### Escrow System

BlackSilk includes a built-in escrow system for trustless transactions:

```rust
// Create escrow contract
let escrow = EscrowContract::new(buyer_key, seller_key, arbiter_key, amount);

// Fund escrow (buyer)
escrow.fund(buyer_signature);

// Release funds (any 2 of 3)
escrow.sign_release(buyer_signature);
escrow.sign_release(arbiter_signature);
escrow.release(); // Funds go to seller

// Dispute resolution with DAO voting
escrow.dispute(buyer_key);
escrow.start_voting();
escrow.submit_vote(voter_key, true); // true = favor buyer
```

### Multisig Support

- **2-of-3 Signatures**: Standard escrow configuration
- **Custom Thresholds**: Configurable N-of-M signatures
- **Hardware Integration**: Hardware wallet multisig support
- **Time Locks**: Optional time-based release conditions

---

## 🌐 Network & Privacy

### Tor Integration

```bash
# Enable Tor hidden service
./target/release/BlackSilk --tor-only --hidden-service-port 3776

# Connect through Tor proxy
./target/release/BlackSilk --tor-proxy 127.0.0.1:9050
```

### I2P Support

```bash
# Enable I2P routing
./target/release/BlackSilk --i2p-enabled --i2p-proxy 127.0.0.1:4444

# Maximum privacy mode (Tor + I2P)
./target/release/BlackSilk --privacy-mode max --no-clearnet
```

### Privacy Modes

| Mode | Description |
|------|-------------|
| `disabled` | Allow all connections |
| `tor` | Prefer Tor, allow clearnet |
| `tor-only` | Only Tor connections |
| `max-privacy` | Tor + I2P, no clearnet |

---

## 🔗 API Reference

### HTTP API Endpoints

```bash
# Get blockchain info
curl http://localhost:9333/info

# Get block by height
curl http://localhost:9333/block/12345

# Submit transaction
curl -X POST http://localhost:9333/send_tx -d '{"tx": "..."}'

# Get mempool
curl http://localhost:9333/mempool

# Mining statistics
curl http://localhost:9333/mining/stats
```

### P2P Protocol

BlackSilk uses a custom P2P protocol with message types:
- `Version` - Node version and capabilities
- `Block` - Block propagation
- `Transaction` - Transaction broadcasting
- `GetBlocks` - Block synchronization
- `Ping/Pong` - Connection keepalive

---

## 🧪 Development & Testing

### Running Tests

```bash
# Run all tests
cargo test

# Test specific modules
cargo test --package primitives
cargo test --package node
cargo test --package wallet

# Privacy features tests
cargo test privacy_commands

# Integration tests
cargo test --test integration
```

### Benchmarks

```bash
# RandomX mining benchmark
cargo run --bin benchmark_mining --release

# Cryptographic benchmarks
cargo bench

# Network performance tests
cargo test --package node --test network_bench
```

### Development Mode

```bash
# Start testnet node for development
BLACKSILK_NETWORK=testnet cargo run -- --port 8333

# Enable debug logging
RUST_LOG=debug cargo run

# Development mining (low difficulty)
cargo run --bin blacksilk-miner -- --testnet --threads 1
```

---

## 📈 Development Roadmap

### ✅ Completed Features

#### Core Blockchain (100% Complete)
- [x] Pure Rust implementation
- [x] RandomX CPU-only mining
- [x] 120-second block time
- [x] 21M BLK supply cap with halving
- [x] No premine, fair launch ready

#### Privacy Technology (95% Complete)
- [x] CryptoNote protocol implementation
- [x] Ring signatures with variable ring sizes
- [x] Stealth addresses for transaction privacy
- [x] Bulletproofs range proofs
- [x] Zero-knowledge proofs (zk-SNARKs)

#### Mining Infrastructure (100% Complete)
- [x] Professional standalone miner
- [x] Cross-platform compatibility
- [x] Real-time statistics and monitoring
- [x] ASIC/GPU resistance verification
- [x] Solo and pool mining support

#### Wallet System (90% Complete)
- [x] Privacy-focused wallet
- [x] Hardware wallet integration (Ledger/Trezor)
- [x] BIP39 mnemonic support
- [x] Multisig functionality
- [x] Encrypted wallet storage

#### Network & Privacy (85% Complete)
- [x] Tor hidden service integration
- [x] I2P networking support
- [x] Privacy-aware connection management
- [x] Configurable privacy modes
- [x] P2P protocol implementation

#### Smart Contracts (80% Complete)
- [x] Escrow contract system
- [x] Multisig support (2-of-3)
- [x] DAO dispute resolution
- [x] Time-locked transactions

### 🚧 In Development

#### Phase 1 - Mainnet Launch Preparation (Q2 2025)
- [ ] Final security audits
- [ ] Testnet stress testing
- [ ] Mining pool software
- [ ] Exchange integration tools
- [ ] Documentation completion

#### Phase 2 - Advanced Features (Q3-Q4 2025)
- [ ] Mobile wallet applications
- [ ] Advanced smart contracts
- [ ] Cross-chain bridge development
- [ ] Decentralized exchange (DEX)
- [ ] Governance system implementation

#### Phase 3 - Ecosystem Growth (2026)
- [ ] DeFi protocol integrations
- [ ] Enterprise privacy solutions
- [ ] Merchant payment systems
- [ ] Developer SDK and tools
- [ ] Academic research partnerships

### 🔮 Future Roadmap

#### 2026-2027: Advanced Privacy
- Post-quantum cryptography research
- Enhanced anonymity sets
- Advanced zero-knowledge circuits
- Privacy-preserving smart contracts

#### 2027-2028: Scalability
- Layer 2 scaling solutions
- Sharding implementation
- Cross-chain interoperability
- Performance optimizations

#### 2028+: Mass Adoption
- Mainstream wallet integrations
- Regulatory compliance tools
- Enterprise adoption programs
- Global payment networks

---

## 🛡️ Security

### Cryptographic Foundations
- **Curve25519**: Elliptic curve cryptography
- **Ed25519**: Digital signatures
- **Blake2b**: Cryptographic hashing
- **RandomX**: ASIC-resistant proof-of-work
- **Bulletproofs**: Zero-knowledge range proofs

### Security Audits
- Internal code reviews completed
- Cryptographic primitives verified
- Network protocol analysis ongoing
- Third-party security audit planned

### Vulnerability Reporting
For security issues, please email: security@blacksilk.io

---

## 🤝 Contributing

### Development Guidelines
1. **Code Quality**: All code must pass `cargo clippy` and `cargo fmt`
2. **Testing**: Minimum 80% test coverage required
3. **Documentation**: All public APIs must be documented
4. **Security**: Security-sensitive code requires peer review

### Getting Started
```bash
# Fork the repository
git clone https://github.com/yourusername/BlackSilk-Blockchain.git

# Create feature branch
git checkout -b feature/new-feature

# Make changes and test
cargo test --all

# Submit pull request
git push origin feature/new-feature
```

### Development Environment
```bash
# Install development dependencies
cargo install cargo-audit cargo-outdated

# Security audit
cargo audit

# Check for outdated dependencies
cargo outdated
```

---

## 📄 License

BlackSilk is open-source software licensed under the **MIT License**.

```
MIT License

Copyright (c) 2025 BlackSilk Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 📞 Community & Support

### Official Channels
- **Website**: https://blacksilk.io
- **GitHub**: https://github.com/blacksilk/BlackSilk-Blockchain
- **Discord**: https://discord.gg/blacksilk
- **Telegram**: https://t.me/blacksilk_official
- **Reddit**: https://reddit.com/r/blacksilk

### Documentation
- **Developer Docs**: https://docs.blacksilk.io
- **API Reference**: https://api.blacksilk.io
- **Mining Guide**: https://mining.blacksilk.io
- **Privacy Manual**: https://privacy.blacksilk.io

### Support
- **General Support**: support@blacksilk.io
- **Technical Issues**: tech@blacksilk.io
- **Business Inquiries**: business@blacksilk.io
- **Security Reports**: security@blacksilk.io

---

## ⚠️ Disclaimer

BlackSilk is experimental software. While we strive for security and reliability, users should:
- Never invest more than they can afford to lose
- Use testnet for development and testing
- Keep private keys secure and backed up
- Stay informed about updates and security advisories

**This is not financial advice. Cryptocurrency investments carry inherent risks.**

---

<div align="center">

**BlackSilk - Privacy by Design, Security by Default**

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![Blockchain](https://img.shields.io/badge/blockchain-privacy-black?style=for-the-badge)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)

*Built with ❤️ by the BlackSilk community*

</div>