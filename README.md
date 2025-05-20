![BlackSilk Blockchain](https://i.imgur.com/cJxsqG0.png)

# BlackSilk Blockchain

A privacy-focused blockchain platform with integrated decentralized marketplace capabilities.

## Overview

BlackSilk is a proof-of-work blockchain that prioritizes privacy and censorship resistance through:
- RandomX (RX/0) mining algorithm optimized for CPU mining
- Ring signatures and stealth addresses for transaction privacy
- Confidential Transactions with Bulletproofs
- Tor/I2P network integration
- Decentralized marketplace with privacy-preserving features

## Features

- **Privacy First**: Ring signatures, stealth addresses, and confidential transactions ensure complete transaction privacy
- **CPU Mining**: RandomX proof-of-work algorithm optimized for CPU mining
- **Block Time**: 2-3 minutes (90-145 seconds)
- **Initial Reward**: 86 BLK
- **Halving**: Every 125,000 blocks (50% reduction)
- **Supply Cap**: 21 million BLK
- **Tail Emission**: 0.5 BLK per block after cap
- **Network Privacy**: Full Tor/I2P integration with optional clearnet
- **Marketplace**: Integrated decentralized marketplace with escrow and IPFS

## Quick Start

### Prerequisites
- Rust 1.70+ with cargo
- Node.js 18+ (for marketplace frontend)
- Python 3.9+ (for marketplace backend)
- Tor/I2P services (optional)

### Building from Source

1. Clone the repository:
```bash
git clone https://github.com/yourusername/blacksilk.git
cd blacksilk
```

2. Build the core node:
```bash
cargo build --release
```

3. Build the wallet:
```bash
cd wallet
cargo build --release
```

4. Start the node:
```bash
./target/release/blacksilk-node
```

5. Generate a wallet:
```bash
./target/release/blacksilk-wallet generate
```

### Running a Node

The node can be run in several modes:
```bash
# Standard mode (clearnet + Tor/I2P)
blacksilk-node

# Tor-only mode
blacksilk-node --tor-only

# With custom port
blacksilk-node --port 1776
```

### Mining

```bash
blacksilk-miner --address YOUR_ADDRESS
```

## Documentation

- [Whitepaper](docs/whitepaper.md)
- [Architecture Overview](docs/architecture.md)
- [API Documentation](docs/api/README.md)
- [Build Instructions](docs/build.md)
- [Marketplace Guide](docs/marketplace.md)

## Development

- [Contributing Guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

BlackSilk builds upon the work of several privacy-focused blockchain projects:
- Monero (RandomX, ring signatures)
- Zcash (zero-knowledge proofs concepts)
- Silk Road (marketplace architecture inspiration)
