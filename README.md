![BlackSilk Blockchain](https://i.imgur.com/cJxsqG0.png)

# BlackSilk Blockchain

**Built from scratch**: BlackSilk is a privacy-focused blockchain and decentralized marketplace, designed and implemented from the ground up to provide robust privacy, security, and censorship resistance.

## Project Overview

BlackSilk is a next-generation, privacy-first blockchain platform with an integrated decentralized marketplace. Inspired by Monero and Silk Road, it leverages advanced cryptography and privacy technologies to enable secure, anonymous commerce. The project is implemented entirely from scratch in Rust, with a modern architecture and extensible design.

Key technologies include:
- **RandomX Proof-of-Work** for ASIC resistance and fair mining
- **Ring Signatures, Stealth Addresses, Bulletproofs** for transaction privacy
- **Tor/I2P Integration** for network anonymity
- **Smart Escrow Contracts** with 2-of-3 multisig and dispute resolution
- **IPFS Integration** for decentralized storage
- **Wallet-based Authentication** (no passwords, no sessions)
- **Extensible Rust Backend** with PostgreSQL for persistent storage
- **Next.js Frontend** (scaffolded)

## Features

- **Privacy First**: Ring signatures, stealth addresses, and confidential transactions ensure complete transaction privacy
- **CPU Mining**: RandomX proof-of-work algorithm optimized for CPU mining
- **Network Privacy**: Full Tor/I2P integration with optional clearnet
- **Marketplace**: Integrated decentralized marketplace with escrow and IPFS
- **Wallet-based Authentication**: Ed25519 signature-based login and endpoint protection
- **Event/Audit Logging**: All escrow actions are logged for transparency and dispute resolution

## Tokenomics

| Parameter         | Value                        |
|------------------|------------------------------|
| Block Time       | 120 seconds (2 minutes)      |
| Initial Reward   | 86 BLK per block             |
| Halving Interval | Every 125,000 blocks         |
| Halving Amount   | 50% reduction per halving    |
| Supply Cap       | 21,000,000 BLK               |
| Tail Emission    | 0.5 BLK per block (post-cap) |
| Emission Curve   | Exponential decay, then flat |

### Emission & Halving Schedule

- **Block reward starts at 86 BLK.**
- **Halving occurs every 125,000 blocks** (~8.6 months at 2 min/block).
- **After supply cap is reached, tail emission of 0.5 BLK/block continues indefinitely.**

#### Example Halving Table

| Halving # | Block Height | Block Reward (BLK) | Cumulative Supply (approx) |
|-----------|--------------|--------------------|---------------------------|
| 0         | 0            | 86                 | 0                         |
| 1         | 125,000      | 43                 | 10,750,000                |
| 2         | 250,000      | 21.5               | 14,562,500                |
| 3         | 375,000      | 10.75              | 16,218,750                |
| 4         | 500,000      | 5.375              | 17,109,375                |
| ...       | ...          | ...                | ...                       |
| N         | ~            | ...                | 21,000,000 (cap)          |

#### Emission Chart (Block Reward vs. Block Height)

```
Block Reward (BLK)
|
| 86 ──────────────┐
|                  │
|                  │
| 43 ──────┐       │
|          │       │
| 21.5 ─┐  │       │
|       │  │       │
| 10.75│  │       │
|   ...│  │       │
|______│__│_______│________________ Block Height
      125k 250k 375k ...

(Tail emission: 0.5 BLK/block after cap)
```

- The emission curve follows an exponential decay until the supply cap, then switches to a flat tail emission.
- This ensures long-term miner incentives and network security.

## Quick Start

### Prerequisites
- Rust 1.70+ with cargo
- Node.js 18+ (for marketplace frontend)
- PostgreSQL (for backend database)
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
cargo run --release -- -n 192.168.1.100:8000 -a blacks1k... -t 4
```

#### Standalone Miner

You can use the standalone miner (`blacksilk-miner`) to mine with multiple PCs on the same network, all mining to a single node.

**Usage:**
```bash
cargo run --release --package blacksilk-miner -- \
  -n NODE_IP:PORT \
  -a YOUR_WALLET_ADDRESS \
  -t NUM_THREADS
```

- `-n` / `--node`: Node address (host:port) to connect to (e.g., `192.168.1.100:8000`)
- `-a` / `--address`: Your wallet address to receive mining rewards
- `-t` / `--threads`: Number of mining threads (default: 1, set to number of CPU cores for best performance)

**Example:**
```bash
cargo run --release --package blacksilk-miner -- -n 192.168.1.100:8000 -a blacks1k1q2w3e4r5t6y7u8i9o0p -t 4
```

You can run this command on multiple PCs, all pointing to the same node, to mine cooperatively.

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
