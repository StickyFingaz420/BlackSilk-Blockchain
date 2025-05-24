# BlackSilk Blockchain

## Overview

BlackSilk is a privacy-focused, censorship-resistant blockchain and decentralized marketplace inspired by Monero, Bitcoin, and the Silk Road. It features a Rust-based node, miner, and wallet, and a Next.js-based frontend. The project emphasizes strong cryptography, anonymous networking, and a robust, open-source stack.

---

## Table of Contents

- [Architecture & Components](#architecture--components)
- [Wallet Features](#wallet-features)
- [Wallet CLI Commands](#wallet-cli-commands)
- [Wallet File Format](#wallet-file-format)
- [Build & Usage Instructions](#build--usage-instructions)
- [What’s Finished](#whats-finished)
- [What’s Under Construction](#whats-under-construction)
- [Marketplace & Node](#marketplace--node)
- [Security & Privacy](#security--privacy)
- [Contributing](#contributing)
- [License](#license)

---

## Architecture & Components

- **Node:** Rust-based, supports CLI, data directory, genesis block, and block/transaction validation. Exposes `/get_blocks?from_height=...` for wallet sync.
- **Miner:** Rust-based, RandomX PoW, CLI for mining configuration.
- **Wallet:** Rust-based, professional CLI wallet with:
  - BIP39 mnemonic/seed generation
  - Stealth address (public view/spend keys)
  - Persistent wallet file (`wallet.json`)
  - Node sync and balance calculation
  - CLI for all major wallet operations
- **Marketplace Frontend:** Next.js, dark web/Silk Road-inspired UI.
- **Marketplace Backend:** Rust/Python (planned), Tor/I2P integration.

---

## Wallet Features

- **Key Generation:** BIP39 mnemonic, private spend/view keys, public spend/view keys, stealth address encoding (Blk...).
- **Persistent Storage:** All wallet data (mnemonic, keys, address, last synced height) saved in `wallet_data/wallet.json`.
- **Node Sync:** Connects to node, fetches blocks, scans for outputs, calculates balance.
- **Balance Calculation:** Scans all outputs for those matching the wallet’s public keys.
- **CLI Options:** Generate wallet, show seed, show keys, check balance, send coins (stub), specify node address.
- **Security:** No private key or mnemonic is ever sent to the node; all scanning is local.
- **Hardware Wallet Integration:** Scaffolded for future Ledger/Trezor support (see `src/hardware.rs`).

---

## Wallet CLI Commands

All commands are run from the `wallet` directory:

### Build the Wallet

```sh
cargo build --release
```

### Generate a New Wallet

```sh
cargo run --release -- --generate
```
- Generates a new mnemonic, keys, and address.
- Saves to `wallet_data/wallet.json`.

### Show Wallet Mnemonic Seed

```sh
cargo run --release -- --show-seed
```

### Show Private Keys

```sh
cargo run --release -- --show-keys
```

### Show Wallet Balance

```sh
cargo run --release -- --balance
```
- Connects to the node (default: `127.0.0.1:8333`).
- Scans for outputs belonging to your wallet.

### Send Coins (Stub)

```sh
cargo run --release -- --send <address> --amount <amount>
```
- **Note:** Sending is not yet implemented; this prints a stub message.

### Specify Node Address

```sh
cargo run --release -- --balance --node <node_address:port>
```

### Help and Version

```sh
cargo run --release -- --help
cargo run --release -- --version
```
- `--version` is handled automatically by `clap`.

---

## Wallet File Format

The wallet is saved as JSON in `wallet_data/wallet.json`:

```json
{
  "mnemonic": "...",
  "priv_spend": "...",
  "priv_view": "...",
  "pub_spend": "...",
  "pub_view": "...",
  "last_height": 0,
  "address": "Blk..."
}
```

---

## Build & Usage Instructions

### Prerequisites

- Rust (latest stable)
- Node.js (for frontend)
- C++ toolchain (for RandomX miner)
- Python 3.x (for some backend tools)
- Tor/I2P (for privacy networking)

### Build All Components

#### Node

```sh
cargo build --release -p node
```

#### Miner

```sh
cd miner
cargo build --release
```

#### Wallet

```sh
cd wallet
cargo build --release
```

#### Marketplace Frontend

```sh
cd marketplace/frontend
npm install
npm run build
```

#### Marketplace Backend (Planned)

```sh
cd marketplace/backend
cargo run --release
# or
python3 -m uvicorn app:app --reload
```

---

## What’s Finished

- **Wallet:**
  - BIP39 mnemonic/seed generation
  - Stealth address and key generation
  - Persistent wallet file with all key/address data
  - CLI for generate, show-seed, show-keys, balance, and node sync
  - Node sync and output scanning (demo logic)
  - All build errors fixed; robust CLI parsing

- **Node:**
  - CLI, data-dir, genesis block, block/tx validation
  - `/get_blocks?from_height=...` endpoint for wallet sync

- **Miner:**
  - CLI, RandomX PoW, buildable and runnable

- **Frontend:**
  - Next.js, dark web/Silk Road-inspired UI

---

## What’s Under Construction

- **Wallet:**
  - Real key-based output scanning (currently demo logic)
  - Outgoing transaction support (send coins)
  - Robust error handling and UX improvements
  - Wallet file encryption
  - Multiple account support
  - Hardware wallet integration (see `src/hardware.rs`)

- **Node:**
  - Full transaction scanning and validation
  - Advanced privacy features (ring signatures, Bulletproofs, etc.)

- **Marketplace Backend:**
  - Escrow logic, arbitration, IPFS integration

- **General:**
  - Production hardening, error handling, and security audits

---

## Marketplace & Node

- **Node:** Rust, CLI, data-dir, genesis block, block/tx validation, `/get_blocks` endpoint.
- **Miner:** Rust, RandomX, CLI.
- **Frontend:** Next.js, privacy-first, no trackers.
- **Backend:** Rust/Python (planned), Tor/I2P integration.

---

## Security & Privacy

- **Stealth Addresses:** All payments use unique, unlinkable addresses.
- **Ring Signatures:** (Planned) Hide sender among decoys.
- **Confidential Transactions:** (Planned) Hide amounts using Bulletproofs.
- **No Private Data Leaks:** All scanning is local; no keys or seeds sent to the node.
- **Hardware Wallets:** Scaffolded for future support.

---

## Contributing

Contributions are welcome! Please see `CONTRIBUTING.md` (to be written) for guidelines. All code must be reviewed and pass security checks. Privacy and security are top priorities.

---

## License

BlackSilk is open-source and released under the MIT License. See `LICENSE` for details.

---

## References & Inspiration

- Monero, Bitcoin, Zcash, Dero, Blockstream, IPFS, Tails OS, Silk Road, and the privacy/anonymity research community.
- See `/docs` for technical deep-dives and protocol details.

---

*This README is a living document and will be updated as the project evolves. For the latest details, see the `/docs` directory and the technical whitepaper.*

---

**Next Steps:**  
- Implement real output scanning and transaction sending in the wallet.
- Harden error handling and UX.
- Complete backend escrow and reputation logic.
- Integrate hardware wallet support.
