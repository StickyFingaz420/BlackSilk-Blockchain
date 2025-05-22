![BlackSilk Blockchain](https://i.imgur.com/cJxsqG0.png)

# BlackSilk Blockchain

**A privacy-first blockchain and decentralized marketplace.**

---

## Project Overview
BlackSilk is a next-generation, privacy-first blockchain and decentralized marketplace inspired by Monero and Silk Road. It leverages advanced cryptography (ring signatures, Bulletproofs, zk-SNARKs), anonymous networking (Tor/I2P), and decentralized arbitration to ensure privacy, security, and censorship resistance for all users.

---

## Architecture
- **Core Node:** Blockchain state, mining (RandomX), P2P, privacy protocols, Tor/I2P, TLS, PFS.
- **Wallet:** Key generation (Ed25519/Curve25519), stealth addresses, ring signatures, Bulletproofs, hardware wallet support, CLI.
- **Marketplace:** Next.js frontend, IPFS uploads, signature-protected APIs, listings/orders, on-chain reputation, DAO-based arbitration.
- **Escrow:** 2-of-3 multisig, event logging, dispute voting.
- **Network:** Tor/I2P enforced, TLS, PFS, zero-trace operation.

---

## Features
- **Privacy & Cryptography:**
  - Ring signatures, stealth addresses, confidential transactions (Bulletproofs), zk-SNARKs.
  - Encrypted P2P and API communications (TLS/PFS).
  - Tor/I2P-only networking (no clearnet leaks).
- **Marketplace:**
  - Listings, orders, and escrow management.
  - Image/file uploads to IPFS (auto-distribution and retrieval).
  - On-chain reputation system and DAO-based dispute voting.
  - Modern Next.js frontend, wallet login via signature.
- **Escrow & Arbitration:**
  - 2-of-3 multisig escrow (buyer/seller/arbiter).
  - Dispute voting and decentralized arbitration.
- **Zero-Trace & Security:**
  - No persistent logs or analytics.
  - Strict security headers (CSP, HSTS, etc.) on all HTTP(S) responses.
  - All private keys encrypted on disk.
- **Hardware Wallet Support:**
  - Ledger/Trezor integration (scaffolded, extendable).

---

## Quick Start

### Prerequisites
- Rust 1.70+
- Node.js 18+
- PostgreSQL
- Tor/I2P (optional, but recommended)

### Build & Run
```powershell
# Clone the project
git clone https://github.com/yourusername/blacksilk.git
cd blacksilk

# Build the core node
cargo build --release

# Build the wallet
cd wallet
cargo build --release

# Run the node
./target/release/blacksilk-node

# Generate a wallet
./target/release/blacksilk-wallet generate
```

### Run the Marketplace
```powershell
# Frontend
cd marketplace/frontend
npm install
npm run dev

# Backend
cd ../backend
cargo run
```

---

## API & Documentation
- [Architecture](docs/architecture.md)
- [Advanced Features](docs/advanced_features.md)
- [API Reference (OpenAPI)](docs/api/openapi.yaml)
- [Marketplace Guide](docs/marketplace.md)
- [Build Guide](docs/build.md)

---

## Security & Privacy
- All connections default to Tor/I2P.
- No analytics or external tracking.
- All private keys are encrypted on disk.
- All listing images/files are uploaded to IPFS.
- All escrow actions are logged for transparency.
- Zero-trace mode: no persistent logs or sensitive data on disk.
- Strict security headers (CSP, HSTS, etc.) enforced everywhere.

---

## Naming & Inspiration
- Default P2P port 1776 (year of American independence).
- Max block size 1984KB (Orwell's 1984).
- Function and symbol names inspired by freedom and resistance.

---

## License
MIT License

---

## Project Status
- Advanced MVP: full blockchain, wallet, and marketplace support.
- All advanced privacy, arbitration, and reputation features implemented and tested.
- See [docs/advanced_features.md](docs/advanced_features.md) for details.

_Last updated: 2025-05-22_
