![BlackSilk Blockchain](https://i.imgur.com/cJxsqG0.png)

# BlackSilk Blockchain

**A privacy-first blockchain and decentralized marketplace project**

---

## Project Overview

BlackSilk is a fully private blockchain with an integrated decentralized marketplace, inspired by Monero and Silk Road. It leverages advanced cryptography and anonymous networking (Tor/I2P) to ensure privacy, security, and censorship resistance for all users.

---

## Project Status

### 1. Completed Features ✅

1. **Core Node**
   - Proof-of-Work blockchain (RandomX) with mempool, P2P, block and transaction management.
   - Network configuration support (Tor/I2P, TLS, PFS).
   - Tokenomics (block reward, halving, tail emission).
   - Escrow event logging.

2. **Privacy & Cryptography**
   - Ring signatures and stealth addresses.
   - Bulletproofs for confidential transactions.
   - Encrypted communications (TLS/PFS).
   - Tor/I2P integration at the network layer.

3. **Wallet**
   - Key generation (Ed25519/Curve25519).
   - Stealth address generation.
   - Transaction signing and ring signature creation.
   - Bulletproofs support.
   - Basic CLI interface.

4. **Marketplace**
   - Modern dark-themed Next.js frontend.
   - Listings, orders, and escrow management.
   - Image uploads to IPFS.
   - Wallet integration (login via signature).
   - Rust/Axum backend APIs with PostgreSQL.
   - API protection via wallet signature.
   - Search, filtering, and order/sales management.

5. **Smart Escrow**
   - 2-of-3 multisig logic (buyer/seller/arbiter).
   - Escrow states (created, funded, completed, disputed, refunded).
   - Event logging for every escrow action.

6. **Documentation**
   - Detailed architecture docs (docs/architecture.md).
   - Tokenomics and emission tables.
   - Build and run instructions.
   - OpenAPI files for the API.

---

### 2. Missing / In Progress Features ❌

1. **Advanced Privacy**
   - zk-SNARKs or advanced ZKPs support.
   - Full hardware wallet support (Ledger/Trezor).
   - Full confidential amounts in all transaction paths.

2. **Marketplace**
   - On-chain reputation system.
   - Decentralized arbitration (DAO or voting).
   - Full Tor/I2P-only operation (some flows are experimental).
   - Advanced IPFS support (auto-distribution and retrieval of images/files).
   - Zero-trace operation (no persistent logs).
   - Full security headers (CSP, HSTS, etc.) in all flows.

3. **Smart Contracts**
   - More advanced contracts (time-locked, DAO).
   - Full escrow operations via the UI (some flows are manual or experimental).

4. **Documentation**
   - Final whitepaper.
   - End-user guides for marketplace and wallet.
   - Complete API documentation (some endpoints only).

---

## Architecture

- **Core Node:** Blockchain state, mining, P2P, privacy protocols.
- **Wallet:** Key generation, signing, CLI, Bulletproofs support.
- **Marketplace:** Next.js frontend, IPFS uploads, signature protection, listings/orders management.
- **Escrow:** Multisig logic, escrow states, event logging.
- **Network:** Tor/I2P, TLS, PFS.

---

## Tokenomics

| Parameter         | Value                        |
|------------------|------------------------------|
| Block Time       | 120 seconds (2 minutes)      |
| Initial Reward   | 86 BLK per block             |
| Halving Interval | Every 125,000 blocks         |
| Halving Amount   | 50%                          |
| Supply Cap       | 21,000,000 BLK               |
| Tail Emission    | 0.5 BLK per block after cap  |

---

## Quick Start

### Prerequisites
- Rust 1.70+
- Node.js 18+
- PostgreSQL
- Tor/I2P (optional)

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

## Documentation & Resources

- [Whitepaper](docs/whitepaper.md) (in progress)
- [Architecture](docs/architecture.md)
- [API Docs](docs/api/README.md)
- [Build Guide](docs/build.md)
- [Marketplace Guide](docs/marketplace.md)

---

## Additional Notes

- All connections default to Tor/I2P.
- No analytics or external tracking included.
- All private keys are encrypted on disk.
- All listing images are uploaded to IPFS.
- All escrow actions are logged for security and transparency.

---

## Naming & Inspiration

- Default P2P port 1776 (year of American independence).
- Max block size 1984KB (reference to Orwell's 1984).
- Function and symbol names inspired by freedom and resistance.

---

## License

MIT License

---

## Project Status

- The project is in an advanced MVP stage, with full blockchain, wallet, and basic marketplace support.
- Some privacy, arbitration, and reputation features are under development.
