# BlackSilk-Blockchain

## Overview

BlackSilk-Blockchain is a next-generation, fully node-driven blockchain platform for decentralized applications, digital asset tokenization, and secure peer-to-peer commerce. All features are powered by on-chain data—no hardcoded or placeholder logic—ensuring transparency, auditability, and trust. The platform includes:
- A Rust-based blockchain node with advanced consensus and privacy.
- Smart contracts for escrow, marketplace, auctions, reviews, and multi-sig.
- Tokenization (fungible, NFT, and standards-compliant assets).
- Developer-friendly APIs, monitoring, and cross-chain capabilities.
- A decentralized marketplace with live, node-driven data.
- Full privacy stack (I2P), robust monitoring, and mainnet readiness.

---

## Features

### Blockchain Core
- **Rust Node**: Secure, performant, modular. Supports P2P, block production, and transaction processing.
- **Consensus**: Pluggable (PoW/PoS hybrid, see Tokenomics).
- **Privacy**: I2P integration for anonymous networking.
- **Monitoring**: Prometheus, Grafana, custom exporter, and alerting.

### Smart Contracts
- **Escrow Contract**: Multi-party, multi-sig, standards-compliant. Supports dispute resolution and trait-based interfaces (`MultiSigEscrow`).
- **Marketplace Contract**: On-chain product listings, auctions, reviews, and bidding. Implements `Reviewable`, `Auctionable` traits.
- **Tokenization**: Native support for fungible tokens (FT), NFTs, and custom asset standards (ERC20/721/1155-like, see Tokenomics).
- **Trait-based Interfaces**: Extensible contract traits for composability and future standards.

### Decentralized Marketplace
- **Frontend**: Next.js/TypeScript, live data from blockchain node (no mock data).
- **Backend**: Rust, exposes all product/order data as on-chain transaction metadata.
- **Features**: List, buy, sell, bid, review, dispute, and manage orders—all on-chain.
- **User Dashboard**: Real-time order, product, and review management.

### Wallets
- **Web Wallet**: Next.js, supports native and token assets, contract interactions, and DApp connections.
- **CLI Wallet**: Rust, for advanced users and automation.

### Block Explorer
- **Next.js**: Real-time blockchain data, contract and token analytics, address/transaction search, and smart contract UI.

### Tokenomics & Asset Support
- **Fungible Tokens**: Native and user-defined, with supply, emission, and standards.
- **NFTs**: On-chain, standard-compliant, with metadata and marketplace integration.
- **Consensus**: Hybrid PoW/PoS (configurable), with emission schedule and staking.
- **Governance Token**: (Planned) for on-chain voting and protocol upgrades.

### Developer Tooling
- **APIs**: REST/GraphQL endpoints for node, contracts, and marketplace.
- **SDKs**: (Planned) for Rust, TypeScript, and cross-chain integration.
- **Documentation**: Full API and contract interface docs.

### Cross-Chain & Interoperability
- **Bridges**: (Planned) for asset and data transfer to/from other blockchains.
- **Standards**: ERC20/721/1155-like, plus custom traits for future-proofing.

### Monitoring & Operations
- **Prometheus/Grafana**: Node, contract, and marketplace metrics.
- **Alertmanager**: Custom rules for uptime, performance, and security.
- **Dockerized**: Full stack deployable via Docker Compose.

### Privacy & Security
- **I2P**: Optional, for all node and wallet communications.
- **Multi-Sig**: Escrow and contract-level multi-signature support.
- **Audits**: (Ongoing) for core, contracts, and cryptography.

---

## Tokenomics

- **Native Token**: $BSK (BlackSilk Token)
- **Total Supply**: 100,000,000 BSK (configurable at genesis)
- **Emission**: Block rewards (PoW/PoS), staking, and governance incentives
- **Consensus**: Hybrid PoW/PoS (configurable, see `chain_spec.json`)
- **Token Standards**: Native FT, NFT, and custom asset standards (ERC20/721/1155-like)
- **Staking**: PoS validators earn rewards, participate in governance
- **Governance**: (Planned) On-chain voting, protocol upgrades, and treasury
- **Marketplace Fees**: Paid in BSK, distributed to validators and treasury
- **Cross-Chain**: (Planned) Asset bridges and wrapped tokens

---

## System Architecture

```
[User/Wallet/Marketplace Frontend]
        |
   [API Layer: REST/GraphQL]
        |
[Blockchain Node (Rust)]
   |        |         |
[Smart Contracts] [Monitoring] [I2P]
   |        |         |
[Escrow] [Marketplace] [Tokenization]
```
- **Node**: Handles consensus, networking, and contract execution
- **Smart Contracts**: Escrow, marketplace, tokenization, auctions, reviews
- **API**: Exposes all on-chain data to frontend and external apps
- **Monitoring**: Prometheus, Grafana, custom exporter
- **Privacy**: I2P for all communications

---

## API & Smart Contract Interfaces

### Marketplace API (Node-Driven, TypeScript)
- `getProducts()`: Fetch all products (on-chain)
- `getProductById(id)`: Fetch product details (on-chain)
- `createProduct(data)`: List new product (on-chain tx)
- `placeBid(productId, amount)`: Place auction bid (on-chain)
- `submitReview(productId, review)`: Submit review (on-chain)
- `getOrders(userId)`: Fetch user orders (on-chain)
- `createOrder(productId, buyer)`: Place order (on-chain)
- All endpoints interact with the blockchain node, no mock data

### Smart Contract Traits
- `Reviewable`: Add/fetch on-chain reviews
- `Auctionable`: Auction logic, bidding, settlement
- `MultiSigEscrow`: Multi-party escrow, dispute resolution
- `TokenStandard`: FT/NFT minting, transfer, and metadata

---

## Roadmap (as of June 2025)

### Phase 1: Core Infrastructure (✔ Complete)
- Blockchain node, wallet, explorer, basic contracts, testnet, Dockerization

### Phase 2: Ecosystem Tools (✔ Complete)
- Block explorer, web wallet, testnet faucet, miner, marketplace v1, monitoring, I2P alpha

### Phase 3: Advanced Features (🚧 In Progress)
- Marketplace v2: On-chain reviews, auctions, bidding, trait-based contracts (✔ Complete)
- Escrow v2: Multi-sig, standards, trait-based (✔ Complete)
- Tokenization: FT/NFT, standards, marketplace integration (✔ Complete)
- Marketplace frontend: Fully node-driven, no mock data (✔ Complete)
- Enhanced explorer/wallet: Token, contract, and analytics support (🚧)
- I2P beta/stable, advanced monitoring, security audits, governance, cross-chain, SDKs (🚧)

### Phase 4: Mainnet & Growth (Planned)
- Mainnet launch, audits, stress tests, bug bounties, ecosystem growth, file storage, ongoing upgrades

---

## Getting Started

### Prerequisites
- Rust (https://www.rust-lang.org/tools/install)
- Node.js & npm (https://nodejs.org/)
- Docker & Docker Compose (https://www.docker.com/get-started)
- Git (https://git-scm.com/downloads)
- (Optional) I2P router

### Clone & Build
```powershell
git clone <repository-url>
cd BlackSilk-Blockchain
cargo build --release
```

### Frontend Setup
```powershell
cd block-explorer; npm install; cd ..
cd web-wallet; npm install; cd ..
cd testnet-faucet; npm install; cd ..
cd marketplace/frontend; npm install; cd ../..
```

### Run with Docker (Recommended)
```powershell
docker-compose up -d
```

### Manual Run (Example)
```powershell
cd node; .\target\release\blacksilk-node --config ..\config\testnet\node_config.toml
cd miner; .\target\release\blacksilk-miner --config ..\config\miner_config.toml
cd wallet; .\target\release\blacksilk-wallet --config ..\config\wallet_config.toml
```

### Next.js Apps (Dev Mode)
```powershell
cd block-explorer; npm run dev
cd web-wallet; npm run dev
cd testnet-faucet; npm run dev
cd marketplace/frontend; npm run dev
```

---

## Testing
- Rust: `cargo test` (all or per-package)
- Frontend: `npm test` (per-app)
- Integration: `cd tests; docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit`

---

## Contributing
1. Fork, branch, code, test, and PR. See CONTRIBUTING.md (if present).
2. Ensure all code is node-driven, on-chain, and standards-compliant.

## License
Specify License (e.g., MIT/Apache 2.0) in LICENSE file.

---

*For detailed API, contract, and architecture docs, see `/docs` or subproject READMEs. All features are node-driven and on-chain—no mock data or placeholders. For questions, open an issue or join the community.*
