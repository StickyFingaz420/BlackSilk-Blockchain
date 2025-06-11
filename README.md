# BlackSilk-Blockchain

## Overview

BlackSilk-Blockchain is a comprehensive blockchain platform designed for building decentralized applications and facilitating secure, peer-to-peer transactions. It includes a full suite of tools for developers and users, including a blockchain node, a wallet, a block explorer, a decentralized marketplace, and robust monitoring tools. The platform emphasizes security, privacy through I2P integration, and developer-friendliness.

## Features

*   **Blockchain Core**: A secure and efficient blockchain implementation built in Rust, forming the backbone of the platform.
*   **Smart Contracts**: Support for custom smart contracts enabling a wide range of decentralized applications.
    *   **Escrow Contract**: Facilitates secure multi-party transactions.
    *   **Marketplace Contract**: Powers the decentralized marketplace functionalities.
*   **Wallet**: User-friendly wallet solutions for managing digital assets and interacting with the BlackSilk-Blockchain.
    *   **Web Wallet**: A Next.js based wallet accessible via a web browser.
    *   **CLI Wallet**: A command-line interface wallet for advanced users and automation.
*   **Block Explorer**: A Next.js based tool to browse and search the blockchain, view transactions, blocks, addresses, and other network data in real-time.
*   **Decentralized Marketplace**: A platform for users to list, discover, and trade goods and services directly, built on BlackSilk-Blockchain.
    *   **Frontend**: User interface for interacting with the marketplace.
    *   **Backend**: Rust-based backend logic for the marketplace.
*   **Miner**: Mining software to support the network, validate transactions, and create new blocks. Includes a `build_pure.rs` for specific build configurations.
*   **Monitoring**: Comprehensive tools for monitoring the health, performance, and status of the network and its components.
    *   **Prometheus**: For metrics collection.
    *   **Grafana**: For data visualization and dashboards.
    *   **Alertmanager**: For handling alerts.
    *   **Exporter**: Custom exporter for blockchain-specific metrics.
*   **I2P Integration**: Optional integration with the Invisible Internet Project (I2P) for enhanced privacy and anonymity of network communications.
*   **Testnet Faucet**: A Next.js based faucet for developers to obtain testnet tokens for building and testing applications on the BlackSilk test network.
*   **Configuration Management**: Dedicated configuration files for different components and network environments (mainnet, testnet).
    *   `miner_config.toml`
    *   `wallet_config.toml`
    *   Network-specific configurations (`bootnodes.txt`, `chain_spec.json`, `node_config.toml`)
*   **Containerization Support**: Dockerfiles and Docker Compose configurations for easy deployment and orchestration of all platform components.
    *   `marketplace.Dockerfile`
    *   `miner.Dockerfile`
    *   `node.Dockerfile`
    *   `wallet.Dockerfile`
    *   `docker-compose.yml` (main and for monitoring)
    *   `docker-compose.prod.yml` (for testnet faucet production)

## Project Structure

The project is organized into several key components, each in its own directory:

```
BlackSilk-Blockchain/
├── Cargo.lock               # Rust workspace lock file
├── Cargo.toml               # Rust workspace manifest
├── docker-compose.yml       # Main Docker Compose file for orchestrating services
├── README.md                # This file
├── blacksilklogos/          # Collection of logos and branding assets
├── block-explorer/          # Next.js based block explorer
│   ├── Cargo.toml           # (If any Rust components are part of it)
│   ├── next.config.js
│   ├── package.json
│   ├── src/
│   └── ...
├── config/                  # Configuration files
│   ├── miner_config.toml
│   ├── wallet_config.toml
│   ├── mainnet/
│   └── testnet/
├── docker/                  # Dockerfiles for various components
├── i2p/                     # I2P network integration components (Rust)
│   ├── Cargo.toml
│   └── src/
├── marketplace/             # Decentralized marketplace application
│   ├── Cargo.toml           # Backend (Rust)
│   ├── frontend/            # Frontend components (likely Next.js or similar)
│   └── src/                 # Backend source (Rust)
├── miner/                   # Blockchain miner software (Rust)
│   ├── Cargo.toml
│   ├── build_pure.rs
│   └── src/
├── monitoring/              # Monitoring stack
│   ├── docker-compose.yml
│   ├── prometheus.yml
│   ├── alertmanager/
│   ├── exporter/
│   ├── grafana/
│   └── rules/
├── node/                    # Core blockchain node implementation (Rust)
│   ├── Cargo.toml
│   └── src/
├── primitives/              # Core data structures and utilities for the blockchain (Rust)
│   ├── Cargo.toml
│   └── src/
├── smart-contracts/         # Smart contract implementations (Rust)
│   ├── Cargo.toml
│   ├── escrow_contract/
│   └── marketplace_contract/
├── src/                     # Main Rust application source (possibly a workspace orchestrator or shared lib)
│   └── main.rs
├── target/                  # Rust build artifacts
├── testnet-faucet/          # Testnet faucet application (Next.js and potentially a Rust backend)
│   ├── next.config.js
│   ├── package.json
│   ├── Dockerfile
│   ├── server/              # (If a separate Node.js backend for faucet)
│   └── src/                 # Frontend source
├── tests/                   # Integration and end-to-end tests
│   └── integration/
├── wallet/                  # CLI wallet application (Rust)
│   ├── Cargo.toml
│   └── src/
├── wallet_data/             # Default or example wallet data
│   └── miner-wallet.json
└── web-wallet/              # Web-based wallet application (Next.js)
    ├── next.config.js
    ├── package.json
    └── src/                 # (Assuming src contains pages, components etc.)
```

## Technologies Used

*   **Primary Backend Language**: Rust
    *   **Frameworks/Libraries**: (e.g., Actix, Tokio, Substrate - *further inspection of Cargo.toml files needed for specifics*)
*   **Frontend**:
    *   **Framework**: Next.js (React)
    *   **Language**: TypeScript
    *   **Styling**: Tailwind CSS
*   **Smart Contracts**: Rust (likely using a framework like `ink!` or a custom setup)
*   **Containerization**: Docker, Docker Compose
*   **Monitoring**: Prometheus, Grafana, Alertmanager
*   **Build Tools**:
    *   Rust: `cargo`
    *   Node.js: `npm` or `yarn` (deduced from `package.json`)
*   **Version Control**: Git

## Prerequisites

Before you begin, ensure you have the following installed:

*   **Rust**: Follow the official installation guide at [rust-lang.org](https://www.rust-lang.org/tools/install)
*   **Node.js and npm/yarn**: Download from [nodejs.org](https://nodejs.org/) (LTS version recommended).
*   **Docker and Docker Compose**: Install from [docker.com](https://www.docker.com/get-started).
*   **Git**: Install from [git-scm.com](https://git-scm.com/downloads).
*   **(Optional) I2P**: If you plan to use I2P integration, install an I2P router.

## Getting Started

### 1. Clone the Repository

```bash
git clone <repository-url> # Replace <repository-url> with the actual URL
cd BlackSilk-Blockchain
```

### 2. Backend Setup (Rust Components)

Most Rust components (node, miner, wallet, marketplace backend, etc.) are part of a Rust workspace.

```bash
# Build all Rust projects in the workspace
cargo build --release # Use --release for optimized builds

# To build a specific package, navigate to its directory or use -p flag
# e.g., for the node:
cd node
cargo build --release
cd ..
# or
cargo build --release -p blacksilk-node # Assuming 'blacksilk-node' is the package name in node/Cargo.toml
```
*Note: Specific package names need to be verified from individual `Cargo.toml` files.*

### 3. Frontend Setup (Next.js Applications)

For each Next.js application (block-explorer, web-wallet, testnet-faucet, marketplace frontend), navigate to its directory and install dependencies:

```bash
# Example for block-explorer
cd block-explorer
npm install # or yarn install
cd ..

# Repeat for web-wallet, testnet-faucet, and marketplace/frontend
```

### 4. Configuration

*   Copy and customize configuration files from `config/` as needed.
    *   `config/mainnet/` and `config/testnet/` contain network-specific chain specifications, bootnodes, and node configurations.
    *   `config/miner_config.toml` and `config/wallet_config.toml` for miner and wallet settings.
*   Set up environment variables if required by any component (check individual component READMEs if they exist, or source code).

## Running the Project

### Using Docker (Recommended for Full System)

The `docker-compose.yml` file is designed to orchestrate the entire BlackSilk ecosystem.

```bash
# Start all services defined in docker-compose.yml in detached mode
docker-compose up -d

# View logs for all services
docker-compose logs -f

# View logs for a specific service (e.g., node)
docker-compose logs -f node # Replace 'node' with the service name in docker-compose.yml

# Stop and remove containers, networks, and volumes
docker-compose down -v
```

The `monitoring/docker-compose.yml` can be used to start the monitoring stack separately if needed.
The `testnet-faucet/docker-compose.prod.yml` is for a production-like deployment of the faucet.

### Running Individual Components Manually

#### Blockchain Node

```bash
cd node
# Ensure config/mainnet/node_config.toml or config/testnet/node_config.toml is correctly set up
# The binary will likely be in target/release/
./target/release/blacksilk-node --config ../config/testnet/node_config.toml # Adjust path and arguments
```
*(Command and arguments are illustrative and need to be verified from the node's implementation)*

#### Miner

```bash
cd miner
# Ensure config/miner_config.toml is configured
./target/release/blacksilk-miner --config ../config/miner_config.toml # Adjust path and arguments
```
*(Command and arguments are illustrative)*

#### CLI Wallet

```bash
cd wallet
./target/release/blacksilk-wallet --config ../config/wallet_config.toml # Adjust path and arguments
```
*(Command and arguments are illustrative)*

#### Next.js Applications (Development Mode)

```bash
# Example for block-explorer
cd block-explorer
npm run dev # or yarn dev

# Example for web-wallet
cd web-wallet
npm run dev # or yarn dev

# Example for testnet-faucet
cd testnet-faucet
npm run dev # or yarn dev

# Example for marketplace frontend (assuming it's in marketplace/frontend)
cd marketplace/frontend
npm run dev # or yarn dev
```
These will typically start the applications on `http://localhost:3000` or another specified port.

## Building for Production

### Rust Components

```bash
cargo build --release
# Binaries will be in target/release/
```

### Next.js Applications

```bash
# Example for block-explorer
cd block-explorer
npm run build
npm run start # To serve the production build

# Repeat for other Next.js applications
```

## Running Tests

### Rust Tests

```bash
# Run all unit and integration tests for the Rust workspace
cargo test

# Run tests for a specific package
cd node
cargo test
cd ..
# or
cargo test -p blacksilk-node
```

### Frontend Tests (Next.js)

Most Next.js projects use Jest or a similar testing framework.

```bash
# Example for block-explorer (assuming test script is configured in package.json)
cd block-explorer
npm test # or yarn test

# Repeat for other Next.js applications
```
The `testnet-faucet` directory contains specific test scripts like `test-complete-system.sh`, `test-http.js`, `test-integration.ts`, `test-request.sh`. These should be investigated for their specific usage.

### End-to-End / Integration Tests

The `tests/integration` directory likely contains broader integration tests. The `tests/docker-compose.test.yml` suggests a Docker-based test environment.

```bash
# Potentially, to run Docker-based integration tests:
cd tests
docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit
# This is an assumption, actual command might differ.
```

## Roadmap

This roadmap outlines the current status and future development plans for the BlackSilk-Blockchain project.

---

### Phase 1: Core Infrastructure & Foundation (Completed & Operational)

*   **[✔] Blockchain Node Core (Rust)**: Initial stable version of the node, capable of P2P communication, block production (e.g., PoW/PoS - *specify consensus*), and transaction processing.
*   **[✔] Primitives (Rust)**: Core data structures (blocks, transactions, accounts) defined and implemented.
*   **[✔] Basic CLI Wallet (Rust)**: Wallet generation, balance checking, sending/receiving native currency.
*   **[✔] Initial Smart Contract Support (Rust)**: Framework for deploying and interacting with basic smart contracts.
    *   **[✔] Escrow Contract v1**: Basic secure escrow functionality.
*   **[✔] Configuration System**: `miner_config.toml`, `wallet_config.toml`, network configs (`chain_spec.json`, `bootnodes.txt`).
*   **[✔] Basic Dockerization**: Dockerfiles for node, miner, wallet.
*   **[✔] Initial Testnet**: Operational test network with bootnodes.
*   **[✔] `src/main.rs`**: Initial workspace runner or utility.

---

### Phase 2: Ecosystem Tools & Enhancements (Completed & Operational)

*   **[✔] Block Explorer v1 (Next.js, TypeScript)**: View blocks, transactions, addresses.
*   **[✔] Web Wallet v1 (Next.js, TypeScript)**: Basic wallet functionalities via a web interface.
*   **[✔] Testnet Faucet v1 (Next.js, TypeScript)**: Dispense testnet tokens.
    *   **[✔] Faucet Backend/Server**: Logic for managing and dispensing tokens.
*   **[✔] Miner Software v1 (Rust)**: Functional miner compatible with the chosen consensus mechanism.
    *   **[✔] `build_pure.rs`**: Specialized build process for miner.
*   **[✔] Marketplace Backend v1 (Rust)**: Core APIs for listing, buying, selling.
*   **[✔] Marketplace Smart Contract v1**: On-chain logic for marketplace operations.
*   **[✔] Basic Monitoring Stack**:
    *   **[✔] Prometheus & Grafana**: Basic dashboards for node health.
    *   **[✔] Exporter**: Initial version for node metrics.
*   **[✔] I2P Integration (Rust) - Alpha**: Basic capability for nodes to communicate over I2P.
*   **[✔] Comprehensive Docker Compose Setup**: `docker-compose.yml` for easy full-stack deployment.
*   **[✔] Unit & Basic Integration Tests**: For core components.
    *   **[✔] `tests/integration`**: Initial set of integration tests.
    *   **[✔] `testnet-faucet/test-*.{sh,js,ts}`**: Faucet specific tests.

---

### Phase 3: Advanced Features & Polish (In Development / To Be Completed)

*   **[🚧] Advanced Smart Contract Capabilities**:
    *   **[ ] Marketplace Contract v2**: More features (e.g., disputes, reviews, auctions).
    *   **[ ] Escrow Contract v2**: Enhanced features, multi-sig options.
    *   **[ ] Support for additional smart contract standards/interfaces.**
*   **[🚧] Marketplace Frontend (Next.js, TypeScript)**: Fully functional user interface for the decentralized marketplace.
*   **[🚧] Enhanced Block Explorer**:
    *   **[ ] Smart contract interaction UI.**
    *   **[ ] Richer analytics and charts.**
    *   **[ ] Token support display.**
*   **[🚧] Enhanced Web Wallet**:
    *   **[ ] Smart contract interaction support.**
    *   **[ ] Token management.**
    *   **[ ] DApp browser/connector.**
*   **[🚧] I2P Integration - Beta/Stable**: Robust and reliable I2P networking for all relevant components (node, wallet).
*   **[🚧] Advanced Monitoring & Alerting**:
    *   **[ ] Comprehensive Grafana dashboards for all services.**
    *   **[ ] Fine-tuned Prometheus rules and Alertmanager configuration.**
*   **[🚧] Performance Optimization**: For node, miner, and smart contract execution.
*   **[🚧] Security Audits**:
    *   **[ ] Core blockchain and cryptography.**
    *   **[ ] Smart contracts (escrow, marketplace).**
*   **[🚧] Governance Mechanism**: On-chain or off-chain governance model design and implementation.
*   **[🚧] Enhanced Developer Tooling**: SDKs, improved documentation for smart contract development.
*   **[🚧] Cross-Chain Interoperability Research/PoC**: Exploring bridges to other blockchains.
*   **[ ] Mobile Wallet (Concept/Design Phase)**

---

### Phase 4: Mainnet Launch & Growth (Future Work)

*   **[ ] Mainnet Launch Readiness**:
    *   **[ ] Final security audits and penetration testing.**
    *   **[ ] Extensive stress testing and performance benchmarking.**
    *   **[ ] Finalized `mainnet/chain_spec.json` and `bootnodes.txt`.**
    *   **[ ] Community bug bounty program.**
*   **[ ] Mainnet Deployment & Monitoring**.
*   **[ ] Ecosystem Growth Initiatives**: Developer grants, community building.
*   **[ ] Ongoing Maintenance & Upgrades**.
*   **[ ] Decentralized File Storage Integration (Research)**.

---

**Legend:**
*   `[✔]` - Completed and Operational
*   `[🚧]` - In Development / Partially Completed
*   `[ ]` - To Be Done / Planned

## Contributing

Contributions are welcome! Please follow these steps:

1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/your-feature-name`).
3.  Make your changes.
4.  Write tests for your changes.
5.  Ensure all tests pass (`cargo test`, `npm test` in relevant frontend directories).
6.  Commit your changes (`git commit -m 'Add some feature'`).
7.  Push to the branch (`git push origin feature/your-feature-name`).
8.  Open a Pull Request.

Please ensure your code adheres to the project's coding standards and includes appropriate documentation.

## License

This project is licensed under the [Specify License, e.g., MIT License, Apache 2.0] - see the LICENSE file for details.
*(A LICENSE file needs to be created if one doesn't exist)*

---

*This README provides a comprehensive overview. Specific details for each component (e.g., API endpoints for the marketplace, specific build instructions for `miner/build_pure.rs`, detailed consensus mechanism) would typically reside in the READMEs of those sub-directories or further documentation.*
