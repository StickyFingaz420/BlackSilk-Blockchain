# BlackSilk Blockchain

BlackSilk is a privacy-focused cryptocurrency utilizing a CPU-only Proof-of-Work (PoW) algorithm based on RandomX. This project aims to provide a secure, decentralized, and ASIC-resistant digital currency.

## Project Structure and Components

BlackSilk is a blockchain project built from the ground up with a strong emphasis on privacy, security, and decentralization. The workspace is organized as follows:

*   **`node`**: The core blockchain node.
    *   **Description:** The backbone of the BlackSilk network. It handles block creation, transaction validation, peer-to-peer communication, and consensus. It features a full RandomX verifier to ensure CPU-only mining.
    *   **Key Dependencies:** `clap` (CLI), `primitives`, `sha2`, `serde`, `ed25519-dalek`, `curve25519-dalek`, `tokio` (async runtime), `tor_client`, `i2p`, `rustls`, `aes`, `argon2`, `blake2`, `rayon`.
    *   **Build:** `cargo build --release --package node`
    *   **Run:** `.\target\release\blacksilk-node.exe` (further arguments may be required)
*   **`wallet`**: Command-line and potentially future GUI wallet.
    *   **Description:** Enables users to manage their BlackSilk (BLK) coins, create transactions, and interact with the blockchain. Includes planned support for hardware wallets.
    *   **Key Dependencies:** `node` (for network interaction), `primitives`, `ed25519-dalek`, `curve25519-dalek`, `bulletproofs`, `merlin` (for ZKPs), `clap` (CLI), `bip39`, `reqwest`.
    *   **Build:** `cargo build --release --package wallet`
    *   **Run:** `.\target\release\wallet.exe` (further arguments may be required)
*   **`miner`**: Standalone CPU miner.
    *   **Description:** A standalone CPU miner for BlackSilk, implemented in pure Rust for cross-platform compatibility and performance. It utilizes a professional-grade RandomX implementation.
    *   **Key Dependencies:** `clap` (CLI), `tokio`, `reqwest` (for connecting to node/pool), `serde`, `hex`, `num_cpus`, `rayon`, `sha2`, `aes`, `argon2`, `blake2`.
    *   **Build:** `cargo build --release --package blacksilk-miner`
    *   **Run:** `.\target\release\blacksilk-miner.exe` (further arguments for node address, threads, etc. will be required)
*   **`primitives`**: Core data structures and cryptographic functions.
    *   **Description:** Contains the core data structures and cryptographic functions used throughout the BlackSilk ecosystem, including block and transaction structures, ring signatures, and zero-knowledge proofs (ZKPs).
    *   **Key Dependencies:** `sha2`, `ed25519-dalek`, `curve25519-dalek`, `serde`, `ark-bls12-381`, `ark-groth16` (for ZKPs).
    *   **Build:** This is a library crate, built as a dependency of other components.
*   **`blacksilk-ui`**: Original Next.js based web interface.
    *   **Description:** A web interface for interacting with the BlackSilk network.
    *   **Key Dependencies:** `next`, `react`, `react-dom`.
    *   **Install:** `cd blacksilk-ui && npm install`
    *   **Run (Dev):** `cd blacksilk-ui && npm run dev`
    *   **Build:** `cd blacksilk-ui && npm run build`
*   **`blacksilk-ui-new`**: Newer Next.js based web interface.
    *   **Description:** An updated web interface, potentially with new features or a revised architecture.
    *   **Key Dependencies:** `next`, `react`, `react-dom`, `ipfs-http-client`, `web3`.
    *   **Install:** `cd blacksilk-ui-new && npm install`
    *   **Run (Dev):** `cd blacksilk-ui-new && npm run dev` (uses Turbopack)
    *   **Build:** `cd blacksilk-ui-new && npm run build`
*   **`blacksilk-ui-new/blacksilk-marketplace`**: A dedicated marketplace UI within the `blacksilk-ui-new` structure.
    *   **Description:** A Next.js application focused on marketplace functionalities on the BlackSilk blockchain.
    *   **Key Dependencies:** `next`, `react`, `react-dom`, `ipfs-http-client`, `web3`.
    *   **Install:** `cd blacksilk-ui-new/blacksilk-marketplace && npm install`
    *   **Run (Dev):** `cd blacksilk-ui-new/blacksilk-marketplace && npm run dev`
    *   **Build:** `cd blacksilk-ui-new/blacksilk-marketplace && npm run build`
*   **`Cargo.toml` (Root):** Workspace definition for the Rust projects.
*   **`benchmark_mining.rs`:** A Rust script for benchmarking mining performance.

## Key Features

*   **Proof-of-Work Algorithm:** RandomX (CPU-only, ASIC-resistant)
*   **Privacy:**
    *   Ring Signatures: Provide sender anonymity.
    *   Stealth Addresses: Ensure recipient privacy.
    *   Zero-Knowledge Proofs (ZKPs): For confidential transactions (planned/under development).
*   **Consensus:** Nakamoto consensus with RandomX PoW.
*   **Block Time:** 120 seconds (2 minutes).
*   **Block Reward:** Initial reward of 5 BLK.
*   **Halving:** Occurs every 1,051,200 blocks (approximately every 4 years).
*   **Total Supply Cap:** 21,000,000 BLK.
*   **Emission:** No premine or ICO. All coins are distributed through mining. No tail emission after the supply cap is reached; miners will then rely solely on transaction fees.
*   **Difficulty Adjustment:** Adjusts every 60 blocks (approximately every 2 hours).
*   **Technology Stack:** Primarily Rust for the backend (node, miner, wallet, primitives) and TypeScript/Next.js with Tailwind CSS for the frontend UIs.

## Technical Details

### RandomX Implementation

BlackSilk utilizes a pure Rust implementation of the RandomX proof-of-work algorithm. This ensures:

*   **CPU-Only Mining:** Designed to be resistant to ASICs and FPGAs, promoting decentralization by allowing anyone with a modern CPU to participate in mining.
*   **Memory-Hard:** Requires significant memory (approx. 2.08 GiB per NUMA node for the dataset) to execute, further deterring specialized hardware.
*   **Security:** The implementation adheres to the RandomX specification, including:
    *   Argon2d for cache generation (2MB).
    *   Blake2b for scratchpad initialization.
    *   SuperscalarHash for dataset expansion (2.08 GB).
    *   A full RandomX Virtual Machine (VM) supporting integer, floating-point, and simulated SIMD operations.
    *   CPU timing enforcement and memory access pattern verification to detect and penalize non-CPU miners.

### Blockchain Primitives

*   **Block Structure:** Includes header (version, previous hash, Merkle root, timestamp, height, difficulty, PoW) and body (coinbase transaction, list of transactions).
*   **Transactions:** Details to be further specified, but will support private and potentially confidential transactions.
*   **Escrow:** Functionality for escrow services is present in the `primitives` and `node` components.

## Getting Started

### Prerequisites:

*   **Rust:** Install from [rust-lang.org](https://www.rust-lang.org/tools/install).
*   **Node.js:** Install from [nodejs.org](https://nodejs.org/) (for UI components).
*   **PowerShell (Windows):** Ensure you are using PowerShell for the commands below.

### Building and Running Components:

Refer to the "Project Structure and Components" section above for specific build and run commands for each part of the BlackSilk project.

**General Build Process for Rust Components:**

From the root of the `BlackSilk-Blockchain` directory:
```powershell
cargo build --release
```
This will build all Rust binaries (node, wallet, miner) into the `.\target\release\` directory.

**General Process for UI Components:**

Navigate to the specific UI directory (e.g., `cd blacksilk-ui`) and then:
```powershell
# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build
```

## Tokenomics & Distribution

*   **Token Name/Ticker:** BLK (BlackSilk)
*   **Total Supply Cap:** 21,000,000 BLK
*   **Distribution Method:** All coins are mined. There is **no premine** and **no ICO** (Initial Coin Offering).
*   **Initial Block Reward:** 5 BLK (specifically, `5_000_000` atomic units as per `node/src/lib.rs`, assuming 1 BLK = 1,000,000 atomic units).
*   **Halving:** The block reward halves every 1,051,200 blocks. With a block time of 120 seconds (2 minutes), this is approximately every 4 years.
*   **Tail Emission:** There is **no tail emission**. After the total supply cap is reached, miners will only receive transaction fees.
*   **Block Time:** 120 seconds (2 minutes), as defined by `BLOCK_TIME_SEC` in `node/src/lib.rs`.
*   **Difficulty Adjustment:** Adjusts every 60 blocks (approximately every 2 hours), as per `DIFFICULTY_ADJUSTMENT_INTERVAL` in `node/src/lib.rs`.

## Roadmap

### Completed and Ready for Use:

*   **Core Blockchain Logic (Rust):**
    *   Basic block and transaction structures (`primitives`).
    *   RandomX PoW implementation (`miner/src/randomx_pro.rs`, `node/src/randomx/`).
    *   CPU-only RandomX verifier with timing and memory enforcement (`node/src/randomx_verifier.rs`).
    *   Node functionality for block propagation and basic consensus (`node`).
    *   Standalone CPU miner (`miner`).
    *   Basic wallet functionalities (CLI) (`wallet`).
    *   Initial tokenomics defined (block time, reward, halving, supply cap) (`node/src/lib.rs`).
*   **Initial UI Development:**
    *   Scaffolding for Next.js based UIs (`blacksilk-ui`, `blacksilk-ui-new`).

### Under Development / Needs Further Development:

*   **Advanced Privacy Features:**
    *   **Zero-Knowledge Proofs (ZKPs):** Implementation for fully confidential transactions. The `primitives/src/zkp.rs` file exists but likely needs significant development.
    *   **Ring Signatures:** While `primitives/src/ring_sig.rs` exists, integration and robust implementation across transactions need completion.
    *   Stealth Addresses: Full implementation and integration.
*   **Network Robustness and Scalability:**
    *   Advanced peer-to-peer networking features (e.g., improved peer discovery, NAT traversal, DoS protection). `node/src/network/privacy.rs` suggests work in this area.
    *   Scalability solutions (if needed in the future, e.g., Layer 2 solutions, sharding - currently not a primary focus).
*   **Smart Contracts / Programmability:**
    *   Currently, there is no clear indication of smart contract capabilities. This would be a major feature addition if desired.
*   **User Interfaces (UI):**
    *   `blacksilk-ui`, `blacksilk-ui-new`, and `blacksilk-ui-new/blacksilk-marketplace` are Next.js projects. They require significant development to become fully functional user-facing applications for wallet management, block exploration, marketplace interaction, etc.
    *   API client (`blacksilk-ui/src/utils/apiClient.ts`, `blacksilk-ui-new/src/utils/apiClient.ts`) needs to be fully integrated with the backend node.
    *   The OpenAPI specification (`openapi.yaml`) in UI folders suggests API-driven development, which needs to be completed.
*   **Escrow System:**
    *   `escrow.rs` files exist in `node` and `primitives`. This feature needs to be fully implemented, tested, and integrated.
*   **Wallet Enhancements:**
    *   GUI Wallet: Development of a user-friendly graphical wallet.
    *   Hardware Wallet Integration: `wallet/src/hardware.rs` indicates intent, but full support and testing are needed.
    *   Mobile Wallets.
*   **Mining Ecosystem:**
    *   Mining pool software (if not relying on existing generic RandomX pool software).
    *   Improved miner efficiency and features.
*   **Documentation and Testing:**
    *   Comprehensive developer documentation for all components.
    *   Extensive unit, integration, and end-to-end tests. `wallet/src/tests/privacy_commands.rs` shows some testing.
    *   Security audits.
*   **Governance Model:**
    *   Definition and implementation of a governance mechanism for future protocol upgrades.
*   **Benchmarking and Optimization:**
    *   `benchmark_mining.rs` exists, suggesting performance testing. Continuous benchmarking and optimization of node and miner performance.

## Contributing

(Standard contribution guidelines would go here: e.g., fork the repo, create a branch, submit a pull request, follow coding standards, add tests.)

## License

(Specify the project's license, e.g., MIT, GPLv3. This is not currently defined in the provided files.)

---
