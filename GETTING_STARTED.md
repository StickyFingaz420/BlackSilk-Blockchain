# Getting Started with BlackSilk Blockchain

This guide will walk you through setting up and running BlackSilk Blockchain components, from running a node to mining, using the wallet, and deploying the marketplace.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Running a Node](#running-a-node)
4. [Mining](#mining)
5. [Using the Wallet](#using-the-wallet)
6. [Marketplace Setup](#marketplace-setup)
7. [Testnet Faucet](#testnet-faucet)
8. [Block Explorer](#block-explorer)
9. [Troubleshooting](#troubleshooting)

## Prerequisites

Before you begin, ensure you have the following installed:

### Required Software

- **Rust 1.70+** with Cargo
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  source ~/.cargo/env
  ```

- **Node.js 18+** and npm (for marketplace frontend)
  ```bash
  # Using Node Version Manager (recommended)
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
  nvm install 18
  nvm use 18
  ```

- **Git** for version control
  ```bash
  # Ubuntu/Debian
  sudo apt update && sudo apt install git
  
  # macOS
  brew install git
  ```

- **PostgreSQL** (for marketplace backend)
  ```bash
  # Ubuntu/Debian
  sudo apt install postgresql postgresql-contrib
  
  # macOS
  brew install postgresql
  ```

- **IPFS** (optional, for marketplace file storage)
  ```bash
  # Download from https://ipfs.io/docs/install/
  # Or use Docker: docker run -d -p 5001:5001 -p 8080:8080 ipfs/go-ipfs
  ```

### System Requirements

- **CPU**: Multi-core processor (RandomX mining is CPU-intensive)
- **Memory**: 4GB+ RAM (8GB+ recommended for mining)
- **Storage**: 10GB+ free space for blockchain data
- **Network**: Stable internet connection with open ports

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/BlackSilkCoin/BlackSilk-Blockchain.git
cd BlackSilk-Blockchain
```

### 2. Initialize Submodules

```bash
git submodule update --init --recursive
```

### 3. Build All Components

```bash
# Build all Rust components
cargo build --release

# This will build:
# - blacksilk-node (main blockchain node)
# - blacksilk-miner (CPU miner)
# - blacksilk-wallet (CLI wallet)
# - blacksilk-marketplace (marketplace backend)
```

### 4. Verify Installation

```bash
# Check that binaries were created
ls -la target/release/

# You should see:
# blacksilk-node
# blacksilk-miner
# blacksilk-wallet
# blacksilk-marketplace
```

## Running a Node

### 1. Prepare Configuration

```bash
# Create data directories
mkdir -p ~/.blacksilk/data/testnet
mkdir -p ~/.blacksilk/logs

# Copy configuration files
cp config/testnet/node_config.toml ~/.blacksilk/
cp config/testnet/chain_spec.json ~/.blacksilk/
```

### 2. Start Testnet Node

```bash
# Start node with default configuration
./target/release/blacksilk-node --network testnet --config ~/.blacksilk/node_config.toml

# Or with custom parameters
./target/release/blacksilk-node \
  --network testnet \
  --p2p-port 19334 \
  --rpc-port 19333 \
  --data-dir ~/.blacksilk/data/testnet
```

### 3. Verify Node is Running

```bash
# Check node status via RPC
curl http://127.0.0.1:19333/status

# Check logs
tail -f ~/.blacksilk/logs/node.log
```

### Expected Output

```json
{
  "status": "syncing",
  "best_block": 1234,
  "peer_count": 3,
  "network": "testnet",
  "version": "1.0.0-testnet"
}
```

## Mining

### 1. Configure Miner

```bash
# Copy miner configuration
cp config/miner_config.toml ~/.blacksilk/

# Edit configuration (set your reward address)
nano ~/.blacksilk/miner_config.toml
```

### 2. Generate Mining Address

```bash
# Create a wallet first (see wallet section)
./target/release/blacksilk-wallet create --name miner-wallet

# Get an address for mining rewards
./target/release/blacksilk-wallet address --wallet miner-wallet
```

### 3. Start Mining

```bash
# Start mining to your address
./target/release/blacksilk-miner \
  --config ~/.blacksilk/miner_config.toml \
  --reward-address <your_mining_address> \
  --threads 4

# Or with command line options
./target/release/blacksilk-miner \
  --node-url http://127.0.0.1:19333 \
  --reward-address <your_address> \
  --threads 4 \
  --network testnet
```

### 4. Monitor Mining

```bash
# Check mining statistics
curl http://127.0.0.1:19333/mining/stats

# View miner logs
tail -f ~/.blacksilk/logs/miner.log
```

## Using the Wallet

### 1. Create a New Wallet

```bash
# Create wallet with mnemonic seed
./target/release/blacksilk-wallet create --name my-wallet

# This will:
# - Generate a 24-word mnemonic phrase
# - Create encrypted wallet file
# - Display your first address
```

### 2. Basic Wallet Operations

```bash
# Show wallet addresses
./target/release/blacksilk-wallet address --wallet my-wallet

# Check balance
./target/release/blacksilk-wallet balance --wallet my-wallet

# Sync with blockchain
./target/release/blacksilk-wallet sync --wallet my-wallet
```

### 3. Get Testnet Funds

```bash
# Use the testnet faucet (see faucet section)
curl -X POST "http://testnet-faucet.blacksilk.io/request" \
  -H "Content-Type: application/json" \
  -d '{"address": "<your_address>"}'
```

### 4. Send Transactions

```bash
# Send regular transaction
./target/release/blacksilk-wallet send \
  --wallet my-wallet \
  --to <recipient_address> \
  --amount 1.5 \
  --fee 0.001

# Send private transaction with ring signatures
./target/release/blacksilk-wallet send \
  --wallet my-wallet \
  --to <recipient_address> \
  --amount 1.5 \
  --privacy \
  --ring-size 11
```

### 5. Privacy Features

```bash
# Generate stealth address
./target/release/blacksilk-wallet address --wallet my-wallet --stealth

# Enable Tor mode
./target/release/blacksilk-wallet --tor send \
  --wallet my-wallet \
  --to <address> \
  --amount 1.0 \
  --privacy
```

## Marketplace Setup

### 1. Database Setup

```bash
# Start PostgreSQL service
sudo systemctl start postgresql

# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE blacksilk_marketplace;
CREATE USER blacksilk_user WITH ENCRYPTED PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE blacksilk_marketplace TO blacksilk_user;
\q
EOF
```

### 2. Backend Setup

```bash
cd marketplace

# Copy environment file and configure
cp .env.example .env
nano .env  # Edit database URL and other settings

# Run migrations (if any)
# cargo run --bin migrate

# Start marketplace backend
cargo run --release
```

### 3. Frontend Setup

```bash
cd marketplace/frontend

# Install dependencies
npm install

# Copy environment file and configure
cp .env.example .env.local
nano .env.local  # Edit API URLs

# Start development server
npm run dev

# Or build for production
npm run build
npm start
```

### 4. IPFS Setup (Optional)

```bash
# Initialize IPFS
ipfs init

# Start IPFS daemon
ipfs daemon

# Verify IPFS is running
curl http://127.0.0.1:5001/api/v0/version
```

### 5. Access Marketplace

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

## Testnet Faucet

The testnet faucet provides free testnet BLK for testing purposes.

### Using the Faucet

```bash
# Request testnet funds
curl -X POST "http://testnet-faucet.blacksilk.io/request" \
  -H "Content-Type: application/json" \
  -d '{
    "address": "<your_testnet_address>",
    "amount": 10.0
  }'

# Check request status
curl "http://testnet-faucet.blacksilk.io/status/<request_id>"
```

### Faucet Limits

- **Amount**: 10 BLK per request
- **Cooldown**: 24 hours between requests per address
- **Daily Limit**: 1000 BLK total per day

## Block Explorer

Access the testnet block explorer to view blockchain data:

- **Testnet Explorer**: http://testnet-explorer.blacksilk.io
- **Local Explorer**: http://localhost:3002 (if running locally)

### Explorer Features

- **Latest Blocks**: View recent blocks and transactions
- **Address Search**: Look up balances and transaction history
- **Transaction Details**: Examine individual transactions
- **Network Stats**: Monitor difficulty, hashrate, and peer count

## Troubleshooting

### Common Issues

#### Node Won't Start

```bash
# Check if ports are available
sudo netstat -tlnp | grep :19333
sudo netstat -tlnp | grep :19334

# Check configuration file
./target/release/blacksilk-node --config ~/.blacksilk/node_config.toml --check-config

# Clear data directory (WARNING: loses blockchain data)
rm -rf ~/.blacksilk/data/testnet/*
```

#### Mining Not Working

```bash
# Verify node is synced
curl http://127.0.0.1:19333/status

# Check mining address is valid
./target/release/blacksilk-wallet validate-address <address>

# Monitor miner logs
tail -f ~/.blacksilk/logs/miner.log
```

#### Wallet Issues

```bash
# Resync wallet
./target/release/blacksilk-wallet sync --wallet my-wallet --rescan

# Check node connection
./target/release/blacksilk-wallet info --wallet my-wallet

# Restore from mnemonic
./target/release/blacksilk-wallet restore --name restored-wallet
```

#### Marketplace Issues

```bash
# Check database connection
psql -U blacksilk_user -d blacksilk_marketplace -c "SELECT 1;"

# Verify IPFS connection
curl http://127.0.0.1:5001/api/v0/version

# Check backend logs
tail -f logs/marketplace.log
```

### Getting Help

- **Documentation**: [https://docs.blacksilk.io](https://docs.blacksilk.io)
- **Discord**: [https://discord.gg/blacksilk](https://discord.gg/blacksilk)
- **GitHub Issues**: [https://github.com/BlackSilkCoin/BlackSilk-Blockchain/issues](https://github.com/BlackSilkCoin/BlackSilk-Blockchain/issues)
- **Telegram**: [https://t.me/blacksilkcoin](https://t.me/blacksilkcoin)

### Useful Commands

```bash
# Show all available commands
./target/release/blacksilk-node --help
./target/release/blacksilk-miner --help
./target/release/blacksilk-wallet --help

# Check versions
./target/release/blacksilk-node --version
./target/release/blacksilk-miner --version
./target/release/blacksilk-wallet --version

# Generate sample configurations
./target/release/blacksilk-node --generate-config > my_node_config.toml
./target/release/blacksilk-miner --generate-config > my_miner_config.toml
```

## Next Steps

Once you have everything running:

1. **Join the Community**: Connect with other testers on Discord or Telegram
2. **Test Marketplace**: List and purchase items using the decentralized marketplace
3. **Run Multiple Nodes**: Set up additional nodes to test network resilience
4. **Contribute**: Report bugs, suggest features, or contribute code
5. **Prepare for Mainnet**: Follow the roadmap for mainnet launch updates

## Security Notes

⚠️ **Important**: This is testnet software for testing purposes only.

- **Never use mainnet private keys on testnet**
- **Testnet tokens have no monetary value**
- **Back up your mnemonic phrases securely**
- **Use different passwords for testnet and mainnet**
- **Keep your software updated**

---

**Happy Testing!** 🚀

For more detailed information, see the specific component documentation in each module's README file.
