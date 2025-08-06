# BlackSilk Testnet Launch Instructions

## Prerequisites
- Docker and Docker Compose installed
- Minimum 4GB RAM
- 50GB storage space
- Open ports:
  - 19334 (P2P)
  - 19333 (RPC)
  - 19999 (Tor)
  - 9090 (Prometheus)
  - 3000 (Grafana)

## Pre-Launch Checklist
1. Verify quantum signature implementation:
   ```sh
   cargo test -p primitives --test quantum_privacy_tests
   ```

2. Check privacy features:
   ```sh
   cargo test -p primitives --test migration_tests
   ```

3. Verify monitoring setup:
   ```sh
   docker-compose -f monitoring/docker-compose.yml config
   ```

## Launching the Testnet
1. Deploy the infrastructure:
   ```sh
   ./scripts/deploy_testnet.sh
   ```

2. Verify the deployment:
   ```sh
   ./healthcheck.sh
   ```

3. Monitor the network:
   - Grafana: http://localhost:3000
   - Prometheus: http://localhost:9090
   - Block Explorer: http://localhost:8080

## Network Configuration
- Genesis timestamp: 1728633600 (February 1, 2025)
- Initial faucet balance: 1,000,000 BSK
- Block time: 120 seconds
- Mining: CPU-only
- Privacy features: Enabled
- Quantum resistance: Enabled

## Seed Nodes
- 12D3KooWTestNode1@testnet-seed1.blacksilk.io:19334
- 12D3KooWTestNode2@testnet-seed2.blacksilk.io:19334
- 12D3KooWTestNode3@testnet-seed3.blacksilk.io:19334

## Running a Node
1. Configure node:
   ```toml
   # config/testnet/node_config.toml
   [network]
   peer_listen_address = "0.0.0.0:19334"
   rpc_listen_address = "0.0.0.0:19333"
   enable_tor = true  # Optional
   ```

2. Start the node:
   ```sh
   docker-compose -f docker-compose.testnet.yml up -d blacksilk-node
   ```

3. Check sync status:
   ```sh
   curl -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}' \
        http://testnet_user:secure_rpc_password@localhost:19333/
   ```

## Mining Setup
1. Enable mining:
   ```sh
   docker-compose -f docker-compose.testnet.yml up -d blacksilk-miner
   ```

2. Monitor hashrate:
   ```sh
   curl -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"getmininginfo","params":[],"id":1}' \
        http://testnet_user:secure_rpc_password@localhost:19333/
   ```

## Troubleshooting
1. Check node logs:
   ```sh
   docker-compose -f docker-compose.testnet.yml logs -f blacksilk-node
   ```

2. Verify network connectivity:
   ```sh
   curl -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"getpeerinfo","params":[],"id":1}' \
        http://testnet_user:secure_rpc_password@localhost:19333/
   ```

3. Reset node (if needed):
   ```sh
   docker-compose -f docker-compose.testnet.yml down
   rm -rf data/testnet/*
   docker-compose -f docker-compose.testnet.yml up -d
   ```

## Support
- Discord: [BlackSilk Community]
- Telegram: [BlackSilk Testnet]
- Documentation: [TESTNET.md]
- Issues: [GitHub Issues]

## Monitoring Alerts
- Node down > 5 minutes
- Block time > 240 seconds
- Peer count < 3
- Memory usage > 90%
- Chain stalled > 1 hour
- Faucet balance < 1,000 BSK

---
For detailed documentation, see TESTNET.md
