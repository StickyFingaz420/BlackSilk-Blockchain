# BlackSilk Testnet Documentation

## Overview
BlackSilk Testnet is a privacy-focused, quantum-resistant blockchain network designed for testing and development purposes.

## Network Information
- Network ID: `blacksilk_testnet`
- P2P Port: 19334
- RPC Port: 19333
- Tor Port: 19999
- Block Time: 120 seconds
- Mining: CPU-only

## Features
- ✅ Quantum-resistant signatures (ML-DSA-44, Dilithium2, Falcon512)
- ✅ Ring signatures for transaction privacy
- ✅ Stealth addresses
- ✅ Decentralized marketplace
- ✅ Escrow contracts
- ✅ Zero-knowledge proofs

## Getting Started

### Prerequisites
- Docker and Docker Compose
- 4GB RAM minimum
- 50GB storage
- Open ports: 19334 (P2P), 19333 (RPC), 19999 (Tor)

### Quick Start
1. Clone the repository:
   ```bash
   git clone https://github.com/StickyFingaz420/BlackSilk-Blockchain.git
   cd BlackSilk-Blockchain
   ```

2. Deploy the testnet:
   ```bash
   ./scripts/deploy_testnet.sh
   ```

3. Access the network:
   - Block Explorer: http://localhost:8080
   - Testnet Faucet: http://localhost:8081
   - Monitoring: http://localhost:3000

### Connecting a Node
1. Configure `config/testnet/node_config.toml`
2. Run:
   ```bash
   docker-compose -f docker-compose.testnet.yml up -d blacksilk-node
   ```

## Development Resources

### RPC Interface
Default endpoint: `http://localhost:19333`
Authentication: Basic Auth (testnet_user/secure_rpc_password)

Example:
```bash
curl -X POST -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}' \
     http://testnet_user:secure_rpc_password@localhost:19333/
```

### Faucet Usage
Request testnet coins:
```bash
curl -X POST http://localhost:8081/faucet \
     -H "Content-Type: application/json" \
     -d '{"address":"YOUR_ADDRESS","amount":1000}'
```

### Building from Source
1. Install dependencies:
   ```bash
   cargo build --release
   ```

2. Run tests:
   ```bash
   cargo test --release
   ```

## Monitoring and Maintenance

### Health Checks
Run the health check script:
```bash
./healthcheck.sh
```

### Logs
View logs:
```bash
docker-compose -f docker-compose.testnet.yml logs -f
```

### Metrics
- Grafana Dashboard: http://localhost:3000
- Prometheus: http://localhost:9090

## Security Considerations

### Network Security
- Enable firewall rules
- Use strong RPC credentials
- Keep software updated
- Monitor system resources

### Privacy Features
- Use ring signatures (recommended size: 11)
- Enable stealth addresses
- Use quantum-resistant signatures
- Enable Tor for enhanced privacy

## Known Issues and Limitations
1. Maximum ring size: 100
2. Block size limit: 2MB
3. Minimum peers for sync: 3
4. Maximum transaction size: 100KB

## Support and Community
- Discord: [BlackSilk Community]
- Telegram: [BlackSilk Testnet]
- GitHub Issues: [Report Issues]

## Contributing
1. Fork the repository
2. Create a feature branch
3. Submit a pull request
4. Follow coding standards
5. Include tests

## License
MIT License - See LICENSE file for details
