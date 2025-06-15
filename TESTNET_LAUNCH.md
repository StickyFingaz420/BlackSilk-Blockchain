# BlackSilk Testnet Launch Instructions

## Prerequisites
- Docker and Docker Compose installed
- Open required ports (19333 for P2P, 18332 for RPC, 19999 for Tor if privacy enabled)

## Launching a Testnet Node
1. Clone the BlackSilk repository and navigate to the project root.
2. Ensure the testnet config files are present in `config/testnet/` (already provided).
3. Start the node:

    ```sh
    docker compose -f docker-compose.testnet.yml up -d
    ```

4. Check logs:

    ```sh
    docker logs -f blacksilk-testnet-node
    ```

5. The node will connect to the testnet bootnodes and begin syncing.

## Connecting to the Testnet
- Use the following bootnodes:
  - 12D3KooWTestNode1@testnet-seed1.blacksilk.io:19334
  - 12D3KooWTestNode2@testnet-seed2.blacksilk.io:19334
  - 12D3KooWTestNode3@testnet-seed3.blacksilk.io:19334
- RPC endpoint: `localhost:18332` (default user/pass: testnet_user/secure_rpc_password)

## Optional: Running a Miner
- Uncomment the `blacksilk-miner` service in `docker-compose.testnet.yml` and rebuild if you want to mine on testnet.

## Troubleshooting
- Ensure your firewall allows the required ports.
- Check the node logs for errors.
- For advanced config, edit `config/testnet/node_config.toml`.

---
For help, visit the BlackSilk community channels.
