#!/bin/bash

# BlackSilk Testnet Seed Node Deployment Script
# This script sets up and deploys seed nodes for the testnet

set -e

echo "🌱 BlackSilk Testnet Seed Node Deployment"
echo "========================================="

# Configuration
SEED_NODE_COUNT=${SEED_NODE_COUNT:-3}
NODE_VERSION=${NODE_VERSION:-"latest"}
DATA_DIR=${DATA_DIR:-"/opt/blacksilk"}
LOG_DIR=${LOG_DIR:-"/var/log/blacksilk"}

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to log messages
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    error "This script should not be run as root for security reasons"
    exit 1
fi

# Function to check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null; then
        error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if required directories exist
    if [[ ! -d "/workspaces/BlackSilk-Blockchain" ]]; then
        error "BlackSilk repository not found. Please ensure you're in the correct directory."
        exit 1
    fi
    
    log "✅ Prerequisites check passed"
}

# Function to build node image
build_node_image() {
    log "Building BlackSilk node Docker image..."
    
    cd /workspaces/BlackSilk-Blockchain
    
    # Create Dockerfile for the node if it doesn't exist
    if [[ ! -f "docker/node.Dockerfile" ]]; then
        mkdir -p docker
        cat > docker/node.Dockerfile << 'EOF'
FROM rust:1.75 as builder

WORKDIR /app
COPY . .

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Build the node
RUN cargo build --release --bin blacksilk-node

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create blacksilk user
RUN useradd -r -s /bin/bash -m blacksilk

# Copy binary and config
COPY --from=builder /app/target/release/blacksilk-node /usr/local/bin/
COPY --from=builder /app/config /etc/blacksilk/config

# Create data directories
RUN mkdir -p /data/blacksilk /logs/blacksilk && \
    chown -R blacksilk:blacksilk /data/blacksilk /logs/blacksilk

USER blacksilk
WORKDIR /data/blacksilk

EXPOSE 19333 19334

CMD ["blacksilk-node", "--network", "testnet", "--config", "/etc/blacksilk/config/testnet/node_config.toml"]
EOF
    fi
    
    # Build the image
    docker build -f docker/node.Dockerfile -t blacksilk/node:${NODE_VERSION} .
    
    log "✅ Node image built successfully"
}

# Function to create seed node configuration
create_seed_config() {
    local node_id=$1
    local p2p_port=$((19334 + node_id))
    local rpc_port=$((19333 + node_id))
    
    log "Creating configuration for seed node ${node_id}..."
    
    mkdir -p "./seed-nodes/node-${node_id}/config"
    mkdir -p "./seed-nodes/node-${node_id}/data"
    mkdir -p "./seed-nodes/node-${node_id}/logs"
    
    # Create node-specific config
    cat > "./seed-nodes/node-${node_id}/config/node_config.toml" << EOF
[network]
listen_address = "0.0.0.0:${p2p_port}"
rpc_listen_address = "0.0.0.0:${rpc_port}"
max_peers = 50
enable_discovery = true
nat_traversal = true

[database]
path = "/data/blacksilk/chaindata"
cache_size_mb = 256
max_open_files = 1000

[logging]
level = "info"
file_path = "/logs/blacksilk/node.log"
max_file_size_mb = 100
max_files = 10

[consensus]
chain_spec_path = "/etc/blacksilk/config/testnet/chain_spec.json"

[rpc]
enabled = true
cors_origins = ["*"]
methods = ["all"]

[mining]
enabled = false  # Seed nodes don't mine

[metrics]
enabled = true
listen_address = "0.0.0.0:9090"
EOF

    log "✅ Configuration created for seed node ${node_id}"
}

# Function to create Docker Compose file for seed nodes
create_docker_compose() {
    log "Creating Docker Compose configuration for seed nodes..."
    
    cat > "./seed-nodes/docker-compose.yml" << 'EOF'
version: '3.8'

services:
EOF

    # Add each seed node service
    for i in $(seq 0 $((SEED_NODE_COUNT - 1))); do
        local p2p_port=$((19334 + i))
        local rpc_port=$((19333 + i))
        local metrics_port=$((9090 + i))
        
        cat >> "./seed-nodes/docker-compose.yml" << EOF
  seed-node-${i}:
    image: blacksilk/node:${NODE_VERSION}
    container_name: blacksilk-seed-${i}
    restart: unless-stopped
    ports:
      - "${p2p_port}:${p2p_port}"
      - "${rpc_port}:${rpc_port}"
      - "${metrics_port}:9090"
    volumes:
      - ./node-${i}/config/node_config.toml:/etc/blacksilk/config/testnet/node_config.toml:ro
      - ./node-${i}/data:/data/blacksilk
      - ./node-${i}/logs:/logs/blacksilk
    environment:
      - RUST_LOG=info
      - BLACKSILK_NETWORK=testnet
    networks:
      - blacksilk-testnet
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:${rpc_port}/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

EOF
    done
    
    # Add networks section
    cat >> "./seed-nodes/docker-compose.yml" << 'EOF'
networks:
  blacksilk-testnet:
    driver: bridge
EOF

    log "✅ Docker Compose configuration created"
}

# Function to deploy seed nodes locally
deploy_local_seed_nodes() {
    log "Deploying seed nodes locally..."
    
    mkdir -p ./seed-nodes
    cd ./seed-nodes
    
    # Create configurations for each seed node
    for i in $(seq 0 $((SEED_NODE_COUNT - 1))); do
        create_seed_config $i
    done
    
    # Create Docker Compose file
    create_docker_compose
    
    # Start the seed nodes
    log "Starting seed nodes..."
    docker-compose up -d
    
    # Wait for nodes to start
    sleep 30
    
    # Check node health
    log "Checking seed node health..."
    for i in $(seq 0 $((SEED_NODE_COUNT - 1))); do
        local rpc_port=$((19333 + i))
        if curl -s http://localhost:${rpc_port}/health > /dev/null; then
            log "✅ Seed node ${i} is healthy (port ${rpc_port})"
        else
            warn "⚠️  Seed node ${i} health check failed (port ${rpc_port})"
        fi
    done
    
    cd ..
}

# Function to generate real peer IDs and update bootnode list
update_bootnode_list() {
    log "Updating bootnode list with real peer IDs..."
    
    # Wait for nodes to generate peer IDs
    sleep 10
    
    # Extract peer IDs from logs
    cd ./seed-nodes
    
    # Create new bootnode list
    cat > ../config/testnet/bootnodes_local.txt << 'EOF'
# BlackSilk Testnet Bootstrap Nodes (Local Development)
# Format: <peer_id>@<ip_address>:<port>
# These are locally running seed nodes for development

EOF
    
    for i in $(seq 0 $((SEED_NODE_COUNT - 1))); do
        local p2p_port=$((19334 + i))
        local container_name="blacksilk-seed-${i}"
        
        # Try to extract peer ID from logs
        local peer_id=$(docker logs ${container_name} 2>&1 | grep -o "Peer ID: [A-Za-z0-9]*" | head -1 | cut -d' ' -f3)
        
        if [[ -n "$peer_id" ]]; then
            echo "# Seed node ${i}" >> ../config/testnet/bootnodes_local.txt
            echo "${peer_id}@127.0.0.1:${p2p_port}" >> ../config/testnet/bootnodes_local.txt
            echo "" >> ../config/testnet/bootnodes_local.txt
            log "✅ Added seed node ${i} with peer ID: ${peer_id}"
        else
            warn "⚠️  Could not extract peer ID for seed node ${i}"
            echo "# Seed node ${i} - peer ID not available" >> ../config/testnet/bootnodes_local.txt
            echo "# UPDATE_ME@127.0.0.1:${p2p_port}" >> ../config/testnet/bootnodes_local.txt
            echo "" >> ../config/testnet/bootnodes_local.txt
        fi
    done
    
    cd ..
    
    log "✅ Bootnode list updated. Check config/testnet/bootnodes_local.txt"
}

# Function to create production deployment guide
create_production_guide() {
    log "Creating production deployment guide..."
    
    cat > "./SEED_NODE_DEPLOYMENT.md" << 'EOF'
# BlackSilk Testnet Seed Node Deployment Guide

## Overview

This guide explains how to deploy BlackSilk testnet seed nodes in production environments.

## VPS Requirements

### Minimum Specifications
- **CPU**: 2 cores
- **RAM**: 4GB
- **Storage**: 50GB SSD
- **Network**: 100 Mbps with static IP
- **OS**: Ubuntu 20.04 LTS or later

### Recommended Specifications
- **CPU**: 4 cores
- **RAM**: 8GB
- **Storage**: 100GB SSD
- **Network**: 1 Gbps with static IP

## Geographic Distribution

Deploy seed nodes across multiple regions:
- **US East**: Virginia/New York
- **EU Central**: Frankfurt/Amsterdam
- **Asia Pacific**: Singapore/Tokyo

## Production Deployment Steps

### 1. VPS Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.21.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Create blacksilk user
sudo useradd -r -s /bin/bash -m blacksilk
sudo usermod -aG docker blacksilk
```

### 2. Firewall Configuration

```bash
# Configure UFW
sudo ufw allow ssh
sudo ufw allow 19333/tcp  # RPC port
sudo ufw allow 19334/tcp  # P2P port
sudo ufw allow 9090/tcp   # Metrics port
sudo ufw --force enable
```

### 3. Deploy Seed Node

```bash
# Switch to blacksilk user
sudo su - blacksilk

# Clone repository
git clone https://github.com/BlackSilk-Blockchain/BlackSilk-Blockchain.git
cd BlackSilk-Blockchain

# Run deployment script
./scripts/deploy-seed-nodes.sh
```

### 4. DNS Configuration

Update DNS records for your seed nodes:
- `testnet-seed1.blacksilk.io` → VPS 1 IP
- `testnet-seed2.blacksilk.io` → VPS 2 IP
- `testnet-seed3.blacksilk.io` → VPS 3 IP

### 5. SSL/TLS (Optional)

For RPC endpoints, configure SSL:

```bash
# Install Certbot
sudo apt install certbot

# Generate certificates
sudo certbot certonly --standalone -d testnet-seed1.blacksilk.io
```

### 6. Monitoring Setup

```bash
# Start monitoring stack
cd monitoring
docker-compose up -d

# Access Grafana
# http://your-vps-ip:3000
# Default: admin/admin
```

## Maintenance

### Log Management

```bash
# View logs
docker-compose logs -f seed-node-0

# Rotate logs
docker-compose exec seed-node-0 logrotate /etc/logrotate.conf
```

### Updates

```bash
# Pull latest changes
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose up -d --build
```

### Health Monitoring

```bash
# Check node health
curl http://localhost:19333/health

# Check peer connections
curl http://localhost:19333/peers

# Check sync status
curl http://localhost:19333/status
```

## Troubleshooting

### Common Issues

1. **Port binding failures**
   - Check if ports are already in use: `netstat -tulpn | grep 19333`
   - Ensure firewall allows the ports

2. **Peer discovery issues**
   - Verify DNS resolution: `nslookup testnet-seed1.blacksilk.io`
   - Check NAT/firewall rules

3. **High resource usage**
   - Monitor with: `docker stats`
   - Adjust resource limits in docker-compose.yml

### Support

For deployment support:
- **GitHub Issues**: https://github.com/BlackSilk-Blockchain/BlackSilk-Blockchain/issues
- **Discord**: #seed-nodes channel
- **Email**: ops@blacksilk.io

EOF

    log "✅ Production deployment guide created: SEED_NODE_DEPLOYMENT.md"
}

# Main function
main() {
    log "Starting BlackSilk seed node deployment..."
    
    check_prerequisites
    build_node_image
    deploy_local_seed_nodes
    update_bootnode_list
    create_production_guide
    
    log "🎉 Seed node deployment completed!"
    log ""
    log "Next steps:"
    log "1. Check seed node status: docker-compose -f seed-nodes/docker-compose.yml ps"
    log "2. View logs: docker-compose -f seed-nodes/docker-compose.yml logs"
    log "3. For production deployment, see: SEED_NODE_DEPLOYMENT.md"
    log "4. Update config/testnet/bootnodes.txt with real VPS IPs when deploying to production"
}

# Run main function
main "$@"
