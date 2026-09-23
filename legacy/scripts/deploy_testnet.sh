#!/bin/bash
# BlackSilk Testnet Deployment Script

set -e

# Configuration
NETWORK="testnet"
BASE_DIR="$(pwd)"
DOCKER_COMPOSE_FILE="docker-compose.testnet.yml"
CONFIG_DIR="config/testnet"
LOG_DIR="logs/testnet"
MONITOR_DIR="monitoring"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}BlackSilk Testnet Deployment Script${NC}"
echo "================================="

# Check prerequisites
echo -e "\n${YELLOW}Checking prerequisites...${NC}"

command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed. Aborting." >&2; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "Docker Compose is required but not installed. Aborting." >&2; exit 1; }

# Create necessary directories
echo -e "\n${YELLOW}Creating directory structure...${NC}"
mkdir -p "$LOG_DIR"
mkdir -p "$MONITOR_DIR/grafana/data"
mkdir -p "$MONITOR_DIR/prometheus/data"

# Configure firewall rules
echo -e "\n${YELLOW}Configuring firewall rules...${NC}"
sudo ufw allow 19334/tcp comment 'BlackSilk Testnet P2P'
sudo ufw allow 19333/tcp comment 'BlackSilk Testnet RPC'
sudo ufw allow 19999/tcp comment 'BlackSilk Testnet Tor'
sudo ufw allow 9090/tcp comment 'Prometheus'
sudo ufw allow 3000/tcp comment 'Grafana'

# Deploy monitoring stack
echo -e "\n${YELLOW}Deploying monitoring stack...${NC}"
docker-compose -f "$MONITOR_DIR/docker-compose.yml" up -d

# Initialize seed nodes
echo -e "\n${YELLOW}Initializing seed nodes...${NC}"
for i in {1..3}; do
    docker-compose -f $DOCKER_COMPOSE_FILE up -d "blacksilk-seed$i"
done

# Wait for seed nodes to be ready
echo "Waiting for seed nodes to initialize..."
sleep 30

# Deploy testnet nodes
echo -e "\n${YELLOW}Deploying testnet nodes...${NC}"
docker-compose -f $DOCKER_COMPOSE_FILE up -d

# Deploy testnet faucet
echo -e "\n${YELLOW}Deploying testnet faucet...${NC}"
docker-compose -f $DOCKER_COMPOSE_FILE up -d blacksilk-faucet

# Deploy block explorer
echo -e "\n${YELLOW}Deploying block explorer...${NC}"
docker-compose -f $DOCKER_COMPOSE_FILE up -d blacksilk-explorer

# Check services status
echo -e "\n${YELLOW}Checking service status...${NC}"
docker-compose -f $DOCKER_COMPOSE_FILE ps

# Set up monitoring alerts
echo -e "\n${YELLOW}Configuring monitoring alerts...${NC}"
curl -X POST http://localhost:9090/-/reload

# Display access information
echo -e "\n${GREEN}Testnet Deployment Complete!${NC}"
echo "================================="
echo "Access Points:"
echo "- Block Explorer: http://localhost:8080"
echo "- Testnet Faucet: http://localhost:8081"
echo "- Monitoring Dashboard: http://localhost:3000"
echo "- Node RPC: http://localhost:19333"
echo ""
echo "Default Credentials:"
echo "- Grafana: admin/admin"
echo "- Node RPC: testnet_user/secure_rpc_password"
echo ""
echo "Logs can be viewed with: docker-compose -f $DOCKER_COMPOSE_FILE logs -f"

# Create healthcheck script
cat > healthcheck.sh << 'EOF'
#!/bin/bash
# Testnet health check script

check_service() {
    local service=$1
    local port=$2
    if nc -z localhost $port; then
        echo "✅ $service is running"
    else
        echo "❌ $service is not responding"
    fi
}

echo "BlackSilk Testnet Health Check"
echo "============================"
check_service "P2P Network" 19334
check_service "RPC Interface" 19333
check_service "Block Explorer" 8080
check_service "Testnet Faucet" 8081
check_service "Prometheus" 9090
check_service "Grafana" 3000

echo -e "\nNode Status:"
curl -s -X POST -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}' \
     http://testnet_user:secure_rpc_password@localhost:19333/
EOF

chmod +x healthcheck.sh

echo -e "\n${GREEN}Setup Complete!${NC}"
echo "Run ./healthcheck.sh to verify the deployment"
