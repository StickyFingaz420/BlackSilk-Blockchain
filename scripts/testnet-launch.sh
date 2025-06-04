#!/bin/bash

# BlackSilk Blockchain Testnet Launch Orchestrator
# Complete testnet deployment and validation pipeline

set -e

echo "🚀 BlackSilk Testnet Launch Orchestrator"
echo "========================================"

# Configuration
TESTNET_NAME="blacksilk-testnet-v1"
LAUNCH_MODE=${LAUNCH_MODE:-"production"}  # development, staging, production
SKIP_TESTS=${SKIP_TESTS:-false}
SKIP_SECURITY=${SKIP_SECURITY:-false}
AUTO_DEPLOY=${AUTO_DEPLOY:-false}

# Service ports
NODE_PORT=${NODE_PORT:-8545}
FAUCET_PORT=${FAUCET_PORT:-3000}
WALLET_PORT=${WALLET_PORT:-3001}
EXPLORER_PORT=${EXPLORER_PORT:-3002}
MONITORING_PORT=${MONITORING_PORT:-3003}

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

success() {
    echo -e "${PURPLE}[SUCCESS] $1${NC}"
}

# Track deployment progress
STEPS_TOTAL=12
STEPS_COMPLETED=0

progress() {
    local step_name="$1"
    ((STEPS_COMPLETED++))
    echo -e "${CYAN}[STEP $STEPS_COMPLETED/$STEPS_TOTAL] $step_name${NC}"
}

# Validate prerequisites
validate_prerequisites() {
    progress "Validating Prerequisites"
    
    local missing_tools=()
    
    # Check required tools
    for tool in docker docker-compose cargo node npm git curl jq; do
        if ! command -v $tool >/dev/null 2>&1; then
            missing_tools+=($tool)
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        error "Missing required tools: ${missing_tools[*]}"
        error "Please install missing tools and re-run the script"
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        error "Docker daemon is not running"
        exit 1
    fi
    
    # Check available ports
    for port in $NODE_PORT $FAUCET_PORT $WALLET_PORT $EXPLORER_PORT $MONITORING_PORT; do
        if netstat -tuln | grep -q ":$port "; then
            warn "Port $port is already in use"
        fi
    done
    
    # Check disk space (need at least 10GB)
    local available_space=$(df . | tail -1 | awk '{print $4}')
    if [ $available_space -lt 10485760 ]; then  # 10GB in KB
        warn "Less than 10GB disk space available"
    fi
    
    success "Prerequisites validation completed"
}

# Build all components
build_components() {
    progress "Building BlackSilk Components"
    
    log "Building Rust components..."
    
    # Build node
    info "Building node..."
    cargo build --release --bin blacksilk-node || {
        error "Failed to build node"
        exit 1
    }
    
    # Build miner
    info "Building miner..."
    cargo build --release --bin blacksilk-miner || {
        error "Failed to build miner"
        exit 1
    }
    
    # Build wallet
    info "Building wallet..."
    cargo build --release --bin wallet || {
        error "Failed to build wallet"
        exit 1
    }
    
    log "Building Docker images..."
    
    # Build Docker images
    docker build -f docker/node.Dockerfile -t blacksilk/node:latest . || {
        error "Failed to build node Docker image"
        exit 1
    }
    
    docker build -f docker/miner.Dockerfile -t blacksilk/miner:latest . || {
        error "Failed to build miner Docker image"
        exit 1
    }
    
    docker build -f docker/wallet.Dockerfile -t blacksilk/wallet:latest . || {
        error "Failed to build wallet Docker image"
        exit 1
    }
    
    success "All components built successfully"
}

# Run security audit
run_security_audit() {
    progress "Running Security Audit"
    
    if [ "$SKIP_SECURITY" = "true" ]; then
        warn "Skipping security audit (SKIP_SECURITY=true)"
        return 0
    fi
    
    log "Preparing security audit..."
    ./scripts/security-audit-prep.sh || {
        error "Security audit preparation failed"
        exit 1
    }
    
    log "Running dependency scans..."
    if command -v cargo-audit >/dev/null 2>&1; then
        cargo audit || warn "cargo-audit found vulnerabilities"
    fi
    
    success "Security audit completed"
}

# Run comprehensive tests
run_tests() {
    progress "Running Comprehensive Tests"
    
    if [ "$SKIP_TESTS" = "true" ]; then
        warn "Skipping tests (SKIP_TESTS=true)"
        return 0
    fi
    
    log "Running unit tests..."
    cargo test --release || {
        error "Unit tests failed"
        exit 1
    }
    
    log "Running integration tests..."
    # Start test environment first
    ./scripts/setup-test-environment.sh || {
        error "Failed to setup test environment"
        exit 1
    }
    
    # Run integration tests
    ./scripts/integration-tests.sh || {
        error "Integration tests failed"
        exit 1
    }
    
    success "All tests passed"
}

# Setup monitoring stack
setup_monitoring() {
    progress "Setting Up Monitoring Stack"
    
    log "Configuring monitoring and alerting..."
    ./scripts/monitoring-alerting-setup.sh || {
        error "Failed to setup monitoring"
        exit 1
    }
    
    success "Monitoring stack configured"
}

# Deploy seed nodes
deploy_seed_nodes() {
    progress "Deploying Seed Nodes"
    
    if [ "$AUTO_DEPLOY" != "true" ]; then
        warn "Skipping seed node deployment (AUTO_DEPLOY=false)"
        warn "Run './scripts/deploy-seed-nodes.sh' manually after testnet launch"
        return 0
    fi
    
    log "Deploying seed nodes..."
    ./scripts/deploy-seed-nodes.sh || {
        error "Failed to deploy seed nodes"
        exit 1
    }
    
    success "Seed nodes deployed"
}

# Setup faucet service
setup_faucet() {
    progress "Setting Up Faucet Service"
    
    log "Configuring testnet faucet..."
    ./scripts/setup-faucet.sh || {
        error "Failed to setup faucet"
        exit 1
    }
    
    # Wait for faucet to be ready
    log "Waiting for faucet service..."
    for i in {1..30}; do
        if curl -s http://localhost:$FAUCET_PORT/health >/dev/null 2>&1; then
            success "Faucet service is ready"
            break
        fi
        sleep 2
        if [ $i -eq 30 ]; then
            error "Faucet service failed to start"
            exit 1
        fi
    done
}

# Setup web wallet
setup_web_wallet() {
    progress "Setting Up Web Wallet"
    
    log "Configuring web wallet..."
    ./scripts/setup-web-wallet.sh || {
        error "Failed to setup web wallet"
        exit 1
    }
    
    # Wait for wallet to be ready
    log "Waiting for web wallet..."
    for i in {1..30}; do
        if curl -s http://localhost:$WALLET_PORT/health >/dev/null 2>&1; then
            success "Web wallet is ready"
            break
        fi
        sleep 2
        if [ $i -eq 30 ]; then
            warn "Web wallet may not be fully ready"
            break
        fi
    done
}

# Start blockchain node
start_blockchain_node() {
    progress "Starting Blockchain Node"
    
    log "Starting BlackSilk node..."
    
    # Create node data directory
    mkdir -p data/testnet
    
    # Start node in background
    nohup ./target/release/blacksilk-node \
        --config config/testnet/node_config.toml \
        --chain-spec config/testnet/chain_spec.json \
        --data-dir data/testnet \
        --port $NODE_PORT \
        --rpc-port $((NODE_PORT + 1)) \
        --bootnodes-file config/testnet/bootnodes.txt \
        > logs/node.log 2>&1 &
    
    local node_pid=$!
    echo $node_pid > data/testnet/node.pid
    
    # Wait for node to be ready
    log "Waiting for node to start..."
    for i in {1..60}; do
        if curl -s http://localhost:$NODE_PORT/health >/dev/null 2>&1; then
            success "Blockchain node is ready"
            return 0
        fi
        sleep 2
        if [ $i -eq 60 ]; then
            error "Node failed to start within 2 minutes"
            exit 1
        fi
    done
}

# Start mining
start_mining() {
    progress "Starting Mining"
    
    log "Starting miner..."
    
    # Start miner in background
    nohup ./target/release/blacksilk-miner \
        --config config/miner_config.toml \
        --node-url http://localhost:$NODE_PORT \
        > logs/miner.log 2>&1 &
    
    local miner_pid=$!
    echo $miner_pid > data/testnet/miner.pid
    
    # Give miner time to connect
    sleep 10
    
    # Verify mining is working
    if curl -s http://localhost:$NODE_PORT/api/mining/status | grep -q '"is_mining":true'; then
        success "Mining started successfully"
    else
        warn "Mining may not be active yet"
    fi
}

# Validate testnet launch
validate_testnet() {
    progress "Validating Testnet Launch"
    
    log "Running post-launch validation..."
    
    # Check all services
    local services_ok=true
    
    # Check node
    if ! curl -s http://localhost:$NODE_PORT/health >/dev/null; then
        error "Node is not responding"
        services_ok=false
    else
        info "✅ Node is healthy"
    fi
    
    # Check faucet
    if ! curl -s http://localhost:$FAUCET_PORT/health >/dev/null; then
        warn "Faucet is not responding"
    else
        info "✅ Faucet is healthy"
    fi
    
    # Check web wallet
    if ! curl -s http://localhost:$WALLET_PORT/health >/dev/null; then
        warn "Web wallet is not responding"
    else
        info "✅ Web wallet is healthy"
    fi
    
    # Run basic integration tests
    log "Running validation tests..."
    ./scripts/integration-tests.sh node || {
        error "Node validation tests failed"
        services_ok=false
    }
    
    if [ "$services_ok" = "true" ]; then
        success "Testnet validation completed successfully"
    else
        error "Testnet validation failed"
        exit 1
    fi
}

# Generate launch summary
generate_launch_summary() {
    progress "Generating Launch Summary"
    
    # Create launch summary document
    cat > "testnet-launch-summary-$(date +%Y%m%d-%H%M%S).md" << EOF
# BlackSilk Testnet Launch Summary

**Launch Date:** $(date)
**Testnet Name:** $TESTNET_NAME
**Launch Mode:** $LAUNCH_MODE

## Service Endpoints

- **Blockchain Node:** http://localhost:$NODE_PORT
- **RPC Endpoint:** http://localhost:$((NODE_PORT + 1))
- **Testnet Faucet:** http://localhost:$FAUCET_PORT
- **Web Wallet:** http://localhost:$WALLET_PORT
- **Block Explorer:** http://localhost:$EXPLORER_PORT
- **Monitoring:** http://localhost:$MONITORING_PORT

## Network Information

- **Chain ID:** $(curl -s http://localhost:$NODE_PORT/api/chain_id 2>/dev/null || echo "N/A")
- **Genesis Hash:** $(curl -s http://localhost:$NODE_PORT/api/genesis_hash 2>/dev/null || echo "N/A")
- **Current Block:** $(curl -s http://localhost:$NODE_PORT/api/latest_block | jq -r '.height' 2>/dev/null || echo "N/A")
- **Peer Count:** $(curl -s http://localhost:$NODE_PORT/api/peers | jq '.peers | length' 2>/dev/null || echo "N/A")

## Getting Started

### For Users
1. Visit the web wallet: http://localhost:$WALLET_PORT
2. Create a new wallet or import existing one
3. Get testnet tokens from faucet: http://localhost:$FAUCET_PORT
4. Start transacting on the testnet

### For Developers
1. RPC endpoint: http://localhost:$((NODE_PORT + 1))
2. WebSocket endpoint: ws://localhost:$((NODE_PORT + 2))
3. API documentation: http://localhost:$NODE_PORT/docs

### For Miners
1. Connect to: http://localhost:$NODE_PORT
2. Use provided mining software
3. Configure with testnet parameters

## Monitoring

- **Prometheus:** http://localhost:9090
- **Grafana:** http://localhost:$MONITORING_PORT (admin/blacksilk2025)
- **Alertmanager:** http://localhost:9093

## Support

- **Documentation:** /docs
- **Issues:** GitHub Issues
- **Community:** Discord/Telegram

## Next Steps

1. Monitor network stability
2. Encourage community participation
3. Gather feedback and metrics
4. Plan mainnet launch based on testnet success

---
*Generated by BlackSilk Testnet Launch Orchestrator*
EOF

    success "Launch summary generated"
}

# Cleanup function
cleanup() {
    log "Cleaning up launch process..."
    
    # Stop any background processes if launch failed
    if [ -f "data/testnet/node.pid" ]; then
        local node_pid=$(cat data/testnet/node.pid)
        if kill -0 $node_pid 2>/dev/null; then
            log "Stopping node process $node_pid"
            kill $node_pid
        fi
    fi
    
    if [ -f "data/testnet/miner.pid" ]; then
        local miner_pid=$(cat data/testnet/miner.pid)
        if kill -0 $miner_pid 2>/dev/null; then
            log "Stopping miner process $miner_pid"
            kill $miner_pid
        fi
    fi
}

# Success celebration
celebrate_launch() {
    echo ""
    echo -e "${GREEN}🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉${NC}"
    echo -e "${GREEN}🎉                                               🎉${NC}"
    echo -e "${GREEN}🎉  BlackSilk Testnet Successfully Launched!     🎉${NC}"
    echo -e "${GREEN}🎉                                               🎉${NC}"
    echo -e "${GREEN}🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉${NC}"
    echo ""
    
    log "🌟 Testnet is now live and ready for use!"
    log "📊 Monitor at: http://localhost:$MONITORING_PORT"
    log "💰 Get testnet tokens: http://localhost:$FAUCET_PORT"
    log "👛 Use web wallet: http://localhost:$WALLET_PORT"
    echo ""
    
    # Display important information
    info "Important Notes:"
    info "- This is a TESTNET - tokens have no real value"
    info "- Use for testing and development only"
    info "- Report any issues to the development team"
    info "- Monitor network health regularly"
    echo ""
    
    info "Next Steps:"
    info "1. Share testnet information with community"
    info "2. Monitor network performance and stability"
    info "3. Gather user feedback and metrics"
    info "4. Iterate based on testnet results"
    info "5. Prepare for mainnet launch"
}

# Main execution
main() {
    echo ""
    log "🚀 Starting BlackSilk Testnet Launch Process..."
    log "=============================================="
    
    # Create necessary directories
    mkdir -p {logs,data/testnet,config/testnet}
    
    # Trap cleanup on exit
    trap cleanup EXIT
    
    # Execute launch steps
    validate_prerequisites
    build_components
    
    if [ "$LAUNCH_MODE" = "production" ]; then
        run_security_audit
    fi
    
    run_tests
    setup_monitoring
    
    if [ "$LAUNCH_MODE" = "production" ]; then
        deploy_seed_nodes
    fi
    
    setup_faucet
    setup_web_wallet
    start_blockchain_node
    start_mining
    validate_testnet
    generate_launch_summary
    
    # Success!
    celebrate_launch
}

# Parse command line arguments
case "${1:-launch}" in
    "launch"|"")
        main
        ;;
    "validate")
        validate_prerequisites
        ;;
    "build")
        build_components
        ;;
    "test")
        run_tests
        ;;
    "security")
        run_security_audit
        ;;
    "monitoring")
        setup_monitoring
        ;;
    "help")
        echo "BlackSilk Testnet Launch Orchestrator"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  launch     - Full testnet launch (default)"
        echo "  validate   - Validate prerequisites only"
        echo "  build      - Build components only"
        echo "  test       - Run tests only"
        echo "  security   - Run security audit only"
        echo "  monitoring - Setup monitoring only"
        echo "  help       - Show this help message"
        echo ""
        echo "Environment Variables:"
        echo "  LAUNCH_MODE=production|staging|development"
        echo "  SKIP_TESTS=true|false"
        echo "  SKIP_SECURITY=true|false"
        echo "  AUTO_DEPLOY=true|false"
        ;;
    *)
        error "Unknown command: $1"
        error "Use '$0 help' for usage information"
        exit 1
        ;;
esac
