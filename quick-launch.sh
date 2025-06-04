#!/bin/bash

# BlackSilk Quick Launch Guide
# Helps users quickly start the BlackSilk blockchain components

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

success() {
    echo -e "${PURPLE}[SUCCESS] $1${NC}"
}

echo "🚀 BlackSilk Blockchain Quick Launch Guide"
echo "==========================================="

# Check if binaries exist
check_binaries() {
    log "Checking for built binaries..."
    
    BINARIES=("BlackSilk" "blacksilk-node" "blacksilk-miner" "blacksilk-marketplace" "wallet")
    MISSING=()
    
    for binary in "${BINARIES[@]}"; do
        if [ -f "target/release/$binary" ]; then
            info "✓ $binary found"
        else
            MISSING+=("$binary")
        fi
    done
    
    if [ ${#MISSING[@]} -ne 0 ]; then
        error "Missing binaries: ${MISSING[*]}"
        echo "Please run './build-full-project.sh' first to build all components."
        exit 1
    fi
    
    success "All binaries found!"
}

# Show launch options
show_launch_options() {
    echo
    log "Choose your launch option:"
    echo "1) 🏗️  Build everything first (recommended for first run)"
    echo "2) 🚀 Launch Testnet (single node)"
    echo "3) ⛏️  Launch Testnet with Miner"
    echo "4) 🛒 Launch Full Environment (Node + Miner + Marketplace + Frontend)"
    echo "5) 🌐 Launch Frontend Services Only"
    echo "6) 🔧 Launch Development Environment"
    echo "7) 📊 Show Running Processes"
    echo "8) 🛑 Stop All Services"
    echo "0) ❌ Exit"
    echo
}

# Build everything
build_all() {
    log "Building all BlackSilk components..."
    if [ -x "./build-full-project.sh" ]; then
        ./build-full-project.sh
    else
        error "build-full-project.sh not found or not executable"
        exit 1
    fi
}

# Launch testnet node only
launch_testnet() {
    log "Starting BlackSilk Testnet Node..."
    
    # Create data directory if it doesn't exist
    mkdir -p data/testnet
    
    info "Node will run on ports: 19333 (P2P), 19334 (RPC), 9090 (Metrics)"
    info "Starting node... (Press Ctrl+C to stop)"
    
    ./target/release/blacksilk-node \
        --testnet \
        --data-dir data/testnet \
        --config config/testnet/node_config.toml
}

# Launch testnet with miner
launch_testnet_with_miner() {
    log "Starting BlackSilk Testnet with Miner..."
    
    # Start node in background
    mkdir -p data/testnet logs
    
    info "Starting node in background..."
    nohup ./target/release/blacksilk-node \
        --testnet \
        --data-dir data/testnet \
        --config config/testnet/node_config.toml \
        > logs/node.log 2>&1 &
    
    NODE_PID=$!
    echo $NODE_PID > logs/node.pid
    
    sleep 3
    
    info "Starting miner..."
    info "Mining will begin shortly... (Press Ctrl+C to stop)"
    
    ./target/release/blacksilk-miner \
        --testnet \
        --config config/miner_config.toml \
        --threads 2
}

# Launch full environment
launch_full_environment() {
    log "Starting Full BlackSilk Environment..."
    
    mkdir -p data/testnet logs
    
    # Start node
    info "Starting blockchain node..."
    nohup ./target/release/blacksilk-node \
        --testnet \
        --data-dir data/testnet \
        --config config/testnet/node_config.toml \
        > logs/node.log 2>&1 &
    echo $! > logs/node.pid
    
    sleep 3
    
    # Start miner
    info "Starting miner..."
    nohup ./target/release/blacksilk-miner \
        --testnet \
        --config config/miner_config.toml \
        --threads 2 \
        > logs/miner.log 2>&1 &
    echo $! > logs/miner.pid
    
    sleep 2
    
    # Start wallet API
    info "Starting wallet API..."
    nohup ./target/release/wallet \
        --testnet \
        --config config/wallet_config.toml \
        --api-port 8080 \
        > logs/wallet.log 2>&1 &
    echo $! > logs/wallet.pid
    
    sleep 2
    
    # Start marketplace
    info "Starting marketplace..."
    nohup ./target/release/blacksilk-marketplace \
        --testnet \
        --config config/marketplace_config.toml \
        --port 3000 \
        > logs/marketplace.log 2>&1 &
    echo $! > logs/marketplace.pid
    
    sleep 3
    
    success "All services started!"
    echo
    echo "🌐 Access Points:"
    echo "  - Node RPC: http://localhost:19334"
    echo "  - Wallet API: http://localhost:8080"
    echo "  - Marketplace: http://localhost:3000"
    echo "  - Node Metrics: http://localhost:9090"
    echo
    echo "📊 Monitor logs:"
    echo "  - tail -f logs/node.log"
    echo "  - tail -f logs/miner.log"
    echo "  - tail -f logs/wallet.log"
    echo "  - tail -f logs/marketplace.log"
}

# Launch frontend services only
launch_frontend() {
    log "Starting Frontend Services..."
    
    # Check if node_modules exist
    if [ ! -d "testnet-faucet/node_modules" ]; then
        warn "Frontend dependencies not installed. Installing..."
        cd testnet-faucet && npm install && cd ..
    fi
    
    mkdir -p logs
    
    info "Starting Testnet Faucet on port 3000..."
    cd testnet-faucet
    nohup npm run start > ../logs/faucet.log 2>&1 &
    echo $! > ../logs/faucet.pid
    cd ..
    
    if [ -d "web-wallet/node_modules" ]; then
        info "Starting Web Wallet on port 3001..."
        cd web-wallet
        nohup npm run start > ../logs/web-wallet.log 2>&1 &
        echo $! > ../logs/web-wallet.pid
        cd ..
    fi
    
    if [ -d "block-explorer/node_modules" ]; then
        info "Starting Block Explorer on port 3002..."
        cd block-explorer
        nohup npm run start > ../logs/block-explorer.log 2>&1 &
        echo $! > ../logs/block-explorer.pid
        cd ..
    fi
    
    success "Frontend services started!"
    echo
    echo "🌐 Access Points:"
    echo "  - Testnet Faucet: http://localhost:3000"
    echo "  - Web Wallet: http://localhost:3001"
    echo "  - Block Explorer: http://localhost:3002"
}

# Show running processes
show_processes() {
    log "BlackSilk Running Processes:"
    
    if [ -f "logs/node.pid" ] && kill -0 $(cat logs/node.pid) 2>/dev/null; then
        info "✓ Node (PID: $(cat logs/node.pid))"
    else
        warn "✗ Node not running"
    fi
    
    if [ -f "logs/miner.pid" ] && kill -0 $(cat logs/miner.pid) 2>/dev/null; then
        info "✓ Miner (PID: $(cat logs/miner.pid))"
    else
        warn "✗ Miner not running"
    fi
    
    if [ -f "logs/wallet.pid" ] && kill -0 $(cat logs/wallet.pid) 2>/dev/null; then
        info "✓ Wallet API (PID: $(cat logs/wallet.pid))"
    else
        warn "✗ Wallet API not running"
    fi
    
    if [ -f "logs/marketplace.pid" ] && kill -0 $(cat logs/marketplace.pid) 2>/dev/null; then
        info "✓ Marketplace (PID: $(cat logs/marketplace.pid))"
    else
        warn "✗ Marketplace not running"
    fi
    
    echo
    info "System processes related to BlackSilk:"
    ps aux | grep -E "(blacksilk|wallet)" | grep -v grep || echo "No BlackSilk processes found"
}

# Stop all services
stop_services() {
    log "Stopping all BlackSilk services..."
    
    for service in node miner wallet marketplace faucet web-wallet block-explorer; do
        if [ -f "logs/$service.pid" ]; then
            PID=$(cat logs/$service.pid)
            if kill -0 $PID 2>/dev/null; then
                info "Stopping $service (PID: $PID)..."
                kill $PID
                rm logs/$service.pid
            fi
        fi
    done
    
    # Kill any remaining BlackSilk processes
    pkill -f "blacksilk" 2>/dev/null || true
    pkill -f "wallet" 2>/dev/null || true
    
    success "All services stopped!"
}

# Main menu loop
main() {
    while true; do
        show_launch_options
        read -p "Enter your choice (0-8): " choice
        
        case $choice in
            1)
                build_all
                ;;
            2)
                check_binaries
                launch_testnet
                ;;
            3)
                check_binaries
                launch_testnet_with_miner
                ;;
            4)
                check_binaries
                launch_full_environment
                ;;
            5)
                launch_frontend
                ;;
            6)
                info "Development environment: Use 'cargo run --bin <binary_name>' for live reloading"
                info "Available binaries: BlackSilk, blacksilk-node, blacksilk-miner, blacksilk-marketplace, wallet"
                ;;
            7)
                show_processes
                ;;
            8)
                stop_services
                ;;
            0)
                info "Goodbye!"
                exit 0
                ;;
            *)
                error "Invalid choice. Please enter 0-8."
                ;;
        esac
        
        echo
        read -p "Press Enter to continue..."
        clear
    done
}

# Run main function
main "$@"
