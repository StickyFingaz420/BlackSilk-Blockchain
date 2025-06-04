#!/bin/bash

# Extract just the prerequisites validation function and test it
set -e

# Configuration from testnet-launch.sh
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
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

# Validate prerequisites
validate_prerequisites() {
    log "Validating Prerequisites"
    
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
        if netstat -tuln 2>/dev/null | grep -q ":$port "; then
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

# Run the validation
validate_prerequisites
