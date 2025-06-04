#!/bin/bash

# BlackSilk Complete Build Script
# Builds all components of the BlackSilk blockchain project

set -e

echo "🏗️  BlackSilk Complete Build Script"
echo "=================================="

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check Rust version
    if ! command -v rustc &> /dev/null; then
        error "Rust not found. Please install Rust 1.77+ from https://rustup.rs/"
        exit 1
    fi
    
    RUST_VERSION=$(rustc --version | grep -oP '\d+\.\d+' | head -1)
    MAJOR=$(echo $RUST_VERSION | cut -d. -f1)
    MINOR=$(echo $RUST_VERSION | cut -d. -f2)
    
    if [ "$MAJOR" -lt 1 ] || ([ "$MAJOR" -eq 1 ] && [ "$MINOR" -lt 77 ]); then
        error "Rust version $RUST_VERSION found. BlackSilk requires Rust 1.77+ for Cargo.lock v4 support"
        exit 1
    fi
    
    info "✓ Rust $RUST_VERSION detected"
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        warn "Node.js not found. Frontend services will be skipped."
        warn "Install Node.js 18+ from https://nodejs.org/ to build frontend components"
        SKIP_FRONTEND=true
    else
        NODE_VERSION=$(node --version | grep -oP '\d+' | head -1)
        if [ "$NODE_VERSION" -lt 18 ]; then
            warn "Node.js version $NODE_VERSION found. Recommended: 18+"
        fi
        info "✓ Node.js $(node --version) detected"
    fi
    
    # Check Cargo
    if ! command -v cargo &> /dev/null; then
        error "Cargo not found. Please ensure Rust is properly installed."
        exit 1
    fi
    
    info "✓ Cargo $(cargo --version | grep -oP '\d+\.\d+\.\d+') detected"
}

# Build Rust components
build_rust_components() {
    log "Building Rust blockchain components..."
    
    info "Building all binaries in release mode..."
    if cargo build --release --bins; then
        log "✓ Rust components built successfully"
    else
        error "Failed to build Rust components"
        exit 1
    fi
    
    # Verify binaries
    log "Verifying built binaries..."
    
    EXPECTED_BINARIES=("BlackSilk" "blacksilk-node" "blacksilk-miner" "blacksilk-marketplace" "wallet")
    MISSING_BINARIES=()
    
    for binary in "${EXPECTED_BINARIES[@]}"; do
        if [ -f "target/release/$binary" ]; then
            info "✓ $binary ($(ls -lh target/release/$binary | awk '{print $5}'))"
        else
            MISSING_BINARIES+=("$binary")
        fi
    done
    
    if [ ${#MISSING_BINARIES[@]} -ne 0 ]; then
        error "Missing binaries: ${MISSING_BINARIES[*]}"
        exit 1
    fi
    
    log "✓ All core blockchain binaries built successfully"
}

# Build frontend components
build_frontend_components() {
    if [ "$SKIP_FRONTEND" = true ]; then
        warn "Skipping frontend builds (Node.js not available)"
        return
    fi
    
    log "Building frontend components..."
    
    # Testnet Faucet
    if [ -d "testnet-faucet" ]; then
        info "Building Testnet Faucet..."
        cd testnet-faucet
        if npm install && npm run build 2>/dev/null; then
            info "✓ Testnet Faucet built"
        else
            warn "Testnet Faucet build failed or no build script"
        fi
        cd ..
    fi
    
    # Block Explorer
    if [ -d "block-explorer" ]; then
        info "Building Block Explorer..."
        cd block-explorer
        if npm install && npm run build 2>/dev/null; then
            info "✓ Block Explorer built"
        else
            warn "Block Explorer build failed or no build script"
        fi
        cd ..
    fi
    
    # Web Wallet
    if [ -d "web-wallet" ]; then
        info "Building Web Wallet..."
        cd web-wallet
        if npm install && npm run build 2>/dev/null; then
            info "✓ Web Wallet built"
        else
            warn "Web Wallet build failed or no build script"
        fi
        cd ..
    fi
    
    # Marketplace Frontend
    if [ -d "marketplace/frontend" ]; then
        info "Building Marketplace Frontend..."
        cd marketplace/frontend
        if npm install && npm run build 2>/dev/null; then
            info "✓ Marketplace Frontend built"
        else
            warn "Marketplace Frontend build failed or no build script"
        fi
        cd ../..
    fi
    
    log "✓ Frontend components build completed"
}

# Display build summary
show_build_summary() {
    log "Build Summary"
    echo "============="
    
    echo "📦 Core Blockchain Binaries:"
    for binary in target/release/BlackSilk target/release/blacksilk-node target/release/blacksilk-miner target/release/blacksilk-marketplace target/release/wallet; do
        if [ -f "$binary" ]; then
            echo "  ✓ $binary ($(ls -lh $binary | awk '{print $5}'))"
        fi
    done
    
    if [ "$SKIP_FRONTEND" != true ]; then
        echo
        echo "🌐 Frontend Services:"
        for dir in testnet-faucet block-explorer web-wallet marketplace/frontend; do
            if [ -d "$dir/node_modules" ]; then
                echo "  ✓ $dir (dependencies installed)"
            fi
        done
    fi
    
    echo
    echo "🚀 Next Steps:"
    echo "  1. Run './target/release/blacksilk-node --testnet' to start the blockchain"
    echo "  2. Run './target/release/blacksilk-miner --testnet' to start mining"
    echo "  3. Run './target/release/wallet --help' for wallet commands"
    echo "  4. Check README.md for complete launch instructions"
    
    if [ "$SKIP_FRONTEND" != true ]; then
        echo "  5. Use 'npm run start' in frontend directories to launch services"
    fi
}

# Main execution
main() {
    check_prerequisites
    build_rust_components
    build_frontend_components
    show_build_summary
    
    log "🎉 BlackSilk build completed successfully!"
}

# Run main function
main "$@"
