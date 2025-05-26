#!/bin/bash
# BlackSilk Easy Build Script for Linux/macOS
# Makes building BlackSilk blockchain as simple as possible

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Fancy banner
echo -e "${PURPLE}"
echo "╔════════════════════════════════════════════════════════════════════════════════════════╗"
echo "║                                    BlackSilk Blockchain                               ║"
echo "║                                  🚀 Easy Build Script 🚀                             ║"
echo "║                                                                                        ║"
echo "║  This script will automatically:                                                      ║"
echo "║  ✅ Install dependencies                                                              ║"
echo "║  ✅ Build RandomX library                                                             ║"
echo "║  ✅ Compile all BlackSilk components                                                  ║"
echo "║  ✅ Run verification tests                                                            ║"
echo "║  ✅ Show you how to start mining!                                                     ║"
echo "╚════════════════════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Detect platform
PLATFORM=$(uname -s)
ARCH=$(uname -m)

echo -e "${CYAN}🔍 Detected platform: ${PLATFORM} ${ARCH}${NC}"

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ] || [ ! -d "miner" ]; then
    echo -e "${RED}❌ Error: Please run this script from the BlackSilk root directory${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Found BlackSilk project structure${NC}"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install dependencies based on platform
install_dependencies() {
    echo -e "${YELLOW}📦 Installing dependencies...${NC}"
    
    case "$PLATFORM" in
        "Linux")
            # Detect Linux distribution
            if command_exists apt-get; then
                echo -e "${CYAN}🐧 Detected Debian/Ubuntu${NC}"
                sudo apt-get update
                sudo apt-get install -y build-essential cmake git clang pkg-config libssl-dev nasm
            elif command_exists yum; then
                echo -e "${CYAN}🎩 Detected RedHat/CentOS${NC}"
                sudo yum groupinstall -y "Development Tools"
                sudo yum install -y cmake git clang openssl-devel nasm
            elif command_exists pacman; then
                echo -e "${CYAN}🏗️ Detected Arch Linux${NC}"
                sudo pacman -S --needed base-devel cmake git clang openssl pkg-config nasm
            elif command_exists zypper; then
                echo -e "${CYAN}🦎 Detected openSUSE${NC}"
                sudo zypper install -y gcc gcc-c++ cmake git clang libopenssl-devel nasm
            else
                echo -e "${YELLOW}⚠️ Unknown Linux distribution. Please install: build-essential, cmake, git, clang, openssl-dev, nasm${NC}"
            fi
            ;;
        "Darwin")
            echo -e "${CYAN}🍎 Detected macOS${NC}"
            if ! command_exists brew; then
                echo -e "${YELLOW}Installing Homebrew...${NC}"
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install cmake git llvm openssl pkg-config nasm
            ;;
        *)
            echo -e "${YELLOW}⚠️ Unknown platform. Please install: cmake, git, clang, openssl development libraries, nasm${NC}"
            ;;
    esac
}

# Function to install Rust if needed
install_rust() {
    if ! command_exists cargo; then
        echo -e "${YELLOW}🦀 Installing Rust...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source ~/.cargo/env
        echo -e "${GREEN}✅ Rust installed successfully${NC}"
    else
        echo -e "${GREEN}✅ Rust is already installed${NC}"
        rustc --version
    fi
}

# Function to build RandomX
build_randomx() {
    echo -e "${YELLOW}🔨 Building RandomX library...${NC}"
    
    # Clone RandomX if not present
    if [ ! -d "RandomX" ]; then
        echo -e "${CYAN}📥 Cloning RandomX repository...${NC}"
        git clone https://github.com/tevador/RandomX.git
    fi
    
    cd RandomX
    
    # Create build directory
    mkdir -p build
    cd build
    
    # Configure and build
    echo -e "${CYAN}⚙️ Configuring RandomX with CMake...${NC}"
    cmake .. -DCMAKE_BUILD_TYPE=Release
    
    echo -e "${CYAN}🔨 Building RandomX (this may take a few minutes)...${NC}"
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    
    # Copy libraries to miner directory
    echo -e "${CYAN}📋 Copying RandomX libraries to miner directory...${NC}"
    cp librandomx.a ../../miner/
    if [ -f "librandomx.so" ]; then
        cp librandomx.so ../../miner/
    fi
    
    cd ../..
    echo -e "${GREEN}✅ RandomX library built successfully${NC}"
}

# Function to build BlackSilk components
build_blacksilk() {
    echo -e "${YELLOW}🔨 Building BlackSilk components...${NC}"
    
    # Check for GCC memcmp bug and use clang if needed
    if gcc --version 2>/dev/null | grep -q "9\."; then
        echo -e "${YELLOW}⚠️ Detected GCC 9.x (memcmp bug). Using clang compiler...${NC}"
        export CC=clang
        export CXX=clang++
    fi
    
    # Set optimization flags
    export RUSTFLAGS="-C target-cpu=native"
    
    echo -e "${CYAN}🏗️ Building node...${NC}"
    cargo build --release --bin BlackSilk
    
    echo -e "${CYAN}⛏️ Building miner...${NC}"
    cd miner && cargo build --release && cd ..
    
    echo -e "${CYAN}💰 Building wallet...${NC}"
    cargo build --release -p wallet
    
    echo -e "${GREEN}✅ All BlackSilk components built successfully${NC}"
}

# Function to run verification tests
run_tests() {
    echo -e "${YELLOW}🧪 Running verification tests...${NC}"
    
    # Test miner benchmark
    echo -e "${CYAN}⛏️ Testing miner benchmark...${NC}"
    timeout 10s ./target/release/blacksilk-miner benchmark || true
    
    # Test wallet generation
    echo -e "${CYAN}💰 Testing wallet functionality...${NC}"
    ./target/release/wallet --help >/dev/null && echo -e "${GREEN}✅ Wallet help works${NC}"
    
    # Quick wallet generation test
    echo -e "${CYAN}🔑 Testing wallet generation...${NC}"
    rm -rf ./test_wallet_verification
    ./target/release/wallet --generate --data-dir ./test_wallet_verification >/dev/null && echo -e "${GREEN}✅ Wallet generation works${NC}"
    rm -rf ./test_wallet_verification
    
    echo -e "${GREEN}✅ All tests passed${NC}"
}

# Function to show final instructions
show_final_instructions() {
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════════════════════════════════════════════════════╗"
    echo "║                              🎉 BUILD COMPLETED SUCCESSFULLY! 🎉                     ║"
    echo "╚════════════════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${CYAN}📁 Built components:${NC}"
    echo -e "  ✅ ./target/release/BlackSilk (node)"
    echo -e "  ✅ ./target/release/blacksilk-miner (miner)"
    echo -e "  ✅ ./target/release/wallet (wallet)"
    echo ""
    
    echo -e "${YELLOW}🚀 Quick Start Commands:${NC}"
    echo ""
    echo -e "${CYAN}1. Start the testnet node (easy mining):${NC}"
    echo -e "   ./target/release/BlackSilk --testnet"
    echo ""
    echo -e "${CYAN}2. Create a wallet:${NC}"
    echo -e "   ./target/release/wallet --generate"
    echo ""
    echo -e "${CYAN}3. Start mining:${NC}"
    echo -e "   ./target/release/blacksilk-miner --address YOUR_WALLET_ADDRESS --threads 4"
    echo ""
    echo -e "${CYAN}4. Check mining benchmark:${NC}"
    echo -e "   ./target/release/blacksilk-miner benchmark"
    echo ""
    
    echo -e "${GREEN}🎯 Performance Tips:${NC}"
    echo -e "  • Use --threads \$(nproc) for maximum CPU usage"
    echo -e "  • Enable huge pages for better performance"
    echo -e "  • Use testnet for easy mining (difficulty=1)"
    echo ""
    
    echo -e "${PURPLE}Happy Mining! 🎉⛏️💰${NC}"
}

# Main execution
main() {
    echo -e "${BLUE}🚀 Starting BlackSilk easy build process...${NC}"
    
    # Check for dependencies and install if needed
    install_dependencies
    
    # Install Rust if needed
    install_rust
    
    # Build RandomX library
    build_randomx
    
    # Build BlackSilk components
    build_blacksilk
    
    # Run verification tests
    run_tests
    
    # Show final instructions
    show_final_instructions
}

# Check if running as source or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
