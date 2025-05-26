#!/bin/bash
# BlackSilk RandomX Setup Script
# This script sets up RandomX for building the BlackSilk miner

set -e

echo "🔧 Setting up RandomX for BlackSilk..."

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "❌ Error: Run this script from the BlackSilk root directory"
    exit 1
fi

# Create RandomX directory if it doesn't exist
if [ ! -d "RandomX" ]; then
    echo "📁 Creating RandomX directory..."
    mkdir -p RandomX
fi

cd RandomX

# Clone RandomX if not already present
if [ ! -d ".git" ]; then
    echo "📥 Cloning RandomX repository..."
    git clone https://github.com/tevador/RandomX.git .
else
    echo "📥 Updating RandomX repository..."
    git pull
fi

echo "🔧 RandomX setup complete!"
echo ""
echo "Next steps:"
echo "1. For Linux: Install development dependencies and build RandomX"
echo "2. For Windows: Use Visual Studio to build RandomX and generate .lib files"
echo "3. Run 'cargo build --release -p blacksilk-miner' to build the miner"
echo ""
echo "See README.md for detailed build instructions."
