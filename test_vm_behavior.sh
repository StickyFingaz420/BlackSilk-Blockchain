#!/bin/bash

echo "Testing RandomX VM behavior..."
echo "Running benchmark for 5 seconds to see the pattern..."

cd /workspaces/BlackSilk-Blockchain

# Run benchmark with timeout to see the exact behavior
timeout 5s ./target/release/blacksilk-miner benchmark 2>&1 | tee vm_test_output.log

echo ""
echo "Test complete. Analyzing output..."
echo ""

# Check for specific patterns
echo "=== Hash computation analysis ==="
grep "Computing hash" vm_test_output.log | head -10

echo ""
echo "=== Thread status analysis ==="
grep "Thread.*Starting\|Thread.*ended\|Thread.*Computing" vm_test_output.log

echo ""
echo "=== Total hash progression ==="
grep "Total:" vm_test_output.log

echo ""
echo "If threads are stopping after initial hashes, this indicates a VM execution issue."
