#!/bin/bash

# BlackSilk Blockchain Integration Tests
# Comprehensive testing suite for testnet validation

set -e

echo "🧪 BlackSilk Integration Tests"
echo "==============================="

# Configuration
TESTNET_PORT=${TESTNET_PORT:-8545}
FAUCET_PORT=${FAUCET_PORT:-3000}
WALLET_PORT=${WALLET_PORT:-3001}
EXPLORER_PORT=${EXPLORER_PORT:-3002}
TEST_TIMEOUT=${TEST_TIMEOUT:-300}

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
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

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()

test_result() {
    local test_name="$1"
    local result="$2"
    
    if [ "$result" = "PASS" ]; then
        log "✅ $test_name: PASSED"
        ((TESTS_PASSED++))
    else
        error "❌ $test_name: FAILED"
        ((TESTS_FAILED++))
        FAILED_TESTS+=("$test_name")
    fi
}

# Utility functions
wait_for_service() {
    local service_name="$1"
    local port="$2"
    local timeout="$3"
    
    log "Waiting for $service_name on port $port..."
    
    for i in $(seq 1 $timeout); do
        if curl -s http://localhost:$port/health >/dev/null 2>&1; then
            log "$service_name is ready"
            return 0
        fi
        sleep 1
    done
    
    error "$service_name failed to start within $timeout seconds"
    return 1
}

# Test 1: Node connectivity and health
test_node_health() {
    log "Testing node health and connectivity..."
    
    local response
    if response=$(curl -s -w "%{http_code}" http://localhost:$TESTNET_PORT/health); then
        local status_code="${response: -3}"
        if [ "$status_code" = "200" ]; then
            test_result "Node Health Check" "PASS"
            return 0
        fi
    fi
    
    test_result "Node Health Check" "FAIL"
    return 1
}

# Test 2: Peer discovery and networking
test_peer_discovery() {
    log "Testing peer discovery..."
    
    local response
    if response=$(curl -s http://localhost:$TESTNET_PORT/api/peers); then
        local peer_count=$(echo "$response" | jq '.peers | length' 2>/dev/null || echo "0")
        if [ "$peer_count" -gt 0 ]; then
            log "Found $peer_count peers"
            test_result "Peer Discovery" "PASS"
            return 0
        fi
    fi
    
    test_result "Peer Discovery" "FAIL"
    return 1
}

# Test 3: Block production and synchronization
test_block_production() {
    log "Testing block production..."
    
    local initial_height
    if initial_height=$(curl -s http://localhost:$TESTNET_PORT/api/latest_block | jq '.height' 2>/dev/null); then
        sleep 30  # Wait for block production
        
        local new_height
        if new_height=$(curl -s http://localhost:$TESTNET_PORT/api/latest_block | jq '.height' 2>/dev/null); then
            if [ "$new_height" -gt "$initial_height" ]; then
                log "Block height increased from $initial_height to $new_height"
                test_result "Block Production" "PASS"
                return 0
            fi
        fi
    fi
    
    test_result "Block Production" "FAIL"
    return 1
}

# Test 4: Transaction processing
test_transaction_processing() {
    log "Testing transaction processing..."
    
    # Create test transaction
    local tx_data='{"from":"test_address","to":"another_address","amount":100,"fee":1}'
    local response
    
    if response=$(curl -s -X POST -H "Content-Type: application/json" \
                       -d "$tx_data" http://localhost:$TESTNET_PORT/api/submit_transaction); then
        local tx_hash=$(echo "$response" | jq -r '.tx_hash' 2>/dev/null)
        
        if [ "$tx_hash" != "null" ] && [ -n "$tx_hash" ]; then
            log "Transaction submitted with hash: $tx_hash"
            
            # Wait for transaction confirmation
            sleep 10
            
            if curl -s http://localhost:$TESTNET_PORT/api/transaction/$tx_hash | jq '.confirmed' | grep -q "true"; then
                test_result "Transaction Processing" "PASS"
                return 0
            fi
        fi
    fi
    
    test_result "Transaction Processing" "FAIL"
    return 1
}

# Test 5: Faucet functionality
test_faucet() {
    log "Testing faucet functionality..."
    
    if ! wait_for_service "Faucet" $FAUCET_PORT 30; then
        test_result "Faucet Service" "FAIL"
        return 1
    fi
    
    # Test faucet request
    local test_address="test_faucet_address_$(date +%s)"
    local response
    
    if response=$(curl -s -X POST -H "Content-Type: application/json" \
                       -d "{\"address\":\"$test_address\"}" \
                       http://localhost:$FAUCET_PORT/api/faucet/request); then
        local success=$(echo "$response" | jq -r '.success' 2>/dev/null)
        
        if [ "$success" = "true" ]; then
            test_result "Faucet Request" "PASS"
            return 0
        fi
    fi
    
    test_result "Faucet Request" "FAIL"
    return 1
}

# Test 6: Web wallet functionality
test_web_wallet() {
    log "Testing web wallet functionality..."
    
    if ! wait_for_service "Web Wallet" $WALLET_PORT 30; then
        test_result "Web Wallet Service" "FAIL"
        return 1
    fi
    
    # Test wallet creation
    local response
    if response=$(curl -s http://localhost:$WALLET_PORT/api/wallet/create); then
        local mnemonic=$(echo "$response" | jq -r '.mnemonic' 2>/dev/null)
        
        if [ -n "$mnemonic" ] && [ "$mnemonic" != "null" ]; then
            log "Wallet created successfully"
            test_result "Web Wallet Creation" "PASS"
            return 0
        fi
    fi
    
    test_result "Web Wallet Creation" "FAIL"
    return 1
}

# Test 7: Mining functionality
test_mining() {
    log "Testing mining functionality..."
    
    # Check if mining is active
    local response
    if response=$(curl -s http://localhost:$TESTNET_PORT/api/mining/status); then
        local is_mining=$(echo "$response" | jq -r '.is_mining' 2>/dev/null)
        
        if [ "$is_mining" = "true" ]; then
            log "Mining is active"
            test_result "Mining Status" "PASS"
            return 0
        fi
    fi
    
    test_result "Mining Status" "FAIL"
    return 1
}

# Test 8: Privacy features
test_privacy_features() {
    log "Testing privacy features..."
    
    # Test private transaction creation
    local private_tx='{"type":"private","amount":50,"recipient":"privacy_test_address"}'
    local response
    
    if response=$(curl -s -X POST -H "Content-Type: application/json" \
                       -d "$private_tx" http://localhost:$TESTNET_PORT/api/private_transaction); then
        local success=$(echo "$response" | jq -r '.success' 2>/dev/null)
        
        if [ "$success" = "true" ]; then
            test_result "Privacy Features" "PASS"
            return 0
        fi
    fi
    
    test_result "Privacy Features" "FAIL"
    return 1
}

# Test 9: API rate limiting
test_rate_limiting() {
    log "Testing API rate limiting..."
    
    local success_count=0
    local rate_limited=false
    
    # Make rapid requests to test rate limiting
    for i in {1..20}; do
        local response
        if response=$(curl -s -w "%{http_code}" http://localhost:$TESTNET_PORT/api/latest_block); then
            local status_code="${response: -3}"
            
            if [ "$status_code" = "429" ]; then
                rate_limited=true
                break
            elif [ "$status_code" = "200" ]; then
                ((success_count++))
            fi
        fi
        sleep 0.1
    done
    
    if [ "$rate_limited" = true ]; then
        log "Rate limiting is working (triggered after $success_count requests)"
        test_result "Rate Limiting" "PASS"
        return 0
    fi
    
    test_result "Rate Limiting" "FAIL"
    return 1
}

# Test 10: Security headers and HTTPS
test_security() {
    log "Testing security headers..."
    
    local response
    if response=$(curl -s -I http://localhost:$TESTNET_PORT/); then
        local has_security_headers=true
        
        # Check for essential security headers
        if ! echo "$response" | grep -qi "X-Frame-Options"; then
            has_security_headers=false
        fi
        
        if ! echo "$response" | grep -qi "X-Content-Type-Options"; then
            has_security_headers=false
        fi
        
        if [ "$has_security_headers" = true ]; then
            test_result "Security Headers" "PASS"
            return 0
        fi
    fi
    
    test_result "Security Headers" "FAIL"
    return 1
}

# Load testing
test_load_performance() {
    log "Running load performance tests..."
    
    if ! command -v ab >/dev/null 2>&1; then
        warn "Apache Bench (ab) not found, skipping load tests"
        test_result "Load Performance" "SKIP"
        return 0
    fi
    
    # Light load test - 100 requests with 10 concurrent
    local ab_output
    if ab_output=$(ab -n 100 -c 10 http://localhost:$TESTNET_PORT/api/latest_block 2>&1); then
        local success_rate=$(echo "$ab_output" | grep "Non-2xx responses:" | awk '{print $3}' || echo "0")
        
        if [ "${success_rate:-0}" -eq 0 ]; then
            log "Load test passed - 100% success rate"
            test_result "Load Performance" "PASS"
            return 0
        fi
    fi
    
    test_result "Load Performance" "FAIL"
    return 1
}

# Database integrity test
test_database_integrity() {
    log "Testing database integrity..."
    
    # Check blockchain data consistency
    local response
    if response=$(curl -s http://localhost:$TESTNET_PORT/api/chain/validate); then
        local is_valid=$(echo "$response" | jq -r '.is_valid' 2>/dev/null)
        
        if [ "$is_valid" = "true" ]; then
            test_result "Database Integrity" "PASS"
            return 0
        fi
    fi
    
    test_result "Database Integrity" "FAIL"
    return 1
}

# Main test execution
run_all_tests() {
    log "Starting comprehensive integration tests..."
    
    # Core functionality tests
    test_node_health
    test_peer_discovery
    test_block_production
    test_transaction_processing
    test_mining
    test_database_integrity
    
    # Service tests
    test_faucet
    test_web_wallet
    
    # Security and performance tests
    test_privacy_features
    test_rate_limiting
    test_security
    test_load_performance
    
    # Summary
    echo ""
    log "Integration Test Results:"
    log "========================="
    log "Tests Passed: $TESTS_PASSED"
    error "Tests Failed: $TESTS_FAILED"
    
    if [ $TESTS_FAILED -gt 0 ]; then
        echo ""
        error "Failed Tests:"
        for test in "${FAILED_TESTS[@]}"; do
            error "  - $test"
        done
        echo ""
        error "Some tests failed. Please review the issues before proceeding to testnet launch."
        exit 1
    else
        echo ""
        log "🎉 All integration tests passed! The testnet is ready for launch."
        exit 0
    fi
}

# Cleanup function
cleanup() {
    log "Cleaning up test environment..."
    # Add any necessary cleanup here
}

# Trap cleanup on exit
trap cleanup EXIT

# Parse command line arguments
case "${1:-all}" in
    "node")
        test_node_health
        test_peer_discovery
        test_block_production
        ;;
    "services")
        test_faucet
        test_web_wallet
        ;;
    "security")
        test_privacy_features
        test_security
        test_rate_limiting
        ;;
    "performance")
        test_load_performance
        ;;
    "all"|*)
        run_all_tests
        ;;
esac
