# BlackSilk Integration Tests

This directory contains comprehensive integration tests for the BlackSilk Blockchain ecosystem.

## Test Categories

### 1. End-to-End Tests (`e2e/`)
- Complete blockchain workflow testing
- Multi-node consensus testing
- Privacy feature validation
- Marketplace transaction flows

### 2. Smoke Tests (`smoke/`)
- Basic functionality verification
- Quick health checks
- Core component availability

### 3. Performance Tests (`performance/`)
- Mining benchmarks
- Network throughput testing
- Memory usage profiling
- Scalability testing

### 4. Security Tests (`security/`)
- Privacy feature validation
- Attack vector testing
- Cryptographic verification

## Running Tests

```bash
# Run all integration tests
cargo test --workspace --test integration_tests

# Run specific test categories
cargo test --test e2e_tests
cargo test --test smoke_tests
cargo test --test performance_tests
cargo test --test security_tests

# Run with specific environment
BLACKSILK_NETWORK=testnet cargo test --test e2e_tests

# Run performance benchmarks
cargo test --test performance_tests --release -- --nocapture
```

## Test Environment Setup

### Prerequisites
- Docker and Docker Compose
- Node.js and npm (for frontend tests)
- Python 3.8+ (for test scripts)

### Setup Test Environment
```bash
# Start test infrastructure
./scripts/setup-test-environment.sh

# Start test nodes
docker-compose -f tests/docker-compose.test.yml up -d

# Initialize test data
./scripts/init-test-data.sh
```

## Test Configuration

Tests use environment variables for configuration:

- `BLACKSILK_NETWORK`: Network to test against (testnet/regtest)
- `TEST_NODE_COUNT`: Number of nodes for multi-node tests
- `TEST_TIMEOUT`: Timeout for test operations
- `TEST_LOG_LEVEL`: Logging level for tests

## CI/CD Integration

Integration tests are automatically run in GitHub Actions:

- **PR Tests**: Smoke tests and critical e2e tests
- **Nightly Tests**: Full integration test suite
- **Release Tests**: Performance benchmarks and security tests
