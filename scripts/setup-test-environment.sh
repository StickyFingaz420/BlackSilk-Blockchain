#!/bin/bash

# BlackSilk Test Environment Setup Script
# Sets up the complete testing infrastructure

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTS_DIR="$PROJECT_ROOT/tests"

echo "🚀 Setting up BlackSilk test environment..."

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
echo "📋 Checking prerequisites..."

if ! command_exists docker; then
    echo "❌ Docker is required but not installed"
    exit 1
fi

if ! command_exists docker-compose; then
    echo "❌ Docker Compose is required but not installed"
    exit 1
fi

if ! command_exists cargo; then
    echo "❌ Rust/Cargo is required but not installed"
    exit 1
fi

echo "✅ Prerequisites satisfied"

# Build test images
echo "🔨 Building test Docker images..."
cd "$PROJECT_ROOT"

# Build node image
docker build -t blacksilk-node:test -f - . <<'EOF'
FROM rust:1.70-slim as builder

WORKDIR /app
COPY . .
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo build --release --bin blacksilk-node

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/blacksilk-node /usr/local/bin/
CMD ["blacksilk-node"]
EOF

# Build marketplace image
docker build -t blacksilk-marketplace:test -f - . <<'EOF'
FROM rust:1.70-slim as builder

WORKDIR /app
COPY . .
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo build --release --bin blacksilk-marketplace

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/blacksilk-marketplace /usr/local/bin/
CMD ["blacksilk-marketplace"]
EOF

# Create test network configuration
echo "🌐 Setting up test network configuration..."
mkdir -p "$TESTS_DIR/config"

cat > "$TESTS_DIR/config/regtest_chain_spec.json" <<'EOF'
{
  "chain_name": "BlackSilk Regtest",
  "network_id": "regtest",
  "genesis": {
    "timestamp": 1640995200,
    "difficulty": 1,
    "nonce": 0,
    "coinbase_reward": 5000000000,
    "initial_supply": 0
  },
  "consensus": {
    "block_time_seconds": 10,
    "difficulty_adjustment_blocks": 10,
    "max_block_size": 2097152,
    "emission": {
      "initial_reward": 5000000000,
      "halving_blocks": 100,
      "final_subsidy": 0
    }
  },
  "network": {
    "p2p_port": 18080,
    "rpc_port": 18081,
    "max_peers": 50,
    "seed_nodes": []
  },
  "privacy": {
    "ring_size_min": 3,
    "ring_size_max": 16,
    "stealth_addresses": true,
    "confidential_amounts": true
  }
}
EOF

# Create nginx configuration for load balancing
echo "⚖️ Setting up load balancer configuration..."
mkdir -p "$TESTS_DIR/nginx"

cat > "$TESTS_DIR/nginx/nginx.conf" <<'EOF'
events {
    worker_connections 1024;
}

http {
    upstream blacksilk_nodes {
        server test-node-1:18081;
        server test-node-2:18091;
        server test-node-3:18101;
    }

    upstream blacksilk_marketplace {
        server test-marketplace:3001;
    }

    server {
        listen 80;
        server_name localhost;

        location /api/node/ {
            proxy_pass http://blacksilk_nodes/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location /api/marketplace/ {
            proxy_pass http://blacksilk_marketplace/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
}
EOF

# Create database initialization script
echo "🗄️ Setting up test database..."
mkdir -p "$TESTS_DIR/sql"

cat > "$TESTS_DIR/sql/init.sql" <<'EOF'
-- BlackSilk Test Database Initialization

CREATE DATABASE blacksilk_test;

\c blacksilk_test;

-- Products table
CREATE TABLE products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seller VARCHAR(255) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    price BIGINT NOT NULL,
    category VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'active'
);

-- Orders table
CREATE TABLE orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id UUID REFERENCES products(id),
    buyer VARCHAR(255) NOT NULL,
    seller VARCHAR(255) NOT NULL,
    amount BIGINT NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    escrow_contract_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Escrow contracts table
CREATE TABLE escrow_contracts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_id VARCHAR(255) UNIQUE NOT NULL,
    buyer VARCHAR(255) NOT NULL,
    seller VARCHAR(255) NOT NULL,
    amount BIGINT NOT NULL,
    status VARCHAR(50) DEFAULT 'created',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert test data
INSERT INTO products (seller, title, description, price, category) VALUES
    ('test_seller_1', 'Test Digital Product', 'A test digital product for integration testing', 1000000, 'digital'),
    ('test_seller_2', 'Test Physical Product', 'A test physical product for integration testing', 2000000, 'physical'),
    ('test_seller_3', 'Test Service', 'A test service for integration testing', 500000, 'services');

-- Create indexes for performance
CREATE INDEX idx_products_category ON products(category);
CREATE INDEX idx_products_seller ON products(seller);
CREATE INDEX idx_orders_buyer ON orders(buyer);
CREATE INDEX idx_orders_seller ON orders(seller);
CREATE INDEX idx_escrow_status ON escrow_contracts(status);
EOF

# Setup test data directory
echo "📁 Setting up test data directories..."
mkdir -p "$TESTS_DIR/data/nodes"
mkdir -p "$TESTS_DIR/data/marketplace"
mkdir -p "$TESTS_DIR/data/logs"

# Create test runner script
echo "🧪 Creating test runner script..."
cat > "$TESTS_DIR/run-tests.sh" <<'EOF'
#!/bin/bash

set -e

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"

echo "🧪 Running BlackSilk integration tests..."

# Start test environment
echo "🚀 Starting test environment..."
cd "$TESTS_DIR"
docker-compose -f docker-compose.test.yml up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 30

# Check service health
echo "🏥 Checking service health..."
for i in {1..30}; do
    if curl -s http://localhost:18081/health > /dev/null; then
        echo "✅ Node 1 is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ Node 1 failed to start"
        exit 1
    fi
    sleep 2
done

for i in {1..30}; do
    if curl -s http://localhost:3001/health > /dev/null; then
        echo "✅ Marketplace is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ Marketplace failed to start"
        exit 1
    fi
    sleep 2
done

# Run tests
echo "🔍 Running smoke tests..."
cd "$PROJECT_ROOT"
export TEST_NODE_URL="http://localhost:18081"
export TEST_MARKETPLACE_URL="http://localhost:3001"
cargo test --test smoke_tests -- --nocapture

echo "🔍 Running e2e tests..."
cargo test --test e2e_tests -- --nocapture

echo "🔍 Running security tests..."
cargo test --test security_tests -- --nocapture

if [ "$1" = "--performance" ]; then
    echo "🔍 Running performance tests..."
    cargo test --test performance_tests --release -- --nocapture
fi

# Cleanup
echo "🧹 Cleaning up test environment..."
cd "$TESTS_DIR"
docker-compose -f docker-compose.test.yml down -v

echo "✅ All tests completed successfully!"
EOF

chmod +x "$TESTS_DIR/run-tests.sh"

# Create Cargo.toml for integration tests
echo "📦 Setting up test dependencies..."
cat > "$TESTS_DIR/Cargo.toml" <<'EOF'
[package]
name = "blacksilk-integration-tests"
version = "0.1.0"
edition = "2021"

[[test]]
name = "e2e_tests"
path = "integration/e2e/mod.rs"

[[test]]
name = "smoke_tests"
path = "integration/smoke/mod.rs"

[[test]]
name = "performance_tests"
path = "integration/performance/mod.rs"

[[test]]
name = "security_tests"
path = "integration/security/mod.rs"

[dependencies]
tokio = { version = "1.0", features = ["full"] }
reqwest = { version = "0.11", features = ["json"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tempfile = "3.0"
criterion = { version = "0.5", features = ["html_reports"] }

[dev-dependencies]
tokio-test = "0.4"
EOF

# Create GitHub Actions workflow for integration tests
echo "🔄 Setting up CI/CD integration..."
mkdir -p "$PROJECT_ROOT/.github/workflows"

cat > "$PROJECT_ROOT/.github/workflows/integration-tests.yml" <<'EOF'
name: Integration Tests

on:
  pull_request:
    branches: [ main, develop ]
  push:
    branches: [ main, develop ]
  schedule:
    # Run nightly at 2 AM UTC
    - cron: '0 2 * * *'

env:
  CARGO_TERM_COLOR: always

jobs:
  smoke-tests:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        network: [testnet, regtest]
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        override: true
    
    - name: Cache cargo registry
      uses: actions/cache@v3
      with:
        path: ~/.cargo/registry
        key: ${{ runner.os }}-cargo-registry-${{ hashFiles('**/Cargo.lock') }}
    
    - name: Cache cargo index
      uses: actions/cache@v3
      with:
        path: ~/.cargo/git
        key: ${{ runner.os }}-cargo-index-${{ hashFiles('**/Cargo.lock') }}
    
    - name: Setup test environment
      run: ./scripts/setup-test-environment.sh
    
    - name: Run smoke tests
      env:
        BLACKSILK_NETWORK: ${{ matrix.network }}
      run: |
        cd tests
        ./run-tests.sh --smoke-only

  e2e-tests:
    runs-on: ubuntu-latest
    needs: smoke-tests
    if: github.event_name != 'schedule'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        override: true
    
    - name: Setup test environment
      run: ./scripts/setup-test-environment.sh
    
    - name: Run E2E tests
      run: |
        cd tests
        ./run-tests.sh --e2e-only

  security-tests:
    runs-on: ubuntu-latest
    needs: smoke-tests
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        override: true
    
    - name: Setup test environment
      run: ./scripts/setup-test-environment.sh
    
    - name: Run security tests
      run: |
        cd tests
        ./run-tests.sh --security-only

  performance-tests:
    runs-on: ubuntu-latest
    needs: smoke-tests
    if: github.event_name == 'schedule' || contains(github.event.head_commit.message, '[performance]')
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        override: true
    
    - name: Setup test environment
      run: ./scripts/setup-test-environment.sh
    
    - name: Run performance tests
      run: |
        cd tests
        ./run-tests.sh --performance

    - name: Upload performance results
      uses: actions/upload-artifact@v3
      with:
        name: performance-results
        path: tests/target/criterion/

  full-integration:
    runs-on: ubuntu-latest
    needs: [smoke-tests, e2e-tests, security-tests]
    if: github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        override: true
    
    - name: Setup test environment
      run: ./scripts/setup-test-environment.sh
    
    - name: Run full integration test suite
      run: |
        cd tests
        ./run-tests.sh --full

    - name: Upload test logs
      if: failure()
      uses: actions/upload-artifact@v3
      with:
        name: test-logs
        path: tests/data/logs/
EOF

echo "✅ Test environment setup completed!"
echo ""
echo "📝 Next steps:"
echo "   1. Run smoke tests: cd tests && ./run-tests.sh --smoke-only"
echo "   2. Run full test suite: cd tests && ./run-tests.sh"
echo "   3. Run with performance tests: cd tests && ./run-tests.sh --performance"
echo ""
echo "🌐 Test services will be available at:"
echo "   - Node 1: http://localhost:18081"
echo "   - Node 2: http://localhost:18091" 
echo "   - Node 3: http://localhost:18101"
echo "   - Marketplace: http://localhost:3001"
echo "   - Load Balancer: http://localhost:8080"
echo "   - Prometheus: http://localhost:9091"
echo "   - Grafana: http://localhost:3001 (admin/test123)"
