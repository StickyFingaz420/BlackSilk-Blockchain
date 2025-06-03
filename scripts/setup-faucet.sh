#!/bin/bash

# BlackSilk Testnet Faucet Service Script
# Automates the setup and deployment of the testnet faucet

set -e

echo "💧 BlackSilk Testnet Faucet Setup"
echo "================================="

# Configuration
FAUCET_AMOUNT=${FAUCET_AMOUNT:-10.0}
COOLDOWN_HOURS=${COOLDOWN_HOURS:-24}
PORT=${PORT:-3000}
BACKEND_PORT=${BACKEND_PORT:-3003}

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

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    if ! command -v node &> /dev/null; then
        error "Node.js is not installed. Please install Node.js 18+"
        exit 1
    fi
    
    if ! command -v npm &> /dev/null; then
        error "npm is not installed"
        exit 1
    fi
    
    # Check Node.js version
    NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [[ $NODE_VERSION -lt 18 ]]; then
        error "Node.js version 18 or higher is required. Current: $(node -v)"
        exit 1
    fi
    
    log "✅ Prerequisites check passed"
}

# Setup faucet service
setup_faucet() {
    log "Setting up testnet faucet service..."
    
    cd /workspaces/BlackSilk-Blockchain/testnet-faucet
    
    # Install dependencies
    log "Installing faucet dependencies..."
    npm install
    
    # Create environment file if it doesn't exist
    if [[ ! -f ".env" ]]; then
        log "Creating environment configuration..."
        cat > .env << EOF
# BlackSilk Testnet Faucet Configuration
NODE_ENV=development
PORT=${PORT}
BACKEND_PORT=${BACKEND_PORT}
FRONTEND_URL=http://localhost:${PORT}
BACKEND_URL=http://localhost:${BACKEND_PORT}

# Database
DATABASE_PATH=./data/faucet.db

# BlackSilk Node Configuration
BLACKSILK_RPC_URL=http://localhost:19333
BLACKSILK_RPC_USER=
BLACKSILK_RPC_PASSWORD=
MOCK_BLOCKCHAIN=true

# Faucet Settings
FAUCET_AMOUNT=${FAUCET_AMOUNT}
MAX_REQUESTS_PER_DAY=1
COOLDOWN_HOURS=${COOLDOWN_HOURS}

# Rate Limiting
RATE_LIMIT_WINDOW_MS=86400000
RATE_LIMIT_MAX_REQUESTS=100

# Security
JWT_SECRET=$(openssl rand -hex 32)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123

# Logging
LOG_LEVEL=info
LOG_FILE=./logs/faucet.log
EOF
        log "✅ Environment file created"
    else
        log "✅ Environment file already exists"
    fi
    
    # Create data directory
    mkdir -p data logs
    
    # Initialize database
    log "Initializing faucet database..."
    npm run setup 2>/dev/null || true
    
    # Seed with initial data
    log "Seeding database with test data..."
    npm run seed 2>/dev/null || true
    
    log "✅ Faucet setup completed"
}

# Start faucet services
start_faucet() {
    log "Starting faucet services..."
    
    cd /workspaces/BlackSilk-Blockchain/testnet-faucet
    
    # Start backend server in background
    log "Starting backend server on port ${BACKEND_PORT}..."
    npm run dev:server > backend.log 2>&1 &
    BACKEND_PID=$!
    echo $BACKEND_PID > backend.pid
    
    # Wait for backend to start
    sleep 5
    
    # Check if backend is running
    if curl -s http://localhost:${BACKEND_PORT}/health > /dev/null; then
        log "✅ Backend server is running"
    else
        error "Backend server failed to start"
        exit 1
    fi
    
    # Start frontend server in background
    log "Starting frontend server on port ${PORT}..."
    npm run dev > frontend.log 2>&1 &
    FRONTEND_PID=$!
    echo $FRONTEND_PID > frontend.pid
    
    # Wait for frontend to start
    sleep 10
    
    # Check if frontend is running
    if curl -s http://localhost:${PORT}/api/health > /dev/null; then
        log "✅ Frontend server is running"
    else
        warn "Frontend server may still be starting..."
    fi
    
    log "🎉 Faucet services started successfully!"
    log ""
    log "📋 Service Information:"
    log "   Frontend: http://localhost:${PORT}"
    log "   Backend:  http://localhost:${BACKEND_PORT}"
    log "   Admin:    http://localhost:${PORT}/admin"
    log ""
    log "🔧 Management:"
    log "   Stop services: ./scripts/stop-faucet.sh"
    log "   View logs:     tail -f testnet-faucet/frontend.log"
    log "   Test system:   ./testnet-faucet/test-complete-system.sh"
}

# Test faucet functionality
test_faucet() {
    log "Testing faucet functionality..."
    
    cd /workspaces/BlackSilk-Blockchain/testnet-faucet
    
    # Wait for services to be fully ready
    sleep 15
    
    # Test backend health
    if curl -s http://localhost:${BACKEND_PORT}/health | grep -q "ok"; then
        log "✅ Backend health check passed"
    else
        warn "⚠️  Backend health check failed"
    fi
    
    # Test frontend health
    if curl -s http://localhost:${PORT}/api/health | grep -q "ok"; then
        log "✅ Frontend health check passed"
    else
        warn "⚠️  Frontend health check failed"
    fi
    
    # Test stats endpoint
    if curl -s http://localhost:${PORT}/api/stats > /dev/null; then
        log "✅ Stats endpoint working"
    else
        warn "⚠️  Stats endpoint failed"
    fi
    
    # Test token request with a test address
    log "Testing token request..."
    TEST_ADDRESS="tBLK123456789012345678901234567890"
    
    RESPONSE=$(curl -s -X POST http://localhost:${PORT}/api/faucet \
        -H "Content-Type: application/json" \
        -d "{\"address\":\"${TEST_ADDRESS}\",\"amount\":1}")
    
    if echo "$RESPONSE" | grep -q "success\|transaction_id"; then
        log "✅ Token request test passed"
    else
        warn "⚠️  Token request test failed: $RESPONSE"
    fi
    
    log "✅ Faucet testing completed"
}

# Create stop script
create_stop_script() {
    log "Creating stop script..."
    
    cat > /workspaces/BlackSilk-Blockchain/scripts/stop-faucet.sh << 'EOF'
#!/bin/bash

echo "🛑 Stopping BlackSilk Testnet Faucet..."

cd /workspaces/BlackSilk-Blockchain/testnet-faucet

# Stop frontend
if [[ -f frontend.pid ]]; then
    FRONTEND_PID=$(cat frontend.pid)
    if kill -0 $FRONTEND_PID 2>/dev/null; then
        echo "Stopping frontend (PID: $FRONTEND_PID)..."
        kill $FRONTEND_PID
        rm frontend.pid
    fi
fi

# Stop backend
if [[ -f backend.pid ]]; then
    BACKEND_PID=$(cat backend.pid)
    if kill -0 $BACKEND_PID 2>/dev/null; then
        echo "Stopping backend (PID: $BACKEND_PID)..."
        kill $BACKEND_PID
        rm backend.pid
    fi
fi

# Kill any remaining Node.js processes related to the faucet
pkill -f "testnet-faucet" 2>/dev/null || true

echo "✅ Faucet services stopped"
EOF

    chmod +x /workspaces/BlackSilk-Blockchain/scripts/stop-faucet.sh
    log "✅ Stop script created"
}

# Create production deployment script
create_production_script() {
    log "Creating production deployment script..."
    
    cat > /workspaces/BlackSilk-Blockchain/scripts/deploy-faucet-production.sh << 'EOF'
#!/bin/bash

# BlackSilk Testnet Faucet - Production Deployment

set -e

echo "🚀 BlackSilk Testnet Faucet - Production Deployment"
echo "==================================================="

# Check if running as non-root
if [[ $EUID -eq 0 ]]; then
   echo "This script should not be run as root"
   exit 1
fi

# Configuration
DOMAIN=${DOMAIN:-"faucet.blacksilk.io"}
SSL_EMAIL=${SSL_EMAIL:-"admin@blacksilk.io"}
NODE_ENV="production"

# Create production environment
create_production_env() {
    echo "Creating production environment..."
    
    cat > .env.production << EOF
NODE_ENV=production
PORT=3000
BACKEND_PORT=3003

# Database (use PostgreSQL in production)
DATABASE_URL=postgresql://faucet_user:secure_password@localhost:5432/blacksilk_faucet

# BlackSilk Node (connect to actual node)
BLACKSILK_RPC_URL=http://testnet-node:19333
BLACKSILK_RPC_USER=faucet_rpc_user
BLACKSILK_RPC_PASSWORD=\${BLACKSILK_RPC_PASSWORD}
MOCK_BLOCKCHAIN=false

# Faucet Settings
FAUCET_AMOUNT=10.0
MAX_REQUESTS_PER_DAY=1
COOLDOWN_HOURS=24

# Security (generate secure values)
JWT_SECRET=\${JWT_SECRET}
ADMIN_USERNAME=\${ADMIN_USERNAME}
ADMIN_PASSWORD=\${ADMIN_PASSWORD}

# Rate Limiting
RATE_LIMIT_WINDOW_MS=86400000
RATE_LIMIT_MAX_REQUESTS=100

# Production Settings
TRUST_PROXY=true
SECURE_COOKIES=true
EOF

    echo "✅ Production environment template created"
    echo "⚠️  Please update .env.production with actual values"
}

# Install system dependencies
install_dependencies() {
    echo "Installing system dependencies..."
    
    # Update system
    sudo apt update
    
    # Install Node.js 18
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt-get install -y nodejs
    
    # Install PM2
    sudo npm install -g pm2
    
    # Install Nginx
    sudo apt install -y nginx
    
    # Install Certbot
    sudo apt install -y certbot python3-certbot-nginx
    
    echo "✅ Dependencies installed"
}

# Setup SSL certificates
setup_ssl() {
    echo "Setting up SSL certificates..."
    
    # Generate certificate
    sudo certbot --nginx -d $DOMAIN --email $SSL_EMAIL --agree-tos --non-interactive
    
    echo "✅ SSL certificates configured"
}

# Setup Nginx reverse proxy
setup_nginx() {
    echo "Setting up Nginx reverse proxy..."
    
    sudo tee /etc/nginx/sites-available/blacksilk-faucet << EOF
# Rate limiting
limit_req_zone \$binary_remote_addr zone=faucet:10m rate=10r/m;
limit_req_zone \$binary_remote_addr zone=api:10m rate=100r/m;

server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    # SSL Configuration (managed by Certbot)
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Rate Limiting
    location /api/faucet {
        limit_req zone=faucet burst=5 nodelay;
        proxy_pass http://127.0.0.1:3000;
        include /etc/nginx/proxy_params;
    }

    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://127.0.0.1:3000;
        include /etc/nginx/proxy_params;
    }

    location / {
        proxy_pass http://127.0.0.1:3000;
        include /etc/nginx/proxy_params;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_cache_bypass \$http_upgrade;
    }

    # Logs
    access_log /var/log/nginx/faucet_access.log;
    error_log /var/log/nginx/faucet_error.log;
}
EOF

    # Enable site
    sudo ln -sf /etc/nginx/sites-available/blacksilk-faucet /etc/nginx/sites-enabled/
    sudo nginx -t
    sudo systemctl reload nginx
    
    echo "✅ Nginx configured"
}

# Setup PM2 ecosystem
setup_pm2() {
    echo "Setting up PM2 ecosystem..."
    
    cat > ecosystem.config.js << EOF
module.exports = {
  apps: [{
    name: 'blacksilk-faucet',
    script: './dist/server/index-new.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    env_file: '.env.production',
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_file: './logs/combined.log',
    time: true,
    max_memory_restart: '1G',
    node_args: '--max-old-space-size=1024',
    watch: false,
    autorestart: true,
    max_restarts: 10,
    min_uptime: '10s'
  }]
};
EOF

    echo "✅ PM2 ecosystem configured"
}

# Deploy application
deploy_app() {
    echo "Deploying application..."
    
    # Install dependencies
    npm ci --only=production
    
    # Build application
    npm run build
    
    # Create production directories
    mkdir -p logs data
    
    # Start with PM2
    pm2 start ecosystem.config.js
    pm2 save
    pm2 startup
    
    echo "✅ Application deployed"
}

# Main deployment function
main() {
    echo "Starting production deployment..."
    
    create_production_env
    install_dependencies
    setup_pm2
    deploy_app
    setup_nginx
    setup_ssl
    
    echo "🎉 Production deployment completed!"
    echo ""
    echo "🌐 Faucet URL: https://$DOMAIN"
    echo "👨‍💼 Admin Panel: https://$DOMAIN/admin"
    echo ""
    echo "📋 Management Commands:"
    echo "   View logs: pm2 logs blacksilk-faucet"
    echo "   Restart:   pm2 restart blacksilk-faucet"
    echo "   Stop:      pm2 stop blacksilk-faucet"
    echo "   Monitor:   pm2 monit"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
EOF

    chmod +x /workspaces/BlackSilk-Blockchain/scripts/deploy-faucet-production.sh
    log "✅ Production deployment script created"
}

# Main function
main() {
    log "Starting testnet faucet setup..."
    
    check_prerequisites
    setup_faucet
    start_faucet
    test_faucet
    create_stop_script
    create_production_script
    
    log "🎉 Testnet faucet setup completed successfully!"
    log ""
    log "🔗 Quick Links:"
    log "   Faucet Web UI: http://localhost:${PORT}"
    log "   Admin Panel:   http://localhost:${PORT}/admin"
    log "   Backend API:   http://localhost:${BACKEND_PORT}"
    log ""
    log "📖 Next Steps:"
    log "1. Test the faucet: ./testnet-faucet/test-complete-system.sh"
    log "2. For production: ./scripts/deploy-faucet-production.sh"
    log "3. Stop services:  ./scripts/stop-faucet.sh"
}

# Execute main function
main "$@"
