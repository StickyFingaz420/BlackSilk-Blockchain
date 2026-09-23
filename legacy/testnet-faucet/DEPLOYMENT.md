# BlackSilk Testnet Faucet - Production Deployment Guide

This guide covers the deployment of the BlackSilk Testnet Faucet in production environments.

## 🏗️ Infrastructure Requirements

### Minimum System Requirements
- **CPU**: 2 cores
- **RAM**: 4GB
- **Storage**: 20GB SSD
- **Network**: 100 Mbps connection
- **OS**: Ubuntu 20.04 LTS or later

### Recommended System Requirements
- **CPU**: 4 cores
- **RAM**: 8GB
- **Storage**: 50GB SSD
- **Network**: 1 Gbps connection
- **OS**: Ubuntu 22.04 LTS

## 🐳 Docker Deployment (Recommended)

### Prerequisites
```bash
# Install Docker and Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.21.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### 1. Prepare the Environment

```bash
# Create deployment directory
sudo mkdir -p /opt/blacksilk-faucet
cd /opt/blacksilk-faucet

# Clone the repository
git clone https://github.com/BlackSilk-Blockchain/BlackSilk-Blockchain.git .
cd testnet-faucet
```

### 2. Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

**Critical Environment Variables:**
```env
# Production Settings
NODE_ENV=production
PORT=3000

# Database
DATABASE_PATH=/app/data/faucet.db

# BlackSilk Node (Update with your node details)
BLACKSILK_RPC_URL=http://blacksilk-node:8332
BLACKSILK_RPC_USER=your_production_rpc_user
BLACKSILK_RPC_PASSWORD=your_secure_rpc_password

# Faucet Wallet (CRITICAL - Use dedicated faucet wallet)
FAUCET_PRIVATE_KEY=your_faucet_wallet_private_key
FAUCET_AMOUNT=10

# Security (Generate strong values)
JWT_SECRET=your_jwt_secret_256_bits_minimum
ADMIN_USERNAME=your_admin_username
ADMIN_PASSWORD=your_secure_admin_password

# Rate Limiting
RATE_LIMIT_HOURS=24
MAX_REQUESTS_PER_IP=100

# SSL/TLS (if using HTTPS)
SSL_CERT_PATH=/etc/ssl/certs/faucet.crt
SSL_KEY_PATH=/etc/ssl/private/faucet.key
```

### 3. SSL Certificate Setup

```bash
# Using Let's Encrypt (recommended)
sudo apt install certbot
sudo certbot certonly --standalone -d faucet.blacksilk.io

# Or generate self-signed certificate for testing
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/faucet.key \
  -out /etc/ssl/certs/faucet.crt
```

### 4. Deploy with Docker Compose

```bash
# Build and start services
docker-compose -f docker-compose.prod.yml up -d

# View logs
docker-compose logs -f

# Check status
docker-compose ps
```

### 5. Initialize Database

```bash
# Run database setup
docker-compose exec faucet npm run setup

# Run migrations
docker-compose exec faucet npm run migrate

# Optional: Seed with test data
docker-compose exec faucet npm run seed
```

## 🔧 Manual Deployment

### 1. System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install PM2 for process management
sudo npm install -g pm2

# Install build tools
sudo apt-get install -y build-essential python3
```

### 2. Application Setup

```bash
# Create application user
sudo useradd -r -s /bin/bash -m blacksilk-faucet
sudo mkdir -p /opt/blacksilk-faucet
sudo chown blacksilk-faucet:blacksilk-faucet /opt/blacksilk-faucet

# Switch to application user
sudo su - blacksilk-faucet
cd /opt/blacksilk-faucet

# Clone and setup
git clone https://github.com/BlackSilk-Blockchain/BlackSilk-Blockchain.git .
cd testnet-faucet

# Install dependencies
npm ci --only=production

# Build application
npm run build
```

### 3. PM2 Configuration

Create `ecosystem.config.js`:
```javascript
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
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_file: './logs/combined.log',
    time: true,
    max_memory_restart: '1G',
    node_args: '--max-old-space-size=1024'
  }]
};
```

### 4. Start Services

```bash
# Start with PM2
pm2 start ecosystem.config.js

# Setup startup script
pm2 startup
pm2 save

# Monitor
pm2 monit
```

## 🌐 Nginx Reverse Proxy

### 1. Install Nginx

```bash
sudo apt install nginx
```

### 2. Configure Nginx

Create `/etc/nginx/sites-available/blacksilk-faucet`:
```nginx
# Rate limiting
limit_req_zone $binary_remote_addr zone=faucet:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;

server {
    listen 80;
    server_name faucet.blacksilk.io;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name faucet.blacksilk.io;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/faucet.crt;
    ssl_certificate_key /etc/ssl/private/faucet.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Rate Limiting
    location /api/faucet {
        limit_req zone=faucet burst=5 nodelay;
        proxy_pass http://127.0.0.1:3000;
        include proxy_params;
    }

    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://127.0.0.1:3000;
        include proxy_params;
    }

    location / {
        proxy_pass http://127.0.0.1:3000;
        include proxy_params;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_cache_bypass $http_upgrade;
    }

    # Static files caching
    location /_next/static/ {
        proxy_pass http://127.0.0.1:3000;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Logs
    access_log /var/log/nginx/faucet_access.log;
    error_log /var/log/nginx/faucet_error.log;
}
```

### 3. Enable Configuration

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/blacksilk-faucet /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
sudo systemctl enable nginx
```

## 🔐 Security Hardening

### 1. Firewall Configuration

```bash
# UFW Configuration
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable

# Block direct access to application port
sudo ufw deny 3000
```

### 2. File Permissions

```bash
# Set correct permissions
sudo chown -R blacksilk-faucet:blacksilk-faucet /opt/blacksilk-faucet
sudo chmod 750 /opt/blacksilk-faucet
sudo chmod 600 /opt/blacksilk-faucet/testnet-faucet/.env
```

### 3. System Security

```bash
# Install fail2ban
sudo apt install fail2ban

# Configure fail2ban for Nginx
sudo tee /etc/fail2ban/jail.local << EOF
[nginx-http-auth]
enabled = true

[nginx-noscript]
enabled = true

[nginx-badbots]
enabled = true

[nginx-noproxy]
enabled = true
EOF

sudo systemctl restart fail2ban
```

### 4. Database Security

```bash
# Set database permissions
sudo chmod 600 /opt/blacksilk-faucet/testnet-faucet/data/faucet.db
sudo chown blacksilk-faucet:blacksilk-faucet /opt/blacksilk-faucet/testnet-faucet/data/faucet.db
```

## 📊 Monitoring & Maintenance

### 1. Log Monitoring

```bash
# View application logs
sudo journalctl -f -u blacksilk-faucet

# View Nginx logs
sudo tail -f /var/log/nginx/faucet_access.log
sudo tail -f /var/log/nginx/faucet_error.log

# PM2 logs
pm2 logs blacksilk-faucet
```

### 2. Health Monitoring

Set up monitoring script `/opt/blacksilk-faucet/scripts/health-check.sh`:
```bash
#!/bin/bash

FAUCET_URL="https://faucet.blacksilk.io"
HEALTH_ENDPOINT="$FAUCET_URL/health"

# Check health endpoint
if curl -f -s "$HEALTH_ENDPOINT" > /dev/null; then
    echo "$(date): Faucet is healthy"
else
    echo "$(date): Faucet health check failed"
    # Alert/restart logic here
    pm2 restart blacksilk-faucet
fi
```

### 3. Automated Backups

Create backup script `/opt/blacksilk-faucet/scripts/backup.sh`:
```bash
#!/bin/bash

BACKUP_DIR="/opt/backups/blacksilk-faucet"
DB_PATH="/opt/blacksilk-faucet/testnet-faucet/data/faucet.db"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Backup database
cp "$DB_PATH" "$BACKUP_DIR/faucet_$DATE.db"

# Keep only last 30 backups
find "$BACKUP_DIR" -name "faucet_*.db" -mtime +30 -delete

echo "Backup completed: faucet_$DATE.db"
```

Add to crontab:
```bash
# Backup every 6 hours
0 */6 * * * /opt/blacksilk-faucet/scripts/backup.sh >> /var/log/faucet-backup.log 2>&1

# Health check every 5 minutes
*/5 * * * * /opt/blacksilk-faucet/scripts/health-check.sh >> /var/log/faucet-health.log 2>&1
```

## 🚀 Updates & Maintenance

### 1. Application Updates

```bash
# Backup current version
cp -r /opt/blacksilk-faucet /opt/blacksilk-faucet.backup.$(date +%Y%m%d)

# Pull latest changes
cd /opt/blacksilk-faucet/testnet-faucet
git pull origin main

# Install dependencies and rebuild
npm ci --only=production
npm run build

# Run migrations
npm run migrate

# Restart application
pm2 restart blacksilk-faucet
```

### 2. System Updates

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Update Node.js (if needed)
sudo npm cache clean -f
sudo npm install -g n
sudo n stable

# Restart services
pm2 restart all
sudo systemctl restart nginx
```

## 🔍 Troubleshooting

### Common Issues

1. **Database locked errors**
   ```bash
   # Check for hanging processes
   sudo lsof /opt/blacksilk-faucet/testnet-faucet/data/faucet.db
   
   # Restart application
   pm2 restart blacksilk-faucet
   ```

2. **High memory usage**
   ```bash
   # Monitor memory
   pm2 monit
   
   # Restart if needed
   pm2 restart blacksilk-faucet
   ```

3. **SSL certificate renewal**
   ```bash
   # Renew Let's Encrypt certificate
   sudo certbot renew
   sudo systemctl reload nginx
   ```

### Performance Optimization

1. **Database optimization**
   ```bash
   # Vacuum database
   sqlite3 /opt/blacksilk-faucet/testnet-faucet/data/faucet.db "VACUUM;"
   
   # Analyze tables
   sqlite3 /opt/blacksilk-faucet/testnet-faucet/data/faucet.db "ANALYZE;"
   ```

2. **Log rotation**
   ```bash
   # Setup log rotation
   sudo tee /etc/logrotate.d/blacksilk-faucet << EOF
   /opt/blacksilk-faucet/testnet-faucet/logs/*.log {
       daily
       missingok
       rotate 30
       compress
       delaycompress
       notifempty
       copytruncate
   }
   EOF
   ```

## 📞 Support

For production deployment support:
- **Email**: ops@blacksilk.io
- **Discord**: #deployment-support
- **Documentation**: https://docs.blacksilk.io/faucet

---

**Production Deployment Checklist:**
- [ ] Server provisioned with adequate resources
- [ ] SSL certificate configured
- [ ] Environment variables set securely
- [ ] Database initialized and secured
- [ ] Nginx reverse proxy configured
- [ ] Firewall rules applied
- [ ] Monitoring and alerting setup
- [ ] Backup strategy implemented
- [ ] Health checks configured
- [ ] Documentation updated with deployment details
