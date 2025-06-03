#!/bin/bash
# BlackSilk Network Monitoring Setup Script
# This script sets up the complete monitoring infrastructure

set -e

echo "🔍 Setting up BlackSilk Network Monitoring..."

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose not found. Please install Docker Compose first."
    exit 1
fi

# Set default environment variables
export BLACKSILK_NETWORK=${BLACKSILK_NETWORK:-testnet}
export PROMETHEUS_USERNAME=${PROMETHEUS_USERNAME:-admin}
export PROMETHEUS_PASSWORD=${PROMETHEUS_PASSWORD:-$(openssl rand -base64 12)}
export GRAFANA_USERNAME=${GRAFANA_USERNAME:-admin}
export GRAFANA_PASSWORD=${GRAFANA_PASSWORD:-$(openssl rand -base64 12)}

# Alert email configuration
export ALERT_EMAIL_DEFAULT=${ALERT_EMAIL_DEFAULT:-admin@localhost}
export ALERT_EMAIL_CRITICAL=${ALERT_EMAIL_CRITICAL:-ops@localhost}
export ALERT_EMAIL_SECURITY=${ALERT_EMAIL_SECURITY:-security@localhost}
export ALERT_EMAIL_MARKETPLACE=${ALERT_EMAIL_MARKETPLACE:-marketplace@localhost}
export ALERT_EMAIL_WARNING=${ALERT_EMAIL_WARNING:-monitoring@localhost}

# SMTP configuration (optional)
export SMTP_HOST=${SMTP_HOST:-localhost:587}
export SMTP_FROM=${SMTP_FROM:-alerts@blacksilk.network}
export SMTP_USERNAME=${SMTP_USERNAME:-}
export SMTP_PASSWORD=${SMTP_PASSWORD:-}

echo "📋 Configuration:"
echo "  Network: $BLACKSILK_NETWORK"
echo "  Prometheus: http://localhost:9090 (user: $PROMETHEUS_USERNAME)"
echo "  Grafana: http://localhost:3001 (user: $GRAFANA_USERNAME)"
echo "  AlertManager: http://localhost:9093"

# Create necessary directories
mkdir -p monitoring/data/{prometheus,grafana,alertmanager,loki}

# Set proper permissions
sudo chown -R 472:472 monitoring/data/grafana
sudo chown -R 65534:65534 monitoring/data/prometheus
sudo chown -R 65534:65534 monitoring/data/alertmanager

# Build custom exporter
echo "🔨 Building BlackSilk metrics exporter..."
cd monitoring/exporter
docker build -t blacksilk-exporter .
cd ../..

# Start monitoring stack
echo "🚀 Starting monitoring stack..."
cd monitoring
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 10

# Check service health
echo "🔍 Checking service health..."

# Check Prometheus
if curl -s http://localhost:9090/-/ready | grep -q "Prometheus is Ready"; then
    echo "✅ Prometheus is ready"
else
    echo "⚠️ Prometheus not ready yet"
fi

# Check Grafana
if curl -s http://localhost:3001/api/health | grep -q "ok"; then
    echo "✅ Grafana is ready"
else
    echo "⚠️ Grafana not ready yet"
fi

# Check AlertManager
if curl -s http://localhost:9093/-/ready | grep -q "Alertmanager is Ready"; then
    echo "✅ AlertManager is ready"
else
    echo "⚠️ AlertManager not ready yet"
fi

# Import Grafana dashboards
echo "📊 Importing Grafana dashboards..."
sleep 5

# Create BlackSilk folder in Grafana
curl -X POST \
  http://$GRAFANA_USERNAME:$GRAFANA_PASSWORD@localhost:3001/api/folders \
  -H 'Content-Type: application/json' \
  -d '{"title":"BlackSilk","uid":"blacksilk"}' \
  2>/dev/null || echo "Folder may already exist"

echo ""
echo "🎉 BlackSilk monitoring setup complete!"
echo ""
echo "📊 Access URLs:"
echo "  Prometheus: http://localhost:9090"
echo "  Grafana: http://localhost:3001 (admin / $GRAFANA_PASSWORD)"
echo "  AlertManager: http://localhost:9093"
echo "  Node Exporter: http://localhost:9100"
echo "  BlackSilk Exporter: http://localhost:9115"
echo ""
echo "🔧 To customize alerts, edit:"
echo "  monitoring/rules/blacksilk-alerts.yml"
echo ""
echo "📧 Alert notifications will be sent to:"
echo "  Default: $ALERT_EMAIL_DEFAULT"
echo "  Critical: $ALERT_EMAIL_CRITICAL"
echo "  Security: $ALERT_EMAIL_SECURITY"
echo ""
echo "🔄 To stop monitoring:"
echo "  cd monitoring && docker-compose down"
echo ""
echo "💾 Save these credentials:"
echo "  Prometheus: $PROMETHEUS_USERNAME / $PROMETHEUS_PASSWORD"
echo "  Grafana: $GRAFANA_USERNAME / $GRAFANA_PASSWORD"

# Create environment file for future reference
cat > monitoring/.env << EOF
BLACKSILK_NETWORK=$BLACKSILK_NETWORK
PROMETHEUS_USERNAME=$PROMETHEUS_USERNAME
PROMETHEUS_PASSWORD=$PROMETHEUS_PASSWORD
GRAFANA_USERNAME=$GRAFANA_USERNAME
GRAFANA_PASSWORD=$GRAFANA_PASSWORD
ALERT_EMAIL_DEFAULT=$ALERT_EMAIL_DEFAULT
ALERT_EMAIL_CRITICAL=$ALERT_EMAIL_CRITICAL
ALERT_EMAIL_SECURITY=$ALERT_EMAIL_SECURITY
ALERT_EMAIL_MARKETPLACE=$ALERT_EMAIL_MARKETPLACE
ALERT_EMAIL_WARNING=$ALERT_EMAIL_WARNING
SMTP_HOST=$SMTP_HOST
SMTP_FROM=$SMTP_FROM
SMTP_USERNAME=$SMTP_USERNAME
SMTP_PASSWORD=$SMTP_PASSWORD
EOF

echo "💾 Configuration saved to monitoring/.env"
