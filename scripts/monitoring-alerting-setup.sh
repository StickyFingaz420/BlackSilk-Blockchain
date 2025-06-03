#!/bin/bash

# BlackSilk Blockchain Monitoring and Alerting Setup
# Comprehensive monitoring stack with real-time alerts

set -e

echo "📊 BlackSilk Monitoring & Alerting Setup"
echo "========================================"

# Configuration
MONITORING_DIR="monitoring-extended"
GRAFANA_PORT=${GRAFANA_PORT:-3003}
PROMETHEUS_PORT=${PROMETHEUS_PORT:-9090}
ALERTMANAGER_PORT=${ALERTMANAGER_PORT:-9093}
SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL:-""}
EMAIL_ALERTS=${EMAIL_ALERTS:-"admin@blacksilk.network"}

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

# Setup monitoring directory structure
setup_monitoring_structure() {
    log "Setting up monitoring directory structure..."
    
    mkdir -p "$MONITORING_DIR"/{prometheus,grafana,alertmanager,exporters,scripts,dashboards}
    cd "$MONITORING_DIR"
    
    log "Monitoring directory structure created"
}

# Configure Prometheus with advanced rules
setup_prometheus_config() {
    log "Configuring Prometheus..."
    
    cat > prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'blacksilk-testnet'
    environment: 'testnet'

rule_files:
  - "alerts/*.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  # BlackSilk Node Metrics
  - job_name: 'blacksilk-node'
    static_configs:
      - targets: ['localhost:8545']
    metrics_path: /metrics
    scrape_interval: 10s
    scrape_timeout: 5s

  # System Metrics
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']
    scrape_interval: 15s

  # Container Metrics
  - job_name: 'cadvisor'
    static_configs:
      - targets: ['localhost:8080']
    scrape_interval: 15s

  # Faucet Service
  - job_name: 'faucet'
    static_configs:
      - targets: ['localhost:3000']
    metrics_path: /metrics
    scrape_interval: 30s

  # Web Wallet
  - job_name: 'web-wallet'
    static_configs:
      - targets: ['localhost:3001']
    metrics_path: /metrics
    scrape_interval: 30s

  # Mining Pool (if applicable)
  - job_name: 'mining-pool'
    static_configs:
      - targets: ['localhost:4000']
    metrics_path: /metrics
    scrape_interval: 30s

  # Custom Business Logic Metrics
  - job_name: 'blacksilk-business-metrics'
    static_configs:
      - targets: ['localhost:8546']
    metrics_path: /business-metrics
    scrape_interval: 60s

  # External Dependencies
  - job_name: 'external-services'
    static_configs:
      - targets: ['api.coingecko.com:443']
    metrics_path: /ping
    scheme: https
    scrape_interval: 300s
EOF

    # Create alert rules directory
    mkdir -p prometheus/alerts
    
    # Create comprehensive alert rules
    cat > prometheus/alerts/blockchain-alerts.yml << 'EOF'
groups:
  - name: blockchain-critical
    rules:
      # Node Health Alerts
      - alert: NodeDown
        expr: up{job="blacksilk-node"} == 0
        for: 30s
        labels:
          severity: critical
          service: node
        annotations:
          summary: "BlackSilk node is down"
          description: "Node {{ $labels.instance }} has been down for more than 30 seconds"

      - alert: NodeNotSyncing
        expr: increase(blacksilk_blocks_height[5m]) == 0
        for: 5m
        labels:
          severity: warning
          service: node
        annotations:
          summary: "Node not producing blocks"
          description: "Node {{ $labels.instance }} hasn't produced blocks in 5 minutes"

      # Network Alerts
      - alert: LowPeerCount
        expr: blacksilk_peer_count < 3
        for: 2m
        labels:
          severity: warning
          service: network
        annotations:
          summary: "Low peer count"
          description: "Node {{ $labels.instance }} has only {{ $value }} peers connected"

      - alert: NetworkPartition
        expr: blacksilk_peer_count == 0
        for: 1m
        labels:
          severity: critical
          service: network
        annotations:
          summary: "Network partition detected"
          description: "Node {{ $labels.instance }} has no peers connected"

      # Performance Alerts
      - alert: HighCPUUsage
        expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
          service: system
        annotations:
          summary: "High CPU usage"
          description: "CPU usage is above 80% for {{ $labels.instance }}"

      - alert: HighMemoryUsage
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 85
        for: 5m
        labels:
          severity: warning
          service: system
        annotations:
          summary: "High memory usage"
          description: "Memory usage is above 85% for {{ $labels.instance }}"

      - alert: DiskSpaceLow
        expr: (1 - (node_filesystem_avail_bytes / node_filesystem_size_bytes)) * 100 > 90
        for: 5m
        labels:
          severity: critical
          service: system
        annotations:
          summary: "Low disk space"
          description: "Disk usage is above 90% for {{ $labels.instance }}"

  - name: blockchain-business
    rules:
      # Transaction Volume Alerts
      - alert: LowTransactionVolume
        expr: rate(blacksilk_transactions_total[1h]) < 0.1
        for: 30m
        labels:
          severity: info
          service: business
        annotations:
          summary: "Low transaction volume"
          description: "Transaction rate is below 0.1 tx/second for 30 minutes"

      - alert: HighTransactionVolume
        expr: rate(blacksilk_transactions_total[5m]) > 100
        for: 5m
        labels:
          severity: warning
          service: business
        annotations:
          summary: "High transaction volume"
          description: "Transaction rate is above 100 tx/second"

      # Mining Alerts
      - alert: MiningDifficultySpike
        expr: increase(blacksilk_difficulty[1h]) / blacksilk_difficulty > 0.5
        for: 5m
        labels:
          severity: info
          service: mining
        annotations:
          summary: "Mining difficulty spike"
          description: "Mining difficulty increased by more than 50% in 1 hour"

      - alert: NoBlocksProduced
        expr: time() - blacksilk_last_block_time > 600
        for: 2m
        labels:
          severity: critical
          service: mining
        annotations:
          summary: "No blocks produced"
          description: "No blocks have been produced for more than 10 minutes"

  - name: services-alerts
    rules:
      # Faucet Service Alerts
      - alert: FaucetDown
        expr: up{job="faucet"} == 0
        for: 1m
        labels:
          severity: warning
          service: faucet
        annotations:
          summary: "Faucet service is down"
          description: "Faucet service has been down for more than 1 minute"

      - alert: FaucetHighErrorRate
        expr: rate(faucet_errors_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
          service: faucet
        annotations:
          summary: "High faucet error rate"
          description: "Faucet error rate is above 10% for 5 minutes"

      # Web Wallet Alerts
      - alert: WebWalletDown
        expr: up{job="web-wallet"} == 0
        for: 1m
        labels:
          severity: warning
          service: wallet
        annotations:
          summary: "Web wallet is down"
          description: "Web wallet service has been down for more than 1 minute"

      - alert: WalletHighResponseTime
        expr: histogram_quantile(0.95, rate(wallet_request_duration_seconds_bucket[5m])) > 2
        for: 5m
        labels:
          severity: warning
          service: wallet
        annotations:
          summary: "High wallet response time"
          description: "95th percentile response time is above 2 seconds"
EOF

    log "Prometheus configuration completed"
}

# Setup Alertmanager configuration
setup_alertmanager_config() {
    log "Configuring Alertmanager..."
    
    cat > alertmanager/alertmanager.yml << EOF
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'alerts@blacksilk.network'

route:
  group_by: ['alertname', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'default-receiver'
  routes:
    - match:
        severity: critical
      receiver: 'critical-alerts'
    - match:
        severity: warning
      receiver: 'warning-alerts'
    - match:
        service: business
      receiver: 'business-alerts'

receivers:
  - name: 'default-receiver'
    email_configs:
      - to: '${EMAIL_ALERTS}'
        subject: 'BlackSilk Alert: {{ .GroupLabels.alertname }}'
        body: |
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          Labels: {{ range .Labels.SortedPairs }}{{ .Name }}: {{ .Value }} {{ end }}
          {{ end }}

  - name: 'critical-alerts'
    email_configs:
      - to: '${EMAIL_ALERTS}'
        subject: '🚨 CRITICAL: BlackSilk Alert'
        body: |
          CRITICAL ALERT TRIGGERED
          
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          Severity: {{ .Labels.severity }}
          Service: {{ .Labels.service }}
          Time: {{ .StartsAt }}
          {{ end }}
EOF

    # Add Slack configuration if webhook URL is provided
    if [ -n "$SLACK_WEBHOOK_URL" ]; then
        cat >> alertmanager/alertmanager.yml << EOF
    slack_configs:
      - api_url: '${SLACK_WEBHOOK_URL}'
        channel: '#blacksilk-alerts'
        title: '🚨 Critical BlackSilk Alert'
        text: |
          {{ range .Alerts }}
          *{{ .Annotations.summary }}*
          {{ .Annotations.description }}
          {{ end }}
EOF
    fi

    cat >> alertmanager/alertmanager.yml << 'EOF'

  - name: 'warning-alerts'
    email_configs:
      - to: '${EMAIL_ALERTS}'
        subject: '⚠️ WARNING: BlackSilk Alert'
        body: |
          WARNING ALERT TRIGGERED
          
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          {{ end }}

  - name: 'business-alerts'
    email_configs:
      - to: '${EMAIL_ALERTS}'
        subject: '📊 BlackSilk Business Alert'
        body: |
          BUSINESS METRIC ALERT
          
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          {{ end }}
EOF

    log "Alertmanager configuration completed"
}

# Create comprehensive Grafana dashboards
setup_grafana_dashboards() {
    log "Setting up Grafana dashboards..."
    
    # Create datasource configuration
    mkdir -p grafana/provisioning/{datasources,dashboards}
    
    cat > grafana/provisioning/datasources/prometheus.yml << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
EOF

    cat > grafana/provisioning/dashboards/dashboards.yml << 'EOF'
apiVersion: 1

providers:
  - name: 'BlackSilk Dashboards'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards
EOF

    # Create main blockchain dashboard
    cat > dashboards/blockchain-overview.json << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "BlackSilk Blockchain Overview",
    "tags": ["blacksilk", "blockchain"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Block Height",
        "type": "stat",
        "targets": [
          {
            "expr": "blacksilk_blocks_height",
            "legendFormat": "Current Height"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "color": {
              "mode": "thresholds"
            },
            "thresholds": {
              "steps": [
                {"color": "green", "value": null}
              ]
            }
          }
        },
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
      },
      {
        "id": 2,
        "title": "Peer Count",
        "type": "stat",
        "targets": [
          {
            "expr": "blacksilk_peer_count",
            "legendFormat": "Connected Peers"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "color": {
              "mode": "thresholds"
            },
            "thresholds": {
              "steps": [
                {"color": "red", "value": null},
                {"color": "yellow", "value": 3},
                {"color": "green", "value": 8}
              ]
            }
          }
        },
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
      },
      {
        "id": 3,
        "title": "Transaction Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(blacksilk_transactions_total[5m])",
            "legendFormat": "Transactions/sec"
          }
        ],
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8}
      },
      {
        "id": 4,
        "title": "Memory Pool Size",
        "type": "graph",
        "targets": [
          {
            "expr": "blacksilk_mempool_size",
            "legendFormat": "Pending Transactions"
          }
        ],
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 16}
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "10s"
  }
}
EOF

    # Create system metrics dashboard
    cat > dashboards/system-metrics.json << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "BlackSilk System Metrics",
    "tags": ["blacksilk", "system"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "CPU Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "100 - (avg by(instance) (irate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)",
            "legendFormat": "CPU Usage %"
          }
        ],
        "yAxes": [
          {"max": 100, "min": 0, "unit": "percent"}
        ],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
      },
      {
        "id": 2,
        "title": "Memory Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100",
            "legendFormat": "Memory Usage %"
          }
        ],
        "yAxes": [
          {"max": 100, "min": 0, "unit": "percent"}
        ],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
      },
      {
        "id": 3,
        "title": "Disk Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "(1 - (node_filesystem_avail_bytes / node_filesystem_size_bytes)) * 100",
            "legendFormat": "Disk Usage %"
          }
        ],
        "yAxes": [
          {"max": 100, "min": 0, "unit": "percent"}
        ],
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8}
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "30s"
  }
}
EOF

    log "Grafana dashboards created"
}

# Create monitoring Docker Compose
create_monitoring_compose() {
    log "Creating monitoring Docker Compose configuration..."
    
    cat > docker-compose.monitoring.yml << EOF
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: blacksilk-prometheus
    ports:
      - "${PROMETHEUS_PORT}:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - ./prometheus/alerts:/etc/prometheus/alerts
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=30d'
      - '--web.enable-lifecycle'
      - '--web.enable-admin-api'
    restart: unless-stopped
    networks:
      - monitoring

  grafana:
    image: grafana/grafana:latest
    container_name: blacksilk-grafana
    ports:
      - "${GRAFANA_PORT}:3000"
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
      - ./dashboards:/etc/grafana/provisioning/dashboards
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=blacksilk2025
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-simple-json-datasource
    restart: unless-stopped
    networks:
      - monitoring

  alertmanager:
    image: prom/alertmanager:latest
    container_name: blacksilk-alertmanager
    ports:
      - "${ALERTMANAGER_PORT}:9093"
    volumes:
      - ./alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml
      - alertmanager-data:/alertmanager
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
      - '--web.external-url=http://localhost:${ALERTMANAGER_PORT}'
    restart: unless-stopped
    networks:
      - monitoring

  node-exporter:
    image: prom/node-exporter:latest
    container_name: blacksilk-node-exporter
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    restart: unless-stopped
    networks:
      - monitoring

  cadvisor:
    image: gcr.io/cadvisor/cadvisor:latest
    container_name: blacksilk-cadvisor
    ports:
      - "8080:8080"
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:rw
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
      - /dev/disk/:/dev/disk:ro
    privileged: true
    restart: unless-stopped
    networks:
      - monitoring

  # Custom BlackSilk metrics exporter
  blacksilk-exporter:
    build:
      context: ../monitoring/exporter
      dockerfile: Dockerfile
    container_name: blacksilk-exporter
    ports:
      - "8546:8546"
    environment:
      - BLACKSILK_NODE_URL=http://host.docker.internal:8545
      - METRICS_PORT=8546
    restart: unless-stopped
    networks:
      - monitoring
    depends_on:
      - prometheus

volumes:
  prometheus-data:
  grafana-data:
  alertmanager-data:

networks:
  monitoring:
    driver: bridge
EOF

    log "Monitoring Docker Compose created"
}

# Create monitoring management scripts
create_monitoring_scripts() {
    log "Creating monitoring management scripts..."
    
    # Start monitoring script
    cat > scripts/start-monitoring.sh << 'EOF'
#!/bin/bash

echo "🚀 Starting BlackSilk Monitoring Stack..."

# Start monitoring services
docker-compose -f docker-compose.monitoring.yml up -d

# Wait for services to be ready
echo "Waiting for services to start..."
sleep 30

# Check service health
echo "Checking service health..."
services=("prometheus:9090" "grafana:3000" "alertmanager:9093")

for service in "${services[@]}"; do
    name=$(echo $service | cut -d: -f1)
    port=$(echo $service | cut -d: -f2)
    
    if curl -s http://localhost:$port/api/health >/dev/null 2>&1 || \
       curl -s http://localhost:$port >/dev/null 2>&1; then
        echo "✅ $name is healthy"
    else
        echo "❌ $name is not responding"
    fi
done

echo ""
echo "📊 Monitoring Stack URLs:"
echo "Prometheus: http://localhost:9090"
echo "Grafana: http://localhost:3000 (admin/blacksilk2025)"
echo "Alertmanager: http://localhost:9093"
EOF

    # Stop monitoring script
    cat > scripts/stop-monitoring.sh << 'EOF'
#!/bin/bash

echo "🛑 Stopping BlackSilk Monitoring Stack..."

docker-compose -f docker-compose.monitoring.yml down

echo "Monitoring stack stopped"
EOF

    # Monitoring health check script
    cat > scripts/check-monitoring.sh << 'EOF'
#!/bin/bash

echo "🔍 BlackSilk Monitoring Health Check"
echo "===================================="

# Check Docker containers
echo "Checking Docker containers..."
docker-compose -f docker-compose.monitoring.yml ps

echo ""
echo "Checking service endpoints..."

# Service endpoints to check
services=(
    "Prometheus:9090:/api/v1/status/config"
    "Grafana:3000:/api/health"
    "Alertmanager:9093:/api/v1/status"
    "Node Exporter:9100:/metrics"
    "cAdvisor:8080:/healthz"
)

for service in "${services[@]}"; do
    name=$(echo $service | cut -d: -f1)
    port=$(echo $service | cut -d: -f2)
    path=$(echo $service | cut -d: -f3)
    
    if curl -s "http://localhost:$port$path" >/dev/null; then
        echo "✅ $name is healthy"
    else
        echo "❌ $name is not responding"
    fi
done

echo ""
echo "Checking alert rules..."
if curl -s http://localhost:9090/api/v1/rules | jq '.data.groups[].rules[].name' >/dev/null 2>&1; then
    echo "✅ Alert rules are loaded"
else
    echo "❌ Alert rules not found"
fi
EOF

    # Make scripts executable
    chmod +x scripts/*.sh
    
    log "Monitoring scripts created and made executable"
}

# Main execution
main() {
    log "Setting up comprehensive monitoring and alerting..."
    
    setup_monitoring_structure
    setup_prometheus_config
    setup_alertmanager_config
    setup_grafana_dashboards
    create_monitoring_compose
    create_monitoring_scripts
    
    echo ""
    log "📊 Monitoring & Alerting Setup Complete!"
    log "========================================"
    log "Monitoring directory: $MONITORING_DIR"
    log ""
    log "To start monitoring:"
    log "  cd $MONITORING_DIR && ./scripts/start-monitoring.sh"
    log ""
    log "Service URLs:"
    log "  Prometheus: http://localhost:$PROMETHEUS_PORT"
    log "  Grafana: http://localhost:$GRAFANA_PORT (admin/blacksilk2025)"
    log "  Alertmanager: http://localhost:$ALERTMANAGER_PORT"
    log ""
    log "Configure alerts by editing:"
    log "  - $MONITORING_DIR/alertmanager/alertmanager.yml"
    log "  - Add Slack webhook URL: SLACK_WEBHOOK_URL environment variable"
}

# Parse command line arguments
case "${1:-all}" in
    "setup")
        setup_monitoring_structure
        ;;
    "prometheus")
        setup_prometheus_config
        ;;
    "alertmanager")
        setup_alertmanager_config
        ;;
    "grafana")
        setup_grafana_dashboards
        ;;
    "docker")
        create_monitoring_compose
        ;;
    "scripts")
        create_monitoring_scripts
        ;;
    "all"|*)
        main
        ;;
esac
