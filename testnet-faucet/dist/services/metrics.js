"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MetricsCollectionService = void 0;
const events_1 = require("events");
class MetricsCollectionService extends events_1.EventEmitter {
    constructor(db, logger) {
        super();
        this.db = db;
        this.logger = logger;
        this.metrics = new Map();
        this.collectors = new Map();
        this.startTime = Date.now();
        this.setupMetricsCollection();
    }
    /**
     * Initialize metrics collection
     */
    setupMetricsCollection() {
        // Start collecting system metrics every 30 seconds
        this.startSystemMetricsCollection(30000);
        // Start collecting database metrics every minute
        this.startDatabaseMetricsCollection(60000);
        // Clean up old metrics every hour
        this.startMetricsCleanup(3600000);
    }
    /**
     * Record a metric
     */
    recordMetric(name, value, type = 'counter', labels) {
        const metric = {
            name,
            value,
            timestamp: Date.now(),
            labels,
            type
        };
        // Store in memory
        if (!this.metrics.has(name)) {
            this.metrics.set(name, []);
        }
        const metricsList = this.metrics.get(name);
        metricsList.push(metric);
        // Keep only last 1000 entries per metric to prevent memory leaks
        if (metricsList.length > 1000) {
            metricsList.splice(0, metricsList.length - 1000);
        }
        // Store in database for persistence
        this.storeMetricInDatabase(metric).catch(error => {
            this.logger.error('Failed to store metric in database:', error);
        });
        // Emit event for real-time monitoring
        this.emit('metric', metric);
    }
    /**
     * Increment a counter metric
     */
    incrementCounter(name, value = 1, labels) {
        this.recordMetric(name, value, 'counter', labels);
    }
    /**
     * Set a gauge metric
     */
    setGauge(name, value, labels) {
        this.recordMetric(name, value, 'gauge', labels);
    }
    /**
     * Record response time
     */
    recordResponseTime(endpoint, duration) {
        this.recordMetric('http_request_duration', duration, 'histogram', { endpoint });
    }
    /**
     * Record faucet distribution
     */
    recordFaucetDistribution(address, amount, success) {
        this.incrementCounter('faucet_distributions_total', 1, {
            success: success.toString(),
            address_type: this.getAddressType(address)
        });
        if (success) {
            this.recordMetric('faucet_tokens_distributed', amount, 'counter');
        }
    }
    /**
     * Record rate limit hit
     */
    recordRateLimitHit(ip, endpoint) {
        this.incrementCounter('rate_limit_hits_total', 1, { ip, endpoint });
    }
    /**
     * Record security event
     */
    recordSecurityEvent(type, ip, details) {
        this.incrementCounter('security_events_total', 1, { type, ip });
        this.logger.warn('Security event recorded:', {
            type,
            ip,
            details,
            timestamp: new Date().toISOString()
        });
    }
    /**
     * Get current performance metrics
     */
    async getPerformanceMetrics() {
        const now = Date.now();
        const oneHourAgo = now - (60 * 60 * 1000);
        const oneMinuteAgo = now - (60 * 1000);
        // Get request metrics
        const requestMetrics = await this.getRequestMetrics(oneHourAgo, oneMinuteAgo);
        // Get faucet metrics
        const faucetMetrics = await this.getFaucetMetrics();
        // Get system metrics
        const systemMetrics = await this.getSystemMetrics();
        // Get security metrics
        const securityMetrics = await this.getSecurityMetrics();
        return {
            requests: requestMetrics,
            faucet: faucetMetrics,
            system: systemMetrics,
            security: securityMetrics
        };
    }
    /**
     * Get metrics for a specific time range
     */
    getMetricsInRange(name, startTime, endTime) {
        const metricsList = this.metrics.get(name) || [];
        return metricsList.filter(m => m.timestamp >= startTime && m.timestamp <= endTime);
    }
    /**
     * Get aggregated metrics
     */
    getAggregatedMetrics(name, timeRangeMs) {
        const endTime = Date.now();
        const startTime = endTime - timeRangeMs;
        const metrics = this.getMetricsInRange(name, startTime, endTime);
        if (metrics.length === 0) {
            return { count: 0, sum: 0, average: 0, min: 0, max: 0 };
        }
        const values = metrics.map(m => m.value);
        const sum = values.reduce((a, b) => a + b, 0);
        return {
            count: metrics.length,
            sum,
            average: sum / metrics.length,
            min: Math.min(...values),
            max: Math.max(...values)
        };
    }
    /**
     * Export metrics in Prometheus format
     */
    getPrometheusMetrics() {
        let output = '';
        for (const [name, metricsList] of this.metrics) {
            if (metricsList.length === 0)
                continue;
            const latestMetric = metricsList[metricsList.length - 1];
            // Add metric help and type
            output += `# HELP ${name} ${this.getMetricDescription(name)}\n`;
            output += `# TYPE ${name} ${latestMetric.type}\n`;
            // Add metric value with labels
            const labels = latestMetric.labels
                ? Object.entries(latestMetric.labels).map(([k, v]) => `${k}="${v}"`).join(',')
                : '';
            output += `${name}${labels ? `{${labels}}` : ''} ${latestMetric.value}\n`;
        }
        return output;
    }
    // Private helper methods
    async storeMetricInDatabase(metric) {
        try {
            await this.db.query(`
        INSERT INTO metrics (name, value, timestamp, labels, type) 
        VALUES (?, ?, ?, ?, ?)
      `, [
                metric.name,
                metric.value,
                metric.timestamp,
                metric.labels ? JSON.stringify(metric.labels) : null,
                metric.type
            ]);
        }
        catch (error) {
            // Don't throw - metrics storage failures shouldn't break the app
            this.logger.error('Failed to store metric in database:', error);
        }
    }
    startSystemMetricsCollection(intervalMs) {
        const interval = setInterval(() => {
            this.collectSystemMetrics();
        }, intervalMs);
        this.collectors.set('system', interval);
    }
    startDatabaseMetricsCollection(intervalMs) {
        const interval = setInterval(() => {
            this.collectDatabaseMetrics();
        }, intervalMs);
        this.collectors.set('database', interval);
    }
    startMetricsCleanup(intervalMs) {
        const interval = setInterval(() => {
            this.cleanupOldMetrics();
        }, intervalMs);
        this.collectors.set('cleanup', interval);
    }
    collectSystemMetrics() {
        const memUsage = process.memoryUsage();
        this.setGauge('system_memory_rss', memUsage.rss);
        this.setGauge('system_memory_heap_total', memUsage.heapTotal);
        this.setGauge('system_memory_heap_used', memUsage.heapUsed);
        this.setGauge('system_uptime', process.uptime());
        this.setGauge('system_process_uptime', (Date.now() - this.startTime) / 1000);
    }
    async collectDatabaseMetrics() {
        try {
            // Count total requests
            const requestCount = await this.db.query('SELECT COUNT(*) as count FROM faucet_requests');
            this.setGauge('database_faucet_requests_total', requestCount[0]?.count || 0);
            // Count by status
            const statusCounts = await this.db.query(`
        SELECT status, COUNT(*) as count 
        FROM faucet_requests 
        GROUP BY status
      `);
            for (const row of statusCounts) {
                this.setGauge('database_faucet_requests_by_status', row.count, { status: row.status });
            }
            // Rate limit metrics
            const rateLimitCount = await this.db.query('SELECT COUNT(*) as count FROM rate_limits');
            this.setGauge('database_rate_limits_total', rateLimitCount[0]?.count || 0);
        }
        catch (error) {
            this.logger.error('Failed to collect database metrics:', error);
        }
    }
    async cleanupOldMetrics() {
        try {
            const cutoff = Date.now() - (7 * 24 * 60 * 60 * 1000); // 7 days ago
            await this.db.query('DELETE FROM metrics WHERE timestamp < ?', [cutoff]);
            this.logger.debug('Old metrics cleaned up');
        }
        catch (error) {
            this.logger.error('Failed to cleanup old metrics:', error);
        }
    }
    async getRequestMetrics(oneHourAgo, oneMinuteAgo) {
        const totalRequests = await this.db.query('SELECT COUNT(*) as count FROM faucet_requests');
        const successfulRequests = await this.db.query(`SELECT COUNT(*) as count FROM faucet_requests WHERE status = 'completed'`);
        const failedRequests = await this.db.query(`SELECT COUNT(*) as count FROM faucet_requests WHERE status = 'failed'`);
        const recentRequests = await this.db.query(`
      SELECT COUNT(*) as count 
      FROM faucet_requests 
      WHERE created_at >= datetime('now', '-1 hour')
    `);
        const lastMinuteRequests = await this.db.query(`
      SELECT COUNT(*) as count 
      FROM faucet_requests 
      WHERE created_at >= datetime('now', '-1 minute')
    `);
        return {
            total: totalRequests[0]?.count || 0,
            successful: successfulRequests[0]?.count || 0,
            failed: failedRequests[0]?.count || 0,
            averageResponseTime: 0, // Would need to calculate from response time metrics
            requestsPerMinute: lastMinuteRequests[0]?.count || 0,
            requestsPerHour: recentRequests[0]?.count || 0
        };
    }
    async getFaucetMetrics() {
        const totalDistributed = await this.db.query(`
      SELECT COALESCE(SUM(amount), 0) as total 
      FROM faucet_requests 
      WHERE status = 'completed'
    `);
        const successfulDistributions = await this.db.query(`
      SELECT COUNT(*) as count 
      FROM faucet_requests 
      WHERE status = 'completed'
    `);
        const failedDistributions = await this.db.query(`
      SELECT COUNT(*) as count 
      FROM faucet_requests 
      WHERE status = 'failed'
    `);
        const uniqueAddresses = await this.db.query(`
      SELECT COUNT(DISTINCT address) as count 
      FROM faucet_requests
    `);
        return {
            totalTokensDistributed: totalDistributed[0]?.total || 0,
            successfulDistributions: successfulDistributions[0]?.count || 0,
            failedDistributions: failedDistributions[0]?.count || 0,
            averageDistributionTime: 0, // Would calculate from timing metrics
            uniqueAddresses: uniqueAddresses[0]?.count || 0,
            balanceRemaining: 0 // Would get from faucet service
        };
    }
    async getSystemMetrics() {
        const memUsage = process.memoryUsage();
        return {
            uptime: process.uptime(),
            memoryUsage: memUsage.heapUsed,
            cpuUsage: 0, // Would need more complex calculation
            diskUsage: 0 // Would need disk space calculation
        };
    }
    async getSecurityMetrics() {
        const rateLimitHits = await this.db.query('SELECT COUNT(*) as count FROM rate_limits');
        const blockedRequests = await this.db.query('SELECT COUNT(*) as count FROM rate_limit_blocks');
        const blacklistedAddresses = await this.db.query('SELECT COUNT(*) as count FROM blacklist');
        return {
            rateLimitHits: rateLimitHits[0]?.count || 0,
            blockedRequests: blockedRequests[0]?.count || 0,
            suspiciousActivity: 0, // Would calculate from various security events
            blacklistedAddresses: blacklistedAddresses[0]?.count || 0
        };
    }
    getAddressType(address) {
        // Simple address type detection - would be more sophisticated in practice
        if (address.startsWith('B'))
            return 'bech32';
        if (address.startsWith('3'))
            return 'p2sh';
        if (address.startsWith('1'))
            return 'p2pkh';
        return 'unknown';
    }
    getMetricDescription(name) {
        const descriptions = {
            'http_request_duration': 'HTTP request duration in milliseconds',
            'faucet_distributions_total': 'Total number of faucet distributions',
            'faucet_tokens_distributed': 'Total tokens distributed by faucet',
            'rate_limit_hits_total': 'Total rate limit hits',
            'security_events_total': 'Total security events',
            'system_memory_rss': 'System RSS memory usage in bytes',
            'system_memory_heap_total': 'System heap total memory in bytes',
            'system_memory_heap_used': 'System heap used memory in bytes',
            'system_uptime': 'System uptime in seconds',
            'system_process_uptime': 'Process uptime in seconds'
        };
        return descriptions[name] || 'Custom metric';
    }
    /**
     * Stop all metric collection
     */
    stop() {
        for (const [name, interval] of this.collectors) {
            clearInterval(interval);
        }
        this.collectors.clear();
    }
}
exports.MetricsCollectionService = MetricsCollectionService;
//# sourceMappingURL=metrics.js.map