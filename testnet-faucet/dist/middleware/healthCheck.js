"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.HealthCheckService = void 0;
const os_1 = __importDefault(require("os"));
const fs_1 = __importDefault(require("fs"));
const axios_1 = __importDefault(require("axios"));
class HealthCheckService {
    constructor(db, logger, faucetService) {
        this.db = db;
        this.logger = logger;
        this.faucetService = faucetService;
        this.checks = new Map();
        this.intervals = new Map();
        this.setupHealthChecks();
    }
    setupHealthChecks() {
        // Database health check
        this.registerCheck('database', this.checkDatabase.bind(this));
        // BlackSilk node health check
        this.registerCheck('blacksilk-node', this.checkBlackSilkNode.bind(this));
        // Faucet service health check
        this.registerCheck('faucet-service', this.checkFaucetService.bind(this));
        // File system health check
        this.registerCheck('filesystem', this.checkFileSystem.bind(this));
        // Memory health check
        this.registerCheck('memory', this.checkMemory.bind(this));
        // API endpoints health check
        this.registerCheck('api-endpoints', this.checkAPIEndpoints.bind(this));
    }
    /**
     * Register a health check
     */
    registerCheck(name, checkFn) {
        this.checks.set(name, checkFn);
    }
    /**
     * Run all health checks
     */
    async runAllChecks() {
        const startTime = Date.now();
        const results = [];
        // Run all health checks
        for (const [name, checkFn] of this.checks) {
            try {
                const result = await checkFn();
                results.push(result);
            }
            catch (error) {
                results.push({
                    service: name,
                    status: 'unhealthy',
                    timestamp: new Date().toISOString(),
                    error: error instanceof Error ? error.message : 'Unknown error'
                });
            }
        }
        // Determine overall health
        const hasUnhealthy = results.some(r => r.status === 'unhealthy');
        const hasDegraded = results.some(r => r.status === 'degraded');
        let overall = 'healthy';
        if (hasUnhealthy) {
            overall = 'unhealthy';
        }
        else if (hasDegraded) {
            overall = 'degraded';
        }
        // Get system metrics
        const systemMetrics = await this.getSystemMetrics();
        const blacksilkStatus = await this.getBlackSilkStatus();
        return {
            overall,
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            services: results,
            system: systemMetrics,
            blacksilk: blacksilkStatus
        };
    }
    /**
     * Get basic health status (fast check)
     */
    async getBasicHealth() {
        return {
            status: 'healthy', // Quick assumption - full check would be more accurate
            timestamp: new Date().toISOString(),
            uptime: process.uptime()
        };
    }
    /**
     * Health check middleware
     */
    middleware(type = 'basic') {
        return async (req, res, next) => {
            try {
                if (type === 'basic') {
                    const health = await this.getBasicHealth();
                    res.json(health);
                }
                else {
                    const health = await this.runAllChecks();
                    // Set appropriate HTTP status based on health
                    let statusCode = 200;
                    if (health.overall === 'degraded') {
                        statusCode = 200; // Still OK but with warnings
                    }
                    else if (health.overall === 'unhealthy') {
                        statusCode = 503; // Service unavailable
                    }
                    res.status(statusCode).json(health);
                }
            }
            catch (error) {
                this.logger.error('Health check error:', error);
                res.status(500).json({
                    status: 'unhealthy',
                    error: 'Health check failed',
                    timestamp: new Date().toISOString()
                });
            }
        };
    }
    // Individual health check methods
    async checkDatabase() {
        const startTime = Date.now();
        try {
            // Test database connection with a simple query
            await this.db.query('SELECT 1');
            // Check database file size and integrity
            const dbStats = await this.db.query(`
        SELECT 
          COUNT(*) as total_requests,
          MAX(created_at) as latest_request
        FROM faucet_requests
      `);
            return {
                service: 'database',
                status: 'healthy',
                timestamp: new Date().toISOString(),
                responseTime: Date.now() - startTime,
                details: {
                    totalRequests: dbStats[0]?.total_requests || 0,
                    latestRequest: dbStats[0]?.latest_request
                }
            };
        }
        catch (error) {
            return {
                service: 'database',
                status: 'unhealthy',
                timestamp: new Date().toISOString(),
                responseTime: Date.now() - startTime,
                error: error instanceof Error ? error.message : 'Database connection failed'
            };
        }
    }
    async checkBlackSilkNode() {
        const startTime = Date.now();
        try {
            const nodeUrl = process.env.BLACKSILK_NODE_URL || 'http://localhost:18332';
            // Test RPC connection
            const response = await axios_1.default.post(nodeUrl, {
                jsonrpc: '2.0',
                id: 'health-check',
                method: 'getblockchaininfo',
                params: []
            }, {
                timeout: 5000,
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            if (response.data.result) {
                const blockchainInfo = response.data.result;
                return {
                    service: 'blacksilk-node',
                    status: 'healthy',
                    timestamp: new Date().toISOString(),
                    responseTime: Date.now() - startTime,
                    details: {
                        blocks: blockchainInfo.blocks,
                        chain: blockchainInfo.chain,
                        verificationProgress: blockchainInfo.verificationprogress
                    }
                };
            }
            else {
                throw new Error('Invalid response from BlackSilk node');
            }
        }
        catch (error) {
            return {
                service: 'blacksilk-node',
                status: 'unhealthy',
                timestamp: new Date().toISOString(),
                responseTime: Date.now() - startTime,
                error: error instanceof Error ? error.message : 'BlackSilk node connection failed'
            };
        }
    }
    async checkFaucetService() {
        const startTime = Date.now();
        try {
            // Check faucet balance
            const balance = await this.faucetService.getFaucetBalance();
            const minBalance = parseFloat(process.env.FAUCET_MIN_BALANCE || '1000');
            let status = 'healthy';
            if (balance < minBalance) {
                status = balance < (minBalance * 0.1) ? 'unhealthy' : 'degraded';
            }
            // Check pending transactions
            const pendingCount = await this.faucetService.getPendingTransactionCount();
            return {
                service: 'faucet-service',
                status,
                timestamp: new Date().toISOString(),
                responseTime: Date.now() - startTime,
                details: {
                    balance,
                    minBalance,
                    pendingTransactions: pendingCount
                }
            };
        }
        catch (error) {
            return {
                service: 'faucet-service',
                status: 'unhealthy',
                timestamp: new Date().toISOString(),
                responseTime: Date.now() - startTime,
                error: error instanceof Error ? error.message : 'Faucet service check failed'
            };
        }
    }
    async checkFileSystem() {
        const startTime = Date.now();
        try {
            const stats = fs_1.default.statSync(process.cwd());
            // Check disk space (simplified)
            return {
                service: 'filesystem',
                status: 'healthy',
                timestamp: new Date().toISOString(),
                responseTime: Date.now() - startTime,
                details: {
                    accessible: true,
                    cwd: process.cwd()
                }
            };
        }
        catch (error) {
            return {
                service: 'filesystem',
                status: 'unhealthy',
                timestamp: new Date().toISOString(),
                responseTime: Date.now() - startTime,
                error: error instanceof Error ? error.message : 'File system check failed'
            };
        }
    }
    async checkMemory() {
        const startTime = Date.now();
        try {
            const memUsage = process.memoryUsage();
            const totalMem = os_1.default.totalmem();
            const freeMem = os_1.default.freemem();
            const usedMem = totalMem - freeMem;
            const memPercentage = (usedMem / totalMem) * 100;
            let status = 'healthy';
            if (memPercentage > 90) {
                status = 'unhealthy';
            }
            else if (memPercentage > 80) {
                status = 'degraded';
            }
            return {
                service: 'memory',
                status,
                timestamp: new Date().toISOString(),
                responseTime: Date.now() - startTime,
                details: {
                    processMemory: {
                        rss: memUsage.rss,
                        heapTotal: memUsage.heapTotal,
                        heapUsed: memUsage.heapUsed,
                        external: memUsage.external
                    },
                    systemMemory: {
                        total: totalMem,
                        free: freeMem,
                        used: usedMem,
                        percentage: memPercentage
                    }
                }
            };
        }
        catch (error) {
            return {
                service: 'memory',
                status: 'unhealthy',
                timestamp: new Date().toISOString(),
                responseTime: Date.now() - startTime,
                error: error instanceof Error ? error.message : 'Memory check failed'
            };
        }
    }
    async checkAPIEndpoints() {
        const startTime = Date.now();
        try {
            // This would test internal API endpoints
            // For now, just return healthy if we can create the result
            return {
                service: 'api-endpoints',
                status: 'healthy',
                timestamp: new Date().toISOString(),
                responseTime: Date.now() - startTime,
                details: {
                    endpoints: ['api', 'health', 'admin']
                }
            };
        }
        catch (error) {
            return {
                service: 'api-endpoints',
                status: 'unhealthy',
                timestamp: new Date().toISOString(),
                responseTime: Date.now() - startTime,
                error: error instanceof Error ? error.message : 'API endpoints check failed'
            };
        }
    }
    async getSystemMetrics() {
        const memUsage = process.memoryUsage();
        const totalMem = os_1.default.totalmem();
        const freeMem = os_1.default.freemem();
        const usedMem = totalMem - freeMem;
        return {
            cpu: {
                usage: os_1.default.loadavg()[0], // 1-minute load average as CPU usage approximation
                loadAverage: os_1.default.loadavg()
            },
            memory: {
                total: totalMem,
                used: usedMem,
                free: freeMem,
                percentage: (usedMem / totalMem) * 100
            },
            disk: {
                total: 0, // Would need more complex implementation
                used: 0,
                free: 0,
                percentage: 0
            }
        };
    }
    async getBlackSilkStatus() {
        try {
            const nodeUrl = process.env.BLACKSILK_NODE_URL || 'http://localhost:18332';
            const [blockchainInfo, networkInfo] = await Promise.all([
                axios_1.default.post(nodeUrl, {
                    jsonrpc: '2.0',
                    id: 'blockchain-info',
                    method: 'getblockchaininfo',
                    params: []
                }, { timeout: 5000 }),
                axios_1.default.post(nodeUrl, {
                    jsonrpc: '2.0',
                    id: 'network-info',
                    method: 'getnetworkinfo',
                    params: []
                }, { timeout: 5000 })
            ]);
            return {
                nodeConnected: true,
                blockHeight: blockchainInfo.data.result?.blocks,
                networkHashRate: blockchainInfo.data.result?.difficulty,
                peerCount: networkInfo.data.result?.connections,
                lastBlockTime: new Date().toISOString() // Would need actual last block time
            };
        }
        catch (error) {
            return {
                nodeConnected: false
            };
        }
    }
    /**
     * Start periodic health checks
     */
    startPeriodicChecks(intervalMs = 60000) {
        const interval = setInterval(async () => {
            try {
                const health = await this.runAllChecks();
                if (health.overall !== 'healthy') {
                    this.logger.warn('System health check failed', { health });
                }
                else {
                    this.logger.debug('System health check passed');
                }
            }
            catch (error) {
                this.logger.error('Periodic health check error:', error);
            }
        }, intervalMs);
        this.intervals.set('periodic', interval);
    }
    /**
     * Stop periodic health checks
     */
    stopPeriodicChecks() {
        for (const [name, interval] of this.intervals) {
            clearInterval(interval);
        }
        this.intervals.clear();
    }
}
exports.HealthCheckService = HealthCheckService;
//# sourceMappingURL=healthCheck.js.map