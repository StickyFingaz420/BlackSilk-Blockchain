#!/usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet"));
const path_1 = __importDefault(require("path"));
const http_1 = require("http");
const next_1 = __importDefault(require("next"));
const database_new_1 = require("./database-new");
const logger_1 = require("./logger");
const faucet_1 = require("./services/faucet");
const rateLimit_1 = require("./middleware/rateLimit");
const errorHandler_1 = require("./middleware/errorHandler");
const healthCheck_1 = require("./middleware/healthCheck");
const metrics_1 = require("./services/metrics");
const admin_1 = require("./routes/admin");
// API Routes (we need to update this)
const express_2 = require("express");
const dev = process.env.NODE_ENV !== 'production';
const hostname = process.env.HOST || '0.0.0.0';
const port = parseInt(process.env.PORT || '3003', 10);
class FaucetServer {
    constructor() {
        this.app = (0, express_1.default)();
        this.nextApp = (0, next_1.default)({ dev, hostname, port });
        this.logger = new logger_1.Logger();
        this.db = new database_new_1.Database(this.logger);
        this.faucetService = new faucet_1.FaucetService(this.db, this.logger);
        this.rateLimitFactory = new rateLimit_1.RateLimitFactory(this.db, this.logger);
        this.errorHandler = new errorHandler_1.ErrorHandler(this.logger);
        this.healthCheck = new healthCheck_1.HealthCheckService(this.db, this.logger, this.faucetService);
        this.metrics = new metrics_1.MetricsCollectionService(this.db, this.logger);
        this.adminRoutes = new admin_1.AdminRoutes(this.db, this.logger, this.faucetService);
        // Setup global error handlers
        this.errorHandler.handleUnhandledRejection();
        this.errorHandler.handleUncaughtException();
    }
    async initialize() {
        try {
            // Initialize logger
            this.logger.info('🚀 Starting BlackSilk Testnet Faucet Service...');
            // Initialize database
            await this.db.initialize();
            this.logger.info('✅ Database initialized');
            // Initialize Next.js
            await this.nextApp.prepare();
            this.logger.info('✅ Next.js initialized');
            // Initialize faucet service
            await this.faucetService.initialize();
            this.logger.info('✅ Faucet service initialized');
            // Setup middleware
            this.setupMiddleware();
            this.logger.info('✅ Middleware configured');
            // Setup routes
            this.setupRoutes();
            this.logger.info('✅ Routes configured');
            // Start health checks
            this.healthCheck.startPeriodicChecks(60000); // Every minute
            this.logger.info('✅ Health checks started');
            // Start metrics collection
            this.logger.info('✅ Metrics collection started');
        }
        catch (error) {
            this.logger.error('❌ Failed to initialize server:', error);
            process.exit(1);
        }
    }
    setupMiddleware() {
        // Request logging (first)
        this.app.use(this.errorHandler.requestLogger());
        // Security headers
        this.app.use(this.errorHandler.securityHeaders());
        // Security middleware
        this.app.use((0, helmet_1.default)({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'", "https:"],
                    scriptSrc: ["'self'", "'unsafe-eval'", "'unsafe-inline'"],
                    imgSrc: ["'self'", "data:", "https:"],
                    connectSrc: ["'self'", "ws:", "wss:"],
                },
            },
            crossOriginEmbedderPolicy: false,
        }));
        // CORS configuration
        this.app.use((0, cors_1.default)({
            origin: dev ? true : [
                'https://testnet-faucet.blacksilk.io',
                'https://explorer.blacksilk.io',
                'https://blacksilk.io'
            ],
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
        }));
        // Request parsing
        this.app.use(express_1.default.json({ limit: '1mb' }));
        this.app.use(express_1.default.urlencoded({ extended: true, limit: '1mb' }));
        // Request timeout
        this.app.use(this.errorHandler.timeoutHandler(30000));
        // Inject services into request
        this.app.use((req, res, next) => {
            req.faucetService = this.faucetService;
            req.db = this.db;
            req.logger = this.logger;
            req.metrics = this.metrics;
            next();
        });
    }
    setupRoutes() {
        const handle = this.nextApp.getRequestHandler();
        // Health check (no rate limiting)
        this.app.get('/health', this.healthCheck.middleware('basic'));
        this.app.get('/health/full', this.healthCheck.middleware('full'));
        // Metrics endpoint (with rate limiting)
        const metricsLimiter = this.rateLimitFactory.createStatusLimiter();
        this.app.get('/metrics', metricsLimiter.middleware(), async (req, res) => {
            try {
                const metrics = await this.metrics.getPerformanceMetrics();
                res.json(metrics);
            }
            catch (error) {
                this.logger.error('Failed to get metrics:', error);
                res.status(500).json({ error: 'Failed to get metrics' });
            }
        });
        // Prometheus metrics
        this.app.get('/metrics/prometheus', metricsLimiter.middleware(), (req, res) => {
            try {
                const prometheusMetrics = this.metrics.getPrometheusMetrics();
                res.set('Content-Type', 'text/plain');
                res.send(prometheusMetrics);
            }
            catch (error) {
                this.logger.error('Failed to get Prometheus metrics:', error);
                res.status(500).send('# Failed to get metrics');
            }
        });
        // API routes with different rate limits
        const apiLimiter = this.rateLimitFactory.createAPILimiter();
        const faucetLimiter = this.rateLimitFactory.createFaucetLimiter();
        this.app.use('/api', apiLimiter.middleware(), this.createAPIRoutes());
        this.app.use('/api/request', faucetLimiter.middleware()); // Extra strict for faucet requests
        // Admin routes with strict rate limiting
        const adminLimiter = this.rateLimitFactory.createAdminLimiter();
        this.app.use('/admin', adminLimiter.middleware(), this.adminRoutes.getRouter());
        // Status endpoint
        this.app.get('/status', metricsLimiter.middleware(), async (req, res) => {
            try {
                const status = await this.faucetService.getStatus();
                res.json(status);
            }
            catch (error) {
                this.logger.error('Status check failed:', error);
                res.status(500).json({ error: 'Status check failed' });
            }
        });
        // Static files for production
        if (!dev) {
            this.app.use('/static', express_1.default.static(path_1.default.join(__dirname, '../.next/static')));
        }
        // Next.js handler for all other routes
        this.app.all('*', (req, res) => {
            return handle(req, res);
        });
        // 404 handler
        this.app.use(this.errorHandler.notFoundHandler());
        // Error handling middleware (must be last)
        this.app.use(this.errorHandler.middleware());
    }
    createAPIRoutes() {
        const router = (0, express_2.Router)();
        // Faucet token request
        router.post('/request', this.errorHandler.wrapAsync(async (req, res) => {
            const { address, captchaToken } = req.body;
            const ip = this.getClientIP(req);
            const userAgent = req.get('User-Agent') || '';
            this.logger.info('Faucet request received', { address, ip });
            this.metrics.incrementCounter('api_requests_total', 1, { endpoint: 'request' });
            try {
                const result = await this.faucetService.processFaucetRequest(address, ip, userAgent, captchaToken);
                this.metrics.recordFaucetDistribution(address, result.amount, result.success);
                if (result.success) {
                    res.json({
                        success: true,
                        message: 'Tokens sent successfully',
                        transactionHash: result.transactionHash,
                        amount: result.amount
                    });
                }
                else {
                    res.status(400).json({
                        success: false,
                        error: result.error
                    });
                }
            }
            catch (error) {
                this.logger.error('Faucet request failed:', error);
                this.metrics.incrementCounter('api_errors_total', 1, { endpoint: 'request' });
                throw error;
            }
        }));
        // Check request status
        router.get('/status/:id', this.errorHandler.wrapAsync(async (req, res) => {
            const { id } = req.params;
            try {
                const status = await this.faucetService.getRequestStatus(id);
                res.json({ success: true, status });
            }
            catch (error) {
                this.logger.error('Status check failed:', error);
                throw error;
            }
        }));
        // Check address cooldown
        router.get('/cooldown/:address', this.errorHandler.wrapAsync(async (req, res) => {
            const { address } = req.params;
            try {
                const cooldown = await this.faucetService.getAddressCooldown(address);
                res.json({ success: true, cooldown });
            }
            catch (error) {
                this.logger.error('Cooldown check failed:', error);
                throw error;
            }
        }));
        // Get faucet statistics
        router.get('/stats', this.errorHandler.wrapAsync(async (req, res) => {
            try {
                const stats = await this.faucetService.getStatistics();
                res.json({ success: true, stats });
            }
            catch (error) {
                this.logger.error('Stats retrieval failed:', error);
                throw error;
            }
        }));
        // Get network info
        router.get('/network', this.errorHandler.wrapAsync(async (req, res) => {
            try {
                const networkInfo = await this.faucetService.getNetworkInfo();
                res.json({ success: true, network: networkInfo });
            }
            catch (error) {
                this.logger.error('Network info failed:', error);
                throw error;
            }
        }));
        // Validate address
        router.post('/validate', this.errorHandler.wrapAsync(async (req, res) => {
            const { address } = req.body;
            try {
                const isValid = await this.faucetService.validateAddress(address);
                res.json({ success: true, valid: isValid });
            }
            catch (error) {
                this.logger.error('Address validation failed:', error);
                throw error;
            }
        }));
        return router;
    }
    getClientIP(req) {
        const forwarded = req.headers['x-forwarded-for'];
        const realIP = req.headers['x-real-ip'];
        if (forwarded) {
            return forwarded.split(',')[0].trim();
        }
        if (realIP) {
            return realIP;
        }
        return req.connection.remoteAddress || req.socket.remoteAddress || 'unknown';
    }
    async start() {
        try {
            const server = (0, http_1.createServer)(this.app);
            server.listen(port, hostname, () => {
                this.logger.info(`🎉 BlackSilk Testnet Faucet running on http://${hostname}:${port}`);
                this.logger.info(`📊 Health check: http://${hostname}:${port}/health`);
                this.logger.info(`📈 Metrics: http://${hostname}:${port}/metrics`);
                this.logger.info(`🔧 Admin: http://${hostname}:${port}/admin`);
                this.logger.info(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
            });
            // Graceful shutdown
            process.on('SIGTERM', () => this.shutdown(server));
            process.on('SIGINT', () => this.shutdown(server));
        }
        catch (error) {
            this.logger.error('❌ Failed to start server:', error);
            process.exit(1);
        }
    }
    async shutdown(server) {
        this.logger.info('🛑 Shutting down server gracefully...');
        server.close(() => {
            this.logger.info('✅ HTTP server closed');
        });
        // Stop services
        await this.faucetService.shutdown();
        this.healthCheck.stopPeriodicChecks();
        this.metrics.stop();
        await this.db.close();
        this.logger.info('👋 Server shutdown complete');
        process.exit(0);
    }
}
// Start the server
if (require.main === module) {
    const server = new FaucetServer();
    server.initialize().then(() => {
        return server.start();
    }).catch((error) => {
        console.error('❌ Fatal error:', error);
        process.exit(1);
    });
}
exports.default = FaucetServer;
//# sourceMappingURL=index-new.js.map