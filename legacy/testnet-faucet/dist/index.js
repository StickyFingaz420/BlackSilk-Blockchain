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
const database_1 = require("./database");
const logger_1 = require("./logger");
const faucet_1 = require("./services/faucet");
const rateLimiter_1 = require("./middleware/rateLimiter");
const errorHandler_1 = require("./middleware/errorHandler");
const healthCheck_1 = require("./middleware/healthCheck");
const metrics_1 = require("./services/metrics");
const api_1 = __importDefault(require("./routes/api"));
const admin_1 = __importDefault(require("./routes/admin"));
const dev = process.env.NODE_ENV !== 'production';
const hostname = process.env.HOST || '0.0.0.0';
const port = parseInt(process.env.PORT || '3003', 10);
class FaucetServer {
    constructor() {
        this.app = (0, express_1.default)();
        this.nextApp = (0, next_1.default)({ dev, hostname, port });
        this.faucetService = new faucet_1.FaucetService();
        this.rateLimiter = new rateLimiter_1.RateLimiter();
    }
    async initialize() {
        try {
            // Initialize logger
            (0, logger_1.initializeLogger)();
            logger_1.logger.info('🚀 Starting BlackSilk Testnet Faucet Service...');
            // Initialize database
            await (0, database_1.initializeDatabase)();
            logger_1.logger.info('✅ Database initialized');
            // Initialize Next.js
            await this.nextApp.prepare();
            logger_1.logger.info('✅ Next.js initialized');
            // Initialize faucet service
            await this.faucetService.initialize();
            logger_1.logger.info('✅ Faucet service initialized');
            // Setup middleware
            this.setupMiddleware();
            logger_1.logger.info('✅ Middleware configured');
            // Setup routes
            this.setupRoutes();
            logger_1.logger.info('✅ Routes configured');
            // Start metrics collection
            metrics_1.metricsCollector.start();
            logger_1.logger.info('✅ Metrics collection started');
        }
        catch (error) {
            logger_1.logger.error('❌ Failed to initialize server:', error);
            process.exit(1);
        }
    }
    setupMiddleware() {
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
        // Health check (before rate limiting)
        this.app.use('/health', healthCheck_1.healthCheck);
        // Rate limiting
        this.app.use('/api/', this.rateLimiter.middleware());
        // Request logging
        this.app.use((req, res, next) => {
            const start = Date.now();
            res.on('finish', () => {
                const duration = Date.now() - start;
                logger_1.logger.info(`${req.method} ${req.path} ${res.statusCode} ${duration}ms`, {
                    method: req.method,
                    path: req.path,
                    statusCode: res.statusCode,
                    duration,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                });
            });
            next();
        });
        // Inject faucet service into request
        this.app.use((req, res, next) => {
            req.faucetService = this.faucetService;
            next();
        });
    }
    setupRoutes() {
        const handle = this.nextApp.getRequestHandler();
        // API routes
        this.app.use('/api', api_1.default);
        this.app.use('/admin', admin_1.default);
        // Metrics endpoint
        this.app.get('/metrics', (req, res) => {
            const metrics = metrics_1.metricsCollector.getMetrics();
            res.json(metrics);
        });
        // Status endpoint
        this.app.get('/status', async (req, res) => {
            try {
                const status = await this.faucetService.getStatus();
                res.json(status);
            }
            catch (error) {
                logger_1.logger.error('Status check failed:', error);
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
        // Error handling middleware (must be last)
        this.app.use(errorHandler_1.errorHandler);
    }
    async start() {
        try {
            const server = (0, http_1.createServer)(this.app);
            server.listen(port, hostname, () => {
                logger_1.logger.info(`🎉 BlackSilk Testnet Faucet running on http://${hostname}:${port}`);
                logger_1.logger.info(`📊 Health check: http://${hostname}:${port}/health`);
                logger_1.logger.info(`📈 Metrics: http://${hostname}:${port}/metrics`);
                logger_1.logger.info(`🔧 Admin: http://${hostname}:${port}/admin`);
            });
            // Graceful shutdown
            process.on('SIGTERM', () => this.shutdown(server));
            process.on('SIGINT', () => this.shutdown(server));
        }
        catch (error) {
            logger_1.logger.error('❌ Failed to start server:', error);
            process.exit(1);
        }
    }
    async shutdown(server) {
        logger_1.logger.info('🛑 Shutting down server gracefully...');
        server.close(() => {
            logger_1.logger.info('✅ HTTP server closed');
        });
        await this.faucetService.shutdown();
        metrics_1.metricsCollector.stop();
        logger_1.logger.info('👋 Server shutdown complete');
        process.exit(0);
    }
}
// Start the server
if (require.main === module) {
    const server = new FaucetServer();
    server.initialize().then(() => {
        return server.start();
    }).catch((error) => {
        logger_1.logger.error('❌ Fatal error:', error);
        process.exit(1);
    });
}
exports.default = FaucetServer;
//# sourceMappingURL=index.js.map