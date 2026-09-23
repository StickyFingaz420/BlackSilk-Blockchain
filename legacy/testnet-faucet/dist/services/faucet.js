"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.FaucetService = void 0;
const axios_1 = __importDefault(require("axios"));
const crypto_1 = __importDefault(require("crypto"));
const logger_1 = require("../logger");
const database_1 = require("../database");
class FaucetService {
    constructor() {
        this.processingQueue = [];
        this.isProcessing = false;
        this.networkInfo = null;
        this.nodeUrl = process.env.BLACKSILK_NODE_URL || 'http://localhost:19333';
        this.faucetPrivateKey = process.env.FAUCET_PRIVATE_KEY || '';
        this.faucetAddress = process.env.FAUCET_ADDRESS || '';
        // Initialize HTTP client for BlackSilk node
        this.nodeClient = axios_1.default.create({
            baseURL: this.nodeUrl,
            timeout: 30000,
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'BlackSilk-Testnet-Faucet/1.0.0'
            }
        });
        // Default configuration
        this.config = {
            faucet_amount: parseFloat(process.env.FAUCET_AMOUNT || '10.0'),
            cooldown_hours: parseInt(process.env.FAUCET_COOLDOWN_HOURS || '24'),
            daily_limit: parseFloat(process.env.FAUCET_MAX_DAILY_LIMIT || '1000'),
            rate_limit_window_ms: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'),
            rate_limit_max_requests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '5'),
            maintenance_mode: false,
            captcha_enabled: true,
            min_balance_alert: 100
        };
    }
    async initialize() {
        try {
            // Load configuration from database
            await this.loadConfig();
            // Test node connection
            await this.updateNetworkInfo();
            // Validate faucet wallet setup
            await this.validateFaucetWallet();
            // Start background processing
            this.startBackgroundProcessing();
            logger_1.logger.info('✅ Faucet service initialized successfully');
        }
        catch (error) {
            logger_1.logger.error('❌ Failed to initialize faucet service:', error);
            throw error;
        }
    }
    async loadConfig() {
        try {
            const configRows = await (0, database_1.query)('SELECT key, value FROM config');
            const dbConfig = {};
            configRows.forEach((row) => {
                const value = row.value;
                // Parse boolean and numeric values
                if (value === 'true')
                    dbConfig[row.key] = true;
                else if (value === 'false')
                    dbConfig[row.key] = false;
                else if (!isNaN(parseFloat(value)))
                    dbConfig[row.key] = parseFloat(value);
                else
                    dbConfig[row.key] = value;
            });
            this.config = { ...this.config, ...dbConfig };
            logger_1.logger.info('Configuration loaded from database');
        }
        catch (error) {
            logger_1.logger.warn('Failed to load config from database, using defaults:', error);
        }
    }
    async updateNetworkInfo() {
        try {
            const response = await this.nodeClient.get('/status');
            const nodeStatus = response.data;
            this.networkInfo = {
                network_name: `BlackSilk ${nodeStatus.network}`,
                node_url: this.nodeUrl,
                block_height: nodeStatus.height,
                peers: nodeStatus.peers,
                difficulty: nodeStatus.difficulty,
                mempool_size: nodeStatus.mempool_size,
                is_synced: nodeStatus.synced,
                last_block_time: Date.now()
            };
            logger_1.logger.debug('Network info updated:', this.networkInfo);
        }
        catch (error) {
            logger_1.logger.error('Failed to update network info:', error);
            throw new Error('Cannot connect to BlackSilk node');
        }
    }
    async validateFaucetWallet() {
        if (!this.faucetPrivateKey || !this.faucetAddress) {
            throw new Error('Faucet wallet not configured. Set FAUCET_PRIVATE_KEY and FAUCET_ADDRESS');
        }
        try {
            const balance = await this.getFaucetBalance();
            logger_1.logger.info(`Faucet wallet balance: ${balance.balance} BLK`);
            if (balance.balance < this.config.min_balance_alert) {
                logger_1.securityLogger.warn('Low faucet balance detected', {
                    balance: balance.balance,
                    address: this.faucetAddress,
                    threshold: this.config.min_balance_alert
                });
            }
        }
        catch (error) {
            logger_1.logger.error('Failed to validate faucet wallet:', error);
            throw new Error('Faucet wallet validation failed');
        }
    }
    async getFaucetBalance() {
        try {
            // Get balance from node - implement according to BlackSilk API
            const response = await this.nodeClient.get(`/get_balance?address=${this.faucetAddress}`);
            const balance = response.data.balance || 0;
            return {
                address: this.faucetAddress,
                balance: balance,
                unconfirmed_balance: response.data.unconfirmed_balance || 0,
                last_updated: new Date().toISOString()
            };
        }
        catch (error) {
            logger_1.logger.error('Failed to get faucet balance:', error);
            throw error;
        }
    }
    async requestTokens(address, ipAddress, userAgent) {
        try {
            // Validate request
            const validation = await this.validateRequest(address, ipAddress);
            if (!validation.isValid) {
                return {
                    success: false,
                    message: validation.errors.join('. '),
                    cooldown_remaining: validation.cooldownRemaining
                };
            }
            // Check maintenance mode
            if (this.config.maintenance_mode) {
                return {
                    success: false,
                    message: 'Faucet is currently under maintenance. Please try again later.'
                };
            }
            // Create database record
            const requestId = crypto_1.default.randomUUID();
            const timestamp = Date.now();
            const result = await (0, database_1.run)(`INSERT INTO faucet_requests 
         (address, amount, ip_address, user_agent, timestamp, status) 
         VALUES (?, ?, ?, ?, ?, ?)`, [address, this.config.faucet_amount, ipAddress, userAgent, timestamp, 'pending']);
            // Add to processing queue
            const queuedRequest = {
                id: requestId,
                address,
                amount: this.config.faucet_amount,
                priority: 1,
                attempts: 0,
                created_at: timestamp
            };
            this.processingQueue.push(queuedRequest);
            logger_1.logger.info(`Token request queued: ${address} (${this.config.faucet_amount} BLK)`, {
                requestId,
                address,
                amount: this.config.faucet_amount,
                ipAddress
            });
            return {
                success: true,
                message: 'Request submitted successfully. Tokens will be sent shortly.',
                request_id: requestId,
                amount: this.config.faucet_amount,
                estimated_confirmation_time: 300 // 5 minutes
            };
        }
        catch (error) {
            logger_1.logger.error('Token request failed:', error);
            return {
                success: false,
                message: 'Internal server error. Please try again later.'
            };
        }
    }
    async validateRequest(address, ipAddress) {
        const errors = [];
        // Validate address format
        if (!this.isValidAddress(address)) {
            errors.push('Invalid BlackSilk address format');
        }
        // Check cooldown period
        const cooldownInfo = await this.checkCooldown(address);
        if (!cooldownInfo.can_request) {
            errors.push(`Address is in cooldown period`);
            return {
                isValid: false,
                errors,
                cooldownRemaining: cooldownInfo.cooldown_remaining
            };
        }
        // Check daily limit
        const dailyDistributed = await this.getDailyDistributed();
        if (dailyDistributed + this.config.faucet_amount > this.config.daily_limit) {
            errors.push('Daily distribution limit reached. Please try again tomorrow.');
        }
        // Check IP rate limiting
        const ipRequests = await this.getRecentRequestsByIP(ipAddress);
        if (ipRequests >= 3) { // Max 3 requests per IP per day
            errors.push('Too many requests from this IP address');
        }
        return {
            isValid: errors.length === 0,
            errors
        };
    }
    isValidAddress(address) {
        // BlackSilk address validation - implement according to address format
        if (!address || typeof address !== 'string')
            return false;
        // Basic validation - adjust according to BlackSilk address format
        if (address.length < 26 || address.length > 95)
            return false;
        // Check for valid characters (base58 or bech32 depending on format)
        const validChars = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/;
        return validChars.test(address);
    }
    async checkCooldown(address) {
        try {
            const lastRequest = await (0, database_1.get)('SELECT timestamp FROM faucet_requests WHERE address = ? AND status = "completed" ORDER BY timestamp DESC LIMIT 1', [address]);
            if (!lastRequest) {
                return {
                    address,
                    last_request_time: 0,
                    cooldown_remaining: 0,
                    can_request: true
                };
            }
            const lastRequestTime = lastRequest.timestamp;
            const cooldownMs = this.config.cooldown_hours * 60 * 60 * 1000;
            const timeSinceLastRequest = Date.now() - lastRequestTime;
            const cooldownRemaining = Math.max(0, cooldownMs - timeSinceLastRequest);
            return {
                address,
                last_request_time: lastRequestTime,
                cooldown_remaining: Math.ceil(cooldownRemaining / 1000), // seconds
                can_request: cooldownRemaining === 0
            };
        }
        catch (error) {
            logger_1.logger.error('Cooldown check failed:', error);
            return {
                address,
                last_request_time: 0,
                cooldown_remaining: 0,
                can_request: false
            };
        }
    }
    async getDailyDistributed() {
        try {
            const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);
            const result = await (0, database_1.get)('SELECT SUM(amount) as total FROM faucet_requests WHERE timestamp > ? AND status = "completed"', [oneDayAgo]);
            return result?.total || 0;
        }
        catch (error) {
            logger_1.logger.error('Failed to get daily distributed amount:', error);
            return 0;
        }
    }
    async getRecentRequestsByIP(ipAddress) {
        try {
            const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);
            const result = await (0, database_1.get)('SELECT COUNT(*) as count FROM faucet_requests WHERE ip_address = ? AND timestamp > ?', [ipAddress, oneDayAgo]);
            return result?.count || 0;
        }
        catch (error) {
            logger_1.logger.error('Failed to get recent requests by IP:', error);
            return 0;
        }
    }
    startBackgroundProcessing() {
        // Process queue every 10 seconds
        setInterval(async () => {
            if (!this.isProcessing && this.processingQueue.length > 0) {
                await this.processQueue();
            }
        }, 10000);
        // Update network info every 30 seconds
        setInterval(async () => {
            try {
                await this.updateNetworkInfo();
            }
            catch (error) {
                logger_1.logger.warn('Failed to update network info:', error);
            }
        }, 30000);
    }
    async processQueue() {
        if (this.isProcessing || this.processingQueue.length === 0)
            return;
        this.isProcessing = true;
        try {
            const request = this.processingQueue.shift();
            await this.processRequest(request);
        }
        catch (error) {
            logger_1.logger.error('Queue processing error:', error);
        }
        finally {
            this.isProcessing = false;
        }
    }
    async processRequest(request) {
        try {
            logger_1.logger.info(`Processing faucet request: ${request.id}`);
            // Create and submit transaction
            const transaction = await this.createTransaction(request.address, request.amount);
            const result = await this.submitTransaction(transaction);
            if (result.success && result.transaction_hash) {
                // Update database with success
                await (0, database_1.run)('UPDATE faucet_requests SET status = ?, transaction_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', ['completed', result.transaction_hash, request.id]);
                logger_1.logger.info(`✅ Tokens sent successfully: ${request.address} (${result.transaction_hash})`);
            }
            else {
                throw new Error(result.error || 'Transaction submission failed');
            }
        }
        catch (error) {
            logger_1.logger.error(`❌ Failed to process request ${request.id}:`, error);
            // Update database with failure
            await (0, database_1.run)('UPDATE faucet_requests SET status = ?, error_message = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', ['failed', error.message, request.id]);
            // Retry logic (up to 3 attempts)
            if (request.attempts < 3) {
                request.attempts++;
                request.retry_after = Date.now() + (60000 * request.attempts); // Exponential backoff
                this.processingQueue.push(request);
                logger_1.logger.info(`Retrying request ${request.id} (attempt ${request.attempts})`);
            }
        }
    }
    async createTransaction(toAddress, amount) {
        // This is a simplified transaction creation
        // In a real implementation, you would need to:
        // 1. Get UTXOs for the faucet address
        // 2. Create proper inputs and outputs
        // 3. Calculate fees
        // 4. Sign the transaction
        const amountAtomic = Math.floor(amount * 1000000); // Convert to atomic units
        const fee = 1000; // 0.001 BLK fee
        // Create a simple transaction structure
        const transaction = {
            inputs: [], // Would be populated with actual UTXOs
            outputs: [
                {
                    address: toAddress,
                    amount: amountAtomic
                }
            ],
            fee,
            metadata: `FAUCET:${Date.now()}`,
            signature: this.signTransaction(toAddress, amountAtomic)
        };
        return transaction;
    }
    signTransaction(toAddress, amount) {
        // Simplified signing - implement proper cryptographic signing
        const data = `${this.faucetAddress}:${toAddress}:${amount}:${Date.now()}`;
        return crypto_1.default.createHash('sha256').update(data + this.faucetPrivateKey).digest('hex');
    }
    async submitTransaction(transaction) {
        try {
            const response = await this.nodeClient.post('/submit_tx', transaction);
            const result = response.data;
            return {
                success: result.success,
                transaction_hash: result.tx_hash,
                error: result.success ? undefined : result.message
            };
        }
        catch (error) {
            logger_1.logger.error('Transaction submission failed:', error);
            return {
                success: false,
                error: error.message || 'Network error'
            };
        }
    }
    async getStats() {
        try {
            const [totalRequests, successfulRequests, failedRequests, totalDistributed, dailyDistributed, activeUsers] = await Promise.all([
                (0, database_1.get)('SELECT COUNT(*) as count FROM faucet_requests'),
                (0, database_1.get)('SELECT COUNT(*) as count FROM faucet_requests WHERE status = "completed"'),
                (0, database_1.get)('SELECT COUNT(*) as count FROM faucet_requests WHERE status = "failed"'),
                (0, database_1.get)('SELECT SUM(amount) as total FROM faucet_requests WHERE status = "completed"'),
                (0, database_1.get)('SELECT SUM(amount) as total FROM faucet_requests WHERE status = "completed" AND timestamp > ?', [Date.now() - 24 * 60 * 60 * 1000]),
                (0, database_1.get)('SELECT COUNT(DISTINCT address) as count FROM faucet_requests WHERE timestamp > ?', [Date.now() - 24 * 60 * 60 * 1000])
            ]);
            const balance = await this.getFaucetBalance();
            return {
                total_requests: totalRequests?.count || 0,
                successful_requests: successfulRequests?.count || 0,
                failed_requests: failedRequests?.count || 0,
                total_distributed: totalDistributed?.total || 0,
                daily_distributed: dailyDistributed?.total || 0,
                daily_limit: this.config.daily_limit,
                active_users_24h: activeUsers?.count || 0,
                average_response_time: 30, // TODO: Calculate actual response time
                uptime_percentage: 99.9, // TODO: Calculate actual uptime
                current_balance: balance.balance,
                last_updated: new Date().toISOString()
            };
        }
        catch (error) {
            logger_1.logger.error('Failed to get stats:', error);
            throw error;
        }
    }
    async getStatus() {
        return {
            status: 'operational',
            network: this.networkInfo,
            config: this.config,
            queue_size: this.processingQueue.length,
            is_processing: this.isProcessing,
            last_updated: new Date().toISOString()
        };
    }
    async updateConfig(newConfig) {
        try {
            for (const [key, value] of Object.entries(newConfig)) {
                await (0, database_1.run)('UPDATE config SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?', [String(value), key]);
                this.config[key] = value;
            }
            logger_1.logger.info('Configuration updated:', newConfig);
        }
        catch (error) {
            logger_1.logger.error('Failed to update configuration:', error);
            throw error;
        }
    }
    async shutdown() {
        logger_1.logger.info('Shutting down faucet service...');
        // Process remaining queue items before shutdown
        while (this.processingQueue.length > 0 && this.processingQueue.length < 10) {
            await this.processQueue();
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
        logger_1.logger.info('Faucet service shutdown complete');
    }
}
exports.FaucetService = FaucetService;
//# sourceMappingURL=faucet.js.map