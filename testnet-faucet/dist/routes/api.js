"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const validator_1 = __importDefault(require("validator"));
const logger_1 = require("../logger");
const router = (0, express_1.Router)();
// Helper function to get client IP
const getClientIP = (req) => {
    return req.headers['x-forwarded-for']?.split(',')[0] ||
        req.connection.remoteAddress ||
        req.socket.remoteAddress ||
        '127.0.0.1';
};
// Helper function to create API response
const createResponse = (success, data, error, message) => {
    return {
        success,
        data,
        error,
        message,
        timestamp: Date.now()
    };
};
// Request tokens endpoint
router.post('/request', async (req, res) => {
    try {
        const { address, captcha } = req.body;
        const ipAddress = getClientIP(req);
        const userAgent = req.get('User-Agent');
        const faucetService = req.faucetService;
        // Input validation
        if (!address) {
            return res.status(400).json(createResponse(false, null, 'Address is required'));
        }
        if (typeof address !== 'string') {
            return res.status(400).json(createResponse(false, null, 'Invalid address format'));
        }
        // Sanitize address input
        const sanitizedAddress = validator_1.default.escape(address.trim());
        if (sanitizedAddress.length > 95 || sanitizedAddress.length < 26) {
            return res.status(400).json(createResponse(false, null, 'Invalid address length'));
        }
        // Log request for security monitoring
        logger_1.securityLogger.info('Faucet request received', {
            address: sanitizedAddress,
            ipAddress,
            userAgent,
            timestamp: Date.now()
        });
        // Process faucet request
        const result = await faucetService.requestTokens(sanitizedAddress, ipAddress, userAgent);
        const statusCode = result.success ? 200 : 400;
        // Log result
        if (result.success) {
            logger_1.logger.info(`Faucet request successful: ${sanitizedAddress}`, {
                address: sanitizedAddress,
                amount: result.amount,
                requestId: result.request_id
            });
        }
        else {
            logger_1.logger.warn(`Faucet request failed: ${sanitizedAddress}`, {
                address: sanitizedAddress,
                error: result.message,
                cooldown: result.cooldown_remaining
            });
        }
        res.status(statusCode).json(createResponse(result.success, result, result.success ? undefined : result.message));
    }
    catch (error) {
        logger_1.logger.error('Faucet request endpoint error:', error);
        res.status(500).json(createResponse(false, null, 'Internal server error'));
    }
});
// Check request status
router.get('/status/:requestId', async (req, res) => {
    try {
        const { requestId } = req.params;
        if (!requestId || !validator_1.default.isUUID(requestId)) {
            return res.status(400).json(createResponse(false, null, 'Invalid request ID'));
        }
        // Query database for request status
        const { query } = await Promise.resolve().then(() => __importStar(require('../database')));
        const request = await query('SELECT * FROM faucet_requests WHERE id = ?', [requestId]);
        if (!request.length) {
            return res.status(404).json(createResponse(false, null, 'Request not found'));
        }
        const requestData = request[0];
        res.json(createResponse(true, {
            id: requestData.id,
            address: requestData.address,
            amount: requestData.amount,
            status: requestData.status,
            transaction_hash: requestData.transaction_hash,
            error_message: requestData.error_message,
            created_at: requestData.created_at,
            updated_at: requestData.updated_at
        }));
    }
    catch (error) {
        logger_1.logger.error('Status check endpoint error:', error);
        res.status(500).json(createResponse(false, null, 'Internal server error'));
    }
});
// Get faucet statistics
router.get('/stats', async (req, res) => {
    try {
        const faucetService = req.faucetService;
        const stats = await faucetService.getStats();
        res.json(createResponse(true, stats));
    }
    catch (error) {
        logger_1.logger.error('Stats endpoint error:', error);
        res.status(500).json(createResponse(false, null, 'Failed to get statistics'));
    }
});
// Check address cooldown
router.get('/cooldown/:address', async (req, res) => {
    try {
        const { address } = req.params;
        if (!address) {
            return res.status(400).json(createResponse(false, null, 'Address is required'));
        }
        const sanitizedAddress = validator_1.default.escape(address.trim());
        // Query for last request
        const { query } = await Promise.resolve().then(() => __importStar(require('../database')));
        const lastRequest = await query('SELECT timestamp FROM faucet_requests WHERE address = ? AND status = "completed" ORDER BY timestamp DESC LIMIT 1', [sanitizedAddress]);
        const cooldownHours = parseInt(process.env.FAUCET_COOLDOWN_HOURS || '24');
        const cooldownMs = cooldownHours * 60 * 60 * 1000;
        let cooldownInfo = {
            address: sanitizedAddress,
            last_request_time: 0,
            cooldown_remaining: 0,
            can_request: true,
            next_request_time: null
        };
        if (lastRequest.length > 0) {
            const lastRequestTime = lastRequest[0].timestamp;
            const timeSinceLastRequest = Date.now() - lastRequestTime;
            const cooldownRemaining = Math.max(0, cooldownMs - timeSinceLastRequest);
            cooldownInfo = {
                address: sanitizedAddress,
                last_request_time: lastRequestTime,
                cooldown_remaining: Math.ceil(cooldownRemaining / 1000), // seconds
                can_request: cooldownRemaining === 0,
                next_request_time: cooldownRemaining > 0
                    ? new Date(Date.now() + cooldownRemaining).toISOString()
                    : null
            };
        }
        res.json(createResponse(true, cooldownInfo));
    }
    catch (error) {
        logger_1.logger.error('Cooldown check endpoint error:', error);
        res.status(500).json(createResponse(false, null, 'Internal server error'));
    }
});
// Get recent requests for address
router.get('/history/:address', async (req, res) => {
    try {
        const { address } = req.params;
        const { limit = '10', offset = '0' } = req.query;
        if (!address) {
            return res.status(400).json(createResponse(false, null, 'Address is required'));
        }
        const sanitizedAddress = validator_1.default.escape(address.trim());
        const requestLimit = Math.min(parseInt(limit) || 10, 100); // Max 100 requests
        const requestOffset = parseInt(offset) || 0;
        const { query } = await Promise.resolve().then(() => __importStar(require('../database')));
        const requests = await query(`SELECT address, amount, status, transaction_hash, created_at, updated_at 
       FROM faucet_requests 
       WHERE address = ? 
       ORDER BY created_at DESC 
       LIMIT ? OFFSET ?`, [sanitizedAddress, requestLimit, requestOffset]);
        res.json(createResponse(true, requests));
    }
    catch (error) {
        logger_1.logger.error('History endpoint error:', error);
        res.status(500).json(createResponse(false, null, 'Internal server error'));
    }
});
// Get network information
router.get('/network', async (req, res) => {
    try {
        const faucetService = req.faucetService;
        const status = await faucetService.getStatus();
        res.json(createResponse(true, status.network));
    }
    catch (error) {
        logger_1.logger.error('Network info endpoint error:', error);
        res.status(500).json(createResponse(false, null, 'Failed to get network information'));
    }
});
// Get faucet balance
router.get('/balance', async (req, res) => {
    try {
        const faucetService = req.faucetService;
        const balance = await faucetService.getFaucetBalance();
        // Don't expose full balance details to public API
        res.json(createResponse(true, {
            sufficient: balance.balance > 10, // Just indicate if balance is sufficient
            last_updated: balance.last_updated
        }));
    }
    catch (error) {
        logger_1.logger.error('Balance endpoint error:', error);
        res.status(500).json(createResponse(false, null, 'Failed to get balance information'));
    }
});
// Get service configuration (public info only)
router.get('/config', async (req, res) => {
    try {
        const faucetService = req.faucetService;
        const status = await faucetService.getStatus();
        // Only expose public configuration
        const publicConfig = {
            faucet_amount: status.config.faucet_amount,
            cooldown_hours: status.config.cooldown_hours,
            daily_limit: status.config.daily_limit,
            maintenance_mode: status.config.maintenance_mode,
            captcha_enabled: status.config.captcha_enabled
        };
        res.json(createResponse(true, publicConfig));
    }
    catch (error) {
        logger_1.logger.error('Config endpoint error:', error);
        res.status(500).json(createResponse(false, null, 'Failed to get configuration'));
    }
});
// Validate address format
router.post('/validate', async (req, res) => {
    try {
        const { address } = req.body;
        if (!address) {
            return res.status(400).json(createResponse(false, null, 'Address is required'));
        }
        // Basic validation (implement proper BlackSilk address validation)
        const isValid = typeof address === 'string' &&
            address.length >= 26 &&
            address.length <= 95 &&
            /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/.test(address);
        res.json(createResponse(true, {
            is_valid: isValid,
            address: isValid ? address : null,
            error: isValid ? null : 'Invalid address format'
        }));
    }
    catch (error) {
        logger_1.logger.error('Address validation endpoint error:', error);
        res.status(500).json(createResponse(false, null, 'Internal server error'));
    }
});
exports.default = router;
//# sourceMappingURL=api.js.map