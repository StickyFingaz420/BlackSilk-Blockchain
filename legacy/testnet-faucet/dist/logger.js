"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.initializeLogger = exports.metricsLogger = exports.securityLogger = exports.requestLogger = exports.logger = void 0;
const winston_1 = __importDefault(require("winston"));
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
// Ensure logs directory exists
const logsDir = path_1.default.join(process.cwd(), 'logs');
if (!fs_1.default.existsSync(logsDir)) {
    fs_1.default.mkdirSync(logsDir, { recursive: true });
}
// Custom log format
const logFormat = winston_1.default.format.combine(winston_1.default.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), winston_1.default.format.errors({ stack: true }), winston_1.default.format.json(), winston_1.default.format.printf(({ timestamp, level, message, ...meta }) => {
    let log = `${timestamp} [${level.toUpperCase()}]: ${message}`;
    if (Object.keys(meta).length > 0) {
        log += ` ${JSON.stringify(meta)}`;
    }
    return log;
}));
// Create logger instance
exports.logger = winston_1.default.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: logFormat,
    defaultMeta: { service: 'blacksilk-testnet-faucet' },
    transports: [
        // Error log file
        new winston_1.default.transports.File({
            filename: path_1.default.join(logsDir, 'error.log'),
            level: 'error',
            maxsize: 5242880, // 5MB
            maxFiles: 5,
        }),
        // Combined log file
        new winston_1.default.transports.File({
            filename: path_1.default.join(logsDir, 'combined.log'),
            maxsize: 5242880, // 5MB
            maxFiles: 10,
        }),
        // Console output
        new winston_1.default.transports.Console({
            format: winston_1.default.format.combine(winston_1.default.format.colorize(), winston_1.default.format.simple(), winston_1.default.format.printf(({ timestamp, level, message, ...meta }) => {
                let log = `${timestamp} [${level}]: ${message}`;
                if (Object.keys(meta).length > 0) {
                    log += ` ${JSON.stringify(meta, null, 2)}`;
                }
                return log;
            }))
        })
    ],
});
// Add request/response logging middleware format
exports.requestLogger = winston_1.default.createLogger({
    level: 'info',
    format: winston_1.default.format.combine(winston_1.default.format.timestamp(), winston_1.default.format.json()),
    transports: [
        new winston_1.default.transports.File({
            filename: path_1.default.join(logsDir, 'requests.log'),
            maxsize: 5242880, // 5MB
            maxFiles: 5,
        })
    ],
});
// Security events logger
exports.securityLogger = winston_1.default.createLogger({
    level: 'warn',
    format: winston_1.default.format.combine(winston_1.default.format.timestamp(), winston_1.default.format.json()),
    transports: [
        new winston_1.default.transports.File({
            filename: path_1.default.join(logsDir, 'security.log'),
            maxsize: 5242880, // 5MB
            maxFiles: 10,
        }),
        new winston_1.default.transports.Console({
            format: winston_1.default.format.combine(winston_1.default.format.colorize(), winston_1.default.format.simple())
        })
    ],
});
// Performance metrics logger
exports.metricsLogger = winston_1.default.createLogger({
    level: 'info',
    format: winston_1.default.format.combine(winston_1.default.format.timestamp(), winston_1.default.format.json()),
    transports: [
        new winston_1.default.transports.File({
            filename: path_1.default.join(logsDir, 'metrics.log'),
            maxsize: 10485760, // 10MB
            maxFiles: 3,
        })
    ],
});
// Initialize logger
const initializeLogger = () => {
    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
        exports.logger.error('Uncaught Exception:', error);
        process.exit(1);
    });
    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
        exports.logger.error('Unhandled Rejection:', { reason, promise });
    });
    exports.logger.info('Logger initialized successfully');
};
exports.initializeLogger = initializeLogger;
// Log levels: error, warn, info, http, verbose, debug, silly
exports.default = exports.logger;
//# sourceMappingURL=logger.js.map