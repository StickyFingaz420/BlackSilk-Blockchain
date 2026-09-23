"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.closeDatabase = exports.transaction = exports.get = exports.run = exports.query = exports.getDatabase = exports.initializeDatabase = void 0;
const sqlite3_1 = __importDefault(require("sqlite3"));
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
const logger_1 = require("./logger");
const DB_PATH = process.env.DATABASE_PATH || path_1.default.join(process.cwd(), 'data', 'faucet.db');
let db;
const initializeDatabase = async () => {
    return new Promise((resolve, reject) => {
        try {
            // Ensure data directory exists
            const dataDir = path_1.default.dirname(DB_PATH);
            if (!fs_1.default.existsSync(dataDir)) {
                fs_1.default.mkdirSync(dataDir, { recursive: true });
            }
            // Open database connection
            db = new sqlite3_1.default.Database(DB_PATH, (err) => {
                if (err) {
                    logger_1.logger.error('Failed to open database:', err);
                    reject(err);
                    return;
                }
                logger_1.logger.info(`Database connected: ${DB_PATH}`);
                createTables().then(resolve).catch(reject);
            });
        }
        catch (error) {
            logger_1.logger.error('Database initialization error:', error);
            reject(error);
        }
    });
};
exports.initializeDatabase = initializeDatabase;
const createTables = async () => {
    return new Promise((resolve, reject) => {
        const queries = [
            // Faucet requests table
            `CREATE TABLE IF NOT EXISTS faucet_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT NOT NULL,
        amount REAL NOT NULL,
        ip_address TEXT NOT NULL,
        user_agent TEXT,
        timestamp INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        transaction_hash TEXT,
        error_message TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,
            // Rate limiting table
            `CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,
            // Rate limit blocks table
            `CREATE TABLE IF NOT EXISTS rate_limit_blocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL UNIQUE,
        block_until INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,
            // Blacklist table
            `CREATE TABLE IF NOT EXISTS blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT NOT NULL UNIQUE,
        reason TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,
            // Metrics table
            `CREATE TABLE IF NOT EXISTS metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        value REAL NOT NULL,
        timestamp INTEGER NOT NULL,
        labels TEXT,
        type TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,
            // Configuration table
            `CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,
            // Transaction history table
            `CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hash TEXT NOT NULL UNIQUE,
        from_address TEXT NOT NULL,
        to_address TEXT NOT NULL,
        amount REAL NOT NULL,
        fee REAL NOT NULL,
        block_height INTEGER,
        confirmations INTEGER DEFAULT 0,
        timestamp INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,
            // System events/logs table
            `CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        data TEXT,
        severity TEXT NOT NULL DEFAULT 'info',
        timestamp INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`
        ];
        // Create indexes
        const indexes = [
            'CREATE INDEX IF NOT EXISTS idx_faucet_requests_address ON faucet_requests(address)',
            'CREATE INDEX IF NOT EXISTS idx_faucet_requests_ip ON faucet_requests(ip_address)',
            'CREATE INDEX IF NOT EXISTS idx_faucet_requests_timestamp ON faucet_requests(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_faucet_requests_status ON faucet_requests(status)',
            'CREATE INDEX IF NOT EXISTS idx_rate_limits_key ON rate_limits(key)',
            'CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits(ip_address)',
            'CREATE INDEX IF NOT EXISTS idx_rate_limit_blocks_key ON rate_limit_blocks(key)',
            'CREATE INDEX IF NOT EXISTS idx_rate_limit_blocks_until ON rate_limit_blocks(block_until)',
            'CREATE INDEX IF NOT EXISTS idx_blacklist_address ON blacklist(address)',
            'CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics(name)',
            'CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_transactions_hash ON transactions(hash)',
            'CREATE INDEX IF NOT EXISTS idx_transactions_address ON transactions(to_address)',
            'CREATE INDEX IF NOT EXISTS idx_events_type ON events(type)',
            'CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)'
        ];
        let completed = 0;
        const total = queries.length + indexes.length;
        const handleComplete = (err) => {
            if (err) {
                logger_1.logger.error('Database table creation error:', err);
                reject(err);
                return;
            }
            completed++;
            if (completed === total) {
                logger_1.logger.info('Database tables and indexes created successfully');
                insertDefaultConfig().then(resolve).catch(reject);
            }
        };
        // Execute table creation queries
        queries.forEach(query => {
            db.run(query, handleComplete);
        });
        // Execute index creation queries
        indexes.forEach(query => {
            db.run(query, handleComplete);
        });
    });
};
const insertDefaultConfig = async () => {
    return new Promise((resolve, reject) => {
        const defaultConfig = [
            ['faucet_amount', process.env.FAUCET_AMOUNT || '10.0'],
            ['cooldown_hours', process.env.FAUCET_COOLDOWN_HOURS || '24'],
            ['daily_limit', process.env.FAUCET_MAX_DAILY_LIMIT || '1000'],
            ['rate_limit_window_ms', process.env.RATE_LIMIT_WINDOW_MS || '900000'],
            ['rate_limit_max_requests', process.env.RATE_LIMIT_MAX_REQUESTS || '5'],
            ['maintenance_mode', 'false'],
            ['captcha_enabled', 'true'],
            ['min_balance_alert', '100'],
            ['version', '1.0.0']
        ];
        let completed = 0;
        const total = defaultConfig.length;
        defaultConfig.forEach(([key, value]) => {
            db.run('INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)', [key, value], (err) => {
                if (err) {
                    logger_1.logger.error(`Failed to insert config ${key}:`, err);
                    reject(err);
                    return;
                }
                completed++;
                if (completed === total) {
                    logger_1.logger.info('Default configuration inserted');
                    resolve();
                }
            });
        });
    });
};
// Database access functions
const getDatabase = () => {
    if (!db) {
        throw new Error('Database not initialized. Call initializeDatabase() first.');
    }
    return db;
};
exports.getDatabase = getDatabase;
const query = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) {
                logger_1.logger.error('Database query error:', { sql, params, error: err });
                reject(err);
            }
            else {
                resolve(rows);
            }
        });
    });
};
exports.query = query;
const run = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) {
                logger_1.logger.error('Database run error:', { sql, params, error: err });
                reject(err);
            }
            else {
                resolve({ id: this.lastID, changes: this.changes });
            }
        });
    });
};
exports.run = run;
const get = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) {
                logger_1.logger.error('Database get error:', { sql, params, error: err });
                reject(err);
            }
            else {
                resolve(row);
            }
        });
    });
};
exports.get = get;
// Transaction helper
const transaction = async (callback) => {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            db.run('BEGIN TRANSACTION');
            callback()
                .then(result => {
                db.run('COMMIT', (err) => {
                    if (err) {
                        logger_1.logger.error('Transaction commit error:', err);
                        reject(err);
                    }
                    else {
                        resolve(result);
                    }
                });
            })
                .catch(error => {
                db.run('ROLLBACK', (rollbackErr) => {
                    if (rollbackErr) {
                        logger_1.logger.error('Transaction rollback error:', rollbackErr);
                    }
                    reject(error);
                });
            });
        });
    });
};
exports.transaction = transaction;
// Close database connection
const closeDatabase = () => {
    return new Promise((resolve, reject) => {
        if (db) {
            db.close((err) => {
                if (err) {
                    logger_1.logger.error('Error closing database:', err);
                    reject(err);
                }
                else {
                    logger_1.logger.info('Database connection closed');
                    resolve();
                }
            });
        }
        else {
            resolve();
        }
    });
};
exports.closeDatabase = closeDatabase;
//# sourceMappingURL=database.js.map