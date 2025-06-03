import sqlite3 from 'sqlite3';
import path from 'path';
import fs from 'fs';
import { logger } from './logger';

export class Database {
  private static instance: Database;
  private db: sqlite3.Database | null = null;
  private dbPath: string;

  private constructor(dbPath?: string) {
    this.dbPath = dbPath || process.env.DATABASE_PATH || path.join(process.cwd(), 'data', 'faucet.db');
  }

  static getInstance(dbPath?: string): Database {
    if (!Database.instance) {
      Database.instance = new Database(dbPath);
    }
    return Database.instance;
  }

  async initialize(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        // Ensure data directory exists
        const dataDir = path.dirname(this.dbPath);
        if (!fs.existsSync(dataDir)) {
          fs.mkdirSync(dataDir, { recursive: true });
        }

        // Open database connection
        this.db = new sqlite3.Database(this.dbPath, (err) => {
          if (err) {
            logger.error('Failed to open database:', err);
            reject(err);
            return;
          }
          
          logger.info(`Database connected: ${this.dbPath}`);
          this.createTables().then(resolve).catch(reject);
        });

      } catch (error) {
        logger.error('Database initialization error:', error);
        reject(error);
      }
    });
  }

  private async createTables(): Promise<void> {
    return new Promise((resolve, reject) => {
      const queries = [
        // Faucet requests table
        `CREATE TABLE IF NOT EXISTS faucet_requests (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          transaction_id TEXT NOT NULL UNIQUE,
          address TEXT NOT NULL,
          amount REAL NOT NULL,
          ip_address TEXT NOT NULL,
          user_agent TEXT,
          timestamp INTEGER DEFAULT (strftime('%s', 'now')),
          status TEXT NOT NULL DEFAULT 'pending',
          transaction_hash TEXT,
          error_message TEXT,
          admin_notes TEXT,
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
          is_active INTEGER DEFAULT 1,
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

      // Execute table creation queries sequentially
      this.executeQueriesSequentially(queries)
        .then(() => this.executeQueriesSequentially(indexes))
        .then(() => {
          logger.info('Database tables and indexes created successfully');
          return this.insertDefaultConfig();
        })
        .then(resolve)
        .catch(reject);
    });
  }

  private async insertDefaultConfig(): Promise<void> {
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
        this.db!.run(
          'INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)',
          [key, value],
          (err) => {
            if (err) {
              logger.error(`Failed to insert config ${key}:`, err);
              reject(err);
              return;
            }
            
            completed++;
            if (completed === total) {
              logger.info('Default configuration inserted');
              resolve();
            }
          }
        );
      });
    });
  }

  private async executeQueriesSequentially(queries: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const executeNext = (index: number) => {
        if (index >= queries.length) {
          resolve();
          return;
        }

        this.db!.run(queries[index], (err) => {
          if (err) {
            logger.error(`Database query error at index ${index}:`, err);
            logger.error(`Query: ${queries[index]}`);
            reject(err);
            return;
          }
          executeNext(index + 1);
        });
      };

      executeNext(0);
    });
  }

  // Database access methods
  async query<T = any>(sql: string, params: any[] = []): Promise<T[]> {
    if (!this.db) {
      throw new Error('Database not initialized');
    }

    return new Promise((resolve, reject) => {
      this.db!.all(sql, params, (err, rows) => {
        if (err) {
          logger.error('Database query error:', { sql, params, error: err });
          reject(err);
        } else {
          resolve(rows as T[]);
        }
      });
    });
  }

  async run(sql: string, params: any[] = []): Promise<{ id?: number; changes: number }> {
    if (!this.db) {
      throw new Error('Database not initialized');
    }

    return new Promise((resolve, reject) => {
      this.db!.run(sql, params, function(err) {
        if (err) {
          logger.error('Database run error:', { sql, params, error: err });
          reject(err);
        } else {
          resolve({ id: this.lastID, changes: this.changes });
        }
      });
    });
  }

  async get<T = any>(sql: string, params: any[] = []): Promise<T | undefined> {
    if (!this.db) {
      throw new Error('Database not initialized');
    }

    return new Promise((resolve, reject) => {
      this.db!.get(sql, params, (err, row) => {
        if (err) {
          logger.error('Database get error:', { sql, params, error: err });
          reject(err);
        } else {
          resolve(row as T | undefined);
        }
      });
    });
  }

  // Transaction helper
  async transaction<T>(callback: () => Promise<T>): Promise<T> {
    if (!this.db) {
      throw new Error('Database not initialized');
    }

    return new Promise((resolve, reject) => {
      this.db!.serialize(() => {
        this.db!.run('BEGIN TRANSACTION');
        
        callback()
          .then(result => {
            this.db!.run('COMMIT', (err) => {
              if (err) {
                logger.error('Transaction commit error:', err);
                reject(err);
              } else {
                resolve(result);
              }
            });
          })
          .catch(error => {
            this.db!.run('ROLLBACK', (rollbackErr) => {
              if (rollbackErr) {
                logger.error('Transaction rollback error:', rollbackErr);
              }
              reject(error);
            });
          });
      });
    });
  }

  // Configuration helpers
  async getConfig(key?: string): Promise<any> {
    if (key) {
      const result = await this.get('SELECT value FROM config WHERE key = ?', [key]);
      return result?.value;
    } else {
      const results = await this.query('SELECT key, value FROM config');
      const config: Record<string, string> = {};
      results.forEach((row: any) => {
        config[row.key] = row.value;
      });
      return config;
    }
  }

  async setConfig(key: string, value: string): Promise<void> {
    await this.run(
      'INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)',
      [key, value]
    );
  }

  // Close database connection
  async close(): Promise<void> {
    if (!this.db) {
      return;
    }

    return new Promise((resolve, reject) => {
      this.db!.close((err) => {
        if (err) {
          logger.error('Error closing database:', err);
          reject(err);
        } else {
          logger.info('Database connection closed');
          this.db = null;
          resolve();
        }
      });
    });
  }

  // Additional convenience methods
  async executeQuery<T = any>(sql: string, params: any[] = []): Promise<T[]> {
    return this.query<T>(sql, params);
  }

  async createRequest(address: string, amount: number, ipAddress: string): Promise<string> {
    const transactionId = `faucet_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    await this.run(
      `INSERT INTO faucet_requests (transaction_id, address, amount, ip_address, status, created_at)
       VALUES (?, ?, ?, ?, 'pending', datetime('now'))`,
      [transactionId, address, amount, ipAddress]
    );
    
    return transactionId;
  }

  async getRequest(transactionId: string): Promise<any> {
    return this.get(
      'SELECT * FROM faucet_requests WHERE transaction_id = ?',
      [transactionId]
    );
  }

  async updateRequestStatus(transactionId: string, status: string, transactionHash?: string): Promise<void> {
    const params = [status, transactionId];
    let sql = 'UPDATE faucet_requests SET status = ?, updated_at = datetime(\'now\')';
    
    if (transactionHash) {
      sql += ', transaction_hash = ?';
      params.splice(1, 0, transactionHash);
    }
    
    sql += ' WHERE transaction_id = ?';
    await this.run(sql, params);
  }

  async canMakeRequest(address: string, ipAddress: string): Promise<boolean> {
    // Check if address is blacklisted
    const blacklisted = await this.get(
      'SELECT 1 FROM blacklist WHERE address = ?',
      [address]
    );
    
    if (blacklisted) return false;

    // Check rate limiting (24 hours)
    const recentRequest = await this.get(
      `SELECT 1 FROM faucet_requests 
       WHERE (address = ? OR ip_address = ?) 
       AND created_at > datetime('now', '-24 hours')`,
      [address, ipAddress]
    );
    
    return !recentRequest;
  }

  async addToBlacklist(address: string, reason: string): Promise<number> {
    const result = await this.run(
      'INSERT INTO blacklist (address, reason, created_at) VALUES (?, ?, datetime(\'now\'))',
      [address, reason]
    );
    return result.id!;
  }

  async removeFromBlacklist(id: number): Promise<void> {
    await this.run('DELETE FROM blacklist WHERE id = ?', [id]);
  }

  async getBlacklist(): Promise<any[]> {
    return this.query('SELECT * FROM blacklist ORDER BY created_at DESC');
  }

  async getStats(): Promise<any> {
    const stats = await Promise.all([
      this.get('SELECT COUNT(*) as totalRequests FROM faucet_requests'),
      this.get('SELECT COUNT(*) as completedRequests FROM faucet_requests WHERE status = \'completed\''),
      this.get('SELECT COUNT(*) as pendingRequests FROM faucet_requests WHERE status = \'pending\''),
      this.get('SELECT COUNT(*) as failedRequests FROM faucet_requests WHERE status = \'failed\''),
      this.get('SELECT COALESCE(SUM(amount), 0) as totalTokensDistributed FROM faucet_requests WHERE status = \'completed\''),
      this.get('SELECT COUNT(*) as uniqueAddresses FROM (SELECT DISTINCT address FROM faucet_requests)'),
      this.get('SELECT COUNT(*) as blacklistedAddresses FROM blacklist')
    ]);

    return {
      totalRequests: stats[0]?.totalRequests || 0,
      completedRequests: stats[1]?.completedRequests || 0,
      pendingRequests: stats[2]?.pendingRequests || 0,
      failedRequests: stats[3]?.failedRequests || 0,
      totalTokensDistributed: stats[4]?.totalTokensDistributed || 0,
      uniqueAddresses: stats[5]?.uniqueAddresses || 0,
      blacklistedAddresses: stats[6]?.blacklistedAddresses || 0,
      successRate: stats[0]?.totalRequests ? 
        ((stats[1]?.completedRequests || 0) / (stats[0]?.totalRequests || 1) * 100).toFixed(2) : 0
    };
  }
}
