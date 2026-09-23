#!/usr/bin/env node

/**
 * Database migration script
 * Handles database schema updates and data migrations
 */

import { Database } from '../server/database-new';
import { logger } from '../server/logger';
import sqlite3 from 'sqlite3';
import path from 'path';

interface Migration {
  version: number;
  description: string;
  up: (db: sqlite3.Database) => Promise<void>;
  down?: (db: sqlite3.Database) => Promise<void>;
}

const migrations: Migration[] = [
  {
    version: 1,
    description: 'Initial database schema',
    up: async (db: sqlite3.Database) => {
      // This is handled by Database.initialize()
      logger.info('Initial schema migration - handled by Database.initialize()');
    }
  },
  {
    version: 2,
    description: 'Add metrics retention policy',
    up: async (db: sqlite3.Database) => {
      return new Promise((resolve, reject) => {
        db.run(`
          ALTER TABLE metrics ADD COLUMN retention_days INTEGER DEFAULT 30
        `, (err) => {
          if (err && !err.message.includes('duplicate column name')) {
            reject(err);
          } else {
            resolve();
          }
        });
      });
    }
  },
  {
    version: 3,
    description: 'Add admin user roles',
    up: async (db: sqlite3.Database) => {
      return new Promise((resolve, reject) => {
        db.run(`
          CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            is_active BOOLEAN DEFAULT 1
          )
        `, (err) => {
          if (err) {
            reject(err);
          } else {
            resolve();
          }
        });
      });
    }
  },
  {
    version: 4,
    description: 'Add request categories and priorities',
    up: async (db: sqlite3.Database) => {
      return new Promise((resolve, reject) => {
        db.serialize(() => {
          db.run(`
            ALTER TABLE requests ADD COLUMN category TEXT DEFAULT 'standard'
          `);
          db.run(`
            ALTER TABLE requests ADD COLUMN priority INTEGER DEFAULT 0
          `);
          db.run(`
            CREATE INDEX IF NOT EXISTS idx_requests_priority ON requests(priority DESC, created_at ASC)
          `, (err) => {
            if (err) {
              reject(err);
            } else {
              resolve();
            }
          });
        });
      });
    }
  }
];

class MigrationManager {
  private db: sqlite3.Database;

  constructor(dbPath: string) {
    this.db = new sqlite3.Database(dbPath);
  }

  async initialize(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.db.run(`
        CREATE TABLE IF NOT EXISTS migrations (
          version INTEGER PRIMARY KEY,
          description TEXT NOT NULL,
          applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `, (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }

  async getCurrentVersion(): Promise<number> {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT MAX(version) as version FROM migrations',
        (err, row: any) => {
          if (err) {
            reject(err);
          } else {
            resolve(row?.version || 0);
          }
        }
      );
    });
  }

  async applyMigration(migration: Migration): Promise<void> {
    logger.info(`Applying migration ${migration.version}: ${migration.description}`);
    
    await migration.up(this.db);
    
    return new Promise((resolve, reject) => {
      this.db.run(
        'INSERT INTO migrations (version, description) VALUES (?, ?)',
        [migration.version, migration.description],
        (err) => {
          if (err) {
            reject(err);
          } else {
            logger.info(`Migration ${migration.version} applied successfully`);
            resolve();
          }
        }
      );
    });
  }

  async runMigrations(): Promise<void> {
    await this.initialize();
    const currentVersion = await this.getCurrentVersion();
    
    logger.info(`Current database version: ${currentVersion}`);
    
    const pendingMigrations = migrations.filter(m => m.version > currentVersion);
    
    if (pendingMigrations.length === 0) {
      logger.info('Database is up to date');
      return;
    }
    
    logger.info(`Found ${pendingMigrations.length} pending migrations`);
    
    for (const migration of pendingMigrations) {
      try {
        await this.applyMigration(migration);
      } catch (error) {
        logger.error(`Failed to apply migration ${migration.version}:`, error);
        throw error;
      }
    }
    
    logger.info('All migrations applied successfully');
  }

  close(): void {
    this.db.close();
  }
}

async function runMigrations() {
  try {
    const dbPath = process.env.DATABASE_PATH || './data/faucet.db';
    logger.info(`Running migrations on database: ${dbPath}`);
    
    const migrationManager = new MigrationManager(dbPath);
    await migrationManager.runMigrations();
    migrationManager.close();
    
    logger.info('Migration process completed successfully');
    process.exit(0);
  } catch (error) {
    logger.error('Migration failed:', error);
    process.exit(1);
  }
}

// Run migrations if called directly
if (require.main === module) {
  runMigrations();
}

export { MigrationManager, runMigrations };
