#!/usr/bin/env node

/**
 * Database setup and initialization script
 * This script initializes the SQLite database with all required tables
 */

import { Database } from '../server/database-new';
import { logger } from '../server/logger';
import path from 'path';
import fs from 'fs';

async function setupDatabase() {
  try {
    logger.info('Starting database setup...');
    
    // Ensure data directory exists
    const dataDir = path.dirname(process.env.DATABASE_PATH || './data/faucet.db');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
      logger.info(`Created data directory: ${dataDir}`);
    }

    // Initialize database
    const db = Database.getInstance();
    await db.initialize();
    
    logger.info('Database setup completed successfully!');
    
    // Show database info
    const dbPath = process.env.DATABASE_PATH || './data/faucet.db';
    const stats = fs.statSync(dbPath);
    logger.info(`Database file: ${dbPath}`);
    logger.info(`Database size: ${Math.round(stats.size / 1024)}KB`);
    
    process.exit(0);
  } catch (error) {
    logger.error('Database setup failed:', error);
    process.exit(1);
  }
}

// Run setup if called directly
if (require.main === module) {
  setupDatabase();
}

export { setupDatabase };
