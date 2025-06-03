#!/usr/bin/env node

/**
 * Database seeding script
 * Populates the database with initial data for development and testing
 */

import { Database } from '../server/database-new';
import { logger } from '../server/logger';
import crypto from 'crypto';
import bcrypt from 'bcrypt';

async function seedDatabase() {
  try {
    logger.info('Starting database seeding...');
    
    const db = Database.getInstance();
    await db.initialize();
    
    // Check if data already exists
    const existingRequests = await db.getStats();
    if (existingRequests.totalRequests > 0) {
      logger.info('Database already contains data. Skipping seed.');
      return;
    }
    
    // Seed sample faucet requests
    await seedFaucetRequests(db);
    
    // Seed admin user (if not exists)
    await seedAdminUser(db);
    
    // Seed sample metrics
    await seedMetrics(db);
    
    logger.info('Database seeding completed successfully!');
    
  } catch (error) {
    logger.error('Database seeding failed:', error);
    throw error;
  }
}

async function seedFaucetRequests(db: Database) {
  logger.info('Seeding sample faucet requests...');
  
  const sampleAddresses = [
    'tBLK1qw8k3s7h9p2x4v6n8m0l5j3g1f9d7c2a4s6',
    'tBLK1zx9c8v7b6n4m3k2j1h0g9f8e7d6c5b4a3s2',
    'tBLK1aq2ws3ed4rf5tg6yh7uj8ik9ol0mp1nq2wr3e',
    'tBLK1sw2de3fr4gt5hy6ju7ki8lo9mp0nq1wr2es3d',
    'tBLK1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0mp1'
  ];
  
  const statuses = ['completed', 'completed', 'completed', 'pending', 'failed'];
  
  for (let i = 0; i < sampleAddresses.length; i++) {
    const address = sampleAddresses[i];
    const status = statuses[i];
    const amount = 10;
    const transactionId = crypto.randomUUID();
    const txHash = status === 'completed' ? crypto.randomBytes(32).toString('hex') : null;
    const ipAddress = `192.168.1.${100 + i}`;
    
    await new Promise<void>((resolve, reject) => {
      db.db.run(`
        INSERT INTO requests (
          address, amount, status, transaction_id, tx_hash, ip_address,
          created_at, processed_at
        ) VALUES (?, ?, ?, ?, ?, ?, datetime('now', '-${i} hours'), ?)
      `, [
        address, amount, status, transactionId, txHash, ipAddress,
        status === 'completed' ? `datetime('now', '-${i} hours', '+5 minutes')` : null
      ], function(err) {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }
  
  logger.info(`Seeded ${sampleAddresses.length} sample faucet requests`);
}

async function seedAdminUser(db: Database) {
  logger.info('Creating default admin user...');
  
  const username = process.env.ADMIN_USERNAME || 'admin';
  const password = process.env.ADMIN_PASSWORD || 'admin123';
  
  // Check if admin user already exists
  const existingUser = await new Promise<any>((resolve, reject) => {
    db.db.get(
      'SELECT * FROM admin_users WHERE username = ?',
      [username],
      (err, row) => {
        if (err) {
          reject(err);
        } else {
          resolve(row);
        }
      }
    );
  });
  
  if (existingUser) {
    logger.info('Admin user already exists, skipping...');
    return;
  }
  
  const passwordHash = await bcrypt.hash(password, 10);
  
  await new Promise<void>((resolve, reject) => {
    db.db.run(`
      INSERT INTO admin_users (username, password_hash, role)
      VALUES (?, ?, 'super_admin')
    `, [username, passwordHash], function(err) {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
  
  logger.info(`Created admin user: ${username}`);
  logger.warn(`Default password: ${password} - CHANGE THIS IN PRODUCTION!`);
}

async function seedMetrics(db: Database) {
  logger.info('Seeding sample metrics...');
  
  const metrics = [
    { name: 'requests_total', value: 5, type: 'counter' },
    { name: 'requests_completed', value: 3, type: 'counter' },
    { name: 'requests_failed', value: 1, type: 'counter' },
    { name: 'tokens_distributed', value: 30, type: 'counter' },
    { name: 'avg_processing_time', value: 45.5, type: 'gauge' },
    { name: 'queue_size', value: 1, type: 'gauge' },
    { name: 'memory_usage_mb', value: 128, type: 'gauge' },
    { name: 'active_connections', value: 5, type: 'gauge' }
  ];
  
  for (const metric of metrics) {
    await new Promise<void>((resolve, reject) => {
      db.db.run(`
        INSERT INTO metrics (name, value, type, labels, created_at)
        VALUES (?, ?, ?, '{}', datetime('now'))
      `, [metric.name, metric.value, metric.type], function(err) {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }
  
  logger.info(`Seeded ${metrics.length} sample metrics`);
}

// Helper function to create test blacklist entries
async function seedBlacklist(db: Database) {
  logger.info('Seeding sample blacklist entries...');
  
  const blacklistEntries = [
    { address: 'tBLK1malicious1address1here1234567890', reason: 'Automated abuse detection' },
    { address: 'tBLK1spam2address2here2345678901234', reason: 'Manual review - excessive requests' }
  ];
  
  for (const entry of blacklistEntries) {
    await new Promise<void>((resolve, reject) => {
      db.db.run(`
        INSERT INTO blacklist (address, reason, created_at)
        VALUES (?, ?, datetime('now'))
      `, [entry.address, entry.reason], function(err) {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }
  
  logger.info(`Seeded ${blacklistEntries.length} blacklist entries`);
}

// Run seeding if called directly
if (require.main === module) {
  seedDatabase().then(() => {
    logger.info('Seeding completed successfully');
    process.exit(0);
  }).catch((error) => {
    logger.error('Seeding failed:', error);
    process.exit(1);
  });
}

export { seedDatabase };
