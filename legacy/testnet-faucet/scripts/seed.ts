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
    // Optionally seed blacklist
    await seedBlacklist(db);
    
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
    // Use db.run and match schema table/column names
    await db.run(`
      INSERT INTO faucet_requests (
        address, amount, status, transaction_id, transaction_hash, ip_address,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, datetime('now', '-${i} hours'), datetime('now', '-${i} hours', '+5 minutes'))
    `, [
      address, amount, status, transactionId, txHash, ipAddress
    ]);
  }

  logger.info(`Seeded ${sampleAddresses.length} sample faucet requests`);
}

async function seedAdminUser(db: Database) {
  logger.info('Creating default admin user...');

  const username = process.env.ADMIN_USERNAME || 'admin';
  const password = process.env.ADMIN_PASSWORD || 'admin123';

  // Check if admin user already exists (use config table as fallback)
  const existingUser = await db.get<any>(
    'SELECT * FROM config WHERE key = ? AND value = ? LIMIT 1',
    ['admin_username', username]
  );

  if (existingUser) {
    logger.info('Admin user already exists, skipping...');
    return;
  }

  const passwordHash = await bcrypt.hash(password, 10);

  // Store admin user in config table (for demo/testnet only)
  await db.run(
    'INSERT INTO config (key, value) VALUES (?, ?)',
    ['admin_username', username]
  );
  await db.run(
    'INSERT INTO config (key, value) VALUES (?, ?)',
    ['admin_password', passwordHash]
  );

  logger.info('Default admin user created successfully!');
}

// Placeholder for seedMetrics function
async function seedMetrics(db: Database) {
  logger.info('Seeding sample metrics...');

  // Sample metrics data
  const sampleMetrics = [
    { key: 'blockchain_height', value: '1000' },
    { key: 'total_supply', value: '21000000' },
    { key: 'circulating_supply', value: '18000000' },
    { key: 'market_cap_usd', value: '600000000' },
    { key: 'block_time', value: '600' }
  ];

  for (const metric of sampleMetrics) {
    // Use db.run and match schema table/column names
    await db.run(`
      INSERT INTO metrics (
        key, value, created_at, updated_at
      ) VALUES (?, ?, datetime('now'), datetime('now'))
    `, [
      metric.key, metric.value
    ]);
  }

  logger.info(`Seeded ${sampleMetrics.length} sample metrics`);
}

// Placeholder for seedBlacklist function
async function seedBlacklist(db: Database) {
  logger.info('Seeding sample blacklist...');

  const sampleBlacklist = [
    '192.168.1.101',
    '192.168.1.102',
    '192.168.1.103'
  ];

  for (const ipAddress of sampleBlacklist) {
    // Use db.run and match schema table/column names
    await db.run(`
      INSERT INTO blacklist (
        ip_address, created_at
      ) VALUES (?, datetime('now'))
    `, [
      ipAddress
    ]);
  }

  logger.info(`Seeded ${sampleBlacklist.length} sample blacklist entries`);
}

// Execute the seeding process
seedDatabase()
  .then(() => logger.info('Seeding script completed.'))
  .catch((error) => logger.error('Seeding script encountered an error:', error));
