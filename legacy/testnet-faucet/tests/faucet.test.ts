import { describe, test, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import { Database } from '../server/database-new';
import { FaucetService } from '../server/services/faucet';
import { MetricsService } from '../server/services/metrics';
import fs from 'fs';
import path from 'path';

describe('BlackSilk Testnet Faucet', () => {
  let db: Database;
  let faucetService: FaucetService;
  let metricsService: MetricsService;
  const testDbPath = './test-faucet.db';

  beforeAll(async () => {
    // Set test environment
    process.env.DATABASE_PATH = testDbPath;
    process.env.NODE_ENV = 'test';
    
    // Initialize services
    db = Database.getInstance();
    await db.initialize();
    
    faucetService = new FaucetService(db);
    metricsService = new MetricsService(db);
  });

  afterAll(async () => {
    // Cleanup test database
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
  });

  beforeEach(async () => {
    // Clear test data before each test
    await new Promise<void>((resolve, reject) => {
      db.db.run('DELETE FROM requests', (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  });

  describe('Database Operations', () => {
    test('should initialize database with correct schema', async () => {
      const tables = await new Promise<any[]>((resolve, reject) => {
        db.db.all("SELECT name FROM sqlite_master WHERE type='table'", (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        });
      });

      const tableNames = tables.map(t => t.name);
      expect(tableNames).toContain('requests');
      expect(tableNames).toContain('rate_limits');
      expect(tableNames).toContain('blacklist');
      expect(tableNames).toContain('metrics');
    });

    test('should store and retrieve faucet requests', async () => {
      const requestData = {
        address: 'tBLK1test123456789',
        amount: 10,
        ipAddress: '127.0.0.1'
      };

      const transactionId = await db.createRequest(
        requestData.address,
        requestData.amount,
        requestData.ipAddress
      );

      expect(transactionId).toBeDefined();
      expect(typeof transactionId).toBe('string');

      const request = await db.getRequest(transactionId);
      expect(request).toBeDefined();
      expect(request?.address).toBe(requestData.address);
      expect(request?.amount).toBe(requestData.amount);
      expect(request?.status).toBe('pending');
    });
  });

  describe('Rate Limiting', () => {
    test('should prevent duplicate requests from same address', async () => {
      const address = 'tBLK1test123456789';
      const ipAddress = '127.0.0.1';

      // First request should succeed
      const canRequest1 = await db.canMakeRequest(address, ipAddress);
      expect(canRequest1).toBe(true);

      // Create first request
      await db.createRequest(address, 10, ipAddress);

      // Second request should be blocked
      const canRequest2 = await db.canMakeRequest(address, ipAddress);
      expect(canRequest2).toBe(false);
    });

    test('should allow requests after rate limit period', async () => {
      const address = 'tBLK1test123456789';
      const ipAddress = '127.0.0.1';

      // Create request with past timestamp (simulate expired rate limit)
      await new Promise<void>((resolve, reject) => {
        db.db.run(`
          INSERT INTO requests (address, amount, status, transaction_id, ip_address, created_at)
          VALUES (?, ?, 'completed', ?, ?, datetime('now', '-25 hours'))
        `, [address, 10, 'test-tx-id', ipAddress], (err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      const canRequest = await db.canMakeRequest(address, ipAddress);
      expect(canRequest).toBe(true);
    });
  });

  describe('Blacklist Operations', () => {
    test('should block blacklisted addresses', async () => {
      const address = 'tBLK1blacklisted123';
      const ipAddress = '127.0.0.1';

      // Add to blacklist
      await db.addToBlacklist(address, 'Test blacklist');

      // Should be blocked
      const canRequest = await db.canMakeRequest(address, ipAddress);
      expect(canRequest).toBe(false);
    });

    test('should manage blacklist entries', async () => {
      const address = 'tBLK1blacklisted123';
      const reason = 'Test blacklist entry';

      // Add to blacklist
      const id = await db.addToBlacklist(address, reason);
      expect(id).toBeDefined();

      // Verify blacklist entry
      const entries = await db.getBlacklist();
      expect(entries.length).toBe(1);
      expect(entries[0].address).toBe(address);
      expect(entries[0].reason).toBe(reason);

      // Remove from blacklist
      await db.removeFromBlacklist(id);
      const entriesAfter = await db.getBlacklist();
      expect(entriesAfter.length).toBe(0);
    });
  });

  describe('Faucet Service', () => {
    test('should process valid token requests', async () => {
      const request = {
        address: 'tBLK1valid123456789',
        amount: 10,
        ipAddress: '127.0.0.1'
      };

      // Mock successful blockchain transaction
      jest.spyOn(faucetService as any, 'sendTransaction').mockResolvedValue({
        txHash: '0x123456789abcdef',
        success: true
      });

      const result = await faucetService.processRequest(
        request.address,
        request.amount,
        request.ipAddress
      );

      expect(result.success).toBe(true);
      expect(result.transactionId).toBeDefined();
      expect(result.message).toContain('queued');
    });

    test('should validate addresses correctly', async () => {
      const validAddresses = [
        'tBLK1qw8k3s7h9p2x4v6n8m0l5j3g1f9d7c2a4s6',
        'tBLK1zx9c8v7b6n4m3k2j1h0g9f8e7d6c5b4a3s2'
      ];

      const invalidAddresses = [
        '',
        'invalid',
        '123',
        'BSK',
        'too-short',
        'BSK1' + 'x'.repeat(100) // too long
      ];

      for (const address of validAddresses) {
        expect(faucetService.validateAddress(address)).toBe(true);
      }

      for (const address of invalidAddresses) {
        expect(faucetService.validateAddress(address)).toBe(false);
      }
    });
  });

  describe('Metrics Service', () => {
    test('should collect and store metrics', async () => {
      await metricsService.increment('test_counter', 5);
      await metricsService.gauge('test_gauge', 100);

      const metrics = await metricsService.getMetrics();
      
      const counter = metrics.find(m => m.name === 'test_counter');
      const gauge = metrics.find(m => m.name === 'test_gauge');

      expect(counter).toBeDefined();
      expect(counter?.value).toBe(5);
      expect(counter?.type).toBe('counter');

      expect(gauge).toBeDefined();
      expect(gauge?.value).toBe(100);
      expect(gauge?.type).toBe('gauge');
    });

    test('should export Prometheus format', async () => {
      await metricsService.increment('http_requests_total', 10);
      await metricsService.gauge('memory_usage_bytes', 1024000);

      const prometheus = await metricsService.exportPrometheus();
      
      expect(prometheus).toContain('# HELP http_requests_total');
      expect(prometheus).toContain('# TYPE http_requests_total counter');
      expect(prometheus).toContain('http_requests_total 10');
      
      expect(prometheus).toContain('# HELP memory_usage_bytes');
      expect(prometheus).toContain('# TYPE memory_usage_bytes gauge');
      expect(prometheus).toContain('memory_usage_bytes 1024000');
    });
  });

  describe('Statistics', () => {
    test('should calculate correct statistics', async () => {
      // Create test requests
      const requests = [
        { address: 'BSK1addr1', amount: 10, status: 'completed' },
        { address: 'BSK1addr2', amount: 10, status: 'completed' },
        { address: 'BSK1addr3', amount: 10, status: 'pending' },
        { address: 'BSK1addr4', amount: 10, status: 'failed' }
      ];

      for (const req of requests) {
        const txId = await db.createRequest(req.address, req.amount, '127.0.0.1');
        if (req.status !== 'pending') {
          await db.updateRequestStatus(txId, req.status);
        }
      }

      const stats = await db.getStats();
      
      expect(stats.totalRequests).toBe(4);
      expect(stats.completedRequests).toBe(2);
      expect(stats.pendingRequests).toBe(1);
      expect(stats.failedRequests).toBe(1);
      expect(stats.totalTokens).toBe(20); // Only completed requests
      expect(stats.successRate).toBe(50); // 2/4 * 100
    });
  });
});
