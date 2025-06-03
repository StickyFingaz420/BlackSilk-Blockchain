import { describe, test, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import { Database } from '../server/database-new';
import { FaucetService } from '../server/services/faucet';
import fs from 'fs';
import path from 'path';

describe('BlackSilk Testnet Faucet', () => {
  let db: Database;
  let faucetService: FaucetService;
  const testDbPath = './test-faucet.db';

  beforeAll(async () => {
    // Set test environment
    (process.env as any).DATABASE_PATH = testDbPath;
    (process.env as any).NODE_ENV = 'test';
    
    // Initialize services
    db = Database.getInstance();
    await db.initialize();
    
    faucetService = new FaucetService();
  });

  afterAll(async () => {
    // Cleanup test database
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
  });

  beforeEach(async () => {
    // Clear test data before each test
    try {
      await db.executeQuery('DELETE FROM requests');
      await db.executeQuery('DELETE FROM blacklist');
      await db.executeQuery('DELETE FROM metrics');
    } catch (error) {
      console.log('Error clearing test data:', error);
    }
  });

  describe('Database Operations', () => {
    test('should initialize database with tables', async () => {
      const tables = await db.executeQuery(
        "SELECT name FROM sqlite_master WHERE type='table'"
      ) as any[];
      
      const tableNames = tables.map(t => t.name);
      expect(tableNames).toContain('requests');
      expect(tableNames).toContain('blacklist');
      expect(tableNames).toContain('metrics');
    });

    test('should create and retrieve a request', async () => {
      const address = 'BLK1234567890abcdef';
      const amount = 10.0;
      const ipAddress = '192.168.1.1';
      
      const transactionId = await db.createRequest(address, amount, ipAddress);
      expect(transactionId).toBeDefined();
      
      const request = await db.getRequest(transactionId);
      expect(request).toBeDefined();
      expect(request?.address).toBe(address);
      expect(request?.amount).toBe(amount);
      expect(request?.ipAddress).toBe(ipAddress);
    });

    test('should enforce rate limiting', async () => {
      const address = 'BLK1234567890abcdef';
      const ipAddress = '192.168.1.1';
      
      // First request should be allowed
      const canRequest1 = await db.canMakeRequest(address, ipAddress);
      expect(canRequest1).toBe(true);
      
      // Create a request
      await db.createRequest(address, 10, ipAddress);
      
      // Second request should be denied due to rate limiting
      const canRequest2 = await db.canMakeRequest(address, ipAddress);
      expect(canRequest2).toBe(false);
    });

    test('should enforce blacklist', async () => {
      const address = 'BLK1234567890abcdef';
      const ipAddress = '192.168.1.1';
      
      // Add to blacklist
      await db.addToBlacklist(address, 'Test blacklist');
      
      // Should not be able to make request
      const canRequest = await db.canMakeRequest(address, ipAddress);
      expect(canRequest).toBe(false);
    });

    test('should manage blacklist entries', async () => {
      const address = 'BLK1234567890abcdef';
      const reason = 'Abuse detected';
      
      const id = await db.addToBlacklist(address, reason);
      expect(id).toBeDefined();
      
      const entries = await db.getBlacklist();
      expect(entries.length).toBe(1);
      expect(entries[0].address).toBe(address);
      expect(entries[0].reason).toBe(reason);
      
      await db.removeFromBlacklist(id);
      const entriesAfter = await db.getBlacklist();
      expect(entriesAfter.length).toBe(0);
    });
  });

  describe('Faucet Service', () => {
    test('should process a token request', async () => {
      const address = 'BLK1234567890abcdef';
      const ipAddress = '192.168.1.100';
      
      const result = await faucetService.requestTokens(address, ipAddress);
      
      expect(result.success).toBe(true);
      expect(result.transactionId).toBeDefined();
      expect(result.message).toContain('Request queued successfully');
    });

    test('should validate BlackSilk addresses', () => {
      const validAddresses = [
        'BLK1234567890abcdef',
        'BLK9876543210fedcba',
        'BLKabcdef1234567890'
      ];
      
      const invalidAddresses = [
        'invalid',
        'BTC1234567890abcdef',
        '1234567890abcdef',
        'BLK123' // too short
      ];
      
      validAddresses.forEach(address => {
        expect(faucetService.isValidAddress(address)).toBe(true);
      });
      
      invalidAddresses.forEach(address => {
        expect(faucetService.isValidAddress(address)).toBe(false);
      });
    });
  });

  describe('Statistics', () => {
    test('should get database statistics', async () => {
      // Create some test data
      const testRequests = [
        { address: 'BLK1234567890abcdef', amount: 10, status: 'completed' },
        { address: 'BLK9876543210fedcba', amount: 5, status: 'pending' },
        { address: 'BLKabcdef1234567890', amount: 15, status: 'failed' }
      ];
      
      for (const req of testRequests) {
        const txId = await db.createRequest(req.address, req.amount, '127.0.0.1');
        if (req.status !== 'pending') {
          await db.updateRequestStatus(txId, req.status);
        }
      }
      
      const stats = await db.getStats();
      expect(stats).toBeDefined();
      expect(stats.totalRequests).toBeGreaterThanOrEqual(3);
      expect(stats.totalTokensDistributed).toBeGreaterThan(0);
    });
  });
});
