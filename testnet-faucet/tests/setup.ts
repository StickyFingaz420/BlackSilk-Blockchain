// Jest setup file
import { jest } from '@jest/globals';

// Mock console methods in test environment
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

// Set test environment variables
(process.env as any).NODE_ENV = 'test';
process.env.DATABASE_PATH = './test-faucet.db';
process.env.JWT_SECRET = 'test-jwt-secret';
process.env.ADMIN_USERNAME = 'testadmin';
process.env.ADMIN_PASSWORD = 'testpassword';
process.env.BLACKSILK_RPC_URL = 'http://localhost:8332';
process.env.BLACKSILK_RPC_USER = 'testuser';
process.env.BLACKSILK_RPC_PASSWORD = 'testpass';
process.env.FAUCET_AMOUNT = '10';
process.env.RATE_LIMIT_HOURS = '24';

// Mock external dependencies
jest.mock('axios', () => ({
  post: jest.fn(() => Promise.resolve({ data: { result: 'mocked' } })),
  create: jest.fn(() => ({
    post: jest.fn(() => Promise.resolve({ data: { result: 'mocked' } }))
  }))
}));

// Increase timeout for database operations
jest.setTimeout(10000);
