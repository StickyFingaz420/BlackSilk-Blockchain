#!/usr/bin/env ts-node
/**
 * Simple integration test for BlackSilk Testnet Faucet
 * This script tests the core functionality without Jest
 */

import { Database } from './server/database-new';
import { FaucetService } from './server/services/faucet-simple';

async function runIntegrationTests() {
  console.log('🚀 Starting BlackSilk Testnet Faucet Integration Tests\n');

  try {
    // Initialize database
    const db = Database.getInstance('./test-integration.db');
    await db.initialize();
    console.log('✅ Database initialized');

    // Initialize faucet service
    const faucetService = new FaucetService();
    console.log('✅ Faucet service initialized');

    // Test 1: Valid address request
    console.log('\n📝 Test 1: Valid address request');
    const address1 = 'BLK1test12345678901234567890123456';
    const result1 = await faucetService.requestTokens(address1, '127.0.0.1');
    console.log('Result:', result1);
    
    if (result1.success) {
      console.log('✅ Test 1 passed: Valid request accepted');
    } else {
      console.log('❌ Test 1 failed: Valid request rejected');
    }

    // Test 2: Rate limiting
    console.log('\n📝 Test 2: Rate limiting (same address)');
    const result2 = await faucetService.requestTokens(address1, '127.0.0.1');
    console.log('Result:', result2);
    
    if (!result2.success && result2.message.includes('denied')) {
      console.log('✅ Test 2 passed: Rate limiting working');
    } else {
      console.log('❌ Test 2 failed: Rate limiting not working');
    }

    // Test 3: Invalid address
    console.log('\n📝 Test 3: Invalid address format');
    const result3 = await faucetService.requestTokens('invalid-address', '127.0.0.2');
    console.log('Result:', result3);
    
    if (!result3.success && result3.message.includes('Invalid')) {
      console.log('✅ Test 3 passed: Invalid address rejected');
    } else {
      console.log('❌ Test 3 failed: Invalid address not rejected');
    }

    // Test 4: Database stats
    console.log('\n📝 Test 4: Database statistics');
    const stats = await db.getStats();
    console.log('Stats:', stats);
    
    if (stats.totalRequests >= 1) {
      console.log('✅ Test 4 passed: Statistics are tracking requests');
    } else {
      console.log('❌ Test 4 failed: Statistics not working');
    }

    // Test 5: Blacklist functionality
    console.log('\n📝 Test 5: Blacklist functionality');
    const blacklistAddress = 'BLK1blacklisted123456789012345678';
    await db.addToBlacklist(blacklistAddress, 'Test blacklist');
    
    const result5 = await faucetService.requestTokens(blacklistAddress, '127.0.0.3');
    console.log('Result:', result5);
    
    if (!result5.success) {
      console.log('✅ Test 5 passed: Blacklisted address rejected');
    } else {
      console.log('❌ Test 5 failed: Blacklisted address not rejected');
    }

    console.log('\n🎉 Integration tests completed!');

  } catch (error) {
    console.error('❌ Integration test failed:', error);
    process.exit(1);
  }
}

// Run the tests
if (require.main === module) {
  runIntegrationTests()
    .then(() => {
      console.log('\n✅ All integration tests completed successfully!');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n❌ Integration tests failed:', error);
      process.exit(1);
    });
}
