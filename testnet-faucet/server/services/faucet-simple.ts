import axios, { AxiosInstance } from 'axios';
import { Database } from '../database-new';
import { logger } from '../logger';

export class FaucetService {
  private nodeUrl: string;
  private nodeClient: AxiosInstance;
  private db: Database;

  constructor() {
    this.db = Database.getInstance();
    this.nodeUrl = process.env.BLACKSILK_RPC_URL || 'http://localhost:19333';
    
    this.nodeClient = axios.create({
      baseURL: this.nodeUrl,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'BlackSilk-Testnet-Faucet/1.0.0'
      },
      auth: {
        username: process.env.BLACKSILK_RPC_USER || 'testuser',
        password: process.env.BLACKSILK_RPC_PASSWORD || 'testpass'
      }
    });
  }

  async requestTokens(address: string, ipAddress: string): Promise<{
    success: boolean;
    message: string;
    transactionId?: string;
    error?: string;
  }> {
    try {
      // Validate address format
      if (!this.isValidAddress(address)) {
        return {
          success: false,
          message: 'Invalid BlackSilk address format'
        };
      }

      // Check if user can make request (rate limiting, blacklist)
      const canRequest = await this.db.canMakeRequest(address, ipAddress);
      if (!canRequest) {
        return {
          success: false,
          message: 'Request denied. You may be rate limited or blacklisted.'
        };
      }

      // Create request in database
      const amount = parseFloat(process.env.FAUCET_AMOUNT || '10.0');
      const transactionId = await this.db.createRequest(address, amount, ipAddress);

      logger.info('Token request created', { 
        transactionId, 
        address: address.substring(0, 10) + '...', 
        amount, 
        ipAddress 
      });

      // In development mode with MOCK_BLOCKCHAIN=true, simulate successful transaction
      if (process.env.MOCK_BLOCKCHAIN === 'true' || process.env.NODE_ENV === 'development') {
        // Simulate async transaction processing
        setTimeout(async () => {
          try {
            const mockTxHash = 'mock_tx_' + Math.random().toString(36).substr(2, 16);
            await this.db.updateRequestStatus(transactionId, 'completed', mockTxHash);
            logger.info('Mock transaction completed', { transactionId, txHash: mockTxHash });
          } catch (error) {
            logger.error('Mock transaction failed', { transactionId, error });
            await this.db.updateRequestStatus(transactionId, 'failed');
          }
        }, 2000);

        return {
          success: true,
          message: 'Request queued successfully. Tokens will be sent shortly.',
          transactionId
        };
      }

      // TODO: Implement real blockchain transaction
      // For now, we'll just queue the request
      logger.info('Real blockchain transaction not implemented yet', { transactionId });
      
      return {
        success: true,
        message: 'Request queued successfully. Real blockchain integration pending.',
        transactionId
      };

    } catch (error) {
      logger.error('Error processing token request', { error, address, ipAddress });
      return {
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  isValidAddress(address: string): boolean {
    // BlackSilk testnet address validation
    // Testnet addresses start with 'tBLK' and have a specific length
    if (!address || typeof address !== 'string') {
      return false;
    }

    // Remove whitespace and check basic format
    address = address.trim();
    
    // Check if starts with tBLK and has reasonable length (adjust as needed)
    if (!address.startsWith('tBLK') || address.length < 20 || address.length > 64) {
      return false;
    }

    // Check for valid characters (alphanumeric)
    const validPattern = /^tBLK[a-zA-Z0-9]+$/;
    return validPattern.test(address);
  }

  async getStats(): Promise<any> {
    try {
      return await this.db.getStats();
    } catch (error) {
      logger.error('Error getting stats', error);
      return {
        totalRequests: 0,
        completedRequests: 0,
        pendingRequests: 0,
        failedRequests: 0,
        totalTokensDistributed: 0,
        uniqueAddresses: 0,
        blacklistedAddresses: 0,
        successRate: 0
      };
    }
  }

  async getNetworkInfo(): Promise<any> {
    try {
      // Try to get info from BlackSilk node
      const response = await this.nodeClient.post('/', {
        jsonrpc: '2.0',
        method: 'getinfo',
        id: 1
      });

      return {
        connected: true,
        blockHeight: response.data.result?.blocks || 0,
        difficulty: response.data.result?.difficulty || 0,
        connections: response.data.result?.connections || 0
      };
    } catch (error) {
      logger.warn('Could not connect to BlackSilk node', error);
      return {
        connected: false,
        error: 'Node connection failed'
      };
    }
  }
}
