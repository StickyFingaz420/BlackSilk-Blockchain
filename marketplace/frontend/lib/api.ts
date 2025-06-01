// BlackSilk Marketplace API - Fully Decentralized Implementation
// Connects directly to BlackSilk nodes, no centralized servers

import { 
  Product, 
  Order, 
  EscrowContract, 
  NodeStatus, 
  Balance, 
  Transaction,
  ApiResponse,
  SearchFilters,
  Category,
  OrderStatus,
  EscrowStatus,
  OrderItem
} from '../types';

export interface BlackSilkNodeConfig {
  nodeURL: string;
  ipfsGateway: string;
  escrowContractAddress?: string;
}

export interface NodeInfoResponse {
  version: string;
  network: string;
  height: number;
  peers: number;
  difficulty: number;
}

export interface SubmitTransactionResponse {
  success: boolean;
  message: string;
  tx_hash?: string;
}

export interface GetMempoolResponse {
  transactions: Transaction[];
  count: number;
}

export class BlackSilkMarketplaceAPI {
  private nodeURL: string;
  private ipfsGateway: string;
  private escrowContractAddress: string;

  constructor(config: BlackSilkNodeConfig) {
    this.nodeURL = config.nodeURL || 'http://localhost:8545';
    this.ipfsGateway = config.ipfsGateway || 'http://localhost:8080';
    this.escrowContractAddress = config.escrowContractAddress || '';
  }

  // Node Communication Methods
  async getNodeStatus(): Promise<NodeStatus> {
    try {
      const response = await fetch(`${this.nodeURL}/info`);
      if (!response.ok) {
        throw new Error(`Node request failed: ${response.statusText}`);
      }
      
      const data: NodeInfoResponse = await response.json();
      
      return {
        connected: true,
        synced: true,
        blockHeight: data.height,
        difficulty: data.difficulty,
        connections: data.peers,
        version: data.version,
        privacyMode: true
      };
    } catch (error) {
      return {
        connected: false,
        synced: false,
        blockHeight: 0,
        difficulty: 0,
        connections: 0,
        version: 'unknown',
        privacyMode: false
      };
    }
  }

  async submitTransaction(transaction: Transaction): Promise<SubmitTransactionResponse> {
    const response = await fetch(`${this.nodeURL}/submit_tx`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(transaction),
    });

    if (!response.ok) {
      throw new Error(`Transaction submission failed: ${response.statusText}`);
    }

    return await response.json();
  }

  async getMempool(): Promise<GetMempoolResponse> {
    const response = await fetch(`${this.nodeURL}/mempool`);
    if (!response.ok) {
      throw new Error(`Mempool request failed: ${response.statusText}`);
    }
    return await response.json();
  }

  async getBlocks(fromHeight: number = 0): Promise<any[]> {
    const response = await fetch(`${this.nodeURL}/get_blocks?from_height=${fromHeight}&simple=true`);
    if (!response.ok) {
      throw new Error(`Blocks request failed: ${response.statusText}`);
    }
    return await response.json();
  }

  // Wallet/Balance Methods
  async getBalance(address: string): Promise<Balance> {
    try {
      // Get all blocks and calculate balance from transactions
      const blocks = await this.getBlocks(0);
      let confirmed = 0;
      let unconfirmed = 0;
      let locked_in_escrow = 0;
      
      for (const block of blocks) {
        if (block.transactions) {
          for (const tx of block.transactions) {
            // Add inputs (spending from this address)
            if (tx.inputs) {
              for (const input of tx.inputs) {
                if (input.address === address) {
                  confirmed -= input.amount || 0;
                }
              }
            }
            
            // Add outputs (receiving to this address)
            if (tx.outputs) {
              for (const output of tx.outputs) {
                if (output.address === address) {
                  confirmed += output.amount || 0;
                }
              }
            }
          }
        }
      }

      return {
        confirmed: Math.max(0, confirmed),
        unconfirmed,
        locked_in_escrow
      };
    } catch (error) {
      console.error('Failed to get balance:', error);
      return {
        confirmed: 0,
        unconfirmed: 0,
        locked_in_escrow: 0
      };
    }
  }

  // IPFS Methods for Decentralized Storage
  async uploadToIPFS(file: File): Promise<string> {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(`${this.ipfsGateway}/api/v0/add`, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      throw new Error(`IPFS upload failed: ${response.statusText}`);
    }

    const result = await response.json();
    return result.Hash;
  }

  async getFromIPFS(hash: string): Promise<string> {
    const response = await fetch(`${this.ipfsGateway}/ipfs/${hash}`);
    if (!response.ok) {
      throw new Error(`IPFS retrieval failed: ${response.statusText}`);
    }
    return response.text();
  }

  // Marketplace Methods (using blockchain as storage)
  async createProduct(product: Omit<Product, 'id' | 'createdAt'>): Promise<ApiResponse<Product>> {
    try {
      // Upload images to IPFS
      const imageHashes: string[] = [];
      if (product.images && product.images.length > 0) {
        for (const imageUrl of product.images) {
          // If it's a string starting with data: or blob:, treat as file data
          if (typeof imageUrl === 'string' && (imageUrl.startsWith('data:') || imageUrl.startsWith('blob:'))) {
            // Convert data URL to blob and upload
            const response = await fetch(imageUrl);
            const blob = await response.blob();
            const file = new File([blob], 'image.jpg', { type: blob.type });
            const hash = await this.uploadToIPFS(file);
            imageHashes.push(`ipfs://${hash}`);
          } else {
            imageHashes.push(imageUrl);
          }
        }
      }

      // Create product transaction
      const productData: Product = {
        ...product,
        id: this.generateId(),
        images: imageHashes,
        createdAt: Date.now(),
      };

      // Create transaction to store product on blockchain
      const transaction: Transaction = {
        txid: this.generateId(),
        from: product.seller,
        to: product.seller,
        amount: 0,
        fee: 100, // 1 BLK fee
        timestamp: new Date().toISOString(),
        confirmations: 0
      };

      const result = await this.submitTransaction(transaction);
      
      if (result.success) {
        return {
          success: true,
          data: productData
        };
      } else {
        return {
          success: false,
          error: result.message
        };
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  async getProducts(filters?: SearchFilters): Promise<ApiResponse<Product[]>> {
    try {
      // Mock data for now - in real implementation, parse from blockchain
      const mockProducts: Product[] = [
        {
          id: '1',
          seller: 'vendor123',
          title: 'Privacy Phone Case',
          description: 'Faraday cage phone case for maximum privacy',
          category: 'electronics',
          price: 50,
          currency: 'BLK',
          stock: 10,
          images: ['ipfs://QmHash1'],
          createdAt: Date.now() - 86400000,
          isActive: true,
          stealthRequired: true,
          escrowRequired: true
        },
        {
          id: '2',
          seller: 'vendor456',
          title: 'Anonymous VPN Service',
          description: '1-year anonymous VPN subscription',
          category: 'digital',
          price: 100,
          currency: 'BLK',
          stock: 100,
          images: ['ipfs://QmHash2'],
          createdAt: Date.now() - 172800000,
          isActive: true,
          stealthRequired: true,
          escrowRequired: false
        }
      ];

      // Apply filters
      let filteredProducts = mockProducts;
      
      if (filters) {
        if (filters.category) {
          filteredProducts = filteredProducts.filter(p => p.category === filters.category);
        }
        if (filters.min_price !== undefined) {
          filteredProducts = filteredProducts.filter(p => p.price >= filters.min_price!);
        }
        if (filters.max_price !== undefined) {
          filteredProducts = filteredProducts.filter(p => p.price <= filters.max_price!);
        }
        if (filters.vendor) {
          filteredProducts = filteredProducts.filter(p => p.seller === filters.vendor);
        }
      }

      return {
        success: true,
        data: filteredProducts
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        data: []
      };
    }
  }

  async getProduct(id: string): Promise<ApiResponse<Product | null>> {
    try {
      const productsResult = await this.getProducts();
      if (productsResult.success && productsResult.data) {
        const product = productsResult.data.find(p => p.id === id);
        return {
          success: true,
          data: product || null
        };
      }
      return {
        success: false,
        error: 'Failed to fetch products',
        data: null
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        data: null
      };
    }
  }

  async createOrder(order: Omit<Order, 'id' | 'createdAt' | 'status'>): Promise<ApiResponse<Order>> {
    try {
      const orderData: Order = {
        ...order,
        id: this.generateId(),
        status: OrderStatus.AwaitingPayment,
        createdAt: Date.now(),
      };

      // Create order transaction
      const transaction: Transaction = {
        txid: this.generateId(),
        from: order.buyer,
        to: order.seller,
        amount: order.totalAmount,
        fee: 100,
        timestamp: new Date().toISOString(),
        confirmations: 0
      };

      const result = await this.submitTransaction(transaction);
      
      if (result.success) {
        return {
          success: true,
          data: orderData
        };
      } else {
        return {
          success: false,
          error: result.message
        };
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  async getOrders(userAddress: string): Promise<ApiResponse<Order[]>> {
    try {
      // Mock data for now - in real implementation, parse from blockchain
      const mockOrders: Order[] = [
        {
          id: '1',
          buyer: userAddress,
          seller: 'vendor123',
          items: [
            {
              productId: '1',
              productTitle: 'Privacy Phone Case',
              quantity: 1,
              price: 50,
              seller: 'vendor123'
            }
          ],
          totalAmount: 50,
          escrowStatus: EscrowStatus.Funded,
          status: OrderStatus.Processing,
          createdAt: Date.now() - 86400000
        }
      ];

      return {
        success: true,
        data: mockOrders
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        data: []
      };
    }
  }

  async getCategories(): Promise<ApiResponse<Category[]>> {
    // Return predefined categories for decentralized marketplace
    const categories: Category[] = [
      { 
        id: 'electronics', 
        name: 'Electronics', 
        description: 'Electronic devices and gadgets',
        icon: '📱',
        count: 150
      },
      { 
        id: 'clothing', 
        name: 'Clothing', 
        description: 'Fashion and apparel',
        icon: '👕',
        count: 200
      },
      { 
        id: 'books', 
        name: 'Books', 
        description: 'Books and publications',
        icon: '📚',
        count: 75
      },
      { 
        id: 'home', 
        name: 'Home & Garden', 
        description: 'Home improvement and gardening',
        icon: '🏠',
        count: 100
      },
      { 
        id: 'sports', 
        name: 'Sports & Outdoors', 
        description: 'Sports equipment and outdoor gear',
        icon: '⚽',
        count: 80
      },
      { 
        id: 'automotive', 
        name: 'Automotive', 
        description: 'Car parts and accessories',
        icon: '🚗',
        count: 60
      },
      { 
        id: 'digital', 
        name: 'Digital Goods', 
        description: 'Software, games, and digital content',
        icon: '💾',
        count: 120
      },
      { 
        id: 'services', 
        name: 'Services', 
        description: 'Professional and personal services',
        icon: '🔧',
        count: 90
      },
    ];

    return {
      success: true,
      data: categories
    };
  }

  // Escrow Methods
  async createEscrow(orderId: string, amount: number, buyerAddress: string, sellerAddress: string): Promise<ApiResponse<EscrowContract>> {
    try {
      const escrow: EscrowContract = {
        contract_id: this.generateId(),
        buyer: buyerAddress,
        seller: sellerAddress,
        arbiter: 'system_arbiter',
        amount,
        status: EscrowStatus.Pending,
        signatures: [],
        created_at: new Date().toISOString(),
      };

      // Create escrow transaction
      const transaction: Transaction = {
        txid: this.generateId(),
        from: buyerAddress,
        to: this.escrowContractAddress,
        amount: amount,
        fee: 100,
        timestamp: new Date().toISOString(),
        confirmations: 0
      };

      const result = await this.submitTransaction(transaction);
      
      if (result.success) {
        return {
          success: true,
          data: escrow
        };
      } else {
        return {
          success: false,
          error: result.message
        };
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  // Utility Methods
  private generateId(): string {
    return Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
  }

  // Health check for the entire system
  async healthCheck(): Promise<{
    node: boolean;
    ipfs: boolean;
    marketplace: boolean;
  }> {
    const checks = {
      node: false,
      ipfs: false,
      marketplace: false
    };

    try {
      const nodeStatus = await this.getNodeStatus();
      checks.node = nodeStatus.connected;
    } catch (e) {
      checks.node = false;
    }

    try {
      const response = await fetch(`${this.ipfsGateway}/api/v0/version`, { method: 'POST' });
      checks.ipfs = response.ok;
    } catch (e) {
      checks.ipfs = false;
    }

    checks.marketplace = checks.node; // Marketplace depends on node

    return checks;
  }
}

// Create default configuration
const createDefaultConfig = (): BlackSilkNodeConfig => {
  // Use client-side safe fallbacks
  return {
    nodeURL: 'http://localhost:8545',
    ipfsGateway: 'http://localhost:8080',
    escrowContractAddress: 'escrow_contract_address'
  };
};

// Export singleton instance
export const marketplaceAPI = new BlackSilkMarketplaceAPI(createDefaultConfig());

export default marketplaceAPI;
