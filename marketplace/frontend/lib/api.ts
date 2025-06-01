import axios, { AxiosInstance, AxiosResponse } from 'axios';
import { 
  Product, 
  User, 
  Order, 
  EscrowContract, 
  NodeInfo, 
  Balance, 
  Transaction,
  ApiResponse,
  SearchFilters,
  Category
} from '@/types';

class MarketplaceAPI {
  private api: AxiosInstance;
  private nodeApi: AxiosInstance;

  constructor() {
    this.api = axios.create({
      baseURL: process.env.NEXT_PUBLIC_MARKETPLACE_API || 'http://localhost:3000',
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.nodeApi = axios.create({
      baseURL: process.env.NEXT_PUBLIC_BLACKSILK_NODE || 'http://localhost:9333',
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Add request interceptors for authentication
    this.api.interceptors.request.use((config) => {
      const credentials = this.getStoredCredentials();
      if (credentials?.publicKey) {
        config.headers['X-Public-Key'] = credentials.publicKey;
        // Add signature for authenticated requests
        if (config.data) {
          config.headers['X-Signature'] = this.signRequest(config.data, credentials.privateKey);
        }
      }
      return config;
    });
  }

  // Authentication
  async login(privateKey: string, recoveryPhrase?: string): Promise<ApiResponse<User>> {
    try {
      const publicKey = this.derivePublicKey(privateKey);
      const response = await this.api.post('/api/login', {
        private_key: privateKey,
        public_key: publicKey,
        recovery_phrase: recoveryPhrase,
      });
      
      if (response.data.success) {
        this.storeCredentials({
          privateKey,
          publicKey,
          address: response.data.data.address,
          recoveryPhrase,
        });
      }
      
      return response.data;
    } catch (error) {
      return { success: false, error: this.handleError(error) };
    }
  }

  logout(): void {
    localStorage.removeItem('blacksilk_credentials');
    sessionStorage.clear();
  }

  // Products
  async getProducts(filters?: SearchFilters): Promise<ApiResponse<Product[]>> {
    try {
      const response = await this.api.get('/api/products', { params: filters });
      return response.data;
    } catch (error) {
      return { success: false, error: this.handleError(error) };
    }
  }

  async getProduct(id: string): Promise<ApiResponse<Product>> {
    try {
      const response = await this.api.get(`/api/products/${id}`);
      return response.data;
    } catch (error) {
      return { success: false, error: this.handleError(error) };
    }
  }

  async createProduct(product: Partial<Product>): Promise<ApiResponse<Product>> {
    try {
      const response = await this.api.post('/api/products', product);
      return response.data;
    } catch (error) {
      return { success: false, error: this.handleError(error) };
    }
  }

  async searchProducts(query: string, filters?: SearchFilters): Promise<ApiResponse<Product[]>> {
    try {
      const response = await this.api.get('/api/search', { 
        params: { q: query, ...filters } 
      });
      return response.data;
    } catch (error) {
      return { success: false, error: this.handleError(error) };
    }
  }

  // Orders
  async createOrder(order: {
    product_id: string;
    quantity: number;
    shipping_address: string;
    buyer_public_key: string;
  }): Promise<ApiResponse<Order>> {
    try {
      const response = await this.api.post('/api/purchase', order);
      return response.data;
    } catch (error) {
      return { success: false, error: this.handleError(error) };
    }
  }

  async getOrders(): Promise<ApiResponse<Order[]>> {
    try {
      const response = await this.api.get('/api/orders');
      return response.data;
    } catch (error) {
      return { success: false, error: this.handleError(error) };
    }
  }

  async getOrder(id: string): Promise<ApiResponse<Order>> {
    try {
      const response = await this.api.get(`/api/orders/${id}`);
      return response.data;
    } catch (error) {
      return { success: false, error: this.handleError(error) };
    }
  }

  // Categories
  async getCategories(): Promise<ApiResponse<Category[]>> {
    try {
      const response = await this.api.get('/api/categories');
      return response.data;
    } catch (error) {
      return { success: false, error: this.handleError(error) };
    }
  }

  // BlackSilk Node API
  async getNodeInfo(): Promise<ApiResponse<NodeInfo>> {
    try {
      const response = await this.nodeApi.get('/api/info');
      return { success: true, data: response.data };
    } catch (error) {
      return { success: false, error: this.handleError(error) };
    }
  }

  async getBalance(publicKey: string): Promise<ApiResponse<Balance>> {
    try {
      const response = await this.nodeApi.get(`/api/balance/${publicKey}`);
      return { success: true, data: response.data };
    } catch (error) {
      return { success: false, error: this.handleError(error) };
    }
  }

  async submitTransaction(transaction: any): Promise<ApiResponse<string>> {
    try {
      const response = await this.nodeApi.post('/api/submit_tx', transaction);
      return { success: true, data: response.data.txid };
    } catch (error) {
      return { success: false, error: this.handleError(error) };
    }
  }

  async getTransactionStatus(txid: string): Promise<ApiResponse<Transaction>> {
    try {
      const response = await this.nodeApi.get(`/api/tx/${txid}`);
      return { success: true, data: response.data };
    } catch (error) {
      return { success: false, error: this.handleError(error) };
    }
  }

  // Escrow
  async getEscrowStatus(contractId: string): Promise<ApiResponse<EscrowContract>> {
    try {
      const response = await this.nodeApi.get(`/api/escrow/${contractId}`);
      return { success: true, data: response.data };
    } catch (error) {
      return { success: false, error: this.handleError(error) };
    }
  }

  async signEscrowRelease(contractId: string): Promise<ApiResponse<string>> {
    try {
      const credentials = this.getStoredCredentials();
      if (!credentials) throw new Error('Not authenticated');

      const response = await this.nodeApi.post('/api/escrow/sign', {
        contract_id: contractId,
        signer: credentials.publicKey,
        signature: this.signMessage(contractId, credentials.privateKey),
      });
      return { success: true, data: response.data.txid };
    } catch (error) {
      return { success: false, error: this.handleError(error) };
    }
  }

  async raiseDispute(contractId: string, reason: string): Promise<ApiResponse<void>> {
    try {
      const response = await this.nodeApi.post('/api/escrow/dispute', {
        contract_id: contractId,
        reason,
      });
      return { success: true };
    } catch (error) {
      return { success: false, error: this.handleError(error) };
    }
  }

  // IPFS
  async uploadImage(file: File): Promise<ApiResponse<string>> {
    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await this.api.post('/api/ipfs/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      return response.data;
    } catch (error) {
      return { success: false, error: this.handleError(error) };
    }
  }

  getIPFSUrl(hash: string): string {
    return `${process.env.NEXT_PUBLIC_IPFS_GATEWAY}/ipfs/${hash}`;
  }

  // WebSocket connection
  connectWebSocket(onMessage: (message: any) => void): WebSocket | null {
    try {
      const wsUrl = (process.env.NEXT_PUBLIC_MARKETPLACE_API || 'http://localhost:3000')
        .replace('http', 'ws') + '/ws';
      
      const ws = new WebSocket(wsUrl);
      
      ws.onopen = () => {
        console.log('🔌 Connected to marketplace WebSocket');
      };
      
      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          onMessage(message);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };
      
      ws.onclose = () => {
        console.log('🔌 Disconnected from marketplace WebSocket');
      };
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
      };

      return ws;
    } catch (error) {
      console.error('Failed to connect WebSocket:', error);
      return null;
    }
  }

  // Helper methods
  private getStoredCredentials(): any {
    try {
      const stored = localStorage.getItem('blacksilk_credentials');
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  }

  private storeCredentials(credentials: any): void {
    localStorage.setItem('blacksilk_credentials', JSON.stringify(credentials));
  }

  private derivePublicKey(privateKey: string): string {
    // TODO: Implement actual key derivation using curve25519-dalek
    // For now, return a placeholder
    return privateKey.length > 32 ? privateKey.slice(0, 32) : privateKey.padEnd(32, '0');
  }

  private signRequest(data: any, privateKey: string): string {
    // TODO: Implement actual signing
    return 'placeholder_signature';
  }

  private signMessage(message: string, privateKey: string): string {
    // TODO: Implement actual message signing
    return 'placeholder_signature';
  }

  private handleError(error: any): string {
    if (error.response?.data?.error) {
      return error.response.data.error;
    }
    if (error.message) {
      return error.message;
    }
    return 'An unexpected error occurred';
  }
}

export const marketplaceAPI = new MarketplaceAPI();
