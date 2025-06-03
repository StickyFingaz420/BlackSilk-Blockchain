import axios, { AxiosInstance, AxiosResponse } from 'axios'
import type { 
  Block, 
  Transaction, 
  Address, 
  NetworkInfo, 
  MempoolTransaction,
  ApiResponse,
  PaginatedResponse,
  BlockFilter,
  TransactionFilter
} from '@/types'

class BlackSilkAPI {
  private client: AxiosInstance

  constructor() {
    const baseURL = process.env.NEXT_PUBLIC_NODE_URL || 'http://localhost:19333'
    
    this.client = axios.create({
      baseURL,
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      },
    })

    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        // Add timestamp to prevent caching
        config.params = {
          ...config.params,
          _t: Date.now(),
        }
        return config
      },
      (error) => Promise.reject(error)
    )

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (error.response?.status === 429) {
          // Rate limited - wait and retry
          await new Promise(resolve => setTimeout(resolve, 1000))
          return this.client.request(error.config)
        }
        return Promise.reject(error)
      }
    )
  }

  // Network Information
  async getNetworkInfo(): Promise<NetworkInfo> {
    const response = await this.client.get('/status')
    return this.transformNetworkInfo(response.data)
  }

  // Blocks
  async getBlocks(filter?: BlockFilter, page = 1, limit = 20): Promise<PaginatedResponse<Block>> {
    const params = {
      page,
      limit,
      ...filter,
    }
    
    const response = await this.client.get('/get_blocks', { params })
    return this.transformBlocksResponse(response.data)
  }

  async getBlock(hashOrHeight: string | number): Promise<Block> {
    const endpoint = typeof hashOrHeight === 'number' 
      ? `/get_block_by_height/${hashOrHeight}`
      : `/get_block/${hashOrHeight}`
    
    const response = await this.client.get(endpoint)
    return this.transformBlock(response.data)
  }

  async getLatestBlocks(count = 10): Promise<Block[]> {
    const response = await this.client.get(`/get_blocks?limit=${count}&sort=desc`)
    return response.data.map(this.transformBlock)
  }

  // Transactions
  async getTransaction(txid: string): Promise<Transaction> {
    const response = await this.client.get(`/get_transaction/${txid}`)
    return this.transformTransaction(response.data)
  }

  async getTransactions(filter?: TransactionFilter, page = 1, limit = 50): Promise<PaginatedResponse<Transaction>> {
    const params = {
      page,
      limit,
      ...filter,
    }
    
    const response = await this.client.get('/get_transactions', { params })
    return this.transformTransactionsResponse(response.data)
  }

  async getMempool(): Promise<MempoolTransaction[]> {
    const response = await this.client.get('/get_mempool')
    return response.data.transactions?.map(this.transformMempoolTransaction) || []
  }

  // Address
  async getAddress(address: string): Promise<Address> {
    const response = await this.client.get(`/get_address/${address}`)
    return this.transformAddress(response.data)
  }

  async getAddressTransactions(address: string, page = 1, limit = 50): Promise<PaginatedResponse<Transaction>> {
    const params = { page, limit }
    const response = await this.client.get(`/get_address_transactions/${address}`, { params })
    return this.transformTransactionsResponse(response.data)
  }

  // Search
  async search(query: string): Promise<any> {
    const response = await this.client.get(`/search`, { params: { q: query } })
    return response.data
  }

  // Statistics
  async getChartData(type: 'blocks' | 'transactions' | 'difficulty' | 'hashrate', period: string = '7d'): Promise<any[]> {
    const response = await this.client.get(`/charts/${type}`, { params: { period } })
    return response.data
  }

  async getPrivacyStats(): Promise<any> {
    const response = await this.client.get('/privacy_stats')
    return response.data
  }

  // WebSocket for real-time updates
  createWebSocket(): WebSocket | null {
    if (typeof window === 'undefined') return null
    
    const wsUrl = process.env.NEXT_PUBLIC_NODE_URL?.replace('http', 'ws') + '/ws'
    return new WebSocket(wsUrl)
  }

  // Transform methods to ensure consistent data structure
  private transformNetworkInfo(data: any): NetworkInfo {
    return {
      version: data.version || '1.0.0',
      network: data.network || 'testnet',
      height: data.height || 0,
      best_block_hash: data.best_block_hash || '',
      difficulty: data.difficulty || 0,
      hashrate: data.hashrate || 0,
      peers: data.peers || 0,
      mempool_size: data.mempool_size || 0,
      block_time: data.block_time || 120,
      next_difficulty_adjustment: data.next_difficulty_adjustment || 0,
      supply: {
        circulating: data.supply?.circulating || 0,
        total_cap: data.supply?.total_cap || 21000000,
        burned: data.supply?.burned || 0,
      },
      mining: {
        algorithm: data.mining?.algorithm || 'RandomX',
        current_reward: data.mining?.current_reward || 5,
        next_halving: data.mining?.next_halving || 0,
      },
    }
  }

  private transformBlock(data: any): Block {
    return {
      height: data.header?.height || data.height || 0,
      hash: data.hash || data.header?.hash || '',
      parent_hash: data.header?.parent_hash || data.parent_hash || '',
      timestamp: data.header?.timestamp || data.timestamp || Date.now() / 1000,
      nonce: data.header?.nonce || data.nonce || 0,
      difficulty: data.header?.difficulty || data.difficulty || 0,
      transactions: data.transactions?.map(this.transformTransaction) || [],
      merkle_root: data.header?.merkle_root || data.merkle_root || '',
      size: data.size || 0,
      tx_count: data.transactions?.length || 0,
      miner: data.miner,
      reward: data.reward,
    }
  }

  private transformTransaction(data: any): Transaction {
    return {
      txid: data.txid || data.hash || '',
      version: data.version || 1,
      size: data.size || 0,
      timestamp: data.timestamp || Date.now() / 1000,
      block_height: data.block_height,
      confirmations: data.confirmations || 0,
      inputs: data.inputs || [],
      outputs: data.outputs || [],
      fee: data.fee || 0,
      type: data.type || 'transfer',
      privacy_level: data.privacy_level || 'public',
      ring_size: data.ring_size,
    }
  }

  private transformMempoolTransaction(data: any): MempoolTransaction {
    return {
      ...this.transformTransaction(data),
      time_in_mempool: data.time_in_mempool || 0,
      priority: data.priority || 'medium',
      fee_rate: data.fee_rate || 0,
    }
  }

  private transformAddress(data: any): Address {
    return {
      address: data.address || '',
      balance: data.balance || 0,
      transactions_count: data.transactions_count || 0,
      first_seen: data.first_seen || 0,
      last_seen: data.last_seen || 0,
      type: data.type || 'regular',
    }
  }

  private transformBlocksResponse(data: any): PaginatedResponse<Block> {
    return {
      items: (data.blocks || data).map(this.transformBlock),
      total: data.total || data.length || 0,
      page: data.page || 1,
      per_page: data.per_page || 20,
      total_pages: data.total_pages || 1,
    }
  }

  private transformTransactionsResponse(data: any): PaginatedResponse<Transaction> {
    return {
      items: (data.transactions || data).map(this.transformTransaction),
      total: data.total || data.length || 0,
      page: data.page || 1,
      per_page: data.per_page || 50,
      total_pages: data.total_pages || 1,
    }
  }
}

export const api = new BlackSilkAPI()
export default api
