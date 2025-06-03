import axios, { AxiosInstance } from 'axios'
import crypto from 'crypto'
import { logger, securityLogger } from '../logger'
import { query, run, get } from '../database'
import type {
  FaucetRequest,
  FaucetResponse,
  FaucetStats,
  AdminConfig,
  NetworkInfo,
  BalanceInfo,
  CooldownInfo,
  QueuedRequest,
  ProcessingResult,
  SubmitTransactionRequest,
  SubmitTransactionResponse,
  NodeStatusResponse
} from '../../src/types'

export class FaucetService {
  private nodeUrl: string
  private nodeClient: AxiosInstance
  private faucetPrivateKey: string
  private faucetAddress: string
  private processingQueue: QueuedRequest[] = []
  private isProcessing = false
  private config: AdminConfig
  private networkInfo: NetworkInfo | null = null

  constructor() {
    this.nodeUrl = process.env.BLACKSILK_NODE_URL || 'http://localhost:19333'
    this.faucetPrivateKey = process.env.FAUCET_PRIVATE_KEY || ''
    this.faucetAddress = process.env.FAUCET_ADDRESS || ''
    
    // Initialize HTTP client for BlackSilk node
    this.nodeClient = axios.create({
      baseURL: this.nodeUrl,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'BlackSilk-Testnet-Faucet/1.0.0'
      }
    })

    // Default configuration
    this.config = {
      faucet_amount: parseFloat(process.env.FAUCET_AMOUNT || '10.0'),
      cooldown_hours: parseInt(process.env.FAUCET_COOLDOWN_HOURS || '24'),
      daily_limit: parseFloat(process.env.FAUCET_MAX_DAILY_LIMIT || '1000'),
      rate_limit_window_ms: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'),
      rate_limit_max_requests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '5'),
      maintenance_mode: false,
      captcha_enabled: true,
      min_balance_alert: 100
    }
  }

  async initialize(): Promise<void> {
    try {
      // Load configuration from database
      await this.loadConfig()
      
      // Test node connection
      await this.updateNetworkInfo()
      
      // Validate faucet wallet setup
      await this.validateFaucetWallet()
      
      // Start background processing
      this.startBackgroundProcessing()
      
      logger.info('✅ Faucet service initialized successfully')
    } catch (error) {
      logger.error('❌ Failed to initialize faucet service:', error)
      throw error
    }
  }

  private async loadConfig(): Promise<void> {
    try {
      const configRows = await query('SELECT key, value FROM config')
      const dbConfig: any = {}
      
      configRows.forEach((row: any) => {
        const value = row.value
        // Parse boolean and numeric values
        if (value === 'true') dbConfig[row.key] = true
        else if (value === 'false') dbConfig[row.key] = false
        else if (!isNaN(parseFloat(value))) dbConfig[row.key] = parseFloat(value)
        else dbConfig[row.key] = value
      })
      
      this.config = { ...this.config, ...dbConfig }
      logger.info('Configuration loaded from database')
    } catch (error) {
      logger.warn('Failed to load config from database, using defaults:', error)
    }
  }

  private async updateNetworkInfo(): Promise<void> {
    try {
      const response = await this.nodeClient.get('/status')
      const nodeStatus: NodeStatusResponse = response.data
      
      this.networkInfo = {
        network_name: `BlackSilk ${nodeStatus.network}`,
        node_url: this.nodeUrl,
        block_height: nodeStatus.height,
        peers: nodeStatus.peers,
        difficulty: nodeStatus.difficulty,
        mempool_size: nodeStatus.mempool_size,
        is_synced: nodeStatus.synced,
        last_block_time: Date.now()
      }
      
      logger.debug('Network info updated:', this.networkInfo)
    } catch (error) {
      logger.error('Failed to update network info:', error)
      throw new Error('Cannot connect to BlackSilk node')
    }
  }

  private async validateFaucetWallet(): Promise<void> {
    if (!this.faucetPrivateKey || !this.faucetAddress) {
      throw new Error('Faucet wallet not configured. Set FAUCET_PRIVATE_KEY and FAUCET_ADDRESS')
    }

    try {
      const balance = await this.getFaucetBalance()
      logger.info(`Faucet wallet balance: ${balance.balance} BLK`)
      
      if (balance.balance < this.config.min_balance_alert) {
        securityLogger.warn('Low faucet balance detected', {
          balance: balance.balance,
          address: this.faucetAddress,
          threshold: this.config.min_balance_alert
        })
      }
    } catch (error) {
      logger.error('Failed to validate faucet wallet:', error)
      throw new Error('Faucet wallet validation failed')
    }
  }

  async getFaucetBalance(): Promise<BalanceInfo> {
    try {
      // Get balance from node - implement according to BlackSilk API
      const response = await this.nodeClient.get(`/get_balance?address=${this.faucetAddress}`)
      const balance = response.data.balance || 0
      
      return {
        address: this.faucetAddress,
        balance: balance,
        unconfirmed_balance: response.data.unconfirmed_balance || 0,
        last_updated: new Date().toISOString()
      }
    } catch (error) {
      logger.error('Failed to get faucet balance:', error)
      throw error
    }
  }

  async requestTokens(address: string, ipAddress: string, userAgent?: string): Promise<FaucetResponse> {
    try {
      // Validate request
      const validation = await this.validateRequest(address, ipAddress)
      if (!validation.isValid) {
        return {
          success: false,
          message: validation.errors.join('. '),
          cooldown_remaining: validation.cooldownRemaining
        }
      }

      // Check maintenance mode
      if (this.config.maintenance_mode) {
        return {
          success: false,
          message: 'Faucet is currently under maintenance. Please try again later.'
        }
      }

      // Create database record
      const requestId = crypto.randomUUID()
      const timestamp = Date.now()
      
      const result = await run(
        `INSERT INTO faucet_requests 
         (address, amount, ip_address, user_agent, timestamp, status) 
         VALUES (?, ?, ?, ?, ?, ?)`,
        [address, this.config.faucet_amount, ipAddress, userAgent, timestamp, 'pending']
      )

      // Add to processing queue
      const queuedRequest: QueuedRequest = {
        id: requestId,
        address,
        amount: this.config.faucet_amount,
        priority: 1,
        attempts: 0,
        created_at: timestamp
      }
      
      this.processingQueue.push(queuedRequest)
      
      logger.info(`Token request queued: ${address} (${this.config.faucet_amount} BLK)`, {
        requestId,
        address,
        amount: this.config.faucet_amount,
        ipAddress
      })

      return {
        success: true,
        message: 'Request submitted successfully. Tokens will be sent shortly.',
        request_id: requestId,
        amount: this.config.faucet_amount,
        estimated_confirmation_time: 300 // 5 minutes
      }

    } catch (error) {
      logger.error('Token request failed:', error)
      return {
        success: false,
        message: 'Internal server error. Please try again later.'
      }
    }
  }

  private async validateRequest(address: string, ipAddress: string): Promise<{
    isValid: boolean
    errors: string[]
    cooldownRemaining?: number
  }> {
    const errors: string[] = []

    // Validate address format
    if (!this.isValidAddress(address)) {
      errors.push('Invalid BlackSilk address format')
    }

    // Check cooldown period
    const cooldownInfo = await this.checkCooldown(address)
    if (!cooldownInfo.can_request) {
      errors.push(`Address is in cooldown period`)
      return {
        isValid: false,
        errors,
        cooldownRemaining: cooldownInfo.cooldown_remaining
      }
    }

    // Check daily limit
    const dailyDistributed = await this.getDailyDistributed()
    if (dailyDistributed + this.config.faucet_amount > this.config.daily_limit) {
      errors.push('Daily distribution limit reached. Please try again tomorrow.')
    }

    // Check IP rate limiting
    const ipRequests = await this.getRecentRequestsByIP(ipAddress)
    if (ipRequests >= 3) { // Max 3 requests per IP per day
      errors.push('Too many requests from this IP address')
    }

    return {
      isValid: errors.length === 0,
      errors
    }
  }

  private isValidAddress(address: string): boolean {
    // BlackSilk address validation - implement according to address format
    if (!address || typeof address !== 'string') return false
    
    // Basic validation - adjust according to BlackSilk address format
    if (address.length < 26 || address.length > 95) return false
    
    // Check for valid characters (base58 or bech32 depending on format)
    const validChars = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/
    return validChars.test(address)
  }

  private async checkCooldown(address: string): Promise<CooldownInfo> {
    try {
      const lastRequest = await get(
        'SELECT timestamp FROM faucet_requests WHERE address = ? AND status = "completed" ORDER BY timestamp DESC LIMIT 1',
        [address]
      )

      if (!lastRequest) {
        return {
          address,
          last_request_time: 0,
          cooldown_remaining: 0,
          can_request: true
        }
      }

      const lastRequestTime = lastRequest.timestamp
      const cooldownMs = this.config.cooldown_hours * 60 * 60 * 1000
      const timeSinceLastRequest = Date.now() - lastRequestTime
      const cooldownRemaining = Math.max(0, cooldownMs - timeSinceLastRequest)

      return {
        address,
        last_request_time: lastRequestTime,
        cooldown_remaining: Math.ceil(cooldownRemaining / 1000), // seconds
        can_request: cooldownRemaining === 0
      }
    } catch (error) {
      logger.error('Cooldown check failed:', error)
      return {
        address,
        last_request_time: 0,
        cooldown_remaining: 0,
        can_request: false
      }
    }
  }

  private async getDailyDistributed(): Promise<number> {
    try {
      const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000)
      const result = await get(
        'SELECT SUM(amount) as total FROM faucet_requests WHERE timestamp > ? AND status = "completed"',
        [oneDayAgo]
      )
      return result?.total || 0
    } catch (error) {
      logger.error('Failed to get daily distributed amount:', error)
      return 0
    }
  }

  private async getRecentRequestsByIP(ipAddress: string): Promise<number> {
    try {
      const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000)
      const result = await get(
        'SELECT COUNT(*) as count FROM faucet_requests WHERE ip_address = ? AND timestamp > ?',
        [ipAddress, oneDayAgo]
      )
      return result?.count || 0
    } catch (error) {
      logger.error('Failed to get recent requests by IP:', error)
      return 0
    }
  }

  private startBackgroundProcessing(): void {
    // Process queue every 10 seconds
    setInterval(async () => {
      if (!this.isProcessing && this.processingQueue.length > 0) {
        await this.processQueue()
      }
    }, 10000)

    // Update network info every 30 seconds
    setInterval(async () => {
      try {
        await this.updateNetworkInfo()
      } catch (error) {
        logger.warn('Failed to update network info:', error)
      }
    }, 30000)
  }

  private async processQueue(): Promise<void> {
    if (this.isProcessing || this.processingQueue.length === 0) return

    this.isProcessing = true
    
    try {
      const request = this.processingQueue.shift()!
      await this.processRequest(request)
    } catch (error) {
      logger.error('Queue processing error:', error)
    } finally {
      this.isProcessing = false
    }
  }

  private async processRequest(request: QueuedRequest): Promise<void> {
    try {
      logger.info(`Processing faucet request: ${request.id}`)
      
      // Create and submit transaction
      const transaction = await this.createTransaction(request.address, request.amount)
      const result = await this.submitTransaction(transaction)
      
      if (result.success && result.transaction_hash) {
        // Update database with success
        await run(
          'UPDATE faucet_requests SET status = ?, transaction_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
          ['completed', result.transaction_hash, request.id]
        )
        
        logger.info(`✅ Tokens sent successfully: ${request.address} (${result.transaction_hash})`)
      } else {
        throw new Error(result.error || 'Transaction submission failed')
      }
      
    } catch (error) {
      logger.error(`❌ Failed to process request ${request.id}:`, error)
      
      // Update database with failure
      await run(
        'UPDATE faucet_requests SET status = ?, error_message = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        ['failed', error.message, request.id]
      )
      
      // Retry logic (up to 3 attempts)
      if (request.attempts < 3) {
        request.attempts++
        request.retry_after = Date.now() + (60000 * request.attempts) // Exponential backoff
        this.processingQueue.push(request)
        logger.info(`Retrying request ${request.id} (attempt ${request.attempts})`)
      }
    }
  }

  private async createTransaction(toAddress: string, amount: number): Promise<SubmitTransactionRequest> {
    // This is a simplified transaction creation
    // In a real implementation, you would need to:
    // 1. Get UTXOs for the faucet address
    // 2. Create proper inputs and outputs
    // 3. Calculate fees
    // 4. Sign the transaction
    
    const amountAtomic = Math.floor(amount * 1000000) // Convert to atomic units
    const fee = 1000 // 0.001 BLK fee
    
    // Create a simple transaction structure
    const transaction: SubmitTransactionRequest = {
      inputs: [], // Would be populated with actual UTXOs
      outputs: [
        {
          address: toAddress,
          amount: amountAtomic
        }
      ],
      fee,
      metadata: `FAUCET:${Date.now()}`,
      signature: this.signTransaction(toAddress, amountAtomic)
    }
    
    return transaction
  }

  private signTransaction(toAddress: string, amount: number): string {
    // Simplified signing - implement proper cryptographic signing
    const data = `${this.faucetAddress}:${toAddress}:${amount}:${Date.now()}`
    return crypto.createHash('sha256').update(data + this.faucetPrivateKey).digest('hex')
  }

  private async submitTransaction(transaction: SubmitTransactionRequest): Promise<ProcessingResult> {
    try {
      const response = await this.nodeClient.post('/submit_tx', transaction)
      const result: SubmitTransactionResponse = response.data
      
      return {
        success: result.success,
        transaction_hash: result.tx_hash,
        error: result.success ? undefined : result.message
      }
    } catch (error) {
      logger.error('Transaction submission failed:', error)
      return {
        success: false,
        error: error.message || 'Network error'
      }
    }
  }

  async getStats(): Promise<FaucetStats> {
    try {
      const [totalRequests, successfulRequests, failedRequests, totalDistributed, dailyDistributed, activeUsers] = await Promise.all([
        get('SELECT COUNT(*) as count FROM faucet_requests'),
        get('SELECT COUNT(*) as count FROM faucet_requests WHERE status = "completed"'),
        get('SELECT COUNT(*) as count FROM faucet_requests WHERE status = "failed"'),
        get('SELECT SUM(amount) as total FROM faucet_requests WHERE status = "completed"'),
        get('SELECT SUM(amount) as total FROM faucet_requests WHERE status = "completed" AND timestamp > ?', [Date.now() - 24 * 60 * 60 * 1000]),
        get('SELECT COUNT(DISTINCT address) as count FROM faucet_requests WHERE timestamp > ?', [Date.now() - 24 * 60 * 60 * 1000])
      ])

      const balance = await this.getFaucetBalance()

      return {
        total_requests: totalRequests?.count || 0,
        successful_requests: successfulRequests?.count || 0,
        failed_requests: failedRequests?.count || 0,
        total_distributed: totalDistributed?.total || 0,
        daily_distributed: dailyDistributed?.total || 0,
        daily_limit: this.config.daily_limit,
        active_users_24h: activeUsers?.count || 0,
        average_response_time: 30, // TODO: Calculate actual response time
        uptime_percentage: 99.9, // TODO: Calculate actual uptime
        current_balance: balance.balance,
        last_updated: new Date().toISOString()
      }
    } catch (error) {
      logger.error('Failed to get stats:', error)
      throw error
    }
  }

  async getStatus(): Promise<any> {
    return {
      status: 'operational',
      network: this.networkInfo,
      config: this.config,
      queue_size: this.processingQueue.length,
      is_processing: this.isProcessing,
      last_updated: new Date().toISOString()
    }
  }

  async updateConfig(newConfig: Partial<AdminConfig>): Promise<void> {
    try {
      for (const [key, value] of Object.entries(newConfig)) {
        await run('UPDATE config SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?', [String(value), key])
        this.config[key as keyof AdminConfig] = value as any
      }
      
      logger.info('Configuration updated:', newConfig)
    } catch (error) {
      logger.error('Failed to update configuration:', error)
      throw error
    }
  }

  async shutdown(): Promise<void> {
    logger.info('Shutting down faucet service...')
    // Process remaining queue items before shutdown
    while (this.processingQueue.length > 0 && this.processingQueue.length < 10) {
      await this.processQueue()
      await new Promise(resolve => setTimeout(resolve, 1000))
    }
    logger.info('Faucet service shutdown complete')
  }
}
