// BlackSilk Testnet Faucet Types

export interface FaucetRequest {
  id?: string
  address: string
  amount: number
  ip_address: string
  user_agent?: string
  timestamp: number
  status: 'pending' | 'completed' | 'failed' | 'expired'
  transaction_hash?: string
  error_message?: string
  created_at: string
  updated_at: string
}

export interface FaucetResponse {
  success: boolean
  message: string
  request_id?: string
  transaction_hash?: string
  amount?: number
  estimated_confirmation_time?: number
  cooldown_remaining?: number
}

export interface FaucetStats {
  total_requests: number
  successful_requests: number
  failed_requests: number
  total_distributed: number
  daily_distributed: number
  daily_limit: number
  active_users_24h: number
  average_response_time: number
  uptime_percentage: number
  current_balance: number
  last_updated: string
}

export interface AdminConfig {
  faucet_amount: number
  cooldown_hours: number
  daily_limit: number
  rate_limit_window_ms: number
  rate_limit_max_requests: number
  maintenance_mode: boolean
  captcha_enabled: boolean
  min_balance_alert: number
}

export interface NetworkInfo {
  network_name: string
  node_url: string
  block_height: number
  peers: number
  difficulty: number
  mempool_size: number
  is_synced: boolean
  last_block_time: number
}

export interface BalanceInfo {
  address: string
  balance: number
  locked_balance?: number
  unconfirmed_balance?: number
  last_updated: string
}

export interface Transaction {
  hash: string
  from_address: string
  to_address: string
  amount: number
  fee: number
  block_height?: number
  confirmations: number
  timestamp: number
  status: 'pending' | 'confirmed' | 'failed'
}

export interface RateLimitInfo {
  ip_address: string
  requests_count: number
  window_start: number
  is_blocked: boolean
  reset_time: number
}

export interface CooldownInfo {
  address: string
  last_request_time: number
  cooldown_remaining: number
  can_request: boolean
}

export interface ApiResponse<T = any> {
  success: boolean
  data?: T
  error?: string
  message?: string
  timestamp: number
}

export interface BlackSilkApiConfig {
  nodeUrl: string
  timeout?: number
  retries?: number
}

// Node API Response Types
export interface NodeStatusResponse {
  version: string
  network: string
  height: number
  peers: number
  difficulty: number
  mempool_size: number
  synced: boolean
}

export interface SubmitTransactionRequest {
  inputs: Array<{
    txid: string
    vout: number
    amount: number
  }>
  outputs: Array<{
    address: string
    amount: number
  }>
  fee: number
  extra?: any[]
  metadata?: string
  signature: string
}

export interface SubmitTransactionResponse {
  success: boolean
  message: string
  tx_hash?: string
}

// Database Models
export interface DbFaucetRequest {
  id: number
  address: string
  amount: number
  ip_address: string
  user_agent: string | null
  timestamp: number
  status: string
  transaction_hash: string | null
  error_message: string | null
  created_at: string
  updated_at: string
}

export interface DbRateLimit {
  id: number
  ip_address: string
  requests_count: number
  window_start: number
  created_at: string
  updated_at: string
}

export interface DbConfig {
  key: string
  value: string
  updated_at: string
}

// Frontend Component Props
export interface FaucetFormProps {
  onSubmit: (address: string) => Promise<void>
  isLoading: boolean
  disabled?: boolean
}

export interface StatsCardProps {
  title: string
  value: string | number
  description?: string
  icon?: React.ReactNode
  trend?: 'up' | 'down' | 'neutral'
  trendValue?: string
}

export interface RequestHistoryProps {
  requests: FaucetRequest[]
  onRefresh: () => void
  isLoading: boolean
}

export interface AdminDashboardProps {
  stats: FaucetStats
  config: AdminConfig
  onConfigUpdate: (config: Partial<AdminConfig>) => Promise<void>
}

// Validation Schemas
export interface AddressValidation {
  isValid: boolean
  error?: string
  normalized?: string
}

export interface RequestValidation {
  isValid: boolean
  errors: string[]
  cooldownRemaining?: number
}

// Monitoring Types
export interface HealthCheck {
  status: 'healthy' | 'degraded' | 'unhealthy'
  checks: {
    database: boolean
    node_connection: boolean
    balance_sufficient: boolean
    rate_limits_working: boolean
  }
  uptime: number
  version: string
  timestamp: number
}

export interface MetricsData {
  requests_per_minute: number[]
  success_rate: number
  average_response_time: number
  error_rate: number
  active_connections: number
  memory_usage: number
  cpu_usage: number
}

// Events
export interface FaucetEvent {
  type: 'request_created' | 'request_completed' | 'request_failed' | 'balance_low' | 'maintenance_mode'
  data: any
  timestamp: number
  severity: 'info' | 'warning' | 'error' | 'critical'
}

// Queue Types
export interface QueuedRequest {
  id: string
  address: string
  amount: number
  priority: number
  attempts: number
  created_at: number
  retry_after?: number
}

export interface ProcessingResult {
  success: boolean
  transaction_hash?: string
  error?: string
  retry_delay?: number
}

export default {}
