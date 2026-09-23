// BlackSilk Blockchain Types
export interface Block {
  height: number
  hash: string
  parent_hash: string
  timestamp: number
  nonce: number
  difficulty: number
  transactions: Transaction[]
  merkle_root: string
  size: number
  tx_count: number
  miner?: string
  reward?: number
}

export interface Transaction {
  txid: string
  version: number
  size: number
  timestamp: number
  block_height?: number
  confirmations?: number
  inputs: TransactionInput[]
  outputs: TransactionOutput[]
  fee?: number
  type: 'coinbase' | 'transfer' | 'privacy' | 'escrow'
  privacy_level?: 'public' | 'private' | 'stealth'
  ring_size?: number
}

export interface TransactionInput {
  previous_output: {
    txid: string
    index: number
  }
  script_sig: string
  sequence: number
  amount?: number
  address?: string
}

export interface TransactionOutput {
  value: number
  script_pub_key: string
  address?: string
  stealth_address?: string
  commitment?: string
}

export interface Address {
  address: string
  balance: number
  transactions_count: number
  first_seen: number
  last_seen: number
  type: 'regular' | 'stealth' | 'multisig'
}

export interface NetworkInfo {
  version: string
  network: string
  height: number
  best_block_hash: string
  difficulty: number
  hashrate: number
  peers: number
  mempool_size: number
  block_time: number
  next_difficulty_adjustment: number
  supply: {
    circulating: number
    total_cap: number
    burned: number
  }
  mining: {
    algorithm: string
    current_reward: number
    next_halving: number
  }
}

export interface MempoolTransaction extends Transaction {
  time_in_mempool: number
  priority: 'high' | 'medium' | 'low'
  fee_rate: number
}

export interface SearchResult {
  type: 'block' | 'transaction' | 'address'
  data: Block | Transaction | Address
  score: number
}

export interface ChartData {
  timestamp: number
  value: number
  label?: string
}

export interface PrivacyInfo {
  ring_signatures: number
  stealth_addresses: number
  confidential_transactions: number
  privacy_percentage: number
}

// API Response Types
export interface ApiResponse<T> {
  success: boolean
  data: T
  error?: string
  timestamp: number
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

// Component Props Types
export interface BlockCardProps {
  block: Block
  isLatest?: boolean
}

export interface TransactionCardProps {
  transaction: Transaction
  showBlockInfo?: boolean
}

export interface AddressCardProps {
  address: Address
}

export interface StatCardProps {
  title: string
  value: string | number
  change?: number
  icon?: React.ReactNode
  loading?: boolean
}

export interface ChartProps {
  data: ChartData[]
  title: string
  color?: string
  height?: number
}

// Filter and Sort Types
export interface BlockFilter {
  from_height?: number
  to_height?: number
  from_time?: number
  to_time?: number
  miner?: string
}

export interface TransactionFilter {
  type?: Transaction['type']
  from_amount?: number
  to_amount?: number
  from_time?: number
  to_time?: number
  privacy_level?: Transaction['privacy_level']
}

export interface SortOptions {
  field: string
  direction: 'asc' | 'desc'
}

// WebSocket Types
export interface WSMessage {
  type: 'new_block' | 'new_transaction' | 'stats_update'
  data: any
  timestamp: number
}

export interface WSConfig {
  url: string
  reconnectInterval: number
  maxReconnectAttempts: number
}
