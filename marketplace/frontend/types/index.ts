// BlackSilk Marketplace Types
export enum PrivacyLevel {
  Low = 'Low',
  Medium = 'Medium',
  High = 'High',
  Maximum = 'Maximum'
}

export interface Product {
  id: string;
  seller: string; // vendor_id mapped to seller for consistency
  title: string;
  description: string;
  category: string;
  subcategory?: string;
  price: number;
  currency?: string;
  stock?: number; // quantity_available mapped to stock
  images?: string[]; // image_hashes mapped to images
  shipsFrom?: string;
  shipsTo?: string[];
  shippingPrice?: number;
  processingTime?: string;
  createdAt: number; // timestamp
  updatedAt?: number;
  isActive?: boolean;
  rating?: number;
  stealthRequired?: boolean;
  escrowRequired?: boolean;
}

export interface User {
  id: string;
  username: string;
  public_key: string;
  created_at: string;
  last_login: string;
  is_vendor: boolean;
  vendor_rating: number;
  total_sales: number;
  profile_description?: string;
  pgp_key?: string;
}

export interface Order {
  id: string;
  buyer: string;
  seller: string;
  items: OrderItem[];
  totalAmount: number;
  escrowAddress?: string;
  escrowStatus: EscrowStatus;
  status: OrderStatus;
  createdAt: number;
  updatedAt?: number;
  shippingAddress?: string;
  trackingNumber?: string;
  disputeReason?: string;
  disputeDeadline?: number;
}

export enum OrderStatus {
  AwaitingPayment = 'AwaitingPayment',
  Paid = 'Paid',
  Processing = 'Processing',
  Shipped = 'Shipped',
  Delivered = 'Delivered',
  Completed = 'Completed',
  Disputed = 'Disputed',
  Cancelled = 'Cancelled',
  Refunded = 'Refunded',
}

export interface EscrowContract {
  contract_id: string;
  buyer: string;
  seller: string;
  arbiter: string;
  amount: number;
  status: EscrowStatus;
  signatures: string[];
  created_at: string;
  funded_at?: string;
  completed_at?: string;
}

export enum EscrowStatus {
  Pending = 'pending',
  Funded = 'funded',
  Completed = 'completed',
  Disputed = 'disputed',
  Refunded = 'refunded',
  Voting = 'voting',
  Resolved = 'resolved',
}

export interface Category {
  id: string;
  name: string;
  description: string;
  icon: string;
  count: number;
}

export interface NodeInfo {
  chain_height: number;
  peers: number;
  difficulty: number;
  hashrate?: number;
  network?: string;
  version?: string;
}

// export interface NodeInfo {
//   chain_height: number;
//   difficulty: number;
//   hashrate: number;
//   peers: number;
//   mempool_size: number;
//   network: string;
// }

export interface Balance {
  confirmed: number;
  unconfirmed: number;
  locked_in_escrow: number;
}

export interface Transaction {
  txid: string;
  from: string;
  to: string;
  amount: number;
  fee: number;
  timestamp: string;
  confirmations: number;
  block_height?: number;
}

export interface WalletCredentials {
  privateKey: string;
  publicKey: string;
  address: string;
  recoveryPhrase?: string;
}

export interface MarketplaceConfig {
  marketplaceApi: string;
  blacksilkNode: string;
  ipfsGateway: string;
  torProxy?: string;
}

export interface SearchFilters {
  category?: string;
  subcategory?: string;
  min_price?: number;
  max_price?: number;
  ships_from?: string;
  vendor?: string;
  sort_by?: 'price' | 'rating' | 'date' | 'popularity';
  sort_order?: 'asc' | 'desc';
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface WebSocketMessage {
  type: 'product_update' | 'order_update' | 'escrow_update' | 'new_block' | 'peer_update';
  data: any;
  timestamp: string;
}

export interface PrivacySettings {
  useTor: boolean;
  useI2P: boolean;
  enableStealth: boolean;
  autoEncrypt: boolean;
}

export interface CartItem {
  productId: string;
  title: string;
  price: number;
  quantity: number;
  seller: string;
  image?: string;
  category: string;
}

export interface OrderItem {
  productId: string;
  productTitle: string;
  quantity: number;
  price: number;
  seller: string;
}

// Node status interface for frontend
export interface NodeStatus {
  connected: boolean;
  synced: boolean;
  blockHeight?: number;
  difficulty?: number;
  hashRate?: number;
  connections?: number;
  version?: string;
  privacyMode?: boolean;
}
