import * as bip39 from 'bip39';
import CryptoJS from 'crypto-js';

export interface WalletConfig {
  mnemonic: string;
  addresses: string[];
  currentAddressIndex: number;
  network: 'testnet' | 'mainnet';
}

export interface TransactionRequest {
  to: string;
  amount: number;
  fee?: number;
}

export interface Balance {
  confirmed: number;
  unconfirmed: number;
  total: number;
}

export interface Transaction {
  id: string;
  from: string;
  to: string;
  amount: number;
  fee: number;
  timestamp: number;
  confirmations: number;
  status: 'pending' | 'confirmed' | 'failed';
}

export class BlackSilkWallet {
  private mnemonic: string = '';
  private addresses: string[] = [];
  private currentIndex = 0;
  private network: 'testnet' | 'mainnet';
  private nodeUrl: string;

  constructor(network: 'testnet' | 'mainnet' = 'testnet') {
    this.network = network;
    this.nodeUrl = process.env.NEXT_PUBLIC_NODE_URL || 'http://localhost:19333';
  }

  // Generate new wallet with mnemonic
  generateWallet(): WalletConfig {
    this.mnemonic = bip39.generateMnemonic(256); // 24 words
    this.addresses = [];
    this.currentIndex = 0;
    
    // Generate first address
    this.generateNewAddress();
    
    return this.getConfig();
  }

  // Restore wallet from mnemonic
  restoreFromMnemonic(mnemonic: string): WalletConfig {
    if (!bip39.validateMnemonic(mnemonic)) {
      throw new Error('Invalid mnemonic phrase');
    }
    
    this.mnemonic = mnemonic;
    this.addresses = [];
    this.currentIndex = 0;
    
    // Generate first address
    this.generateNewAddress();
    
    return this.getConfig();
  }

  // Generate new address
  generateNewAddress(): string {
    if (!this.mnemonic) {
      throw new Error('Wallet not initialized');
    }

    // Simplified address generation (in production, use proper derivation)
    const seed = bip39.mnemonicToSeedSync(this.mnemonic);
    const index = this.addresses.length;
    const addressSeed = CryptoJS.SHA256(seed.toString('hex') + index.toString());
    
    // Generate testnet address with tBLK prefix
    const prefix = this.network === 'testnet' ? 'tBLK' : 'BLK';
    const address = prefix + addressSeed.toString(CryptoJS.enc.Hex).substring(0, 32);
    
    this.addresses.push(address);
    return address;
  }

  // Get current address
  getCurrentAddress(): string {
    if (this.addresses.length === 0) {
      return this.generateNewAddress();
    }
    return this.addresses[this.currentIndex];
  }

  // Get all addresses
  getAddresses(): string[] {
    return [...this.addresses];
  }

  // Get wallet configuration
  getConfig(): WalletConfig {
    return {
      mnemonic: this.mnemonic,
      addresses: [...this.addresses],
      currentAddressIndex: this.currentIndex,
      network: this.network,
    };
  }

  // Get balance for address
  async getBalance(address?: string): Promise<Balance> {
    const addr = address || this.getCurrentAddress();
    
    try {
      const response = await fetch(`${this.nodeUrl}/balance/${addr}`);
      if (!response.ok) {
        throw new Error('Failed to fetch balance');
      }
      
      const data = await response.json();
      return {
        confirmed: data.confirmed || 0,
        unconfirmed: data.unconfirmed || 0,
        total: (data.confirmed || 0) + (data.unconfirmed || 0),
      };
    } catch (error) {
      console.error('Error fetching balance:', error);
      return { confirmed: 0, unconfirmed: 0, total: 0 };
    }
  }

  // Get transaction history
  async getTransactions(address?: string): Promise<Transaction[]> {
    const addr = address || this.getCurrentAddress();
    
    try {
      const response = await fetch(`${this.nodeUrl}/transactions/${addr}`);
      if (!response.ok) {
        throw new Error('Failed to fetch transactions');
      }
      
      const data = await response.json();
      return data.transactions || [];
    } catch (error) {
      console.error('Error fetching transactions:', error);
      return [];
    }
  }

  // Send transaction
  async sendTransaction(request: TransactionRequest): Promise<string> {
    const fromAddress = this.getCurrentAddress();
    
    // In a real implementation, this would:
    // 1. Build transaction with inputs/outputs
    // 2. Sign with private key derived from mnemonic
    // 3. Broadcast to network
    
    const transaction = {
      from: fromAddress,
      to: request.to,
      amount: request.amount,
      fee: request.fee || this.calculateFee(request.amount),
    };
    
    try {
      const response = await fetch(`${this.nodeUrl}/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(transaction),
      });
      
      if (!response.ok) {
        throw new Error('Failed to send transaction');
      }
      
      const result = await response.json();
      return result.transaction_id;
    } catch (error) {
      console.error('Error sending transaction:', error);
      throw error;
    }
  }

  // Calculate transaction fee
  private calculateFee(amount: number): number {
    // Simple fee calculation: 0.1% of amount, minimum 0.001 BLK
    return Math.max(amount * 0.001, 0.001);
  }

  // Encrypt wallet for storage
  encryptWallet(password: string): string {
    const config = this.getConfig();
    return CryptoJS.AES.encrypt(JSON.stringify(config), password).toString();
  }

  // Decrypt wallet from storage
  static decryptWallet(encryptedData: string, password: string): WalletConfig {
    try {
      const decrypted = CryptoJS.AES.decrypt(encryptedData, password);
      const decryptedString = decrypted.toString(CryptoJS.enc.Utf8);
      return JSON.parse(decryptedString);
    } catch (error) {
      throw new Error('Invalid password or corrupted wallet data');
    }
  }
}

// Utility functions
export const formatBalance = (amount: number): string => {
  return (amount / 1000000).toFixed(6) + ' BLK';
};

export const formatAddress = (address: string): string => {
  if (address.length <= 16) return address;
  return `${address.substring(0, 8)}...${address.substring(address.length - 8)}`;
};

export const validateAddress = (address: string): boolean => {
  // Basic validation for BlackSilk addresses
  const testnetPattern = /^tBLK[1-9A-HJ-NP-Za-km-z]{24,60}$/;
  const mainnetPattern = /^BLK[1-9A-HJ-NP-Za-km-z]{24,60}$/;
  
  return testnetPattern.test(address) || mainnetPattern.test(address);
};
