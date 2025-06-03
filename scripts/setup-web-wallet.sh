#!/bin/bash

# BlackSilk Web Wallet Setup Script
# Creates a modern web-based wallet with mnemonic support

set -e

echo "💳 BlackSilk Web Wallet Setup"
echo "============================="

# Configuration
WALLET_PORT=${WALLET_PORT:-3001}
WALLET_NAME="blacksilk-web-wallet"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Create web wallet directory structure
create_wallet_structure() {
    log "Creating web wallet directory structure..."
    
    mkdir -p web-wallet/{src,public,components,pages,lib,styles,types}
    cd web-wallet
    
    # Initialize package.json
    cat > package.json << 'EOF'
{
  "name": "blacksilk-web-wallet",
  "version": "1.0.0",
  "description": "BlackSilk Web Wallet - Privacy-first blockchain wallet",
  "main": "index.js",
  "scripts": {
    "dev": "next dev -p 3001",
    "build": "next build",
    "start": "next start -p 3001",
    "lint": "next lint",
    "type-check": "tsc --noEmit"
  },
  "dependencies": {
    "next": "^14.0.0",
    "react": "^18.0.0",
    "react-dom": "^18.0.0",
    "typescript": "^5.0.0",
    "@types/react": "^18.0.0",
    "@types/react-dom": "^18.0.0",
    "@types/node": "^20.0.0",
    "tailwindcss": "^3.3.0",
    "autoprefixer": "^10.4.0",
    "postcss": "^8.4.0",
    "@headlessui/react": "^1.7.0",
    "@heroicons/react": "^2.0.0",
    "bip39": "^3.1.0",
    "crypto-js": "^4.2.0",
    "qrcode": "^1.5.0",
    "react-qr-scanner": "^1.0.0",
    "zustand": "^4.4.0",
    "axios": "^1.6.0",
    "react-hot-toast": "^2.4.0"
  },
  "devDependencies": {
    "eslint": "^8.0.0",
    "eslint-config-next": "^14.0.0",
    "@types/crypto-js": "^4.2.0",
    "@types/qrcode": "^1.5.0"
  },
  "keywords": ["blockchain", "wallet", "privacy", "cryptocurrency"],
  "author": "BlackSilk Team",
  "license": "MIT"
}
EOF

    log "✅ Package.json created"
}

# Create Next.js configuration
create_nextjs_config() {
    log "Creating Next.js configuration..."
    
    cat > next.config.js << 'EOF'
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  env: {
    NEXT_PUBLIC_NODE_URL: process.env.NEXT_PUBLIC_NODE_URL || 'http://localhost:19333',
    NEXT_PUBLIC_NETWORK: process.env.NEXT_PUBLIC_NETWORK || 'testnet',
  },
  webpack: (config, { isServer }) => {
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
        net: false,
        tls: false,
        crypto: require.resolve('crypto-browserify'),
        stream: require.resolve('stream-browserify'),
        buffer: require.resolve('buffer'),
      };
    }
    return config;
  },
}

module.exports = nextConfig
EOF

    # Create TypeScript config
    cat > tsconfig.json << 'EOF'
{
  "compilerOptions": {
    "target": "es5",
    "lib": ["dom", "dom.iterable", "es6"],
    "allowJs": true,
    "skipLibCheck": true,
    "strict": true,
    "forceConsistentCasingInFileNames": true,
    "noEmit": true,
    "esModuleInterop": true,
    "module": "esnext",
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "preserve",
    "incremental": true,
    "plugins": [
      {
        "name": "next"
      }
    ],
    "paths": {
      "@/*": ["./src/*"],
      "@/components/*": ["./components/*"],
      "@/lib/*": ["./lib/*"],
      "@/types/*": ["./types/*"]
    }
  },
  "include": ["next-env.d.ts", "**/*.ts", "**/*.tsx", ".next/types/**/*.ts"],
  "exclude": ["node_modules"]
}
EOF

    # Create Tailwind config
    cat > tailwind.config.js << 'EOF'
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#f0f9ff',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
        },
        dark: {
          900: '#111827',
          800: '#1f2937',
          700: '#374151',
        }
      },
    },
  },
  plugins: [],
}
EOF

    # Create PostCSS config
    cat > postcss.config.js << 'EOF'
module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
EOF

    log "✅ Configuration files created"
}

# Create wallet library functions
create_wallet_lib() {
    log "Creating wallet library functions..."
    
    mkdir -p lib
    
    # Wallet service
    cat > lib/wallet.ts << 'EOF'
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
  private mnemonic: string;
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
    const address = prefix + addressSeed.toString(CryptoJS.enc.Base58).substring(0, 32);
    
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
EOF

    # State management
    cat > lib/store.ts << 'EOF'
import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { BlackSilkWallet, WalletConfig, Balance, Transaction } from './wallet';

interface WalletState {
  // Wallet state
  wallet: BlackSilkWallet | null;
  isUnlocked: boolean;
  config: WalletConfig | null;
  
  // UI state
  isLoading: boolean;
  currentView: 'welcome' | 'create' | 'restore' | 'unlock' | 'dashboard';
  
  // Data
  balance: Balance;
  transactions: Transaction[];
  
  // Actions
  initializeWallet: () => void;
  createWallet: () => WalletConfig;
  restoreWallet: (mnemonic: string) => WalletConfig;
  unlockWallet: (password: string) => void;
  lockWallet: () => void;
  updateBalance: () => Promise<void>;
  updateTransactions: () => Promise<void>;
  sendTransaction: (to: string, amount: number) => Promise<string>;
  setView: (view: string) => void;
  setLoading: (loading: boolean) => void;
}

export const useWalletStore = create<WalletState>()(
  persist(
    (set, get) => ({
      // Initial state
      wallet: null,
      isUnlocked: false,
      config: null,
      isLoading: false,
      currentView: 'welcome',
      balance: { confirmed: 0, unconfirmed: 0, total: 0 },
      transactions: [],

      // Initialize wallet
      initializeWallet: () => {
        const wallet = new BlackSilkWallet('testnet');
        set({ wallet });
      },

      // Create new wallet
      createWallet: () => {
        const { wallet } = get();
        if (!wallet) throw new Error('Wallet not initialized');
        
        const config = wallet.generateWallet();
        set({ config, isUnlocked: true, currentView: 'dashboard' });
        return config;
      },

      // Restore wallet from mnemonic
      restoreWallet: (mnemonic: string) => {
        const { wallet } = get();
        if (!wallet) throw new Error('Wallet not initialized');
        
        const config = wallet.restoreFromMnemonic(mnemonic);
        set({ config, isUnlocked: true, currentView: 'dashboard' });
        return config;
      },

      // Unlock existing wallet
      unlockWallet: (password: string) => {
        const encryptedData = localStorage.getItem('blacksilk-wallet-encrypted');
        if (!encryptedData) throw new Error('No wallet found');
        
        try {
          const config = BlackSilkWallet.decryptWallet(encryptedData, password);
          const wallet = new BlackSilkWallet(config.network);
          
          // Restore wallet state
          wallet.restoreFromMnemonic(config.mnemonic);
          
          set({ 
            wallet, 
            config, 
            isUnlocked: true, 
            currentView: 'dashboard' 
          });
        } catch (error) {
          throw new Error('Invalid password');
        }
      },

      // Lock wallet
      lockWallet: () => {
        set({ 
          isUnlocked: false, 
          currentView: 'unlock',
          balance: { confirmed: 0, unconfirmed: 0, total: 0 },
          transactions: [] 
        });
      },

      // Update balance
      updateBalance: async () => {
        const { wallet } = get();
        if (!wallet) return;
        
        try {
          set({ isLoading: true });
          const balance = await wallet.getBalance();
          set({ balance });
        } catch (error) {
          console.error('Failed to update balance:', error);
        } finally {
          set({ isLoading: false });
        }
      },

      // Update transactions
      updateTransactions: async () => {
        const { wallet } = get();
        if (!wallet) return;
        
        try {
          const transactions = await wallet.getTransactions();
          set({ transactions });
        } catch (error) {
          console.error('Failed to update transactions:', error);
        }
      },

      // Send transaction
      sendTransaction: async (to: string, amount: number) => {
        const { wallet } = get();
        if (!wallet) throw new Error('Wallet not initialized');
        
        set({ isLoading: true });
        try {
          const txId = await wallet.sendTransaction({ to, amount });
          
          // Refresh balance and transactions
          await get().updateBalance();
          await get().updateTransactions();
          
          return txId;
        } finally {
          set({ isLoading: false });
        }
      },

      // UI actions
      setView: (currentView: any) => set({ currentView }),
      setLoading: (isLoading: boolean) => set({ isLoading }),
    }),
    {
      name: 'blacksilk-wallet-state',
      partialize: (state) => ({
        // Only persist non-sensitive UI state
        currentView: state.currentView,
      }),
    }
  )
);
EOF

    log "✅ Wallet library created"
}

# Create React components
create_components() {
    log "Creating React components..."
    
    mkdir -p components
    
    # Main layout component
    cat > components/Layout.tsx << 'EOF'
import React from 'react';
import Head from 'next/head';

interface LayoutProps {
  children: React.ReactNode;
  title?: string;
}

export default function Layout({ children, title = 'BlackSilk Wallet' }: LayoutProps) {
  return (
    <>
      <Head>
        <title>{title}</title>
        <meta name="description" content="BlackSilk Web Wallet - Privacy-first blockchain wallet" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.ico" />
      </Head>
      
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-gray-900">
        <main className="container mx-auto px-4 py-8">
          {children}
        </main>
      </div>
    </>
  );
}
EOF

    # Welcome screen component
    cat > components/WelcomeScreen.tsx << 'EOF'
import React from 'react';
import { useWalletStore } from '../lib/store';

export default function WelcomeScreen() {
  const { setView } = useWalletStore();

  return (
    <div className="max-w-md mx-auto">
      <div className="bg-white rounded-lg shadow-xl p-8">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            BlackSilk Wallet
          </h1>
          <p className="text-gray-600">
            Privacy-first blockchain wallet for BlackSilk network
          </p>
        </div>

        <div className="space-y-4">
          <button
            onClick={() => setView('create')}
            className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg hover:bg-blue-700 transition-colors font-medium"
          >
            Create New Wallet
          </button>
          
          <button
            onClick={() => setView('restore')}
            className="w-full bg-gray-200 text-gray-900 py-3 px-4 rounded-lg hover:bg-gray-300 transition-colors font-medium"
          >
            Restore Existing Wallet
          </button>
        </div>

        <div className="mt-8 text-center">
          <p className="text-sm text-gray-500">
            Secure • Private • Decentralized
          </p>
        </div>
      </div>
    </div>
  );
}
EOF

    # Create wallet component
    cat > components/CreateWallet.tsx << 'EOF'
import React, { useState } from 'react';
import { useWalletStore } from '../lib/store';
import { EyeIcon, EyeSlashIcon, ClipboardIcon } from '@heroicons/react/24/outline';

export default function CreateWallet() {
  const { createWallet, setView } = useWalletStore();
  const [step, setStep] = useState(1);
  const [mnemonic, setMnemonic] = useState('');
  const [showMnemonic, setShowMnemonic] = useState(false);
  const [confirmed, setConfirmed] = useState(false);

  const handleCreateWallet = () => {
    const config = createWallet();
    setMnemonic(config.mnemonic);
    setStep(2);
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(mnemonic);
    // You could add a toast notification here
  };

  if (step === 1) {
    return (
      <div className="max-w-md mx-auto">
        <div className="bg-white rounded-lg shadow-xl p-8">
          <h2 className="text-2xl font-bold text-gray-900 mb-6">Create New Wallet</h2>
          
          <div className="mb-6">
            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
              <h3 className="font-medium text-yellow-800 mb-2">Important Security Notice</h3>
              <ul className="text-sm text-yellow-700 space-y-1">
                <li>• Your recovery phrase is the ONLY way to restore your wallet</li>
                <li>• Write it down and store it safely offline</li>
                <li>• Never share it with anyone</li>
                <li>• BlackSilk Team will never ask for your recovery phrase</li>
              </ul>
            </div>
          </div>

          <button
            onClick={handleCreateWallet}
            className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg hover:bg-blue-700 transition-colors font-medium mb-4"
          >
            Generate Recovery Phrase
          </button>
          
          <button
            onClick={() => setView('welcome')}
            className="w-full bg-gray-200 text-gray-900 py-2 px-4 rounded-lg hover:bg-gray-300 transition-colors"
          >
            Back
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-md mx-auto">
      <div className="bg-white rounded-lg shadow-xl p-8">
        <h2 className="text-2xl font-bold text-gray-900 mb-6">Your Recovery Phrase</h2>
        
        <div className="mb-6">
          <div className="bg-gray-50 border-2 border-dashed border-gray-300 rounded-lg p-4 relative">
            <div className={`${showMnemonic ? 'block' : 'blur-sm'} font-mono text-sm leading-relaxed`}>
              {mnemonic.split(' ').map((word, index) => (
                <span key={index} className="inline-block mr-2 mb-1 bg-white px-2 py-1 rounded">
                  <span className="text-gray-500 text-xs">{index + 1}.</span> {word}
                </span>
              ))}
            </div>
            
            <div className="absolute top-2 right-2 flex space-x-2">
              <button
                onClick={() => setShowMnemonic(!showMnemonic)}
                className="p-1 text-gray-500 hover:text-gray-700"
              >
                {showMnemonic ? <EyeSlashIcon className="w-5 h-5" /> : <EyeIcon className="w-5 h-5" />}
              </button>
              <button
                onClick={copyToClipboard}
                className="p-1 text-gray-500 hover:text-gray-700"
              >
                <ClipboardIcon className="w-5 h-5" />
              </button>
            </div>
          </div>
        </div>

        <div className="mb-6">
          <label className="flex items-center">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
              className="mr-2"
            />
            <span className="text-sm text-gray-600">
              I have written down my recovery phrase and stored it safely
            </span>
          </label>
        </div>

        <button
          onClick={() => setView('dashboard')}
          disabled={!confirmed}
          className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg hover:bg-blue-700 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Continue to Wallet
        </button>
      </div>
    </div>
  );
}
EOF

    log "✅ React components created"
}

# Create main pages
create_pages() {
    log "Creating main application pages..."
    
    mkdir -p src/pages
    
    # Create main index page
    cat > src/pages/index.tsx << 'EOF'
import React, { useEffect } from 'react';
import Layout from '../../components/Layout';
import WelcomeScreen from '../../components/WelcomeScreen';
import CreateWallet from '../../components/CreateWallet';
import { useWalletStore } from '../lib/store';

export default function Home() {
  const { wallet, currentView, initializeWallet } = useWalletStore();

  useEffect(() => {
    if (!wallet) {
      initializeWallet();
    }
  }, [wallet, initializeWallet]);

  const renderCurrentView = () => {
    switch (currentView) {
      case 'create':
        return <CreateWallet />;
      case 'restore':
        return <div>Restore wallet component</div>;
      case 'unlock':
        return <div>Unlock wallet component</div>;
      case 'dashboard':
        return <div>Dashboard component</div>;
      default:
        return <WelcomeScreen />;
    }
  };

  return (
    <Layout title="BlackSilk Web Wallet">
      {renderCurrentView()}
    </Layout>
  );
}
EOF

    # Create global styles
    mkdir -p src/styles
    cat > src/styles/globals.css << 'EOF'
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  html {
    font-family: system-ui, sans-serif;
  }
}

@layer components {
  .btn-primary {
    @apply bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors;
  }
  
  .btn-secondary {
    @apply bg-gray-200 text-gray-900 px-4 py-2 rounded-lg hover:bg-gray-300 transition-colors;
  }
  
  .card {
    @apply bg-white rounded-lg shadow-lg p-6;
  }
}
EOF

    # Create _app.tsx
    cat > src/pages/_app.tsx << 'EOF'
import type { AppProps } from 'next/app';
import '../styles/globals.css';

export default function App({ Component, pageProps }: AppProps) {
  return <Component {...pageProps} />;
}
EOF

    log "✅ Main pages created"
}

# Main function
main() {
    log "Starting BlackSilk Web Wallet setup..."
    
    cd /workspaces/BlackSilk-Blockchain
    
    create_wallet_structure
    create_nextjs_config
    create_wallet_lib
    create_components
    create_pages
    
    # Install dependencies
    log "Installing dependencies..."
    cd web-wallet
    npm install
    
    log "🎉 BlackSilk Web Wallet setup completed!"
    log ""
    log "📋 Next Steps:"
    log "1. cd web-wallet"
    log "2. npm run dev"
    log "3. Open http://localhost:3001"
    log ""
    log "🔧 Development Commands:"
    log "   npm run dev     - Start development server"
    log "   npm run build   - Build for production"
    log "   npm run lint    - Run linting"
}

# Execute main function
main "$@"
