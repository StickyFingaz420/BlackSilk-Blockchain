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
