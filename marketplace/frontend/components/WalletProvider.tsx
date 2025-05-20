import React, { createContext, useContext, useState, useEffect } from 'react';
import { connectWallet, getCurrentWallet } from '../utils/wallet';

interface WalletContextProps {
  address: string | null;
  connect: () => Promise<void>;
  disconnect: () => void;
}

const WalletContext = createContext<WalletContextProps>({
  address: null,
  connect: async () => {},
  disconnect: () => {},
});

export const useWallet = () => useContext(WalletContext);

export const WalletProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [address, setAddress] = useState<string | null>(null);

  useEffect(() => {
    getCurrentWallet().then(setAddress);
    if (typeof window !== 'undefined' && (window as any).ethereum) {
      (window as any).ethereum.on('accountsChanged', (accounts: string[]) => {
        setAddress(accounts[0] || null);
      });
    }
  }, []);

  const connect = async () => {
    const addr = await connectWallet();
    setAddress(addr);
  };

  const disconnect = () => {
    setAddress(null);
  };

  return (
    <WalletContext.Provider value={{ address, connect, disconnect }}>
      {children}
    </WalletContext.Provider>
  );
}; 