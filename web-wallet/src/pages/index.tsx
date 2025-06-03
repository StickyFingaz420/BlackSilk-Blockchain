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
