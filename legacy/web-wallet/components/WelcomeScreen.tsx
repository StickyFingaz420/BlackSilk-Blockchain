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
