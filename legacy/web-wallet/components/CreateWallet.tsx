import React, { useState } from 'react';
import { useWalletStore } from '../lib/store';
import { Eye, EyeOff, Copy } from 'lucide-react';

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
                {showMnemonic ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
              <button
                onClick={copyToClipboard}
                className="p-1 text-gray-500 hover:text-gray-700"
              >
                <Copy className="w-5 h-5" />
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
