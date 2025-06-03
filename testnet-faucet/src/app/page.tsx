'use client';

import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import { FaucetRequest, FaucetResponse, StatusResponse } from '../types';

export default function Home() {
  const [address, setAddress] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [lastRequest, setLastRequest] = useState<FaucetResponse | null>(null);
  const [stats, setStats] = useState<any>(null);

  // Load stats on component mount
  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await fetch('/api/stats');
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    }
  };

  const validateAddress = (addr: string): boolean => {
    // BlackSilk address validation - must start with BLK and be 26-42 characters
    if (!addr || addr.length < 26 || addr.length > 42) {
      return false;
    }
    // Must start with BLK prefix
    if (!addr.startsWith('BLK')) {
      return false;
    }
    // Check if it contains only valid base58 characters
    if (!addr.match(/^BLK[1-9A-HJ-NP-Za-km-z]+$/)) {
      return false;
    }
    return true;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!address.trim()) {
      toast.error('Please enter a BlackSilk address');
      return;
    }

    if (!validateAddress(address.trim())) {
      toast.error('Please enter a valid BlackSilk address (must start with BLK)');
      return;
    }

    setIsLoading(true);

    try {
      const requestData: FaucetRequest = {
        address: address.trim(),
        amount: 10, // Default 10 BSK tokens
      };

      const response = await fetch('/api/faucet', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestData),
      });

      const data: FaucetResponse = await response.json();

      if (response.ok) {
        setLastRequest(data);
        toast.success('Tokens requested successfully! Transaction pending...');
        setAddress('');
        fetchStats(); // Refresh stats
      } else {
        toast.error(data.message || 'Failed to request tokens');
      }
    } catch (error) {
      console.error('Error requesting tokens:', error);
      toast.error('Network error. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const checkStatus = async (transactionId: string) => {
    try {
      const response = await fetch(`/api/status/${transactionId}`);
      if (response.ok) {
        const data: StatusResponse = await response.json();
        
        if (data.status === 'completed') {
          toast.success('Transaction completed successfully!');
          setLastRequest(prev => prev ? { ...prev, status: 'completed' } : null);
        } else if (data.status === 'failed') {
          toast.error('Transaction failed. Please try again.');
          setLastRequest(prev => prev ? { ...prev, status: 'failed' } : null);
        }
      }
    } catch (error) {
      console.error('Error checking status:', error);
    }
  };

  return (
    <main className="min-h-screen flex items-center justify-center p-4">
      <div className="w-full max-w-4xl mx-auto">
        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="text-5xl md:text-6xl font-bold mb-6">
            <span className="gradient-text">BlackSilk</span>
            <br />
            <span className="text-white">Testnet Faucet</span>
          </h1>
          <p className="text-xl text-gray-300 max-w-2xl mx-auto">
            Get free BlackSilk testnet tokens for development and testing. 
            Perfect for developers building on the BlackSilk blockchain.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Faucet Form */}
          <div className="lg:col-span-2 space-y-6">
            <div className="card">
              <h2 className="text-2xl font-semibold text-white mb-6">
                Request Testnet Tokens
              </h2>
              
              <form onSubmit={handleSubmit} className="space-y-6">
                <div>
                  <label htmlFor="address" className="block text-sm font-medium text-gray-300 mb-2">
                    BlackSilk Address
                  </label>
                  <input
                    type="text"
                    id="address"
                    value={address}
                    onChange={(e) => setAddress(e.target.value)}
                    placeholder="Enter your BlackSilk testnet address"
                    className="input-field"
                    disabled={isLoading}
                  />
                  <p className="text-sm text-gray-400 mt-2">
                    You will receive 10 BSK testnet tokens
                  </p>
                </div>

                <button
                  type="submit"
                  disabled={isLoading}
                  className="btn-primary w-full flex items-center justify-center"
                >
                  {isLoading ? (
                    <>
                      <div className="loading-spinner mr-2" />
                      Processing...
                    </>
                  ) : (
                    'Request Tokens'
                  )}
                </button>
              </form>
            </div>

            {/* Last Request Status */}
            {lastRequest && (
              <div className="card animate-fadeIn">
                <h3 className="text-lg font-semibold text-white mb-4">
                  Latest Request
                </h3>
                
                <div className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-gray-300">Transaction ID:</span>
                    <code className="text-purple-400 text-sm">
                      {lastRequest.transactionId}
                    </code>
                  </div>
                  
                  <div className="flex justify-between items-center">
                    <span className="text-gray-300">Amount:</span>
                    <span className="text-white font-semibold">
                      {lastRequest.amount} BSK
                    </span>
                  </div>
                  
                  <div className="flex justify-between items-center">
                    <span className="text-gray-300">Status:</span>
                    <span className={`status-${lastRequest.status}`}>
                      {lastRequest.status.charAt(0).toUpperCase() + lastRequest.status.slice(1)}
                    </span>
                  </div>

                  {lastRequest.txHash && (
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300">TX Hash:</span>
                      <code className="text-purple-400 text-sm truncate ml-2">
                        {lastRequest.txHash}
                      </code>
                    </div>
                  )}
                </div>

                {lastRequest.status === 'pending' && (
                  <button
                    onClick={() => checkStatus(lastRequest.transactionId)}
                    className="btn-secondary w-full mt-4"
                  >
                    Check Status
                  </button>
                )}
              </div>
            )}
          </div>

          {/* Sidebar - Stats and Info */}
          <div className="space-y-6">
            {/* Network Stats */}
            {stats && (
              <div className="card">
                <h3 className="text-lg font-semibold text-white mb-4">
                  Network Stats
                </h3>
                
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-300">Total Requests:</span>
                    <span className="text-white font-semibold">
                      {stats.totalRequests?.toLocaleString() || 0}
                    </span>
                  </div>
                  
                  <div className="flex justify-between">
                    <span className="text-gray-300">Tokens Distributed:</span>
                    <span className="text-white font-semibold">
                      {stats.totalTokens?.toLocaleString() || 0} BSK
                    </span>
                  </div>
                  
                  <div className="flex justify-between">
                    <span className="text-gray-300">Success Rate:</span>
                    <span className="text-green-400 font-semibold">
                      {stats.successRate || 0}%
                    </span>
                  </div>
                  
                  <div className="flex justify-between">
                    <span className="text-gray-300">Queue Size:</span>
                    <span className="text-yellow-400 font-semibold">
                      {stats.queueSize || 0}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Info Panel */}
            <div className="card">
              <h3 className="text-lg font-semibold text-white mb-4">
                Important Information
              </h3>
              
              <div className="space-y-4 text-sm text-gray-300">
                <div>
                  <h4 className="font-medium text-white mb-2">Rate Limits</h4>
                  <p>Each address can request tokens once per 24 hours.</p>
                </div>
                
                <div>
                  <h4 className="font-medium text-white mb-2">Token Amount</h4>
                  <p>Each request provides 10 BSK testnet tokens.</p>
                </div>
                
                <div>
                  <h4 className="font-medium text-white mb-2">Processing Time</h4>
                  <p>Requests are typically processed within 1-2 minutes.</p>
                </div>
                
                <div>
                  <h4 className="font-medium text-white mb-2">Network</h4>
                  <p>These are testnet tokens only. They have no real value.</p>
                </div>
              </div>
            </div>

            {/* Links */}
            <div className="card">
              <h3 className="text-lg font-semibold text-white mb-4">
                Useful Links
              </h3>
              
              <div className="space-y-3">
                <a
                  href="https://github.com/BlackSilk-Blockchain"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block text-purple-400 hover:text-purple-300 transition-colors"
                >
                  📚 Documentation
                </a>
                
                <a
                  href="https://github.com/BlackSilk-Blockchain"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block text-purple-400 hover:text-purple-300 transition-colors"
                >
                  🔗 GitHub Repository
                </a>
                
                <a
                  href="#"
                  className="block text-purple-400 hover:text-purple-300 transition-colors"
                >
                  🌐 Block Explorer
                </a>
                
                <a
                  href="#"
                  className="block text-purple-400 hover:text-purple-300 transition-colors"
                >
                  💬 Discord Community
                </a>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="text-center mt-12 text-gray-400 text-sm">
          <p>
            BlackSilk Testnet Faucet - Built for developers, by developers
          </p>
          <p className="mt-2">
            Need help? Join our{' '}
            <a href="#" className="text-purple-400 hover:text-purple-300">
              Discord community
            </a>
          </p>
        </div>
      </div>
    </main>
  );
}
