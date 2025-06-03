'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import toast from 'react-hot-toast';

interface AdminStats {
  totalRequests: number;
  pendingRequests: number;
  completedRequests: number;
  failedRequests: number;
  totalTokensDistributed: number;
  uniqueAddresses: number;
  averageProcessingTime: number;
  queueSize: number;
  systemHealth: {
    status: string;
    database: boolean;
    blacksilkNode: boolean;
    memoryUsage: number;
    uptime: number;
  };
}

interface FaucetRequest {
  id: number;
  address: string;
  amount: number;
  status: string;
  transactionId: string;
  txHash?: string;
  createdAt: string;
  processedAt?: string;
  ipAddress: string;
}

interface BlacklistEntry {
  id: number;
  address: string;
  reason: string;
  createdAt: string;
}

export default function AdminDashboard() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [loginForm, setLoginForm] = useState({ username: '', password: '' });
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [requests, setRequests] = useState<FaucetRequest[]>([]);
  const [blacklist, setBlacklist] = useState<BlacklistEntry[]>([]);
  const [config, setConfig] = useState<any>(null);
  const router = useRouter();

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const response = await fetch('/api/admin/verify', {
        credentials: 'include'
      });
      
      if (response.ok) {
        setIsAuthenticated(true);
        loadDashboardData();
      }
    } catch (error) {
      console.error('Auth check failed:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await fetch('/api/admin/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(loginForm),
      });

      if (response.ok) {
        setIsAuthenticated(true);
        setLoginForm({ username: '', password: '' });
        toast.success('Login successful');
        loadDashboardData();
      } else {
        const data = await response.json();
        toast.error(data.message || 'Login failed');
      }
    } catch (error) {
      toast.error('Network error. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await fetch('/api/admin/logout', {
        method: 'POST',
        credentials: 'include'
      });
      setIsAuthenticated(false);
      toast.success('Logged out successfully');
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  const loadDashboardData = async () => {
    try {
      // Load stats
      const statsResponse = await fetch('/api/admin/stats', {
        credentials: 'include'
      });
      if (statsResponse.ok) {
        setStats(await statsResponse.json());
      }

      // Load recent requests
      const requestsResponse = await fetch('/api/admin/requests?limit=50', {
        credentials: 'include'
      });
      if (requestsResponse.ok) {
        setRequests(await requestsResponse.json());
      }

      // Load blacklist
      const blacklistResponse = await fetch('/api/admin/blacklist', {
        credentials: 'include'
      });
      if (blacklistResponse.ok) {
        setBlacklist(await blacklistResponse.json());
      }

      // Load config
      const configResponse = await fetch('/api/admin/config', {
        credentials: 'include'
      });
      if (configResponse.ok) {
        setConfig(await configResponse.json());
      }

    } catch (error) {
      console.error('Failed to load dashboard data:', error);
      toast.error('Failed to load dashboard data');
    }
  };

  const addToBlacklist = async (address: string, reason: string) => {
    try {
      const response = await fetch('/api/admin/blacklist', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({ address, reason }),
      });

      if (response.ok) {
        toast.success('Address added to blacklist');
        loadDashboardData();
      } else {
        const data = await response.json();
        toast.error(data.message || 'Failed to add to blacklist');
      }
    } catch (error) {
      toast.error('Network error');
    }
  };

  const removeFromBlacklist = async (id: number) => {
    try {
      const response = await fetch(`/api/admin/blacklist/${id}`, {
        method: 'DELETE',
        credentials: 'include'
      });

      if (response.ok) {
        toast.success('Address removed from blacklist');
        loadDashboardData();
      } else {
        toast.error('Failed to remove from blacklist');
      }
    } catch (error) {
      toast.error('Network error');
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="loading-spinner" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4">
        <div className="card w-full max-w-md">
          <h2 className="text-2xl font-bold text-white mb-6 text-center">
            Admin Login
          </h2>
          
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Username
              </label>
              <input
                type="text"
                value={loginForm.username}
                onChange={(e) => setLoginForm(prev => ({ ...prev, username: e.target.value }))}
                className="input-field"
                required
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Password
              </label>
              <input
                type="password"
                value={loginForm.password}
                onChange={(e) => setLoginForm(prev => ({ ...prev, password: e.target.value }))}
                className="input-field"
                required
              />
            </div>
            
            <button
              type="submit"
              disabled={isLoading}
              className="btn-primary w-full"
            >
              {isLoading ? 'Logging in...' : 'Login'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold text-white">
            BlackSilk Faucet Admin Dashboard
          </h1>
          <button
            onClick={handleLogout}
            className="btn-secondary"
          >
            Logout
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="flex space-x-1 mb-8">
          {[
            { id: 'overview', label: 'Overview' },
            { id: 'requests', label: 'Requests' },
            { id: 'blacklist', label: 'Blacklist' },
            { id: 'config', label: 'Configuration' },
            { id: 'logs', label: 'System Logs' }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                activeTab === tab.id
                  ? 'bg-purple-600 text-white'
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Overview Tab */}
        {activeTab === 'overview' && stats && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            {/* Stats Cards */}
            <div className="card">
              <h3 className="text-lg font-semibold text-white mb-2">Total Requests</h3>
              <p className="text-3xl font-bold text-purple-400">{stats.totalRequests}</p>
            </div>
            
            <div className="card">
              <h3 className="text-lg font-semibold text-white mb-2">Pending</h3>
              <p className="text-3xl font-bold text-yellow-400">{stats.pendingRequests}</p>
            </div>
            
            <div className="card">
              <h3 className="text-lg font-semibold text-white mb-2">Completed</h3>
              <p className="text-3xl font-bold text-green-400">{stats.completedRequests}</p>
            </div>
            
            <div className="card">
              <h3 className="text-lg font-semibold text-white mb-2">Failed</h3>
              <p className="text-3xl font-bold text-red-400">{stats.failedRequests}</p>
            </div>

            {/* System Health */}
            <div className="card lg:col-span-2">
              <h3 className="text-lg font-semibold text-white mb-4">System Health</h3>
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-gray-300">Overall Status:</span>
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                    stats.systemHealth.status === 'healthy' 
                      ? 'bg-green-400/10 text-green-400 border border-green-400/20'
                      : 'bg-red-400/10 text-red-400 border border-red-400/20'
                  }`}>
                    {stats.systemHealth.status}
                  </span>
                </div>
                
                <div className="flex justify-between items-center">
                  <span className="text-gray-300">Database:</span>
                  <span className={stats.systemHealth.database ? 'text-green-400' : 'text-red-400'}>
                    {stats.systemHealth.database ? 'Connected' : 'Disconnected'}
                  </span>
                </div>
                
                <div className="flex justify-between items-center">
                  <span className="text-gray-300">BlackSilk Node:</span>
                  <span className={stats.systemHealth.blacksilkNode ? 'text-green-400' : 'text-red-400'}>
                    {stats.systemHealth.blacksilkNode ? 'Connected' : 'Disconnected'}
                  </span>
                </div>
                
                <div className="flex justify-between items-center">
                  <span className="text-gray-300">Memory Usage:</span>
                  <span className="text-white">{stats.systemHealth.memoryUsage}%</span>
                </div>
                
                <div className="flex justify-between items-center">
                  <span className="text-gray-300">Uptime:</span>
                  <span className="text-white">{Math.floor(stats.systemHealth.uptime / 3600)}h</span>
                </div>
              </div>
            </div>

            {/* Quick Stats */}
            <div className="card lg:col-span-2">
              <h3 className="text-lg font-semibold text-white mb-4">Quick Stats</h3>
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-gray-300">Tokens Distributed:</span>
                  <span className="text-white font-semibold">{stats.totalTokensDistributed} tBLK</span>
                </div>
                
                <div className="flex justify-between items-center">
                  <span className="text-gray-300">Unique Addresses:</span>
                  <span className="text-white font-semibold">{stats.uniqueAddresses}</span>
                </div>
                
                <div className="flex justify-between items-center">
                  <span className="text-gray-300">Avg Processing Time:</span>
                  <span className="text-white font-semibold">{stats.averageProcessingTime}s</span>
                </div>
                
                <div className="flex justify-between items-center">
                  <span className="text-gray-300">Queue Size:</span>
                  <span className="text-white font-semibold">{stats.queueSize}</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Requests Tab */}
        {activeTab === 'requests' && (
          <div className="card">
            <h3 className="text-xl font-semibold text-white mb-6">Recent Requests</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 px-4 text-gray-300">Address</th>
                    <th className="text-left py-3 px-4 text-gray-300">Amount</th>
                    <th className="text-left py-3 px-4 text-gray-300">Status</th>
                    <th className="text-left py-3 px-4 text-gray-300">TX Hash</th>
                    <th className="text-left py-3 px-4 text-gray-300">Created</th>
                    <th className="text-left py-3 px-4 text-gray-300">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {requests.map((request) => (
                    <tr key={request.id} className="border-b border-gray-800">
                      <td className="py-3 px-4">
                        <code className="text-purple-400 text-xs">
                          {request.address}
                        </code>
                      </td>
                      <td className="py-3 px-4 text-white">{request.amount} tBLK</td>
                      <td className="py-3 px-4">
                        <span className={`status-${request.status}`}>
                          {request.status}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        {request.txHash ? (
                          <code className="text-purple-400 text-xs">
                            {request.txHash.substring(0, 10)}...
                          </code>
                        ) : (
                          <span className="text-gray-500">-</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-gray-300">
                        {new Date(request.createdAt).toLocaleDateString()}
                      </td>
                      <td className="py-3 px-4">
                        <button
                          onClick={() => addToBlacklist(request.address, 'Manual blacklist')}
                          className="text-red-400 hover:text-red-300 text-xs"
                        >
                          Blacklist
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Blacklist Tab */}
        {activeTab === 'blacklist' && (
          <div className="space-y-6">
            <div className="card">
              <h3 className="text-xl font-semibold text-white mb-4">Add to Blacklist</h3>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const formData = new FormData(e.target as HTMLFormElement);
                  const address = formData.get('address') as string;
                  const reason = formData.get('reason') as string;
                  addToBlacklist(address, reason);
                  (e.target as HTMLFormElement).reset();
                }}
                className="flex gap-4"
              >
                <input
                  name="address"
                  type="text"
                  placeholder="BlackSilk address"
                  className="input-field flex-1"
                  required
                />
                <input
                  name="reason"
                  type="text"
                  placeholder="Reason"
                  className="input-field flex-1"
                  required
                />
                <button type="submit" className="btn-primary">
                  Add
                </button>
              </form>
            </div>

            <div className="card">
              <h3 className="text-xl font-semibold text-white mb-6">Blacklisted Addresses</h3>
              <div className="space-y-4">
                {blacklist.map((entry) => (
                  <div
                    key={entry.id}
                    className="flex justify-between items-center p-4 bg-gray-800/50 rounded-lg"
                  >
                    <div>
                      <code className="text-purple-400">{entry.address}</code>
                      <p className="text-sm text-gray-400 mt-1">{entry.reason}</p>
                      <p className="text-xs text-gray-500">
                        Added: {new Date(entry.createdAt).toLocaleDateString()}
                      </p>
                    </div>
                    <button
                      onClick={() => removeFromBlacklist(entry.id)}
                      className="text-red-400 hover:text-red-300 text-sm"
                    >
                      Remove
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Config Tab */}
        {activeTab === 'config' && config && (
          <div className="card">
            <h3 className="text-xl font-semibold text-white mb-6">Configuration</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {Object.entries(config).map(([key, value]) => (
                <div key={key} className="space-y-2">
                  <label className="block text-sm font-medium text-gray-300">
                    {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                  </label>
                  <input
                    type="text"
                    value={String(value)}
                    className="input-field"
                    readOnly
                  />
                </div>
              ))}
            </div>
          </div>
        )}

        {/* System Logs Tab */}
        {activeTab === 'logs' && (
          <div className="card">
            <h3 className="text-xl font-semibold text-white mb-6">System Logs</h3>
            <div className="bg-gray-900 p-4 rounded-lg max-h-96 overflow-y-auto">
              <pre className="text-green-400 text-sm font-mono">
                {/* Logs would be loaded from API */}
                [2024-01-15 10:30:15] INFO: Faucet service started
                [2024-01-15 10:30:16] INFO: Database connected successfully
                [2024-01-15 10:30:17] INFO: BlackSilk node connection established
                [2024-01-15 10:35:22] INFO: Token request processed: 0x123...
                [2024-01-15 10:40:18] WARN: Rate limit exceeded for IP: 192.168.1.100
                [2024-01-15 10:45:30] INFO: Token request processed: 0x456...
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
