import { useState, useEffect } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { OrderTracking, NodeStatus, PrivacyIndicator, ShoppingCart } from '../components';
import { useAuth, useOrders, useBalance } from '../hooks';
import { Order, Product } from '../types';

const DashboardPage = () => {
  const { user, logout } = useAuth();
  const { balance } = useBalance();
  const [activeTab, setActiveTab] = useState<'orders' | 'selling' | 'settings'>('orders');
  const [orders, setOrders] = useState<Order[]>([]);
  const [sellingProducts, setSellingProducts] = useState<Product[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (user) {
      loadDashboardData();
    }
  }, [user]);

  const loadDashboardData = async () => {
    setLoading(true);
    try {
      // Mock data - replace with actual API calls
      const mockOrders: Order[] = [
        {
          id: 'order_1',
          buyer: user?.id || '',
          seller: 'vendor123',
          items: [
            {
              productId: 'prod_1',
              productTitle: 'Premium VPN Service',
              quantity: 1,
              price: 0.150,
              seller: 'vendor123'
            }
          ],
          totalAmount: 0.150,
          escrowAddress: 'BLK1234567890abcdef',
          escrowStatus: 'funded',
          status: 'Paid',
          createdAt: Date.now() / 1000 - 86400,
          disputeDeadline: Date.now() / 1000 + 604800
        },
        {
          id: 'order_2',
          buyer: user?.id || '',
          seller: 'vendor456',
          items: [
            {
              productId: 'prod_2',
              productTitle: 'Cryptocurrency Course Bundle',
              quantity: 1,
              price: 0.075,
              seller: 'vendor456'
            }
          ],
          totalAmount: 0.075,
          escrowAddress: 'BLK0987654321fedcba',
          escrowStatus: 'completed',
          status: 'Completed',
          createdAt: Date.now() / 1000 - 172800
        }
      ];

      const mockSellingProducts: Product[] = [
        {
          id: 'my_prod_1',
          seller: user?.id || '',
          title: 'Security Audit Service',
          description: 'Professional security audit for smart contracts and web applications.',
          category: 'services',
          price: 0.500,
          stock: 10,
          rating: 4.9,
          createdAt: Date.now() / 1000 - 259200,
          isActive: true,
          escrowRequired: true
        }
      ];

      setOrders(mockOrders);
      setSellingProducts(mockSellingProducts);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleOrderAction = async (action: string, orderId: string) => {
    console.log(`${action} action for order ${orderId}`);
    // Implement order actions (pay, confirm, dispute)
    alert(`${action} action initiated for order ${orderId}`);
  };

  const formatPrice = (price: number) => {
    return `${price.toFixed(3)} BLK`;
  };

  const formatDate = (timestamp: number) => {
    return new Date(timestamp * 1000).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  if (!user) {
    return (
      <div className="min-h-screen bg-black text-white flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl text-amber-300 mb-4">Access Required</h1>
          <p className="text-gray-400 mb-6">Please access your wallet to view your dashboard.</p>
          <Link href="/login">
            <span className="bg-amber-900/50 hover:bg-amber-800/50 text-amber-300 px-6 py-3 rounded-lg font-semibold">
              Access Wallet
            </span>
          </Link>
        </div>
      </div>
    );
  }

  return (
    <>
      <Head>
        <title>Dashboard - BlackSilk Marketplace</title>
        <meta name="description" content="Manage your orders, listings, and account on BlackSilk Marketplace" />
      </Head>

      <div className="min-h-screen bg-black text-white">
        {/* Header */}
        <header className="border-b border-amber-800/30 bg-black/50 backdrop-blur-sm sticky top-0 z-40">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center py-4">
              <Link href="/">
                <div className="flex items-center space-x-3 cursor-pointer">
                  <div className="text-2xl">🕸️</div>
                  <span className="text-xl font-bold text-amber-300">BlackSilk</span>
                </div>
              </Link>

              <nav className="hidden md:flex space-x-8">
                <Link href="/category/digital">
                  <span className="text-gray-300 hover:text-amber-300 transition-colors">Digital</span>
                </Link>
                <Link href="/category/services">
                  <span className="text-gray-300 hover:text-amber-300 transition-colors">Services</span>
                </Link>
                <Link href="/category/physical">
                  <span className="text-gray-300 hover:text-amber-300 transition-colors">Physical</span>
                </Link>
              </nav>

              <div className="flex items-center space-x-4">
                <Link href="/sell">
                  <span className="bg-amber-900/50 hover:bg-amber-800/50 text-amber-300 px-4 py-2 rounded-lg">Sell</span>
                </Link>
                <ShoppingCart />
                <button
                  onClick={logout}
                  className="text-red-400 hover:text-red-300"
                >
                  Logout
                </button>
              </div>
            </div>
          </div>
        </header>

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
            {/* Sidebar */}
            <div className="space-y-6">
              {/* User Info */}
              <div className="bg-black/40 border border-amber-800/30 rounded-lg p-6">
                <h2 className="text-amber-300 text-lg font-semibold mb-4">Account</h2>
                <div className="space-y-3 text-sm">
                  <div>
                    <div className="text-gray-400">Address:</div>
                    <div className="text-amber-300 font-mono text-xs break-all">
                      {user.id}
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-400">Member Since:</div>
                    <div className="text-amber-300">
                      {formatDate(parseInt(user.created_at))}
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-400">Account Type:</div>
                    <div className="text-amber-300">
                      {user.is_vendor ? 'Vendor' : 'Buyer'}
                    </div>
                  </div>
                </div>
              </div>

              {/* Balance */}
              <div className="bg-black/40 border border-amber-800/30 rounded-lg p-6">
                <h3 className="text-amber-300 font-semibold mb-4">Wallet Balance</h3>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Available:</span>
                    <span className="text-green-400 font-semibold">
                      {balance ? formatPrice(balance.confirmed) : '0.000 BLK'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Pending:</span>
                    <span className="text-yellow-400">
                      {balance ? formatPrice(balance.unconfirmed) : '0.000 BLK'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">In Escrow:</span>
                    <span className="text-blue-400">
                      {balance ? formatPrice(balance.locked_in_escrow) : '0.000 BLK'}
                    </span>
                  </div>
                </div>
              </div>

              <NodeStatus />
              <PrivacyIndicator level="enhanced" />
            </div>

            {/* Main Content */}
            <div className="lg:col-span-3">
              {/* Dashboard Header */}
              <div className="mb-8">
                <h1 className="text-3xl font-bold text-amber-300 mb-2">Dashboard</h1>
                <p className="text-gray-400">
                  Manage your orders, listings, and account settings
                </p>
              </div>

              {/* Tabs */}
              <div className="flex space-x-6 mb-8 border-b border-amber-800/30">
                <button
                  onClick={() => setActiveTab('orders')}
                  className={`pb-4 px-2 font-medium transition-colors ${
                    activeTab === 'orders'
                      ? 'text-amber-300 border-b-2 border-amber-500'
                      : 'text-gray-400 hover:text-amber-300'
                  }`}
                >
                  My Orders ({orders.length})
                </button>
                <button
                  onClick={() => setActiveTab('selling')}
                  className={`pb-4 px-2 font-medium transition-colors ${
                    activeTab === 'selling'
                      ? 'text-amber-300 border-b-2 border-amber-500'
                      : 'text-gray-400 hover:text-amber-300'
                  }`}
                >
                  Selling ({sellingProducts.length})
                </button>
                <button
                  onClick={() => setActiveTab('settings')}
                  className={`pb-4 px-2 font-medium transition-colors ${
                    activeTab === 'settings'
                      ? 'text-amber-300 border-b-2 border-amber-500'
                      : 'text-gray-400 hover:text-amber-300'
                  }`}
                >
                  Settings
                </button>
              </div>

              {/* Tab Content */}
              {loading ? (
                <div className="space-y-6">
                  {Array.from({ length: 3 }).map((_, i) => (
                    <div key={i} className="bg-black/40 border border-amber-800/30 rounded-lg p-6 animate-pulse">
                      <div className="h-4 bg-gray-800 rounded w-1/3 mb-4"></div>
                      <div className="h-3 bg-gray-800 rounded w-full mb-2"></div>
                      <div className="h-3 bg-gray-800 rounded w-2/3"></div>
                    </div>
                  ))}
                </div>
              ) : (
                <>
                  {activeTab === 'orders' && (
                    <div className="space-y-6">
                      {orders.length > 0 ? (
                        orders.map((order) => (
                          <OrderTracking
                            key={order.id}
                            order={order}
                            onAction={handleOrderAction}
                          />
                        ))
                      ) : (
                        <div className="text-center py-12">
                          <div className="text-6xl mb-4">📦</div>
                          <h3 className="text-xl text-amber-300 mb-2">No orders yet</h3>
                          <p className="text-gray-400 mb-6">
                            Start shopping to see your orders here.
                          </p>
                          <Link href="/">
                            <span className="bg-amber-900/50 hover:bg-amber-800/50 text-amber-300 px-6 py-3 rounded-lg font-semibold">
                              Browse Products
                            </span>
                          </Link>
                        </div>
                      )}
                    </div>
                  )}

                  {activeTab === 'selling' && (
                    <div className="space-y-6">
                      {sellingProducts.length > 0 ? (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                          {sellingProducts.map((product) => (
                            <div key={product.id} className="bg-black/40 border border-amber-800/30 rounded-lg p-6">
                              <div className="flex justify-between items-start mb-4">
                                <h3 className="text-amber-300 font-semibold">{product.title}</h3>
                                <span className={`px-2 py-1 rounded-full text-xs ${
                                  product.isActive ? 'bg-green-900/50 text-green-300' : 'bg-red-900/50 text-red-300'
                                }`}>
                                  {product.isActive ? 'Active' : 'Inactive'}
                                </span>
                              </div>
                              
                              <div className="space-y-2 text-sm mb-4">
                                <div className="flex justify-between">
                                  <span className="text-gray-400">Price:</span>
                                  <span className="text-amber-300">{formatPrice(product.price)}</span>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-gray-400">Stock:</span>
                                  <span className="text-amber-300">{product.stock}</span>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-gray-400">Rating:</span>
                                  <span className="text-amber-300">
                                    {product.rating ? `★ ${product.rating.toFixed(1)}` : 'No ratings'}
                                  </span>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-gray-400">Created:</span>
                                  <span className="text-amber-300">{formatDate(product.createdAt)}</span>
                                </div>
                              </div>
                              
                              <div className="flex space-x-2">
                                <Link href={`/product/${product.id}`}>
                                  <span className="flex-1 bg-amber-900/50 hover:bg-amber-800/50 text-amber-300 px-4 py-2 rounded-lg text-center text-sm">
                                    View
                                  </span>
                                </Link>
                                <button className="flex-1 bg-gray-800/50 hover:bg-gray-700/50 text-gray-300 px-4 py-2 rounded-lg text-sm">
                                  Edit
                                </button>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="text-center py-12">
                          <div className="text-6xl mb-4">🏪</div>
                          <h3 className="text-xl text-amber-300 mb-2">No products listed</h3>
                          <p className="text-gray-400 mb-6">
                            Start selling by creating your first product listing.
                          </p>
                          <Link href="/sell">
                            <span className="bg-amber-900/50 hover:bg-amber-800/50 text-amber-300 px-6 py-3 rounded-lg font-semibold">
                              Create Listing
                            </span>
                          </Link>
                        </div>
                      )}
                    </div>
                  )}

                  {activeTab === 'settings' && (
                    <div className="space-y-6">
                      {/* Privacy Settings */}
                      <div className="bg-black/40 border border-amber-800/30 rounded-lg p-6">
                        <h3 className="text-amber-300 font-semibold mb-4">Privacy Settings</h3>
                        <div className="space-y-4">
                          <label className="flex items-center space-x-3">
                            <input type="checkbox" className="form-checkbox text-amber-500" defaultChecked />
                            <span className="text-gray-300">Use Tor network for enhanced privacy</span>
                          </label>
                          <label className="flex items-center space-x-3">
                            <input type="checkbox" className="form-checkbox text-amber-500" />
                            <span className="text-gray-300">Enable I2P routing</span>
                          </label>
                          <label className="flex items-center space-x-3">
                            <input type="checkbox" className="form-checkbox text-amber-500" defaultChecked />
                            <span className="text-gray-300">Use stealth addresses</span>
                          </label>
                        </div>
                      </div>

                      {/* Security Settings */}
                      <div className="bg-black/40 border border-amber-800/30 rounded-lg p-6">
                        <h3 className="text-amber-300 font-semibold mb-4">Security</h3>
                        <div className="space-y-4">
                          <button className="w-full bg-amber-900/50 hover:bg-amber-800/50 text-amber-300 py-3 rounded-lg font-semibold">
                            Export Private Key
                          </button>
                          <button className="w-full bg-blue-900/50 hover:bg-blue-800/50 text-blue-300 py-3 rounded-lg font-semibold">
                            View Recovery Phrase
                          </button>
                          <button className="w-full bg-red-900/50 hover:bg-red-800/50 text-red-300 py-3 rounded-lg font-semibold">
                            Delete Account
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <footer className="border-t border-amber-800/30 bg-black/50 mt-16">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <div className="text-center text-gray-400">
              <p className="mb-2">🔒 BlackSilk Marketplace - Privacy First, Decentralized Forever</p>
              <p className="text-sm">
                Secured by blockchain • No tracking • Your keys, your crypto
              </p>
            </div>
          </div>
        </footer>
      </div>
    </>
  );
};

export default DashboardPage;
