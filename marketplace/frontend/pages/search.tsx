import { useState, useEffect } from 'react';
import { useRouter } from 'next/router';
import Head from 'next/head';
import Link from 'next/link';
import { ProductCard, NodeStatus, PrivacyIndicator, ShoppingCart } from '../components';
import { useAuth } from '../hooks';
import { Product } from '../types';

const SearchPage = () => {
  const router = useRouter();
  const { q, category, minPrice, maxPrice } = router.query;
  const { user } = useAuth();
  const [products, setProducts] = useState<Product[]>([]);
  const [loading, setLoading] = useState(true);
  const [sortBy, setSortBy] = useState<'relevance' | 'price' | 'date' | 'rating'>('relevance');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [filters, setFilters] = useState({
    category: category as string || '',
    minPrice: minPrice ? parseFloat(minPrice as string) : 0,
    maxPrice: maxPrice ? parseFloat(maxPrice as string) : 1000,
    vendor: '',
    inStock: true
  });

  useEffect(() => {
    if (q) {
      performSearch();
    }
  }, [q, category, minPrice, maxPrice, sortBy, sortOrder, filters]);

  const performSearch = async () => {
    setLoading(true);
    try {
      // Mock search results - replace with actual API call
      const allProducts: Product[] = [
        {
          id: '1',
          seller: 'vendor1',
          title: 'Privacy VPN Service - 1 Year Subscription',
          description: 'Premium VPN service with no logs, military-grade encryption, and Tor compatibility.',
          category: 'digital',
          price: 0.150,
          stock: 50,
          images: ['https://via.placeholder.com/400x300?text=VPN'],
          rating: 4.8,
          createdAt: Date.now() / 1000,
          escrowRequired: true
        },
        {
          id: '2',
          seller: 'vendor2',
          title: 'Cryptocurrency Trading Course Bundle',
          description: 'Complete guide to cryptocurrency trading, blockchain technology, and privacy coins.',
          category: 'digital',
          price: 0.075,
          stock: 100,
          images: ['https://via.placeholder.com/400x300?text=Course'],
          rating: 4.6,
          createdAt: Date.now() / 1000 - 86400,
          escrowRequired: true
        },
        {
          id: '3',
          seller: 'vendor3',
          title: 'Hardware Security Key FIDO2',
          description: 'FIDO2/WebAuthn hardware security key for two-factor authentication.',
          category: 'physical',
          price: 0.025,
          stock: 25,
          images: ['https://via.placeholder.com/400x300?text=Hardware'],
          rating: 4.9,
          createdAt: Date.now() / 1000 - 172800,
          escrowRequired: true
        },
        {
          id: '4',
          seller: 'vendor4',
          title: 'Penetration Testing Service',
          description: 'Professional penetration testing and security audit for your systems.',
          category: 'services',
          price: 0.500,
          stock: 5,
          images: ['https://via.placeholder.com/400x300?text=Security'],
          rating: 5.0,
          createdAt: Date.now() / 1000 - 259200,
          escrowRequired: true
        },
        {
          id: '5',
          seller: 'vendor5',
          title: 'Privacy-focused Email Service',
          description: 'Encrypted email service with anonymous registration and Tor support.',
          category: 'digital',
          price: 0.030,
          stock: 200,
          images: ['https://via.placeholder.com/400x300?text=Email'],
          rating: 4.7,
          createdAt: Date.now() / 1000 - 345600,
          escrowRequired: true
        }
      ];

      // Filter by search query
      let filteredProducts = allProducts;
      if (q) {
        const searchTerm = (q as string).toLowerCase();
        filteredProducts = allProducts.filter(product =>
          product.title.toLowerCase().includes(searchTerm) ||
          product.description.toLowerCase().includes(searchTerm) ||
          product.category.toLowerCase().includes(searchTerm)
        );
      }

      // Apply filters
      if (filters.category) {
        filteredProducts = filteredProducts.filter(product => product.category === filters.category);
      }

      if (filters.vendor) {
        filteredProducts = filteredProducts.filter(product => 
          product.seller.toLowerCase().includes(filters.vendor.toLowerCase())
        );
      }

      if (filters.inStock) {
        filteredProducts = filteredProducts.filter(product => 
          product.stock && product.stock > 0
        );
      }

      // Apply price range
      filteredProducts = filteredProducts.filter(product => 
        product.price >= filters.minPrice && product.price <= filters.maxPrice
      );

      // Apply sorting
      filteredProducts.sort((a, b) => {
        let compareValue = 0;
        
        switch (sortBy) {
          case 'price':
            compareValue = a.price - b.price;
            break;
          case 'rating':
            compareValue = (a.rating || 0) - (b.rating || 0);
            break;
          case 'date':
            compareValue = a.createdAt - b.createdAt;
            break;
          case 'relevance':
          default:
            // Simple relevance based on how many times search term appears
            if (q) {
              const searchTerm = (q as string).toLowerCase();
              const aRelevance = (a.title.toLowerCase().match(new RegExp(searchTerm, 'g')) || []).length +
                               (a.description.toLowerCase().match(new RegExp(searchTerm, 'g')) || []).length;
              const bRelevance = (b.title.toLowerCase().match(new RegExp(searchTerm, 'g')) || []).length +
                               (b.description.toLowerCase().match(new RegExp(searchTerm, 'g')) || []).length;
              compareValue = aRelevance - bRelevance;
            } else {
              compareValue = b.createdAt - a.createdAt; // Default to newest first
            }
            break;
        }
        
        return sortOrder === 'asc' ? compareValue : -compareValue;
      });

      setProducts(filteredProducts);
    } catch (error) {
      console.error('Search failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const updateFilter = (key: string, value: any) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const clearFilters = () => {
    setFilters({
      category: '',
      minPrice: 0,
      maxPrice: 1000,
      vendor: '',
      inStock: true
    });
  };

  return (
    <>
      <Head>
        <title>{q ? `Search: ${q}` : 'Search'} - BlackSilk Marketplace</title>
        <meta name="description" content={`Search results for "${q}" on BlackSilk Marketplace`} />
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

              {/* Search Bar */}
              <div className="flex-1 max-w-2xl mx-8">
                <div className="relative">
                  <input
                    type="text"
                    placeholder="Search products, services..."
                    defaultValue={q as string}
                    onKeyPress={(e) => {
                      if (e.key === 'Enter') {
                        const value = (e.target as HTMLInputElement).value;
                        if (value.trim()) {
                          router.push(`/search?q=${encodeURIComponent(value.trim())}`);
                        }
                      }
                    }}
                    className="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-2 text-white placeholder-gray-400 focus:border-amber-500 focus:outline-none"
                  />
                  <div className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400">
                    🔍
                  </div>
                </div>
              </div>

              <div className="flex items-center space-x-4">
                {user ? (
                  <>
                    <Link href="/dashboard">
                      <span className="text-amber-400 hover:text-amber-300">Dashboard</span>
                    </Link>
                    <Link href="/sell">
                      <span className="bg-amber-900/50 hover:bg-amber-800/50 text-amber-300 px-4 py-2 rounded-lg">Sell</span>
                    </Link>
                  </>
                ) : (
                  <Link href="/login">
                    <span className="bg-amber-900/50 hover:bg-amber-800/50 text-amber-300 px-4 py-2 rounded-lg">Access Wallet</span>
                  </Link>
                )}
                <ShoppingCart />
              </div>
            </div>
          </div>
        </header>

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
            {/* Sidebar Filters */}
            <div className="space-y-6">
              <NodeStatus />
              <PrivacyIndicator level="enhanced" />

              {/* Search Filters */}
              <div className="bg-black/40 border border-amber-800/30 rounded-lg p-6">
                <div className="flex justify-between items-center mb-4">
                  <h3 className="text-amber-300 font-semibold">Filters</h3>
                  <button
                    onClick={clearFilters}
                    className="text-amber-400 hover:text-amber-300 text-sm underline"
                  >
                    Clear All
                  </button>
                </div>

                {/* Category Filter */}
                <div className="mb-4">
                  <label className="block text-gray-400 text-sm mb-2">Category</label>
                  <select
                    value={filters.category}
                    onChange={(e) => updateFilter('category', e.target.value)}
                    className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white text-sm"
                  >
                    <option value="">All Categories</option>
                    <option value="digital">Digital Goods</option>
                    <option value="services">Services</option>
                    <option value="physical">Physical Goods</option>
                  </select>
                </div>

                {/* Price Range */}
                <div className="mb-4">
                  <label className="block text-gray-400 text-sm mb-2">Price Range (BLK)</label>
                  <div className="grid grid-cols-2 gap-2">
                    <input
                      type="number"
                      placeholder="Min"
                      value={filters.minPrice}
                      onChange={(e) => updateFilter('minPrice', Number(e.target.value))}
                      className="bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white text-sm"
                      step="0.001"
                      min="0"
                    />
                    <input
                      type="number"
                      placeholder="Max"
                      value={filters.maxPrice}
                      onChange={(e) => updateFilter('maxPrice', Number(e.target.value))}
                      className="bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white text-sm"
                      step="0.001"
                      min="0"
                    />
                  </div>
                </div>

                {/* Vendor Filter */}
                <div className="mb-4">
                  <label className="block text-gray-400 text-sm mb-2">Vendor</label>
                  <input
                    type="text"
                    placeholder="Vendor address or name"
                    value={filters.vendor}
                    onChange={(e) => updateFilter('vendor', e.target.value)}
                    className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white text-sm"
                  />
                </div>

                {/* Stock Filter */}
                <div>
                  <label className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={filters.inStock}
                      onChange={(e) => updateFilter('inStock', e.target.checked)}
                      className="form-checkbox text-amber-500"
                    />
                    <span className="text-gray-300 text-sm">In stock only</span>
                  </label>
                </div>
              </div>
            </div>

            {/* Main Content */}
            <div className="lg:col-span-3">
              {/* Search Results Header */}
              <div className="flex justify-between items-center mb-6">
                <div>
                  <h1 className="text-3xl font-bold text-amber-300 mb-2">
                    {q ? `Search Results for "${q}"` : 'All Products'}
                  </h1>
                  <p className="text-gray-400">
                    {loading ? 'Searching...' : `${products.length} results found`}
                  </p>
                </div>

                {/* Sort Options */}
                <div className="flex items-center space-x-3">
                  <span className="text-gray-400 text-sm">Sort by:</span>
                  <select
                    value={sortBy}
                    onChange={(e) => setSortBy(e.target.value as any)}
                    className="bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white text-sm"
                  >
                    <option value="relevance">Relevance</option>
                    <option value="date">Date Added</option>
                    <option value="price">Price</option>
                    <option value="rating">Rating</option>
                  </select>
                  <select
                    value={sortOrder}
                    onChange={(e) => setSortOrder(e.target.value as 'asc' | 'desc')}
                    className="bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white text-sm"
                  >
                    <option value="desc">High to Low</option>
                    <option value="asc">Low to High</option>
                  </select>
                </div>
              </div>

              {/* Results Grid */}
              {loading ? (
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                  {Array.from({ length: 6 }).map((_, i) => (
                    <div key={i} className="bg-black/40 border border-amber-800/30 rounded-lg h-80 animate-pulse">
                      <div className="h-48 bg-gray-800 rounded-t-lg"></div>
                      <div className="p-4 space-y-3">
                        <div className="h-4 bg-gray-800 rounded"></div>
                        <div className="h-3 bg-gray-800 rounded w-3/4"></div>
                        <div className="h-4 bg-gray-800 rounded w-1/2"></div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : products.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                  {products.map((product) => (
                    <ProductCard key={product.id} product={product} />
                  ))}
                </div>
              ) : (
                <div className="text-center py-12">
                  <div className="text-6xl mb-4">🔍</div>
                  <h3 className="text-xl text-amber-300 mb-2">No results found</h3>
                  <p className="text-gray-400 mb-6">
                    {q ? `No products found for "${q}". Try different keywords or adjust your filters.` 
                       : 'No products match your current filters.'}
                  </p>
                  <div className="space-x-4">
                    <button
                      onClick={clearFilters}
                      className="bg-amber-900/50 hover:bg-amber-800/50 text-amber-300 px-6 py-3 rounded-lg font-semibold"
                    >
                      Clear Filters
                    </button>
                    <Link href="/">
                      <span className="bg-gray-800/50 hover:bg-gray-700/50 text-gray-300 px-6 py-3 rounded-lg font-semibold">
                        Browse All
                      </span>
                    </Link>
                  </div>
                </div>
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

export default SearchPage;
