import { useState, useEffect } from 'react';
import { useRouter } from 'next/router';
import Head from 'next/head';
import Link from 'next/link';
import { ProductCard, NodeStatus, PrivacyIndicator, ShoppingCart } from '../../components';
import { useProducts, useAuth } from '../../hooks';
import { Product, PrivacyLevel } from '../../types';

interface CategoryPageProps {
  category?: string;
}

const CategoryPage = ({ category }: CategoryPageProps) => {
  const router = useRouter();
  const { id } = router.query;
  const categoryId = category || id;
  const { user } = useAuth();
  const [products, setProducts] = useState<Product[]>([]);
  const [loading, setLoading] = useState(true);
  const [sortBy, setSortBy] = useState<'price' | 'date' | 'rating'>('date');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [priceRange, setPriceRange] = useState<{ min: number; max: number }>({ min: 0, max: 1000 });

  const categoryInfo = {
    digital: {
      name: 'Digital Goods',
      description: 'Software, ebooks, digital art, cryptocurrencies, and other digital assets',
      icon: '💾',
      color: 'from-purple-900/20 to-purple-800/20'
    },
    services: {
      name: 'Services',
      description: 'Professional services, consulting, education, and digital assistance',
      icon: '🛠️',
      color: 'from-blue-900/20 to-blue-800/20'
    },
    physical: {
      name: 'Physical Goods',
      description: 'Electronics, hardware, books, art, and other physical items',
      icon: '📦',
      color: 'from-green-900/20 to-green-800/20'
    }
  };

  const currentCategory = categoryInfo[categoryId as keyof typeof categoryInfo];

  useEffect(() => {
    if (categoryId) {
      loadCategoryProducts();
    }
  }, [categoryId, sortBy, sortOrder, priceRange]);

  const loadCategoryProducts = async () => {
    setLoading(true);
    try {
      // Mock data - replace with actual API call
      const mockProducts: Product[] = [
        {
          id: '1',
          seller: 'vendor1',
          title: 'Privacy VPN Service - 1 Year',
          description: 'Premium VPN service with no logs, military-grade encryption, and Tor compatibility. Perfect for maintaining privacy while browsing.',
          category: categoryId as string,
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
          title: 'Cryptocurrency Course Bundle',
          description: 'Complete guide to cryptocurrency trading, blockchain technology, and privacy coins. Includes video tutorials and PDF guides.',
          category: categoryId as string,
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
          title: 'Hardware Security Key',
          description: 'FIDO2/WebAuthn hardware security key for two-factor authentication. Supports USB-A and NFC.',
          category: categoryId as string,
          price: 0.025,
          stock: 25,
          images: ['https://via.placeholder.com/400x300?text=Hardware'],
          rating: 4.9,
          createdAt: Date.now() / 1000 - 172800,
          escrowRequired: true
        }
      ];

      // Apply sorting
      const sortedProducts = [...mockProducts].sort((a, b) => {
        let compareValue = 0;
        
        switch (sortBy) {
          case 'price':
            compareValue = a.price - b.price;
            break;
          case 'rating':
            compareValue = (a.rating || 0) - (b.rating || 0);
            break;
          case 'date':
          default:
            compareValue = a.createdAt - b.createdAt;
            break;
        }
        
        return sortOrder === 'asc' ? compareValue : -compareValue;
      });

      // Apply price filter
      const filteredProducts = sortedProducts.filter(product => 
        product.price >= priceRange.min && product.price <= priceRange.max
      );

      setProducts(filteredProducts);
    } catch (error) {
      console.error('Failed to load products:', error);
    } finally {
      setLoading(false);
    }
  };

  if (!currentCategory) {
    return (
      <div className="min-h-screen bg-black text-white flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl text-amber-300 mb-4">Category Not Found</h1>
          <Link href="/">
            <span className="text-amber-400 hover:text-amber-300 underline">
              Return to Homepage
            </span>
          </Link>
        </div>
      </div>
    );
  }

  return (
    <>
      <Head>
        <title>{currentCategory.name} - BlackSilk Marketplace</title>
        <meta name="description" content={`Browse ${currentCategory.name.toLowerCase()} on the BlackSilk decentralized marketplace`} />
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
            {/* Sidebar */}
            <div className="space-y-6">
              {/* Node Status */}
              <NodeStatus />

              {/* Privacy Status */}
              <PrivacyIndicator level={PrivacyLevel.High} />

              {/* Category Info */}
              <div className={`bg-gradient-to-br ${currentCategory.color} border border-amber-800/30 rounded-lg p-6`}>
                <div className="text-center">
                  <div className="text-4xl mb-4">{currentCategory.icon}</div>
                  <h2 className="text-amber-300 text-xl font-bold mb-2">
                    {currentCategory.name}
                  </h2>
                  <p className="text-gray-400 text-sm">
                    {currentCategory.description}
                  </p>
                </div>
              </div>

              {/* Filters */}
              <div className="bg-black/40 border border-amber-800/30 rounded-lg p-6">
                <h3 className="text-amber-300 font-semibold mb-4">Filters</h3>
                
                {/* Price Range */}
                <div className="mb-4">
                  <label className="block text-gray-400 text-sm mb-2">Price Range (BLK)</label>
                  <div className="grid grid-cols-2 gap-2">
                    <input
                      type="number"
                      placeholder="Min"
                      value={priceRange.min}
                      onChange={(e) => setPriceRange(prev => ({ ...prev, min: Number(e.target.value) }))}
                      className="bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white text-sm"
                      step="0.001"
                      min="0"
                    />
                    <input
                      type="number"
                      placeholder="Max"
                      value={priceRange.max}
                      onChange={(e) => setPriceRange(prev => ({ ...prev, max: Number(e.target.value) }))}
                      className="bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white text-sm"
                      step="0.001"
                      min="0"
                    />
                  </div>
                </div>

                {/* Sort Options */}
                <div className="mb-4">
                  <label className="block text-gray-400 text-sm mb-2">Sort By</label>
                  <select
                    value={sortBy}
                    onChange={(e) => setSortBy(e.target.value as 'price' | 'date' | 'rating')}
                    className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white text-sm"
                  >
                    <option value="date">Date Added</option>
                    <option value="price">Price</option>
                    <option value="rating">Rating</option>
                  </select>
                </div>

                <div>
                  <label className="block text-gray-400 text-sm mb-2">Order</label>
                  <select
                    value={sortOrder}
                    onChange={(e) => setSortOrder(e.target.value as 'asc' | 'desc')}
                    className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white text-sm"
                  >
                    <option value="desc">Descending</option>
                    <option value="asc">Ascending</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Main Content */}
            <div className="lg:col-span-3">
              {/* Results Header */}
              <div className="flex justify-between items-center mb-6">
                <h1 className="text-3xl font-bold text-amber-300">
                  {currentCategory.name}
                </h1>
                <div className="text-gray-400">
                  {loading ? 'Loading...' : `${products.length} items found`}
                </div>
              </div>

              {/* Products Grid */}
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
                  <h3 className="text-xl text-amber-300 mb-2">No products found</h3>
                  <p className="text-gray-400 mb-6">
                    Try adjusting your filters or check back later for new listings.
                  </p>
                  <Link href="/">
                    <span className="bg-amber-900/50 hover:bg-amber-800/50 text-amber-300 px-6 py-3 rounded-lg font-semibold">
                      Browse All Categories
                    </span>
                  </Link>
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

export default CategoryPage;

// Static generation for export
export async function getStaticPaths() {
  // Define the static paths for the categories
  const paths = [
    { params: { id: 'digital' } },
    { params: { id: 'services' } },
    { params: { id: 'physical' } }
  ];

  return {
    paths,
    fallback: false // Set to false since we know all possible category IDs
  };
}

export async function getStaticProps({ params }: { params: { id: string } }) {
  // Validate that the category exists
  const validCategories = ['digital', 'services', 'physical'];
  
  if (!validCategories.includes(params.id)) {
    return {
      notFound: true
    };
  }

  return {
    props: {
      category: params.id
    }
  };
}
