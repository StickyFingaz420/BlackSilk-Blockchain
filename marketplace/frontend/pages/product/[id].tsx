import { useState, useEffect } from 'react';
import { useRouter } from 'next/router';
import Head from 'next/head';
import Link from 'next/link';
import { NodeStatus, PrivacyIndicator, ShoppingCart } from '../../components';
import { useAuth, useCart } from '../../hooks';
import { Product, EscrowStatus } from '../../types';

const ProductPage = () => {
  const router = useRouter();
  const { id } = router.query;
  const { user } = useAuth();
  const { addToCart, isInCart, getCartItem } = useCart();
  const [product, setProduct] = useState<Product | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedImage, setSelectedImage] = useState(0);
  const [quantity, setQuantity] = useState(1);
  const [showFullDescription, setShowFullDescription] = useState(false);

  useEffect(() => {
    if (id) {
      loadProduct();
    }
  }, [id]);

  const loadProduct = async () => {
    setLoading(true);
    try {
      // Mock product data - replace with actual API call
      const mockProduct: Product = {
        id: id as string,
        seller: 'vendor123',
        title: 'Premium Privacy VPN Service - Annual Subscription',
        description: `Get complete online privacy and security with our premium VPN service. Features include:

• No-logs policy with annual transparency reports
• Military-grade AES-256 encryption
• Support for OpenVPN, WireGuard, and IKEv2 protocols
• 5000+ servers in 60+ countries
• Unlimited bandwidth and simultaneous connections
• Built-in ad and malware blocking
• Tor over VPN for maximum anonymity
• 24/7 customer support via encrypted channels
• Compatible with all major platforms
• Kill switch and DNS leak protection

Perfect for activists, journalists, privacy enthusiasts, and anyone who values their digital rights. This service is specifically optimized for users who require maximum privacy and security.

Installation is simple and setup takes less than 5 minutes. You'll receive your account credentials immediately after payment confirmation through our secure escrow system.`,
        category: 'digital',
        subcategory: 'privacy-tools',
        price: 0.150,
        stock: 50,
        images: [
          'https://via.placeholder.com/600x400?text=VPN+Service',
          'https://via.placeholder.com/600x400?text=Server+Map',
          'https://via.placeholder.com/600x400?text=Speed+Test',
          'https://via.placeholder.com/600x400?text=Security+Features'
        ],
        shipsFrom: 'Digital Delivery',
        shipsTo: ['Worldwide'],
        processingTime: 'Instant',
        rating: 4.8,
        createdAt: Date.now() / 1000 - 86400,
        isActive: true,
        stealthRequired: false,
        escrowRequired: true
      };

      setProduct(mockProduct);
    } catch (error) {
      console.error('Failed to load product:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAddToCart = () => {
    if (product) {
      addToCart(product, quantity);
      // Show success message
      alert(`Added ${quantity} x ${product.title} to cart!`);
    }
  };

  const handleBuyNow = () => {
    if (!user) {
      router.push('/login');
      return;
    }

    if (product) {
      addToCart(product, quantity);
      // Redirect to checkout
      router.push('/checkout');
    }
  };

  const formatPrice = (price: number) => {
    return `${price.toFixed(3)} BLK`;
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'digital':
        return 'bg-purple-900/50 text-purple-300';
      case 'services':
        return 'bg-blue-900/50 text-blue-300';
      case 'physical':
        return 'bg-green-900/50 text-green-300';
      default:
        return 'bg-gray-700/50 text-gray-300';
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-black text-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="animate-pulse">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <div className="h-96 bg-gray-800 rounded-lg"></div>
              <div className="space-y-4">
                <div className="h-8 bg-gray-800 rounded w-3/4"></div>
                <div className="h-4 bg-gray-800 rounded w-1/2"></div>
                <div className="h-32 bg-gray-800 rounded"></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!product) {
    return (
      <div className="min-h-screen bg-black text-white flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl text-amber-300 mb-4">Product Not Found</h1>
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
        <title>{product.title} - BlackSilk Marketplace</title>
        <meta name="description" content={product.description.slice(0, 160)} />
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
          {/* Breadcrumb */}
          <nav className="mb-8">
            <ol className="flex items-center space-x-2 text-sm">
              <li>
                <Link href="/">
                  <span className="text-amber-400 hover:text-amber-300">Home</span>
                </Link>
              </li>
              <li className="text-gray-500">/</li>
              <li>
                <Link href={`/category/${product.category}`}>
                  <span className="text-amber-400 hover:text-amber-300 capitalize">{product.category}</span>
                </Link>
              </li>
              <li className="text-gray-500">/</li>
              <li className="text-gray-400 truncate max-w-xs">{product.title}</li>
            </ol>
          </nav>

          <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
            {/* Sidebar */}
            <div className="space-y-6">
              <NodeStatus />
              <PrivacyIndicator level="enhanced" />
              
              {/* Seller Info */}
              <div className="bg-black/40 border border-amber-800/30 rounded-lg p-4">
                <h3 className="text-amber-300 font-semibold mb-3">Seller Information</h3>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Address:</span>
                    <span className="text-amber-300 font-mono text-xs">
                      {product.seller.slice(0, 8)}...
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Rating:</span>
                    <div className="flex items-center">
                      <span className="text-amber-400">★★★★★</span>
                      <span className="text-gray-400 ml-1">(4.8)</span>
                    </div>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Sales:</span>
                    <span className="text-amber-300">127</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Main Content */}
            <div className="lg:col-span-3">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Product Images */}
                <div className="space-y-4">
                  <div className="aspect-square bg-gray-900/50 rounded-lg overflow-hidden">
                    <img
                      src={product.images?.[selectedImage]}
                      alt={product.title}
                      className="w-full h-full object-cover"
                    />
                  </div>
                  
                  {product.images && product.images.length > 1 && (
                    <div className="grid grid-cols-4 gap-2">
                      {product.images.map((image, index) => (
                        <button
                          key={index}
                          onClick={() => setSelectedImage(index)}
                          className={`aspect-square bg-gray-900/50 rounded-lg overflow-hidden border-2 transition-colors ${
                            selectedImage === index ? 'border-amber-500' : 'border-transparent hover:border-amber-700'
                          }`}
                        >
                          <img
                            src={image}
                            alt={`${product.title} ${index + 1}`}
                            className="w-full h-full object-cover"
                          />
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                {/* Product Info */}
                <div className="space-y-6">
                  {/* Title and Category */}
                  <div>
                    <div className="mb-3">
                      <span className={`px-3 py-1 rounded-full text-sm font-medium ${getCategoryColor(product.category)}`}>
                        {product.category}
                      </span>
                    </div>
                    <h1 className="text-3xl font-bold text-amber-300 mb-2">
                      {product.title}
                    </h1>
                    {product.rating && (
                      <div className="flex items-center space-x-2">
                        <div className="flex text-amber-400">
                          {Array.from({ length: 5 }, (_, i) => (
                            <span key={i} className={i < Math.floor(product.rating!) ? 'text-amber-400' : 'text-gray-600'}>
                              ★
                            </span>
                          ))}
                        </div>
                        <span className="text-gray-400">({product.rating.toFixed(1)})</span>
                      </div>
                    )}
                  </div>

                  {/* Price */}
                  <div className="bg-amber-900/20 border border-amber-700/50 rounded-lg p-4">
                    <div className="text-3xl font-bold text-amber-300 mb-2">
                      {formatPrice(product.price)}
                    </div>
                    <div className="text-sm text-gray-400">
                      ≈ ${(product.price * 50000).toLocaleString()} USD
                    </div>
                  </div>

                  {/* Stock and Quantity */}
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Stock:</span>
                      <span className={`font-semibold ${product.stock && product.stock > 0 ? 'text-green-400' : 'text-red-400'}`}>
                        {product.stock && product.stock > 0 ? `${product.stock} available` : 'Out of stock'}
                      </span>
                    </div>
                    
                    {product.stock && product.stock > 0 && (
                      <div className="flex items-center space-x-3">
                        <span className="text-gray-400">Quantity:</span>
                        <div className="flex items-center space-x-2">
                          <button
                            onClick={() => setQuantity(Math.max(1, quantity - 1))}
                            className="w-8 h-8 bg-gray-700 hover:bg-gray-600 rounded text-amber-300"
                          >
                            -
                          </button>
                          <span className="w-12 text-center font-semibold text-amber-300">
                            {quantity}
                          </span>
                          <button
                            onClick={() => setQuantity(Math.min(product.stock!, quantity + 1))}
                            className="w-8 h-8 bg-gray-700 hover:bg-gray-600 rounded text-amber-300"
                          >
                            +
                          </button>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Purchase Buttons */}
                  {product.stock && product.stock > 0 ? (
                    <div className="space-y-3">
                      <button
                        onClick={handleBuyNow}
                        className="w-full bg-amber-900/50 hover:bg-amber-800/50 text-amber-300 py-3 rounded-lg font-semibold transition-colors"
                      >
                        Buy Now - {formatPrice(product.price * quantity)}
                      </button>
                      
                      <button
                        onClick={handleAddToCart}
                        className="w-full bg-gray-800/50 hover:bg-gray-700/50 text-gray-300 py-3 rounded-lg font-semibold transition-colors border border-gray-600"
                      >
                        {isInCart(product.id, product.seller) ? 'Update Cart' : 'Add to Cart'}
                      </button>
                    </div>
                  ) : (
                    <div className="bg-red-900/20 border border-red-700/50 rounded-lg p-4 text-center">
                      <span className="text-red-400 font-semibold">Out of Stock</span>
                    </div>
                  )}

                  {/* Security Features */}
                  <div className="bg-green-900/20 border border-green-700/50 rounded-lg p-4">
                    <h3 className="text-green-300 font-semibold mb-2">Security Features</h3>
                    <ul className="space-y-1 text-sm text-gray-300">
                      <li>🔒 Escrow protection enabled</li>
                      <li>🛡️ Dispute resolution available</li>
                      <li>🔐 Anonymous transactions</li>
                      <li>⚡ Instant digital delivery</li>
                    </ul>
                  </div>

                  {/* Shipping Info */}
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <div className="text-gray-400">Ships From:</div>
                      <div className="text-amber-300">{product.shipsFrom}</div>
                    </div>
                    <div>
                      <div className="text-gray-400">Processing Time:</div>
                      <div className="text-amber-300">{product.processingTime}</div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Product Description */}
              <div className="mt-8 bg-black/40 border border-amber-800/30 rounded-lg p-6">
                <h2 className="text-xl font-bold text-amber-300 mb-4">Description</h2>
                <div className="text-gray-300 space-y-4">
                  {showFullDescription ? (
                    <div className="whitespace-pre-wrap">{product.description}</div>
                  ) : (
                    <div className="whitespace-pre-wrap">
                      {product.description.slice(0, 500)}
                      {product.description.length > 500 && '...'}
                    </div>
                  )}
                  
                  {product.description.length > 500 && (
                    <button
                      onClick={() => setShowFullDescription(!showFullDescription)}
                      className="text-amber-400 hover:text-amber-300 underline"
                    >
                      {showFullDescription ? 'Show Less' : 'Show More'}
                    </button>
                  )}
                </div>
              </div>
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

export default ProductPage;
