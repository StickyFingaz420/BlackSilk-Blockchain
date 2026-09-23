import { useState, useEffect } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { Shield, Globe, Eye, Users, TrendingUp, Package } from 'lucide-react';
import { useProducts, useNodeStatus, useWebSocket } from '@/hooks';
import { ProductCard } from '@/components/ProductCard';
import { CategoryCard } from '@/components/CategoryCard';
import { NodeStatus } from '@/components/NodeStatus';
import { CommunityWarning } from '@/components/CommunityWarning';

export default function HomePage() {
  const { products, isLoading: productsLoading } = useProducts({ limit: 8 });
  const { nodeInfo, isOnline } = useNodeStatus();
  const { isConnected } = useWebSocket();

  const categories = [
    {
      id: 'digital',
      name: 'Digital Goods',
      description: 'Software, E-books, Digital Services',
      icon: '💾',
      count: 0,
    },
    {
      id: 'services',
      name: 'Services',
      description: 'Consulting, Design, Education',
      icon: '🛠️',
      count: 0,
    },
    {
      id: 'physical',
      name: 'Physical Goods',
      description: 'Electronics, Clothing, Supplies',
      icon: '📦',
      count: 0,
    },
  ];

  const stats = [
    { label: 'Active Products', value: products.length, icon: Package },
    { label: 'Network Peers', value: nodeInfo?.peers || 0, icon: Users },
    { label: 'Chain Height', value: nodeInfo?.chain_height || 0, icon: TrendingUp },
    { label: 'Difficulty', value: nodeInfo?.difficulty || 0, icon: Globe },
  ];

  return (
    <>
      <Head>
        <title>BlackSilk Marketplace - Decentralized Commerce</title>
        <meta name="description" content="Privacy-first decentralized marketplace powered by BlackSilk blockchain" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <div className="min-h-screen bg-silk-gradient">
        {/* Header */}
        <header className="silk-nav sticky top-0 z-50">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center h-16">
              {/* Logo */}
              <Link href="/" className="flex items-center space-x-2">
                <Shield className="h-8 w-8 text-silk-accent" />
                <span className="text-xl font-bold text-silk-text">BlackSilk</span>
              </Link>

              {/* Navigation */}
              <nav className="hidden md:flex items-center space-x-8">
                <Link href="/category/digital" className="text-silk-muted hover:text-silk-accent transition-colors">
                  Digital
                </Link>
                <Link href="/category/services" className="text-silk-muted hover:text-silk-accent transition-colors">
                  Services
                </Link>
                <Link href="/category/physical" className="text-silk-muted hover:text-silk-accent transition-colors">
                  Physical
                </Link>
                <Link href="/sell" className="silk-button">
                  Sell
                </Link>
              </nav>

              {/* Status Indicators */}
              {/* Status Indicators */}
              <div className="flex items-center space-x-4">
                <NodeStatus />
                <Link href="/login" className="silk-button-secondary">
                  Login
                </Link>
              </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {/* Community Warning */}
          <CommunityWarning 
            onAccept={() => console.log('Accepted')}
            onDecline={() => console.log('Declined')}
          />

          {/* Hero Section */}
          <div className="text-center py-12">
            <h1 className="text-4xl md:text-6xl font-bold text-silk-text mb-6">
              Decentralized
              <span className="block text-silk-accent">Marketplace</span>
            </h1>
            <p className="text-xl text-silk-muted max-w-3xl mx-auto mb-8">
              Privacy-first commerce powered by BlackSilk blockchain. 
              Trade with confidence using escrow protection and Tor privacy.
            </p>
            
            {/* Search Bar */}
            <div className="max-w-2xl mx-auto mb-8">
              <div className="relative">
                <input
                  type="text"
                  placeholder="Search products..."
                  className="silk-input w-full py-4 px-6 text-lg pl-12"
                />
                <Eye className="absolute left-4 top-1/2 transform -translate-y-1/2 text-silk-muted h-5 w-5" />
              </div>
            </div>

            {/* Quick Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-12">
              {stats.map((stat, index) => (
                <div key={index} className="silk-card text-center">
                  <stat.icon className="h-8 w-8 text-silk-accent mx-auto mb-2" />
                  <div className="text-2xl font-bold text-silk-text">{stat.value.toLocaleString()}</div>
                  <div className="text-sm text-silk-muted">{stat.label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Categories */}
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-silk-text mb-8 text-center">
              Browse Categories
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {categories.map((category) => (
                <CategoryCard 
                  key={category.id} 
                  id={category.id}
                  name={category.name}
                  description={category.description}
                  icon={category.icon}
                  productCount={category.count}
                  color="amber"
                />
              ))}
            </div>
          </section>

          {/* Featured Products */}
          <section className="mb-12">
            <div className="flex justify-between items-center mb-8">
              <h2 className="text-3xl font-bold text-silk-text">
                Featured Products
              </h2>
              <Link href="/products" className="text-silk-accent hover:text-silk-purple transition-colors">
                View All →
              </Link>
            </div>

            {productsLoading ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {[...Array(8)].map((_, i) => (
                  <div key={i} className="silk-card animate-pulse">
                    <div className="h-48 bg-silk-gray rounded mb-4"></div>
                    <div className="h-4 bg-silk-gray rounded mb-2"></div>
                    <div className="h-4 bg-silk-gray rounded w-3/4"></div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="product-grid">
                {products.slice(0, 8).map((product) => (
                  <ProductCard key={product.id} product={product} />
                ))}
              </div>
            )}
          </section>

          {/* Privacy Features */}
          <section className="mb-12">
            <div className="silk-card text-center py-12">
              <h2 className="text-3xl font-bold text-silk-text mb-6">
                Built for Privacy
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                <div className="flex flex-col items-center">
                  <Shield className="h-12 w-12 text-silk-accent mb-4" />
                  <h3 className="text-xl font-semibold text-silk-text mb-2">Escrow Protection</h3>
                  <p className="text-silk-muted text-center">
                    All transactions protected by smart contract escrow with dispute resolution
                  </p>
                </div>
                <div className="flex flex-col items-center">
                  <Eye className="h-12 w-12 text-silk-accent mb-4" />
                  <h3 className="text-xl font-semibold text-silk-text mb-2">Tor Privacy</h3>
                  <p className="text-silk-muted text-center">
                    Built-in Tor support for anonymous browsing and transactions
                  </p>
                </div>
                <div className="flex flex-col items-center">
                  <Globe className="h-12 w-12 text-silk-accent mb-4" />
                  <h3 className="text-xl font-semibold text-silk-text mb-2">Decentralized</h3>
                  <p className="text-silk-muted text-center">
                    No central authority - powered by BlackSilk blockchain
                  </p>
                </div>
              </div>
            </div>
          </section>
        </main>

        {/* Footer */}
        <footer className="silk-footer mt-16">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
              <div>
                <div className="flex items-center space-x-2 mb-4">
                  <Shield className="h-6 w-6 text-silk-accent" />
                  <span className="text-lg font-bold text-silk-text">BlackSilk</span>
                </div>
                <p className="text-silk-muted">
                  Decentralized marketplace for the privacy-conscious
                </p>
              </div>
              
              <div>
                <h3 className="text-silk-text font-semibold mb-4">Marketplace</h3>
                <ul className="space-y-2 text-silk-muted">
                  <li><Link href="/category/digital" className="hover:text-silk-accent">Digital Goods</Link></li>
                  <li><Link href="/category/services" className="hover:text-silk-accent">Services</Link></li>
                  <li><Link href="/category/physical" className="hover:text-silk-accent">Physical Goods</Link></li>
                  <li><Link href="/sell" className="hover:text-silk-accent">Start Selling</Link></li>
                </ul>
              </div>
              
              <div>
                <h3 className="text-silk-text font-semibold mb-4">Privacy</h3>
                <ul className="space-y-2 text-silk-muted">
                  <li><a href="#" className="hover:text-silk-accent">Tor Setup</a></li>
                  <li><a href="#" className="hover:text-silk-accent">Privacy Guide</a></li>
                  <li><a href="#" className="hover:text-silk-accent">Security Tips</a></li>
                  <li><a href="#" className="hover:text-silk-accent">Escrow System</a></li>
                </ul>
              </div>
              
              <div>
                <h3 className="text-silk-text font-semibold mb-4">Resources</h3>
                <ul className="space-y-2 text-silk-muted">
                  <li><a href="#" className="hover:text-silk-accent">Documentation</a></li>
                  <li><a href="#" className="hover:text-silk-accent">API Reference</a></li>
                  <li><a href="#" className="hover:text-silk-accent">Community</a></li>
                  <li><a href="#" className="hover:text-silk-accent">Support</a></li>
                </ul>
              </div>
            </div>
            
            <div className="border-t border-silk-gray mt-8 pt-8 text-center text-silk-muted">
              <p>&copy; 2025 BlackSilk Marketplace. Built for privacy and freedom.</p>
              <p className="mt-2 text-sm">
                Community Standards: Don't be sick. We maintain zero tolerance for inappropriate content.
              </p>
            </div>
          </div>
        </footer>
      </div>
    </>
  );
}
