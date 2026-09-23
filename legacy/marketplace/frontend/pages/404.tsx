import React from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { NodeStatus, PrivacyIndicator } from '../components';
import { PrivacyLevel } from '../types';

const Custom404: React.FC = () => {
  return (
    <>
      <Head>
        <title>Page Not Found - BlackSilk Marketplace</title>
        <meta name="description" content="The page you're looking for could not be found" />
      </Head>

      <div className="min-h-screen bg-gray-900 text-white">
        <div className="container mx-auto px-4 py-8">
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center space-x-4">
              <Link href="/" className="text-purple-400 hover:text-purple-300">
                ← Back to Marketplace
              </Link>
              <PrivacyIndicator level={PrivacyLevel.High} />
            </div>
            <NodeStatus />
          </div>

          {/* 404 Content */}
          <div className="flex flex-col items-center justify-center text-center py-20">
            {/* Large 404 */}
            <div className="mb-8">
              <h1 className="text-8xl font-bold text-purple-500 mb-4">404</h1>
              <div className="w-32 h-1 bg-gradient-to-r from-purple-500 to-pink-500 mx-auto"></div>
            </div>

            {/* Error Message */}
            <div className="max-w-md mb-8">
              <h2 className="text-2xl font-semibold mb-4">Page Not Found</h2>
              <p className="text-gray-400 mb-6">
                The page you're looking for seems to have vanished into the digital void. 
                It might have been moved, deleted, or never existed in the first place.
              </p>
            </div>

            {/* Silk Road Themed Message */}
            <div className="bg-gray-800 rounded-lg p-6 max-w-lg mb-8">
              <div className="flex items-center space-x-3 mb-3">
                <div className="w-8 h-8 bg-purple-600 rounded-full flex items-center justify-center">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                  </svg>
                </div>
                <h3 className="font-semibold text-purple-400">Lost on the Digital Silk Road?</h3>
              </div>
              <p className="text-sm text-gray-300">
                Even the most experienced traders sometimes take a wrong turn. 
                Let's get you back to the main marketplace where the real treasures await.
              </p>
            </div>

            {/* Navigation Options */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 w-full max-w-2xl">
              <Link 
                href="/"
                className="bg-purple-600 hover:bg-purple-700 text-white p-4 rounded-lg text-center transition-colors group"
              >
                <div className="text-2xl mb-2 group-hover:scale-110 transition-transform">🏠</div>
                <h3 className="font-semibold mb-1">Marketplace</h3>
                <p className="text-sm text-purple-200">Browse all products</p>
              </Link>

              <Link 
                href="/search"
                className="bg-gray-700 hover:bg-gray-600 text-white p-4 rounded-lg text-center transition-colors group"
              >
                <div className="text-2xl mb-2 group-hover:scale-110 transition-transform">🔍</div>
                <h3 className="font-semibold mb-1">Search</h3>
                <p className="text-sm text-gray-300">Find specific items</p>
              </Link>

              <Link 
                href="/dashboard"
                className="bg-gray-700 hover:bg-gray-600 text-white p-4 rounded-lg text-center transition-colors group"
              >
                <div className="text-2xl mb-2 group-hover:scale-110 transition-transform">👤</div>
                <h3 className="font-semibold mb-1">Dashboard</h3>
                <p className="text-sm text-gray-300">Your account</p>
              </Link>
            </div>

            {/* Popular Categories */}
            <div className="mt-12 w-full max-w-2xl">
              <h3 className="text-lg font-semibold mb-4 text-center">Popular Categories</h3>
              <div className="flex flex-wrap justify-center gap-2">
                {[
                  'Electronics', 'Fashion', 'Collectibles', 'Digital Goods', 
                  'Art & Crafts', 'Books', 'Gaming', 'Software'
                ].map((category) => (
                  <Link
                    key={category}
                    href={`/category/${category.toLowerCase().replace(/\s+/g, '-')}`}
                    className="bg-gray-800 hover:bg-purple-600 text-gray-300 hover:text-white px-4 py-2 rounded-full text-sm transition-colors"
                  >
                    {category}
                  </Link>
                ))}
              </div>
            </div>

            {/* Help Section */}
            <div className="mt-12 text-center">
              <p className="text-gray-400 mb-4">Still need help finding what you're looking for?</p>
              <div className="flex flex-wrap justify-center gap-4">
                <Link 
                  href="/help"
                  className="text-purple-400 hover:text-purple-300 underline"
                >
                  Help Center
                </Link>
                <Link 
                  href="/contact"
                  className="text-purple-400 hover:text-purple-300 underline"
                >
                  Contact Support
                </Link>
                <Link 
                  href="/sitemap"
                  className="text-purple-400 hover:text-purple-300 underline"
                >
                  Site Map
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default Custom404;
