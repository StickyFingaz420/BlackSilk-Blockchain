import React, { useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { NodeStatus, PrivacyIndicator, CommunityWarning } from '../components';
import { PrivacyLevel } from '../types';

interface FAQItem {
  id: string;
  question: string;
  answer: string;
  category: string;
}

const HelpPage: React.FC = () => {
  const [activeCategory, setActiveCategory] = useState('getting-started');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedFAQ, setExpandedFAQ] = useState<string | null>(null);
  const [showWarning, setShowWarning] = useState(true);

  const faqData: FAQItem[] = [
    {
      id: '1',
      category: 'getting-started',
      question: 'How do I create an account on BlackSilk?',
      answer: 'To create an account, click the "Login" button in the top navigation and select "Create Account". You\'ll need to provide a username, secure password, and verify your email. We recommend using a VPN for additional privacy.'
    },
    {
      id: '2',
      category: 'getting-started',
      question: 'What is BSK and how do I get it?',
      answer: 'BSK (BlackSilk Coin) is our native cryptocurrency used for all transactions. You can acquire BSK through our integrated exchanges, by selling products, or by transferring from supported wallets. 1 BSK maintains stable value for marketplace transactions.'
    },
    {
      id: '3',
      category: 'getting-started',
      question: 'How do I make my first purchase?',
      answer: 'Browse products, add items to your cart, and proceed to checkout. You\'ll need BSK in your wallet and a delivery address. All payments are held in escrow until you confirm delivery, ensuring both buyer and seller protection.'
    },
    {
      id: '4',
      category: 'security',
      question: 'How does the escrow system work?',
      answer: 'When you place an order, your BSK is held in a secure escrow smart contract. The seller receives payment only after you confirm delivery. If there\'s a dispute, our mediation system helps resolve issues fairly.'
    },
    {
      id: '5',
      category: 'security',
      question: 'What privacy protections do you offer?',
      answer: 'We use end-to-end encryption for all communications, Tor-compatible browsing, encrypted delivery addresses, and optional anonymous payments. Your personal data is never stored in plaintext, and we support privacy-focused payment methods.'
    },
    {
      id: '6',
      category: 'security',
      question: 'How do I enable two-factor authentication?',
      answer: 'Go to Dashboard > Security Settings > Enable 2FA. We support TOTP authenticators like Google Authenticator or Authy. For maximum security, we also offer hardware key support and encrypted backup codes.'
    },
    {
      id: '7',
      category: 'selling',
      question: 'How do I start selling on BlackSilk?',
      answer: 'Visit the "Sell" page to create your first listing. You\'ll need to verify your account, provide product details, set pricing in BSK, and configure shipping options. All listings are reviewed for compliance with community standards.'
    },
    {
      id: '8',
      category: 'selling',
      question: 'What are the seller fees?',
      answer: 'We charge a 2.5% transaction fee on completed sales, plus blockchain gas fees for BSK transfers. There are no listing fees or monthly subscription costs. Fees are automatically deducted when escrow releases payment.'
    },
    {
      id: '9',
      category: 'selling',
      question: 'What products are allowed?',
      answer: 'We follow our "Don\'t be sick" community standards. Prohibited items include illegal goods, weapons, stolen items, and anything harmful to minors. Digital goods, art, collectibles, electronics, and other legal items are welcome.'
    },
    {
      id: '10',
      category: 'orders',
      question: 'How do I track my order?',
      answer: 'Go to Dashboard > Orders to view all your purchases. Each order shows real-time status updates, escrow progress, and tracking information when available. You\'ll receive notifications for all status changes.'
    },
    {
      id: '11',
      category: 'orders',
      question: 'What if my order doesn\'t arrive?',
      answer: 'If your order is significantly delayed or doesn\'t arrive, you can open a dispute through the order tracking page. Our mediation team will investigate and can authorize refunds from escrow if necessary.'
    },
    {
      id: '12',
      category: 'orders',
      question: 'Can I cancel or modify my order?',
      answer: 'Orders can be cancelled within 1 hour of placement if the seller hasn\'t begun processing. After that, you\'ll need to contact the seller directly. Modifications require mutual agreement between buyer and seller.'
    },
    {
      id: '13',
      category: 'technical',
      question: 'What browsers are supported?',
      answer: 'BlackSilk works best with Firefox, Chrome, Brave, and Tor Browser. We recommend using browsers with enhanced privacy settings and ad blockers for the best experience.'
    },
    {
      id: '14',
      category: 'technical',
      question: 'Can I use BlackSilk with Tor or VPN?',
      answer: 'Yes! We fully support Tor Browser and VPN connections. Many of our users prefer these tools for additional privacy. Some features may load slightly slower through Tor due to network latency.'
    },
    {
      id: '15',
      category: 'technical',
      question: 'What if the site is down or slow?',
      answer: 'Check our status page for known issues. We maintain backup access points and mirror sites for reliability. You can also try clearing your browser cache or switching to a different network connection.'
    }
  ];

  const categories = [
    { id: 'getting-started', name: 'Getting Started', icon: '🚀' },
    { id: 'security', name: 'Security & Privacy', icon: '🔒' },
    { id: 'selling', name: 'Selling', icon: '💼' },
    { id: 'orders', name: 'Orders & Shipping', icon: '📦' },
    { id: 'technical', name: 'Technical Support', icon: '⚙️' }
  ];

  const filteredFAQs = faqData.filter(faq => {
    const matchesCategory = activeCategory === 'all' || faq.category === activeCategory;
    const matchesSearch = searchTerm === '' || 
      faq.question.toLowerCase().includes(searchTerm.toLowerCase()) ||
      faq.answer.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  const toggleFAQ = (id: string) => {
    setExpandedFAQ(expandedFAQ === id ? null : id);
  };

  return (
    <>
      <Head>
        <title>Help Center - BlackSilk Marketplace</title>
        <meta name="description" content="Get help with BlackSilk marketplace - FAQs, guides, and support" />
      </Head>

      <div className="min-h-screen bg-gray-900 text-white">
        <div className="container mx-auto px-4 py-8">
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center space-x-4">
              <Link href="/" className="text-purple-400 hover:text-purple-300">
                ← Back to Marketplace
              </Link>
              <h1 className="text-3xl font-bold">Help Center</h1>
              <PrivacyIndicator level={PrivacyLevel.High} />
            </div>
            <NodeStatus />
          </div>

          {/* Community Warning */}
          {showWarning && (
            <CommunityWarning 
              onDismiss={() => setShowWarning(false)}
              customMessage="Remember our community standards: Don't be sick. Report any violations you encounter."
            />
          )}

          {/* Quick Links */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <Link href="/contact" className="bg-purple-600 hover:bg-purple-700 p-4 rounded-lg text-center transition-colors">
              <div className="text-2xl mb-2">💬</div>
              <h3 className="font-semibold">Contact Support</h3>
              <p className="text-sm text-purple-200">Get direct help</p>
            </Link>
            <Link href="/status" className="bg-gray-700 hover:bg-gray-600 p-4 rounded-lg text-center transition-colors">
              <div className="text-2xl mb-2">📊</div>
              <h3 className="font-semibold">System Status</h3>
              <p className="text-sm text-gray-300">Service health</p>
            </Link>
            <Link href="/community" className="bg-gray-700 hover:bg-gray-600 p-4 rounded-lg text-center transition-colors">
              <div className="text-2xl mb-2">👥</div>
              <h3 className="font-semibold">Community</h3>
              <p className="text-sm text-gray-300">User forums</p>
            </Link>
            <Link href="/guides" className="bg-gray-700 hover:bg-gray-600 p-4 rounded-lg text-center transition-colors">
              <div className="text-2xl mb-2">📚</div>
              <h3 className="font-semibold">Guides</h3>
              <p className="text-sm text-gray-300">Detailed tutorials</p>
            </Link>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
            {/* Category Sidebar */}
            <div className="lg:col-span-1">
              <div className="bg-gray-800 rounded-lg p-6 sticky top-4">
                <h2 className="text-lg font-semibold mb-4">Categories</h2>
                
                {/* Search */}
                <div className="mb-4">
                  <input
                    type="text"
                    placeholder="Search FAQs..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-sm focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                  />
                </div>

                {/* Category List */}
                <div className="space-y-2">
                  <button
                    onClick={() => setActiveCategory('all')}
                    className={`w-full text-left p-3 rounded-lg transition-colors ${
                      activeCategory === 'all' 
                        ? 'bg-purple-600 text-white' 
                        : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                    }`}
                  >
                    <div className="flex items-center space-x-2">
                      <span>📋</span>
                      <span>All Topics</span>
                    </div>
                  </button>
                  {categories.map((category) => (
                    <button
                      key={category.id}
                      onClick={() => setActiveCategory(category.id)}
                      className={`w-full text-left p-3 rounded-lg transition-colors ${
                        activeCategory === category.id 
                          ? 'bg-purple-600 text-white' 
                          : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                      }`}
                    >
                      <div className="flex items-center space-x-2">
                        <span>{category.icon}</span>
                        <span>{category.name}</span>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* FAQ Content */}
            <div className="lg:col-span-3">
              <div className="bg-gray-800 rounded-lg p-6">
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-xl font-semibold">
                    {activeCategory === 'all' 
                      ? 'All Frequently Asked Questions' 
                      : categories.find(cat => cat.id === activeCategory)?.name || 'FAQs'
                    }
                  </h2>
                  <span className="text-sm text-gray-400">
                    {filteredFAQs.length} question{filteredFAQs.length !== 1 ? 's' : ''}
                  </span>
                </div>

                {/* FAQ List */}
                <div className="space-y-4">
                  {filteredFAQs.length === 0 ? (
                    <div className="text-center py-8">
                      <div className="text-4xl mb-4">🔍</div>
                      <h3 className="text-lg font-semibold mb-2">No results found</h3>
                      <p className="text-gray-400">
                        Try adjusting your search terms or browse different categories.
                      </p>
                    </div>
                  ) : (
                    filteredFAQs.map((faq) => (
                      <div 
                        key={faq.id} 
                        className="border border-gray-700 rounded-lg overflow-hidden"
                      >
                        <button
                          onClick={() => toggleFAQ(faq.id)}
                          className="w-full text-left p-4 hover:bg-gray-700 transition-colors flex items-center justify-between"
                        >
                          <span className="font-medium">{faq.question}</span>
                          <svg 
                            className={`w-5 h-5 transform transition-transform ${
                              expandedFAQ === faq.id ? 'rotate-180' : ''
                            }`}
                            fill="none" 
                            stroke="currentColor" 
                            viewBox="0 0 24 24"
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7"></path>
                          </svg>
                        </button>
                        {expandedFAQ === faq.id && (
                          <div className="px-4 pb-4 border-t border-gray-700">
                            <p className="text-gray-300 leading-relaxed pt-4">
                              {faq.answer}
                            </p>
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Still Need Help */}
              <div className="bg-gray-800 rounded-lg p-6 mt-6">
                <h3 className="text-lg font-semibold mb-4">Still need help?</h3>
                <p className="text-gray-400 mb-4">
                  Can't find what you're looking for? Our support team is here to help.
                </p>
                <div className="flex flex-wrap gap-4">
                  <Link 
                    href="/contact"
                    className="bg-purple-600 hover:bg-purple-700 text-white px-6 py-2 rounded-lg font-semibold transition-colors"
                  >
                    Contact Support
                  </Link>
                  <Link 
                    href="/community"
                    className="bg-gray-600 hover:bg-gray-700 text-white px-6 py-2 rounded-lg font-semibold transition-colors"
                  >
                    Ask Community
                  </Link>
                  <button 
                    onClick={() => window.history.back()}
                    className="bg-gray-600 hover:bg-gray-700 text-white px-6 py-2 rounded-lg font-semibold transition-colors"
                  >
                    Go Back
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default HelpPage;
