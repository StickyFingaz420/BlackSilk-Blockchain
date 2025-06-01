import React, { useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { NodeStatus, PrivacyIndicator, CommunityWarning } from '../components';
import { useAuth } from '../hooks';
import { PrivacyLevel } from '../types';

const ContactPage: React.FC = () => {
  const { user } = useAuth();
  const [formData, setFormData] = useState({
    name: user?.username || '',
    email: '',
    subject: '',
    category: 'general',
    message: '',
    priority: 'normal'
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [showWarning, setShowWarning] = useState(true);

  const categories = [
    { value: 'general', label: 'General Inquiry' },
    { value: 'technical', label: 'Technical Support' },
    { value: 'account', label: 'Account Issues' },
    { value: 'payment', label: 'Payment & Escrow' },
    { value: 'dispute', label: 'Order Dispute' },
    { value: 'security', label: 'Security Concern' },
    { value: 'seller', label: 'Seller Support' },
    { value: 'report', label: 'Report Violation' }
  ];

  const priorities = [
    { value: 'low', label: 'Low', description: 'General questions' },
    { value: 'normal', label: 'Normal', description: 'Standard support' },
    { value: 'high', label: 'High', description: 'Account/payment issues' },
    { value: 'urgent', label: 'Urgent', description: 'Security/safety concerns' }
  ];

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);

    try {
      // In real implementation, this would call the API
      const response = await fetch('/api/support/contact', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': user ? `Bearer ${localStorage.getItem('token')}` : ''
        },
        body: JSON.stringify({
          ...formData,
          userId: user?.id,
          timestamp: new Date().toISOString()
        })
      });

      if (response.ok) {
        setSubmitted(true);
        setFormData({
          name: user?.username || '',
          email: '',
          subject: '',
          category: 'general',
          message: '',
          priority: 'normal'
        });
      } else {
        throw new Error('Failed to submit contact form');
      }
    } catch (error) {
      console.error('Contact form submission failed:', error);
      alert('Failed to submit your message. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (submitted) {
    return (
      <>
        <Head>
          <title>Message Sent - BlackSilk Marketplace</title>
          <meta name="description" content="Your message has been sent to BlackSilk support" />
        </Head>

        <div className="min-h-screen bg-gray-900 text-white">
          <div className="container mx-auto px-4 py-8">
            <div className="flex items-center justify-between mb-8">
              <div className="flex items-center space-x-4">
                <Link href="/" className="text-purple-400 hover:text-purple-300">
                  ← Back to Marketplace
                </Link>
                <PrivacyIndicator level={PrivacyLevel.High} />
              </div>
              <NodeStatus />
            </div>

            <div className="max-w-2xl mx-auto text-center py-20">
              <div className="w-16 h-16 bg-green-500 rounded-full flex items-center justify-center mx-auto mb-6">
                <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                </svg>
              </div>
              
              <h1 className="text-3xl font-bold text-green-400 mb-4">Message Sent Successfully!</h1>
              <p className="text-gray-300 mb-8">
                Thank you for contacting BlackSilk support. We've received your message and will respond 
                within 24 hours. For urgent matters, please check our help center or community forums.
              </p>

              <div className="flex flex-wrap gap-4 justify-center">
                <Link 
                  href="/help"
                  className="bg-purple-600 hover:bg-purple-700 text-white px-6 py-3 rounded-lg font-semibold transition-colors"
                >
                  Browse Help Center
                </Link>
                <Link 
                  href="/dashboard"
                  className="bg-gray-600 hover:bg-gray-700 text-white px-6 py-3 rounded-lg font-semibold transition-colors"
                >
                  Go to Dashboard
                </Link>
                <button
                  onClick={() => setSubmitted(false)}
                  className="bg-gray-600 hover:bg-gray-700 text-white px-6 py-3 rounded-lg font-semibold transition-colors"
                >
                  Send Another Message
                </button>
              </div>
            </div>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <Head>
        <title>Contact Support - BlackSilk Marketplace</title>
        <meta name="description" content="Get help from BlackSilk support team" />
      </Head>

      <div className="min-h-screen bg-gray-900 text-white">
        <div className="container mx-auto px-4 py-8">
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center space-x-4">
              <Link href="/" className="text-purple-400 hover:text-purple-300">
                ← Back to Marketplace
              </Link>
              <h1 className="text-3xl font-bold">Contact Support</h1>
              <PrivacyIndicator level={PrivacyLevel.High} />
            </div>
            <NodeStatus />
          </div>

          {/* Community Warning */}
          {showWarning && (
            <CommunityWarning 
              onDismiss={() => setShowWarning(false)}
              customMessage="For fastest support, check our Help Center first. Emergency security issues get priority response."
            />
          )}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Contact Info */}
            <div className="lg:col-span-1">
              <div className="bg-gray-800 rounded-lg p-6">
                <h2 className="text-xl font-semibold mb-4">Get Help Fast</h2>
                
                <div className="space-y-4 mb-6">
                  <Link href="/help" className="flex items-center space-x-3 p-3 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors">
                    <div className="w-8 h-8 bg-purple-600 rounded-full flex items-center justify-center">
                      <span className="text-sm">❓</span>
                    </div>
                    <div>
                      <h3 className="font-medium">Help Center</h3>
                      <p className="text-sm text-gray-400">Browse FAQs and guides</p>
                    </div>
                  </Link>

                  <Link href="/community" className="flex items-center space-x-3 p-3 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors">
                    <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center">
                      <span className="text-sm">👥</span>
                    </div>
                    <div>
                      <h3 className="font-medium">Community Forums</h3>
                      <p className="text-sm text-gray-400">Ask other users</p>
                    </div>
                  </Link>

                  <Link href="/status" className="flex items-center space-x-3 p-3 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors">
                    <div className="w-8 h-8 bg-green-600 rounded-full flex items-center justify-center">
                      <span className="text-sm">📊</span>
                    </div>
                    <div>
                      <h3 className="font-medium">System Status</h3>
                      <p className="text-sm text-gray-400">Check service health</p>
                    </div>
                  </Link>
                </div>

                <div className="border-t border-gray-700 pt-4">
                  <h3 className="font-semibold mb-2">Response Times</h3>
                  <div className="text-sm text-gray-400 space-y-1">
                    <div className="flex justify-between">
                      <span>Urgent:</span>
                      <span className="text-red-400">2-4 hours</span>
                    </div>
                    <div className="flex justify-between">
                      <span>High:</span>
                      <span className="text-yellow-400">8-12 hours</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Normal:</span>
                      <span className="text-green-400">24 hours</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Low:</span>
                      <span className="text-gray-400">48-72 hours</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Contact Form */}
            <div className="lg:col-span-2">
              <div className="bg-gray-800 rounded-lg p-6">
                <h2 className="text-xl font-semibold mb-6">Send us a Message</h2>

                <form onSubmit={handleSubmit} className="space-y-6">
                  {/* Name and Email */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium mb-2">
                        Name *
                      </label>
                      <input
                        type="text"
                        name="name"
                        value={formData.name}
                        onChange={handleInputChange}
                        required
                        className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium mb-2">
                        Email Address *
                      </label>
                      <input
                        type="email"
                        name="email"
                        value={formData.email}
                        onChange={handleInputChange}
                        required
                        className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                      />
                    </div>
                  </div>

                  {/* Category and Priority */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium mb-2">
                        Category *
                      </label>
                      <select
                        name="category"
                        value={formData.category}
                        onChange={handleInputChange}
                        required
                        className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                      >
                        {categories.map((cat) => (
                          <option key={cat.value} value={cat.value}>
                            {cat.label}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm font-medium mb-2">
                        Priority *
                      </label>
                      <select
                        name="priority"
                        value={formData.priority}
                        onChange={handleInputChange}
                        required
                        className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                      >
                        {priorities.map((priority) => (
                          <option key={priority.value} value={priority.value}>
                            {priority.label} - {priority.description}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>

                  {/* Subject */}
                  <div>
                    <label className="block text-sm font-medium mb-2">
                      Subject *
                    </label>
                    <input
                      type="text"
                      name="subject"
                      value={formData.subject}
                      onChange={handleInputChange}
                      required
                      placeholder="Brief description of your issue"
                      className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                    />
                  </div>

                  {/* Message */}
                  <div>
                    <label className="block text-sm font-medium mb-2">
                      Message *
                    </label>
                    <textarea
                      name="message"
                      value={formData.message}
                      onChange={handleInputChange}
                      required
                      rows={6}
                      placeholder="Please provide detailed information about your issue, including any error messages, steps you've tried, and relevant order/product IDs..."
                      className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                    />
                    <p className="text-xs text-gray-400 mt-1">
                      Be specific to help us assist you faster. Include order IDs, error messages, and steps taken.
                    </p>
                  </div>

                  {/* Privacy Notice */}
                  <div className="bg-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-2 flex items-center">
                      <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                      </svg>
                      Privacy Notice
                    </h3>
                    <p className="text-sm text-gray-300">
                      Your message will be encrypted and only viewed by authorized support staff. 
                      We never share personal information with third parties.
                    </p>
                  </div>

                  {/* Submit Button */}
                  <button
                    type="submit"
                    disabled={isSubmitting}
                    className="w-full bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-semibold py-3 px-6 rounded-lg transition-colors"
                  >
                    {isSubmitting ? (
                      <div className="flex items-center justify-center space-x-2">
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                        <span>Sending Message...</span>
                      </div>
                    ) : (
                      'Send Message'
                    )}
                  </button>
                </form>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default ContactPage;
