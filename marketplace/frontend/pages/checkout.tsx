import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/router';
import Head from 'next/head';
import Link from 'next/link';
import { 
  ShoppingCart, 
  NodeStatus, 
  EscrowStatus, 
  PrivacyIndicator,
  CommunityWarning 
} from '../components';
import { useAuth, useCart } from '../hooks';
import { Order, EscrowStatus as EscrowStatusEnum, PrivacyLevel } from '../types';

const CheckoutPage: React.FC = () => {
  const router = useRouter();
  const { user } = useAuth();
  const { items, total, clearCart } = useCart();
  const [isLoading, setIsLoading] = useState(false);
  const [escrowAddress, setEscrowAddress] = useState('');
  const [deliveryAddress, setDeliveryAddress] = useState('');
  const [encryptedNotes, setEncryptedNotes] = useState('');
  const [selectedShipping, setSelectedShipping] = useState('standard');
  const [agreedToTerms, setAgreedToTerms] = useState(false);
  const [showWarning, setShowWarning] = useState(true);

  // Redirect if cart is empty or user not authenticated
  useEffect(() => {
    if (!user) {
      router.push('/login?redirect=/checkout');
      return;
    }
    if (items.length === 0) {
      router.push('/');
      return;
    }
  }, [user, items, router]);

  const handlePlaceOrder = async () => {
    if (!agreedToTerms || !deliveryAddress || !escrowAddress) {
      alert('Please fill in all required fields and agree to terms');
      return;
    }

    setIsLoading(true);
    try {
      // Create order with escrow
      const orderData: Partial<Order> = {
        buyerId: user?.id,
        items: items.map(item => ({
          productId: item.product.id,
          quantity: item.quantity,
          price: item.product.price,
          sellerId: item.product.sellerId
        })),
        totalAmount: total,
        escrowStatus: EscrowStatusEnum.Pending,
        deliveryAddress: deliveryAddress,
        encryptedNotes: encryptedNotes,
        shippingMethod: selectedShipping,
        createdAt: new Date().toISOString()
      };

      // In real implementation, this would call the API
      const response = await fetch('/api/orders', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify(orderData)
      });

      if (response.ok) {
        const order = await response.json();
        clearCart();
        router.push(`/order/confirmation?id=${order.id}`);
      } else {
        throw new Error('Failed to create order');
      }
    } catch (error) {
      console.error('Order creation failed:', error);
      alert('Failed to place order. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const shippingOptions = [
    { id: 'standard', name: 'Standard Shipping', time: '7-14 days', price: 0.001 },
    { id: 'express', name: 'Express Shipping', time: '3-7 days', price: 0.003 },
    { id: 'overnight', name: 'Overnight Delivery', time: '1-2 days', price: 0.008 }
  ];

  if (!user || items.length === 0) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-500 mx-auto mb-4"></div>
          <p className="text-gray-300">Loading checkout...</p>
        </div>
      </div>
    );
  }

  return (
    <>
      <Head>
        <title>Checkout - BlackSilk Marketplace</title>
        <meta name="description" content="Complete your secure order on BlackSilk marketplace" />
      </Head>

      <div className="min-h-screen bg-gray-900 text-white">
        <div className="container mx-auto px-4 py-8">
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center space-x-4">
              <Link href="/" className="text-purple-400 hover:text-purple-300">
                ← Back to Marketplace
              </Link>
              <h1 className="text-3xl font-bold">Secure Checkout</h1>
              <PrivacyIndicator level={PrivacyLevel.High} />
            </div>
            <NodeStatus />
          </div>

          {/* Community Warning */}
          {showWarning && (
            <CommunityWarning 
              onDismiss={() => setShowWarning(false)}
              customMessage="Ensure all purchases comply with BlackSilk community standards. Remember: Don't be sick."
            />
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Order Summary */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-xl font-semibold mb-4">Order Summary</h2>
              
              <div className="space-y-4 mb-6">
                {items.map((item) => (
                  <div key={`${item.product.id}-${item.quantity}`} className="flex items-center space-x-4">
                    <img 
                      src={item.product.imageUrl} 
                      alt={item.product.name}
                      className="w-16 h-16 object-cover rounded-lg"
                    />
                    <div className="flex-1">
                      <h3 className="font-medium">{item.product.name}</h3>
                      <p className="text-gray-400">Quantity: {item.quantity}</p>
                      <p className="text-purple-400">{item.product.price} BSK each</p>
                    </div>
                    <div className="text-right">
                      <p className="font-semibold">{(item.product.price * item.quantity).toFixed(6)} BSK</p>
                    </div>
                  </div>
                ))}
              </div>

              {/* Shipping Options */}
              <div className="border-t border-gray-700 pt-4 mb-4">
                <h3 className="font-semibold mb-3">Shipping Options</h3>
                <div className="space-y-2">
                  {shippingOptions.map((option) => (
                    <label key={option.id} className="flex items-center justify-between p-3 border border-gray-600 rounded-lg cursor-pointer hover:border-purple-500">
                      <div className="flex items-center space-x-3">
                        <input
                          type="radio"
                          name="shipping"
                          value={option.id}
                          checked={selectedShipping === option.id}
                          onChange={(e) => setSelectedShipping(e.target.value)}
                          className="text-purple-500"
                        />
                        <div>
                          <p className="font-medium">{option.name}</p>
                          <p className="text-sm text-gray-400">{option.time}</p>
                        </div>
                      </div>
                      <p className="font-semibold">{option.price} BSK</p>
                    </label>
                  ))}
                </div>
              </div>

              {/* Total */}
              <div className="border-t border-gray-700 pt-4">
                <div className="flex justify-between items-center text-lg font-semibold">
                  <span>Total (including shipping):</span>
                  <span className="text-purple-400">
                    {(total + shippingOptions.find(opt => opt.id === selectedShipping)?.price || 0).toFixed(6)} BSK
                  </span>
                </div>
              </div>
            </div>

            {/* Checkout Form */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-xl font-semibold mb-4">Payment & Delivery</h2>
              
              <form className="space-y-6">
                {/* Escrow Address */}
                <div>
                  <label className="block text-sm font-medium mb-2">
                    Escrow Wallet Address *
                  </label>
                  <input
                    type="text"
                    value={escrowAddress}
                    onChange={(e) => setEscrowAddress(e.target.value)}
                    placeholder="Enter your BSK wallet address for escrow"
                    className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                    required
                  />
                  <p className="text-xs text-gray-400 mt-1">
                    Funds will be held in escrow until you confirm delivery
                  </p>
                </div>

                {/* Delivery Address */}
                <div>
                  <label className="block text-sm font-medium mb-2">
                    Encrypted Delivery Address *
                  </label>
                  <textarea
                    value={deliveryAddress}
                    onChange={(e) => setDeliveryAddress(e.target.value)}
                    placeholder="Enter your delivery address (will be encrypted)"
                    rows={3}
                    className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                    required
                  />
                  <p className="text-xs text-gray-400 mt-1">
                    Address will be encrypted before storage
                  </p>
                </div>

                {/* Special Instructions */}
                <div>
                  <label className="block text-sm font-medium mb-2">
                    Special Instructions (Optional)
                  </label>
                  <textarea
                    value={encryptedNotes}
                    onChange={(e) => setEncryptedNotes(e.target.value)}
                    placeholder="Any special delivery instructions..."
                    rows={2}
                    className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                  />
                </div>

                {/* Escrow Status Display */}
                <div className="bg-gray-700 rounded-lg p-4">
                  <h3 className="font-semibold mb-2">Escrow Protection</h3>
                  <EscrowStatus status={EscrowStatusEnum.Pending} />
                  <p className="text-sm text-gray-400 mt-2">
                    Your payment will be secured in escrow until delivery is confirmed.
                    This protects both buyer and seller.
                  </p>
                </div>

                {/* Terms Agreement */}
                <div className="flex items-start space-x-3">
                  <input
                    type="checkbox"
                    checked={agreedToTerms}
                    onChange={(e) => setAgreedToTerms(e.target.checked)}
                    className="mt-1 text-purple-500"
                  />
                  <label className="text-sm text-gray-300">
                    I agree to the{' '}
                    <Link href="/terms" className="text-purple-400 hover:text-purple-300">
                      Terms of Service
                    </Link>{' '}
                    and{' '}
                    <Link href="/privacy" className="text-purple-400 hover:text-purple-300">
                      Privacy Policy
                    </Link>
                    . I understand that all transactions are final and payments are held in escrow.
                  </label>
                </div>

                {/* Place Order Button */}
                <button
                  type="button"
                  onClick={handlePlaceOrder}
                  disabled={isLoading || !agreedToTerms || !deliveryAddress || !escrowAddress}
                  className="w-full bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-semibold py-3 px-6 rounded-lg transition-colors"
                >
                  {isLoading ? (
                    <div className="flex items-center justify-center space-x-2">
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                      <span>Processing Order...</span>
                    </div>
                  ) : (
                    `Place Order (${(total + shippingOptions.find(opt => opt.id === selectedShipping)?.price || 0).toFixed(6)} BSK)`
                  )}
                </button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default CheckoutPage;
