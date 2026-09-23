import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/router';
import Head from 'next/head';
import Link from 'next/link';
import { 
  OrderTracking, 
  NodeStatus, 
  EscrowStatus, 
  PrivacyIndicator 
} from '../../components';
import { useAuth } from '../../hooks';
import { Order, EscrowStatus as EscrowStatusEnum, OrderStatus, PrivacyLevel } from '../../types';

const OrderConfirmationPage: React.FC = () => {
  const router = useRouter();
  const { id } = router.query;
  const { user } = useAuth();
  const [order, setOrder] = useState<Order | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!user) {
      router.push('/login');
      return;
    }

    if (id) {
      fetchOrder(id as string);
    }
  }, [user, id, router]);

  const fetchOrder = async (orderId: string) => {
    try {
      // In real implementation, this would call the API
      const response = await fetch(`/api/orders/${orderId}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (response.ok) {
        const orderData = await response.json();
        setOrder(orderData);
      } else {
        throw new Error('Order not found');
      }
    } catch (error) {
      console.error('Failed to fetch order:', error);
      // For demo purposes, create a mock order
      const mockOrder: Order = {
        id: orderId,
        buyer: user?.id || '',
        seller: 'seller_1',
        items: [
          {
            productId: 'prod_1',
            productTitle: 'Sample Product',
            quantity: 2,
            price: 0.145,
            seller: 'seller_1'
          }
        ],
        totalAmount: 0.293,
        escrowStatus: EscrowStatusEnum.Pending,
        status: OrderStatus.AwaitingPayment,
        createdAt: Date.now(),
        updatedAt: Date.now()
      };
      setOrder(mockOrder);
    } finally {
      setIsLoading(false);
    }
  };

  const copyOrderId = () => {
    if (order?.id) {
      navigator.clipboard.writeText(order.id);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const getEstimatedDelivery = () => {
    const shippingDays = {
      'standard': 14,
      'express': 7,
      'overnight': 2
    };
    
    const days = shippingDays['standard']; // Default to standard shipping
    const deliveryDate = new Date();
    deliveryDate.setDate(deliveryDate.getDate() + days);
    
    return deliveryDate.toLocaleDateString('en-US', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-500 mx-auto mb-4"></div>
          <p className="text-gray-300">Loading order confirmation...</p>
        </div>
      </div>
    );
  }

  if (!order) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-red-400 mb-4">Order Not Found</h1>
          <p className="text-gray-300 mb-6">The order you're looking for doesn't exist or you don't have permission to view it.</p>
          <Link href="/dashboard" className="bg-purple-600 hover:bg-purple-700 text-white px-6 py-2 rounded-lg">
            Go to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  return (
    <>
      <Head>
        <title>Order Confirmation - BlackSilk Marketplace</title>
        <meta name="description" content="Your order has been placed successfully" />
      </Head>

      <div className="min-h-screen bg-gray-900 text-white">
        <div className="container mx-auto px-4 py-8">
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center space-x-4">
              <h1 className="text-3xl font-bold text-green-400">Order Confirmed!</h1>
              <PrivacyIndicator level={PrivacyLevel.High} />
            </div>
            <NodeStatus />
          </div>

          {/* Success Message */}
          <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-6 mb-8">
            <div className="flex items-center space-x-3 mb-4">
              <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center">
                <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                </svg>
              </div>
              <h2 className="text-xl font-semibold text-green-400">Your order has been placed successfully!</h2>
            </div>
            <p className="text-gray-300">
              Your payment has been secured in escrow and the seller has been notified. 
              You'll receive updates as your order progresses through the fulfillment process.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Order Details */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-xl font-semibold mb-4">Order Details</h2>
              
              {/* Order ID */}
              <div className="mb-6">
                <label className="block text-sm font-medium text-gray-400 mb-2">Order ID</label>
                <div className="flex items-center space-x-2">
                  <code className="bg-gray-700 px-3 py-2 rounded text-purple-400 font-mono text-sm flex-1">
                    {order.id}
                  </code>
                  <button
                    onClick={copyOrderId}
                    className="bg-purple-600 hover:bg-purple-700 px-3 py-2 rounded text-sm transition-colors"
                  >
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>

              {/* Order Items */}
              <div className="mb-6">
                <h3 className="font-semibold mb-3">Items Ordered</h3>
                <div className="space-y-3">
                  {order.items.map((item, index) => (
                    <div key={index} className="flex items-center justify-between p-3 bg-gray-700 rounded-lg">
                      <div>
                        <p className="font-medium">Product ID: {item.productId}</p>
                        <p className="text-sm text-gray-400">Quantity: {item.quantity}</p>
                        <p className="text-sm text-gray-400">Seller: {item.seller}</p>
                      </div>
                      <div className="text-right">
                        <p className="font-semibold">{item.price} BSK each</p>
                        <p className="text-purple-400">{(item.price * item.quantity).toFixed(6)} BSK total</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Order Summary */}
              <div className="border-t border-gray-700 pt-4">
                <div className="flex justify-between items-center mb-2">
                  <span>Subtotal:</span>
                  <span>{order.totalAmount.toFixed(6)} BSK</span>
                </div>
                <div className="flex justify-between items-center mb-2">
                  <span>Shipping:</span>
                  <span>0.001 BSK</span>
                </div>
                <div className="flex justify-between items-center text-lg font-semibold border-t border-gray-700 pt-2">
                  <span>Total:</span>
                  <span className="text-purple-400">{(order.totalAmount + 0.001).toFixed(6)} BSK</span>
                </div>
              </div>

              {/* Estimated Delivery */}
              <div className="mt-6 p-4 bg-gray-700 rounded-lg">
                <h3 className="font-semibold mb-2">Estimated Delivery</h3>
                <p className="text-purple-400 font-medium">{getEstimatedDelivery()}</p>
                <p className="text-sm text-gray-400 mt-1">
                  Standard shipping (14 days)
                </p>
              </div>
            </div>

            {/* Order Tracking & Escrow */}
            <div className="space-y-6">
              {/* Escrow Status */}
              <div className="bg-gray-800 rounded-lg p-6">
                <h2 className="text-xl font-semibold mb-4">Escrow Protection</h2>
                <EscrowStatus 
                  status={order.escrowStatus}
                  escrowAddress={order.escrowAddress || 'pending...'}
                  amount={order.totalAmount}
                />
                <div className="mt-4 p-4 bg-gray-700 rounded-lg">
                  <h3 className="font-semibold mb-2">How Escrow Works</h3>
                  <ol className="text-sm text-gray-300 space-y-1">
                    <li>1. Your payment is held securely in escrow</li>
                    <li>2. Seller prepares and ships your order</li>
                    <li>3. You receive the package and confirm delivery</li>
                    <li>4. Payment is released to the seller</li>
                  </ol>
                </div>
              </div>

              {/* Order Tracking */}
              <div className="bg-gray-800 rounded-lg p-6">
                <h2 className="text-xl font-semibold mb-4">Order Tracking</h2>
                <OrderTracking order={order} />
              </div>

              {/* Next Steps */}
              <div className="bg-gray-800 rounded-lg p-6">
                <h2 className="text-xl font-semibold mb-4">What's Next?</h2>
                <div className="space-y-3 text-sm">
                  <div className="flex items-start space-x-3">
                    <div className="w-6 h-6 bg-purple-600 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                      <span className="text-xs font-bold">1</span>
                    </div>
                    <div>
                      <p className="font-medium">Seller Notification</p>
                      <p className="text-gray-400">The seller has been notified of your order and will begin processing it.</p>
                    </div>
                  </div>
                  <div className="flex items-start space-x-3">
                    <div className="w-6 h-6 bg-gray-600 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                      <span className="text-xs font-bold">2</span>
                    </div>
                    <div>
                      <p className="font-medium">Order Preparation</p>
                      <p className="text-gray-400">Your items will be prepared and packaged for shipping.</p>
                    </div>
                  </div>
                  <div className="flex items-start space-x-3">
                    <div className="w-6 h-6 bg-gray-600 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                      <span className="text-xs font-bold">3</span>
                    </div>
                    <div>
                      <p className="font-medium">Shipment & Tracking</p>
                      <p className="text-gray-400">You'll receive tracking information once the package ships.</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap gap-4 mt-8 justify-center">
            <Link 
              href="/dashboard"
              className="bg-purple-600 hover:bg-purple-700 text-white px-6 py-3 rounded-lg font-semibold transition-colors"
            >
              View in Dashboard
            </Link>
            <Link 
              href="/"
              className="bg-gray-600 hover:bg-gray-700 text-white px-6 py-3 rounded-lg font-semibold transition-colors"
            >
              Continue Shopping
            </Link>
            <button 
              onClick={() => window.print()}
              className="bg-gray-600 hover:bg-gray-700 text-white px-6 py-3 rounded-lg font-semibold transition-colors"
            >
              Print Confirmation
            </button>
          </div>
        </div>
      </div>
    </>
  );
};

export default OrderConfirmationPage;
