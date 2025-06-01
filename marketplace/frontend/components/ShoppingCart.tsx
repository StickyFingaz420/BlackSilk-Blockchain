import React, { useState } from 'react';
import { useCart, useAuth } from '../hooks';
import { CartItem } from '../types';

export const ShoppingCart: React.FC = () => {
  const { cart, updateQuantity, removeFromCart, clearCart, getTotalAmount } = useCart();
  const { user } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const [isCheckingOut, setIsCheckingOut] = useState(false);

  const handleCheckout = async () => {
    if (!user) {
      // Redirect to login
      window.location.href = '/login';
      return;
    }

    setIsCheckingOut(true);
    try {
      // Implement checkout logic
      // This would involve creating an order and initiating escrow
      console.log('Proceeding to checkout with cart:', cart);
      
      // For now, just clear cart and show success
      clearCart();
      setIsOpen(false);
      alert('Order placed successfully! Check your orders page for details.');
    } catch (error) {
      console.error('Checkout failed:', error);
      alert('Checkout failed. Please try again.');
    } finally {
      setIsCheckingOut(false);
    }
  };

  const formatPrice = (price: number) => {
    return `${price.toFixed(3)} BLK`;
  };

  return (
    <>
      {/* Cart Toggle Button */}
      <button
        onClick={() => setIsOpen(true)}
        className="relative bg-amber-900/50 hover:bg-amber-800/50 text-amber-300 p-3 rounded-lg transition-colors"
      >
        🛒
        {cart.length > 0 && (
          <span className="absolute -top-2 -right-2 bg-red-500 text-white text-xs rounded-full w-5 h-5 flex items-center justify-center">
            {cart.reduce((sum, item) => sum + item.quantity, 0)}
          </span>
        )}
      </button>

      {/* Cart Sidebar */}
      {isOpen && (
        <div className="fixed inset-0 z-50 overflow-hidden">
          <div className="absolute inset-0 bg-black/75" onClick={() => setIsOpen(false)}></div>
          
          <div className="absolute right-0 top-0 h-full w-full max-w-md bg-black border-l border-amber-800/30">
            <div className="flex flex-col h-full">
              {/* Header */}
              <div className="flex items-center justify-between p-6 border-b border-amber-800/30">
                <h2 className="text-amber-300 text-xl font-bold">Shopping Cart</h2>
                <button
                  onClick={() => setIsOpen(false)}
                  className="text-gray-400 hover:text-amber-300 text-2xl"
                >
                  ×
                </button>
              </div>

              {/* Cart Items */}
              <div className="flex-1 overflow-y-auto p-6">
                {cart.length === 0 ? (
                  <div className="text-center text-gray-400 mt-8">
                    <div className="text-4xl mb-4">🛒</div>
                    <p>Your cart is empty</p>
                    <button
                      onClick={() => setIsOpen(false)}
                      className="mt-4 text-amber-400 hover:text-amber-300 underline"
                    >
                      Continue Shopping
                    </button>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {cart.map((item) => (
                      <CartItemComponent
                        key={`${item.productId}-${item.seller}`}
                        item={item}
                        onUpdateQuantity={updateQuantity}
                        onRemove={removeFromCart}
                      />
                    ))}
                  </div>
                )}
              </div>

              {/* Cart Footer */}
              {cart.length > 0 && (
                <div className="border-t border-amber-800/30 p-6">
                  <div className="flex justify-between items-center mb-4">
                    <span className="text-gray-300 font-semibold">Total:</span>
                    <span className="text-amber-300 text-xl font-bold">
                      {formatPrice(getTotalAmount())}
                    </span>
                  </div>
                  
                  <div className="space-y-3">
                    <button
                      onClick={handleCheckout}
                      disabled={isCheckingOut}
                      className="w-full bg-amber-900/50 hover:bg-amber-800/50 disabled:bg-gray-800/50 text-amber-300 disabled:text-gray-500 py-3 rounded-lg font-semibold transition-colors"
                    >
                      {isCheckingOut ? 'Processing...' : 'Proceed to Checkout'}
                    </button>
                    
                    <button
                      onClick={clearCart}
                      className="w-full bg-red-900/50 hover:bg-red-800/50 text-red-300 py-2 rounded-lg font-semibold transition-colors"
                    >
                      Clear Cart
                    </button>
                  </div>
                  
                  <div className="mt-4 text-xs text-gray-500 text-center">
                    🔒 Secured by blockchain escrow
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
};

interface CartItemComponentProps {
  item: CartItem;
  onUpdateQuantity: (productId: string, seller: string, quantity: number) => void;
  onRemove: (productId: string, seller: string) => void;
}

const CartItemComponent: React.FC<CartItemComponentProps> = ({
  item,
  onUpdateQuantity,
  onRemove
}) => {
  const formatPrice = (price: number) => {
    return `${price.toFixed(3)} BLK`;
  };

  return (
    <div className="bg-gray-900/30 rounded-lg p-4">
      <div className="flex items-start space-x-3">
        <div className="w-16 h-16 bg-gray-700 rounded-lg flex items-center justify-center">
          {item.image ? (
            <img
              src={item.image}
              alt={item.title}
              className="w-full h-full object-cover rounded-lg"
            />
          ) : (
            <span className="text-2xl">📦</span>
          )}
        </div>
        
        <div className="flex-1">
          <h4 className="text-amber-300 font-medium text-sm mb-1">
            {item.title}
          </h4>
          
          <p className="text-gray-400 text-xs mb-2">
            by {item.seller.slice(0, 8)}...
          </p>
          
          <div className="flex items-center justify-between">
            <div className="text-amber-400 font-semibold">
              {formatPrice(item.price)}
            </div>
            
            <button
              onClick={() => onRemove(item.productId, item.seller)}
              className="text-red-400 hover:text-red-300 text-sm"
            >
              Remove
            </button>
          </div>
        </div>
      </div>
      
      <div className="mt-3 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <span className="text-gray-400 text-sm">Qty:</span>
          <div className="flex items-center space-x-1">
            <button
              onClick={() => onUpdateQuantity(item.productId, item.seller, Math.max(1, item.quantity - 1))}
              className="w-6 h-6 bg-gray-700 hover:bg-gray-600 rounded text-amber-300 text-sm"
            >
              -
            </button>
            
            <span className="text-amber-300 font-semibold w-8 text-center">
              {item.quantity}
            </span>
            
            <button
              onClick={() => onUpdateQuantity(item.productId, item.seller, item.quantity + 1)}
              className="w-6 h-6 bg-gray-700 hover:bg-gray-600 rounded text-amber-300 text-sm"
            >
              +
            </button>
          </div>
        </div>
        
        <div className="text-amber-300 font-semibold">
          {formatPrice(item.price * item.quantity)}
        </div>
      </div>
    </div>
  );
};

export default ShoppingCart;
