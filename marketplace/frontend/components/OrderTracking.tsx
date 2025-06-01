import React, { useState } from 'react';
import { Order, EscrowStatus } from '../types';

interface OrderTrackingProps {
  order: Order;
  onAction?: (action: string, orderId: string) => void;
}

export const OrderTracking: React.FC<OrderTrackingProps> = ({ order, onAction }) => {
  const getStatusColor = (status: EscrowStatus) => {
    switch (status) {
      case 'pending':
        return 'text-yellow-400 bg-yellow-900/20';
      case 'funded':
        return 'text-blue-400 bg-blue-900/20';
      case 'completed':
        return 'text-green-400 bg-green-900/20';
      case 'disputed':
        return 'text-red-400 bg-red-900/20';
      case 'refunded':
        return 'text-gray-400 bg-gray-900/20';
      default:
        return 'text-gray-400 bg-gray-900/20';
    }
  };

  const getStatusIcon = (status: EscrowStatus) => {
    switch (status) {
      case 'pending':
        return '⏳';
      case 'funded':
        return '💰';
      case 'completed':
        return '✅';
      case 'disputed':
        return '⚖️';
      case 'refunded':
        return '↩️';
      default:
        return '❓';
    }
  };

  const getStatusText = (status: EscrowStatus) => {
    switch (status) {
      case 'pending':
        return 'Awaiting Payment';
      case 'funded':
        return 'Payment Confirmed';
      case 'completed':
        return 'Order Completed';
      case 'disputed':
        return 'Under Dispute';
      case 'refunded':
        return 'Refunded';
      default:
        return 'Unknown Status';
    }
  };

  const formatDate = (timestamp: number) => {
    return new Date(timestamp * 1000).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getProgressPercentage = (status: EscrowStatus) => {
    switch (status) {
      case 'pending':
        return 25;
      case 'funded':
        return 50;
      case 'completed':
        return 100;
      case 'disputed':
        return 75;
      case 'refunded':
        return 100;
      default:
        return 0;
    }
  };

  return (
    <div className="bg-black/40 border border-amber-800/30 rounded-lg p-6">
      {/* Order Header */}
      <div className="flex justify-between items-start mb-6">
        <div>
          <h3 className="text-amber-300 text-lg font-semibold mb-1">
            Order #{order.id.slice(0, 8)}...
          </h3>
          <p className="text-gray-400 text-sm">
            Placed {formatDate(order.createdAt)}
          </p>
        </div>
        
        <div className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(order.escrowStatus)}`}>
          {getStatusIcon(order.escrowStatus)} {getStatusText(order.escrowStatus)}
        </div>
      </div>

      {/* Progress Bar */}
      <div className="mb-6">
        <div className="flex justify-between text-xs text-gray-400 mb-2">
          <span>Order Progress</span>
          <span>{getProgressPercentage(order.escrowStatus)}%</span>
        </div>
        <div className="w-full bg-gray-800 rounded-full h-2">
          <div 
            className="bg-amber-500 h-2 rounded-full transition-all duration-500"
            style={{ width: `${getProgressPercentage(order.escrowStatus)}%` }}
          ></div>
        </div>
      </div>

      {/* Order Items */}
      <div className="space-y-3 mb-6">
        {order.items.map((item, index) => (
          <div key={index} className="flex items-center space-x-4 p-3 bg-gray-900/30 rounded-lg">
            <div className="w-12 h-12 bg-gray-700 rounded-lg flex items-center justify-center">
              📦
            </div>
            <div className="flex-1">
              <h4 className="text-amber-300 font-medium">{item.productTitle}</h4>
              <p className="text-gray-400 text-sm">
                Quantity: {item.quantity} × {item.price.toFixed(3)} BLK
              </p>
            </div>
            <div className="text-amber-400 font-semibold">
              {(item.quantity * item.price).toFixed(3)} BLK
            </div>
          </div>
        ))}
      </div>

      {/* Order Details */}
      <div className="grid grid-cols-2 gap-4 mb-6 text-sm">
        <div>
          <div className="text-gray-400">Total Amount</div>
          <div className="text-amber-300 font-semibold">
            {order.totalAmount.toFixed(3)} BLK
          </div>
        </div>
        
        <div>
          <div className="text-gray-400">Escrow Address</div>
          <div className="text-amber-300 font-mono text-xs">
            {order.escrowAddress?.slice(0, 12)}...
          </div>
        </div>
        
        <div>
          <div className="text-gray-400">Seller</div>
          <div className="text-amber-300 font-mono text-xs">
            {order.seller.slice(0, 12)}...
          </div>
        </div>
        
        <div>
          <div className="text-gray-400">Dispute Deadline</div>
          <div className="text-amber-300 text-xs">
            {order.disputeDeadline ? formatDate(order.disputeDeadline) : 'N/A'}
          </div>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="flex space-x-3">
        {order.escrowStatus === 'pending' && (
          <button
            onClick={() => onAction?.('pay', order.id)}
            className="flex-1 bg-amber-900/50 hover:bg-amber-800/50 text-amber-300 px-4 py-2 rounded-lg font-semibold transition-colors"
          >
            Complete Payment
          </button>
        )}
        
        {order.escrowStatus === 'funded' && (
          <>
            <button
              onClick={() => onAction?.('confirm', order.id)}
              className="flex-1 bg-green-900/50 hover:bg-green-800/50 text-green-300 px-4 py-2 rounded-lg font-semibold transition-colors"
            >
              Confirm Receipt
            </button>
            <button
              onClick={() => onAction?.('dispute', order.id)}
              className="flex-1 bg-red-900/50 hover:bg-red-800/50 text-red-300 px-4 py-2 rounded-lg font-semibold transition-colors"
            >
              Open Dispute
            </button>
          </>
        )}
        
        {order.escrowStatus === 'disputed' && (
          <div className="flex-1 text-center text-gray-400 py-2">
            Dispute in progress - awaiting DAO resolution
          </div>
        )}
        
        {(order.escrowStatus === 'completed' || order.escrowStatus === 'refunded') && (
          <div className="flex-1 text-center text-gray-400 py-2">
            Order {order.escrowStatus}
          </div>
        )}
      </div>

      {/* Privacy Notice */}
      <div className="mt-4 pt-4 border-t border-amber-800/20">
        <div className="flex items-center text-xs text-gray-500">
          <span className="mr-2">🔒</span>
          <span>All transactions are private and secured by blockchain escrow</span>
        </div>
      </div>
    </div>
  );
};

interface EscrowStatusProps {
  escrowAddress: string;
  status: EscrowStatus;
  amount: number;
  disputeDeadline?: number;
  className?: string;
}

export const EscrowStatus: React.FC<EscrowStatusProps> = ({
  escrowAddress,
  status,
  amount,
  disputeDeadline,
  className = ''
}) => {
  const getStatusConfig = () => {
    switch (status) {
      case 'pending':
        return {
          color: 'text-yellow-400',
          bg: 'bg-yellow-900/20',
          border: 'border-yellow-700/50',
          icon: '⏳',
          text: 'Pending Payment'
        };
      case 'funded':
        return {
          color: 'text-blue-400',
          bg: 'bg-blue-900/20',
          border: 'border-blue-700/50',
          icon: '💰',
          text: 'Funds Secured'
        };
      case 'completed':
        return {
          color: 'text-green-400',
          bg: 'bg-green-900/20',
          border: 'border-green-700/50',
          icon: '✅',
          text: 'Released to Seller'
        };
      case 'disputed':
        return {
          color: 'text-red-400',
          bg: 'bg-red-900/20',
          border: 'border-red-700/50',
          icon: '⚖️',
          text: 'Under Dispute'
        };
      case 'refunded':
        return {
          color: 'text-gray-400',
          bg: 'bg-gray-900/20',
          border: 'border-gray-700/50',
          icon: '↩️',
          text: 'Refunded to Buyer'
        };
      default:
        return {
          color: 'text-gray-400',
          bg: 'bg-gray-900/20',
          border: 'border-gray-700/50',
          icon: '❓',
          text: 'Unknown Status'
        };
    }
  };

  const config = getStatusConfig();

  return (
    <div className={`${config.bg} ${config.border} border rounded-lg p-4 ${className}`}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center space-x-2">
          <span className="text-lg">{config.icon}</span>
          <div className={`${config.color} font-semibold`}>
            {config.text}
          </div>
        </div>
        
        <div className="text-amber-300 font-semibold">
          {amount.toFixed(3)} BLK
        </div>
      </div>
      
      <div className="space-y-2 text-sm">
        <div className="flex justify-between">
          <span className="text-gray-400">Escrow Address:</span>
          <span className="text-amber-300 font-mono">
            {escrowAddress.slice(0, 12)}...
          </span>
        </div>
        
        {disputeDeadline && (
          <div className="flex justify-between">
            <span className="text-gray-400">Dispute Deadline:</span>
            <span className="text-amber-300">
              {new Date(disputeDeadline * 1000).toLocaleDateString()}
            </span>
          </div>
        )}
      </div>
    </div>
  );
};

export default OrderTracking;
