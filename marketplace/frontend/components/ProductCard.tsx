import React from 'react';
import Link from 'next/link';
import { Product } from '../types';

interface ProductCardProps {
  product: Product;
  showSeller?: boolean;
}

export const ProductCard: React.FC<ProductCardProps> = ({ product, showSeller = true }) => {
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

  return (
    <Link href={`/product/${product.id}`}>
      <div className="bg-black/40 border border-amber-800/30 rounded-lg overflow-hidden hover:border-amber-600/50 transition-all duration-300 hover:shadow-lg hover:shadow-amber-900/20 cursor-pointer group">
        {/* Product Image */}
        <div className="relative h-48 bg-gray-900/50 overflow-hidden">
          {product.images && product.images.length > 0 ? (
            <img
              src={product.images[0]}
              alt={product.title}
              className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
            />
          ) : (
            <div className="w-full h-full flex items-center justify-center">
              <div className="text-gray-500 text-6xl">📦</div>
            </div>
          )}
          
          {/* Privacy Indicator */}
          <div className="absolute top-2 right-2">
            <div className="bg-black/70 text-amber-400 px-2 py-1 rounded text-xs flex items-center">
              🔒 Private
            </div>
          </div>

          {/* Category Badge */}
          <div className="absolute bottom-2 left-2">
            <span className={`px-2 py-1 rounded-full text-xs font-medium ${getCategoryColor(product.category)}`}>
              {product.category}
            </span>
          </div>
        </div>

        {/* Product Info */}
        <div className="p-4">
          <h3 className="text-amber-300 font-semibold text-lg mb-2 group-hover:text-amber-200 transition-colors">
            {product.title}
          </h3>
          
          <p className="text-gray-400 text-sm mb-3 line-clamp-2">
            {product.description}
          </p>

          <div className="flex justify-between items-center">
            <div className="text-amber-400 font-bold text-xl">
              {formatPrice(product.price)}
            </div>
            
            {showSeller && (
              <div className="text-gray-500 text-sm">
                by {product.seller.slice(0, 8)}...
              </div>
            )}
          </div>

          {/* Stock Status */}
          {product.stock !== undefined && (
            <div className="mt-2 flex items-center text-sm">
              {product.stock > 0 ? (
                <span className="text-green-400">✓ In Stock ({product.stock})</span>
              ) : (
                <span className="text-red-400">✗ Out of Stock</span>
              )}
            </div>
          )}

          {/* Rating if available */}
          {product.rating && (
            <div className="mt-2 flex items-center text-sm">
              <div className="flex text-amber-400">
                {Array.from({ length: 5 }, (_, i) => (
                  <span key={i} className={i < Math.floor(product.rating!) ? 'text-amber-400' : 'text-gray-600'}>
                    ★
                  </span>
                ))}
              </div>
              <span className="text-gray-500 ml-2">({product.rating.toFixed(1)})</span>
            </div>
          )}
        </div>
      </div>
    </Link>
  );
};

export default ProductCard;
