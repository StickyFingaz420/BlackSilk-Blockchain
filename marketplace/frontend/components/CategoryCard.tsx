import React from 'react';
import Link from 'next/link';

interface CategoryCardProps {
  id: string;
  name: string;
  description: string;
  icon: string;
  productCount: number;
  color: string;
}

export const CategoryCard: React.FC<CategoryCardProps> = ({
  id,
  name,
  description,
  icon,
  productCount,
  color
}) => {
  return (
    <Link href={`/category/${id}`}>
      <div className={`bg-black/40 border border-amber-800/30 rounded-lg p-6 hover:border-amber-600/50 transition-all duration-300 hover:shadow-lg hover:shadow-amber-900/20 cursor-pointer group ${color}`}>
        <div className="text-center">
          <div className="text-4xl mb-4 group-hover:scale-110 transition-transform duration-300">
            {icon}
          </div>
          
          <h3 className="text-amber-300 font-bold text-xl mb-2 group-hover:text-amber-200 transition-colors">
            {name}
          </h3>
          
          <p className="text-gray-400 text-sm mb-4">
            {description}
          </p>
          
          <div className="text-amber-500 font-semibold">
            {productCount} {productCount === 1 ? 'item' : 'items'}
          </div>
          
          <div className="mt-4 text-xs text-gray-500 flex items-center justify-center">
            🔒 Private & Secure
          </div>
        </div>
      </div>
    </Link>
  );
};

export default CategoryCard;
