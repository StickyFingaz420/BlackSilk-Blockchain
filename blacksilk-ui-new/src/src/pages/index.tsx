import React from 'react';
import { fetchProducts } from '../utils/apiClient';

export async function getStaticProps() {
    // Fetch featured products and categories
    const categories = [
        { id: '1', name: 'Software' },
        { id: '2', name: 'E-books' },
        { id: '3', name: 'Services' },
        { id: '4', name: 'Physical Goods' },
    ];

    const featuredProducts = await fetchProducts('featured');

    return {
        props: {
            categories,
            featuredProducts,
        },
    };
}

type Category = {
    id: string;
    name: string;
};

type Product = {
    id: string;
    name: string;
};

type HomePageProps = {
    categories: Category[];
    featuredProducts: Product[];
};

const HomePage = ({ categories, featuredProducts }: HomePageProps) => {
  return (
    <div className="container mx-auto p-4">
      <h1 className="text-3xl font-bold">Welcome to BlackSilk Marketplace</h1>
      <p className="mt-4">Explore categories and featured products below.</p>

      <section>
          <h2>Categories</h2>
          <ul>
              {categories.map((category) => (
                  <li key={category.id}>{category.name}</li>
              ))}
          </ul>
      </section>

      <section>
          <h2>Featured Products</h2>
          <ul>
              {featuredProducts.map((product) => (
                  <li key={product.id}>{product.name}</li>
              ))}
          </ul>
      </section>
    </div>
  );
};

export default HomePage;
