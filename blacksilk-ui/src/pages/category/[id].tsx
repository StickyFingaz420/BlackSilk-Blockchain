import React from 'react';
import { GetServerSideProps } from 'next';
import { useRouter } from 'next/router';
import { fetchProducts } from '../../utils/apiClient';

interface Product {
  id: string;
  name: string;
  price: string;
}

interface CategoryPageProps {
  products: Product[];
}

export const getServerSideProps: GetServerSideProps = async (context) => {
  const { id } = context.params as { id: string };
  const products = await fetchProducts(id);

  return {
    props: {
      products,
    },
  };
};

const CategoryPage: React.FC<CategoryPageProps> = ({ products }) => {
  const router = useRouter();
  const { id } = router.query;

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-2xl font-bold">Category: {id}</h1>
      <ul className="mt-4">
        {products.map((product) => (
          <li key={product.id} className="mb-2">
            {product.name} - {product.price} crypto
          </li>
        ))}
      </ul>
    </div>
  );
};

export default CategoryPage;
