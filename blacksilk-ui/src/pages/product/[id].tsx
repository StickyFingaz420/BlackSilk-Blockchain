import React from 'react';
import { useRouter } from 'next/router';
import { GetServerSideProps } from 'next';
import { fetchProductDetails } from '../../utils/apiClient';

interface Product {
  id: string;
  name: string;
  description: string;
  price: string;
}

interface ProductPageProps {
  product: Product;
}

export const getServerSideProps: GetServerSideProps = async (context) => {
  const { id } = context.params as { id: string };
  const product = await fetchProductDetails(id);

  return {
    props: {
      product,
    },
  };
};

const ProductPage: React.FC<ProductPageProps> = ({ product }) => {
  const router = useRouter();
  const { id } = router.query;

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-2xl font-bold">{product.name}</h1>
      <p className="mt-4">{product.description}</p>
      <p className="mt-2">Price: {product.price} crypto</p>
    </div>
  );
};

export default ProductPage;
