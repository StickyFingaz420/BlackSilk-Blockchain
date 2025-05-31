import React from 'react';
import { useRouter } from 'next/router';
import { sendTransaction } from '../../utils/blockchainClient';

const ProductPage = () => {
  const router = useRouter();
  const { id } = router.query;

  const handleBuy = async () => {
    try {
      const receipt = await sendTransaction(
        '0xYourAddress', // Replace with buyer's address
        '0xSellerAddress', // Replace with seller's address
        '0.01', // Replace with product price
        '0xYourPrivateKey' // Replace with buyer's private key
      );
      console.log('Transaction successful:', receipt);
    } catch (error) {
      console.error('Error processing transaction:', error);
    }
  };

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-3xl font-bold mb-4">Product Details</h1>
      <p className="text-lg">Product ID: {id}</p>
      <div className="mt-6">
        <h2 className="text-xl font-semibold">Product Name</h2>
        <p>Description of the product.</p>
        <p className="text-lg font-bold mt-4">Price: 0.01 BTC</p>
        <button
          onClick={handleBuy}
          className="mt-4 px-4 py-2 bg-blue-500 text-white rounded"
        >
          Buy Now
        </button>
      </div>
    </div>
  );
};

export default ProductPage;
