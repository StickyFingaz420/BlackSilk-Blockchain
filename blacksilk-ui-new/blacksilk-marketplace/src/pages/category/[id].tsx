import React from 'react';
import { useRouter } from 'next/router';

const CategoryPage = () => {
  const router = useRouter();
  const { id } = router.query;

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-3xl font-bold mb-4">Category: {id}</h1>
      <p className="text-lg">Browse products in this category:</p>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
        {/* Example products */}
        <div className="p-4 border rounded shadow">
          <h2 className="text-xl font-semibold">Product 1</h2>
          <p>Description of product 1.</p>
        </div>
        <div className="p-4 border rounded shadow">
          <h2 className="text-xl font-semibold">Product 2</h2>
          <p>Description of product 2.</p>
        </div>
        <div className="p-4 border rounded shadow">
          <h2 className="text-xl font-semibold">Product 3</h2>
          <p>Description of product 3.</p>
        </div>
      </div>
    </div>
  );
};

export default CategoryPage;
