import React, { useState } from 'react';
import { uploadToIPFS } from '../utils/ipfsClient';

const AddProductPage = () => {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [price, setPrice] = useState('');
  const [image, setImage] = useState<File | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      let imageCID = '';
      if (image) {
        imageCID = await uploadToIPFS(image);
        console.log('Image uploaded to IPFS with CID:', imageCID);
      }
      // Handle product submission logic here
      console.log({ title, description, price, imageCID });
    } catch (error) {
      console.error('Error submitting product:', error);
    }
  };

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-3xl font-bold mb-4">Add a New Product</h1>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-lg font-semibold">Title</label>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="w-full p-2 border rounded"
            required
          />
        </div>
        <div>
          <label className="block text-lg font-semibold">Description</label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="w-full p-2 border rounded"
            required
          />
        </div>
        <div>
          <label className="block text-lg font-semibold">Price (in BTC)</label>
          <input
            type="number"
            value={price}
            onChange={(e) => setPrice(e.target.value)}
            className="w-full p-2 border rounded"
            required
          />
        </div>
        <div>
          <label className="block text-lg font-semibold">Image</label>
          <input
            type="file"
            onChange={(e) => setImage(e.target.files?.[0] || null)}
            className="w-full p-2 border rounded"
          />
        </div>
        <button type="submit" className="px-4 py-2 bg-green-500 text-white rounded">
          Submit
        </button>
      </form>
    </div>
  );
};

export default AddProductPage;
