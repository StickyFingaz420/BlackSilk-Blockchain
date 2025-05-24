import { useState } from 'react';
import { uploadToIPFS } from '../utils/ipfs';
import { addProduct } from '../utils/nodeApi';
import { CircularProgress, Alert } from '@mui/material';

export default function SellPage() {
  const [title, setTitle] = useState('');
  const [desc, setDesc] = useState('');
  const [price, setPrice] = useState('');
  const [image, setImage] = useState<File|null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess(false);
    try {
      let imageCid = '';
      if (image) {
        imageCid = await uploadToIPFS(image);
      }
      await addProduct({ title, description: desc, price: parseFloat(price), imageCid, category: 'uncategorized' });
      setSuccess(true);
      setTitle(''); setDesc(''); setPrice(''); setImage(null);
    } catch (err: any) {
      setError(err.message || 'Failed to add product');
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="max-w-xl mx-auto py-12 px-4">
      <h2 className="text-2xl font-bold mb-4">Add New Product</h2>
      <form className="space-y-4" onSubmit={handleSubmit}>
        <input className="w-full border p-2 rounded" placeholder="Title" value={title} onChange={e => setTitle(e.target.value)} />
        <textarea className="w-full border p-2 rounded" placeholder="Description" value={desc} onChange={e => setDesc(e.target.value)} />
        <input className="w-full border p-2 rounded" placeholder="Price (BLK)" value={price} onChange={e => setPrice(e.target.value)} />
        <input type="file" accept="image/*" onChange={e => setImage(e.target.files?.[0] || null)} />
        <button type="submit" className="w-full bg-black text-white py-2 rounded hover:bg-gray-800" disabled={loading}>
          {loading ? <span className="flex items-center"><CircularProgress size={18} className="mr-2" /> Submitting...</span> : 'Submit'}
        </button>
        {error && <Alert severity="error">{error}</Alert>}
        {success && <Alert severity="success">Product added successfully!</Alert>}
      </form>
    </main>
  );
}
