import { GetStaticPaths, GetStaticProps } from 'next';
import { useRouter } from 'next/router';
import { fetchProduct } from '../../utils/nodeApi';
import { Product } from '../../types/product';
import { hexToBytes } from '@noble/hashes/utils';
import { sign } from '@noble/ed25519';
import { useState } from 'react';
import { useOrderStatusUpdates } from '../../utils/useOrderStatusUpdates';
import { CircularProgress, Alert } from '@mui/material';

export default function ProductPage({ product }: { product: Product }) {
  const router = useRouter();
  const { id } = router.query;
  const [buying, setBuying] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [orderId, setOrderId] = useState<string | null>(null);
  const [orderStatus, setOrderStatus] = useState<string | null>(null);

  useOrderStatusUpdates(orderId || '', (status) => setOrderStatus(status));

  async function handleBuy() {
    setBuying(true);
    setError('');
    setSuccess('');
    try {
      // Retrieve private key from session (set on login)
      const priv = sessionStorage.getItem('blacksilk_priv');
      if (!priv) throw new Error('Please log in with your wallet first.');
      const privBytes = hexToBytes(priv);
      // Prepare transaction data (simplified)
      const tx = JSON.stringify({ productId: product.id, price: product.price });
      // Sign transaction
      const signature = await sign(new TextEncoder().encode(tx), privBytes);
      // Send to node (replace with actual endpoint)
      const res = await fetch(`/api/buy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tx, signature: Array.from(signature) }),
      });
      if (!res.ok) throw new Error('Transaction failed');
      const data = await res.json();
      setSuccess('Purchase submitted!');
      setOrderId(data.orderId || null);
    } catch (err: any) {
      setError(err.message || 'Failed to buy');
    } finally {
      setBuying(false);
    }
  }

  return (
    <main className="max-w-2xl mx-auto py-12 px-4">
      <h2 className="text-2xl font-bold mb-4">{product.title}</h2>
      <div className="bg-white rounded shadow p-6">
        {product.imageCid && (
          <img
            src={`https://ipfs.io/ipfs/${product.imageCid}`}
            alt={product.title}
            className="mb-4 h-48 object-cover rounded"
          />
        )}
        <div className="font-semibold">{product.title}</div>
        <div className="text-gray-600">{product.description}</div>
        <div className="mt-4 font-bold">Price: {product.price} BLK</div>
        <button
          className="mt-6 px-4 py-2 bg-black text-white rounded hover:bg-gray-800"
          onClick={handleBuy}
          disabled={buying}
        >
          {buying ? (
            <span className="flex items-center">
              <CircularProgress size={18} className="mr-2" /> Processing...
            </span>
          ) : (
            'Buy'
          )}
        </button>
        {error && <Alert severity="error" className="mt-2">{error}</Alert>}
        {success && <Alert severity="success" className="mt-2">{success}</Alert>}
        {orderId && (
          <div className="mt-2 text-blue-600">
            Order ID: {orderId}{' '}
            {orderStatus && <span>- Status: {orderStatus}</span>}
          </div>
        )}
      </div>
    </main>
  );
}

export const getStaticPaths: GetStaticPaths = async () => {
  // Fetch all product IDs from the node (stubbed for now)
  // In production, fetch from API
  return {
    paths: [],
    fallback: 'blocking',
  };
};

export const getStaticProps: GetStaticProps = async (context) => {
  const id = context.params?.id as string;
  try {
    const product = await fetchProduct(id);
    return { props: { product }, revalidate: 60 };
  } catch {
    return { notFound: true };
  }
};
