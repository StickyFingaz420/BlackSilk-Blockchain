// Utility for connecting to BlackSilk node (REST API)
// Supports HTTPS/WSS, Tor, and I2P endpoints via .env.local
const NODE_API = process.env.NEXT_PUBLIC_NODE_API_URL || 'http://localhost:1776';

function secureFetch(url: string, options?: RequestInit) {
  // Enforce HTTPS for clearnet, allow .onion/.i2p for privacy
  if (!url.startsWith('http://localhost') && !url.startsWith('https://') && !url.includes('.onion') && !url.includes('.i2p')) {
    throw new Error('Insecure endpoint: use HTTPS, .onion, or .i2p');
  }
  return fetch(url, options);
}

export async function fetchProducts(category?: string) {
  const url = category ? `${NODE_API}/api/products?category=${category}` : `${NODE_API}/api/products`;
  const res = await secureFetch(url);
  if (!res.ok) throw new Error('Failed to fetch products');
  return res.json();
}

export async function fetchProduct(id: string) {
  const url = `${NODE_API}/api/products/${id}`;
  const res = await secureFetch(url);
  if (!res.ok) throw new Error('Failed to fetch product');
  return res.json();
}

export async function addProduct(data: any) {
  const res = await secureFetch(`${NODE_API}/api/products`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to add product');
  return res.json();
}
