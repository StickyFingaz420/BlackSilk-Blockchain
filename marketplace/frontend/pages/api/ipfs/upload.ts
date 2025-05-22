import type { NextApiRequest, NextApiResponse } from 'next';

// Proxy to backend IPFS upload endpoint
export const config = {
  api: {
    bodyParser: false, // Required for multipart
  },
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }
  // Forward the multipart request to the backend
  const backendUrl = process.env.BACKEND_URL || 'http://localhost:8080/ipfs/upload';
  const response = await fetch(backendUrl, {
    method: 'POST',
    headers: req.headers as any, // Forward headers (cookies, etc.)
    body: req,
  });
  const data = await response.json();
  res.status(response.status).json(data);
}
