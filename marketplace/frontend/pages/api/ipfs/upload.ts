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
  // Use req as a stream (Node.js readable stream)
  const response = await fetch(backendUrl, {
    method: 'POST',
    headers: req.headers as any, // Forward headers (cookies, etc.)
    body: req as any, // Node.js streams are supported by fetch in Next.js API routes
  });
  // If fetch fails, fallback to piping manually (for older Node/fetch versions)
  // const response = await new Promise((resolve, reject) => {
  //   const proxyReq = http.request(backendUrl, { method: 'POST', headers: req.headers }, (proxyRes) => {
  //     let data = '';
  //     proxyRes.on('data', chunk => data += chunk);
  //     proxyRes.on('end', () => resolve({
  //       status: proxyRes.statusCode,
  //       json: () => Promise.resolve(JSON.parse(data)),
  //     }));
  //   });
  //   req.pipe(proxyReq);
  // });
  const data = await response.json();
  res.status(response.status).json(data);
}
