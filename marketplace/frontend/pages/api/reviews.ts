import type { NextApiRequest, NextApiResponse } from 'next';

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'GET') {
    // Proxy GET /reviews?reviewed=...
    const { reviewed } = req.query;
    const url = `${BACKEND_URL}/reviews${reviewed ? `?reviewed=${reviewed}` : ''}`;
    const backendRes = await fetch(url);
    const data = await backendRes.json();
    res.status(backendRes.status).json(data);
  } else if (req.method === 'POST') {
    // Proxy POST /reviews
    const backendRes = await fetch(`${BACKEND_URL}/reviews`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body),
    });
    const data = await backendRes.json();
    res.status(backendRes.status).json(data);
  } else {
    res.setHeader('Allow', ['GET', 'POST']);
    res.status(405).end(`Method ${req.method} Not Allowed`);
  }
}
