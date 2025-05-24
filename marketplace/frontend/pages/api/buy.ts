// Simple API route stub for buy endpoint
import type { NextApiRequest, NextApiResponse } from 'next';

const NODE_API = process.env.NODE_API_URL || 'http://localhost:1776';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') return res.status(405).end();
  try {
    // Relay signed transaction to node
    const nodeRes = await fetch(`${NODE_API}/api/buy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body),
    });
    const data = await nodeRes.json();
    if (!nodeRes.ok) return res.status(nodeRes.status).json(data);
    res.status(200).json(data);
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Node relay failed' });
  }
}
