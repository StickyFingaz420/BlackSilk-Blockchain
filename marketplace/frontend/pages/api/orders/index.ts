import type { NextApiRequest, NextApiResponse } from 'next';
import { Order, OrderStatus } from '../../../types';
import { v4 as uuidv4 } from 'uuid';

// In-memory storage for demo
let orders: Order[] = [];

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  switch (req.method) {
    case 'GET':
      return handleGet(req, res);
    case 'POST':
      return handlePost(req, res);
    default:
      res.setHeader('Allow', ['GET', 'POST']);
      res.status(405).end(`Method ${req.method} Not Allowed`);
  }
}

async function handleGet(req: NextApiRequest, res: NextApiResponse) {
  const { address } = req.query;
  let filtered = orders;
  if (address) {
    filtered = orders.filter(o => o.buyer === address || o.seller === address);
  }
  res.status(200).json(filtered);
}

async function handlePost(req: NextApiRequest, res: NextApiResponse) {
  try {
    const { listing_id, buyer, seller, amount } = req.body;
    if (!listing_id || !buyer || !seller || !amount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    const newOrder: Order = {
      id: uuidv4(),
      listing_id,
      buyer,
      seller,
      amount,
      escrow_address: 'simulated-escrow-address',
      status: OrderStatus.Created,
      created_at: Date.now(),
    };
    orders.push(newOrder);
    res.status(201).json(newOrder);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create order' });
  }
} 