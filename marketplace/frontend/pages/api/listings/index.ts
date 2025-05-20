import type { NextApiRequest, NextApiResponse } from 'next';
import { Listing, ListingStatus, ItemCondition } from '../../../types';
import { v4 as uuidv4 } from 'uuid';

// In-memory storage for demo
// TODO: Replace with proper database
let listings: Listing[] = [];

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
  const { category, query, sort, page = '1', limit = '10' } = req.query;
  
  let filteredListings = [...listings];
  
  // Apply filters
  if (category) {
    filteredListings = filteredListings.filter(l => l.category === category);
  }
  
  if (query) {
    const searchQuery = (query as string).toLowerCase();
    filteredListings = filteredListings.filter(l => 
      l.title.toLowerCase().includes(searchQuery) ||
      l.description.toLowerCase().includes(searchQuery) ||
      l.tags?.some(tag => tag.toLowerCase().includes(searchQuery))
    );
  }
  
  // Apply sorting
  if (sort) {
    switch (sort) {
      case 'price_low_to_high':
        filteredListings.sort((a, b) => a.price - b.price);
        break;
      case 'price_high_to_low':
        filteredListings.sort((a, b) => b.price - a.price);
        break;
      case 'most_viewed':
        filteredListings.sort((a, b) => (b.views || 0) - (a.views || 0));
        break;
      case 'top_rated':
        filteredListings.sort((a, b) => (b.rating || 0) - (a.rating || 0));
        break;
      default:
        // Default to recently listed
        filteredListings.sort((a, b) => b.created_at - a.created_at);
    }
  }
  
  // Apply pagination
  const pageNum = parseInt(page as string);
  const limitNum = parseInt(limit as string);
  const startIndex = (pageNum - 1) * limitNum;
  const endIndex = startIndex + limitNum;
  const paginatedListings = filteredListings.slice(startIndex, endIndex);
  
  res.status(200).json({
    listings: paginatedListings,
    total: filteredListings.length,
    page: pageNum,
    totalPages: Math.ceil(filteredListings.length / limitNum)
  });
}

async function handlePost(req: NextApiRequest, res: NextApiResponse) {
  try {
    const listing: Partial<Listing> = req.body;
    
    // Validate required fields
    if (!listing.title || !listing.description || !listing.price || !listing.category) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Create new listing
    const newListing: Listing = {
      id: uuidv4(),
      title: listing.title,
      description: listing.description,
      price: listing.price,
      seller: 'TODO: Get from auth', // TODO: Get from authenticated user
      images: listing.images || [],
      category: listing.category,
      subcategory: listing.subcategory || '',
      tags: listing.tags || [],
      condition: listing.condition || ItemCondition.New,
      shipping: listing.shipping || [],
      location: listing.location || '',
      quantity: listing.quantity || 1,
      created_at: Date.now(),
      updated_at: Date.now(),
      status: ListingStatus.Active,
      views: 0,
      rating: 0,
      ratings_count: 0,
    };
    
    // Store listing
    listings.push(newListing);
    
    res.status(201).json(newListing);
  } catch (error) {
    console.error('Error creating listing:', error);
    res.status(500).json({ error: 'Failed to create listing' });
  }
} 