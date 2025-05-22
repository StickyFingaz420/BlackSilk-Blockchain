import { useEffect, useState } from 'react';
import {
  Container,
  Typography,
  Box,
  Card,
  CardContent,
  Button,
  Chip,
  Grid,
  CircularProgress,
  Alert,
  Link as MuiLink,
} from '@mui/material';
import Link from 'next/link';
import { Order, OrderStatus, Listing, Review } from '../types';
import { useWallet } from '../components/WalletProvider';
import ReviewForm from '../components/ReviewForm';

export default function OrdersPage() {
  const { address } = useWallet();
  const [orders, setOrders] = useState<Order[]>([]);
  const [listings, setListings] = useState<Listing[]>([]);
  const [reviews, setReviews] = useState<Review[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!address) return;
    setLoading(true);
    Promise.all([
      fetch(`/api/orders?address=${address}`).then(res => res.json()),
      fetch(`/api/listings?query=&page=1&limit=1000`).then(res => res.json()),
      fetch(`/api/reviews?reviewed=${address}`).then(res => res.json()),
    ])
      .then(([ordersData, listingsData, reviewsData]) => {
        setOrders(ordersData);
        setListings(listingsData.listings);
        setReviews(reviewsData);
        setLoading(false);
      })
      .catch(() => {
        setError('Failed to load orders');
        setLoading(false);
      });
  }, [address]);

  const handleReviewSubmit = async (review: Omit<Review, 'id' | 'created_at'>) => {
    await fetch('/api/reviews', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(review),
    });
    // Optionally refetch reviews
  };

  if (!address) return <Alert severity="info">Connect your wallet to view your orders.</Alert>;
  if (loading) return <Box sx={{ textAlign: 'center', py: 8 }}><CircularProgress /></Box>;
  if (error) return <Alert severity="error">{error}</Alert>;

  const getListing = (id: string) => listings.find(l => l.id === id);

  const purchases = orders.filter(o => o.buyer === address);
  const sales = orders.filter(o => o.seller === address);

  const handleReviewSubmit = async (review: Omit<Review, 'id' | 'created_at'>) => {
    await fetch('/api/reviews', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(review),
    });
    // Optionally refetch reviews
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Typography variant="h4" gutterBottom>My Orders</Typography>
      {/* Seller reputation summary */}
      <Box sx={{ mb: 2 }}>
        <Typography variant="subtitle1">Your Reputation</Typography>
        {/* TODO: Fetch and display average rating and count from /api/reviews?reviewed=address */}
      </Box>
      {/* Purchases */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h6">Purchases</Typography>
        {purchases.length === 0 ? (
          <Typography color="text.secondary">No purchases yet.</Typography>
        ) : (
          <Grid container spacing={2}>
            {purchases.map(order => {
              const listing = getListing(order.listing_id);
              const alreadyReviewed = reviews.some(r => r.order_id === order.id && r.reviewer === address);
              return (
                <Grid item xs={12} md={6} key={order.id}>
                  <Card>
                    <CardContent>
                      <Typography variant="h6">
                        <Link href={`/listings/${order.listing_id}`} passHref legacyBehavior>
                          <MuiLink underline="hover">{listing?.title || 'Listing'}</MuiLink>
                        </Link>
                      </Typography>
                      <Typography>Amount: ₿{order.amount}</Typography>
                      <Chip label={order.status} color="primary" sx={{ mt: 1, mb: 1 }} />
                      <Typography variant="body2" color="text.secondary">Order ID: {order.id}</Typography>
                      {/* Show ReviewForm if order is completed and not already reviewed */}
                      {order.status === 'Completed' && !alreadyReviewed && (
                        <ReviewForm
                          orderId={order.id}
                          reviewer={address}
                          reviewed={order.seller}
                          onSubmit={handleReviewSubmit}
                        />
                      )}
                    </CardContent>
                  </Card>
                </Grid>
              );
            })}
          </Grid>
        )}
      </Box>
      {/* Sales section unchanged */}
      <Box>
        <Typography variant="h6">Sales</Typography>
        {sales.length === 0 ? (
          <Typography color="text.secondary">No sales yet.</Typography>
        ) : (
          <Grid container spacing={2}>
            {sales.map(order => {
              const listing = getListing(order.listing_id);
              return (
                <Grid item xs={12} md={6} key={order.id}>
                  <Card>
                    <CardContent>
                      <Typography variant="h6">
                        <Link href={`/listings/${order.listing_id}`} passHref legacyBehavior>
                          <MuiLink underline="hover">{listing?.title || 'Listing'}</MuiLink>
                        </Link>
                      </Typography>
                      <Typography>Amount: ₿{order.amount}</Typography>
                      <Chip label={order.status} color="primary" sx={{ mt: 1, mb: 1 }} />
                      <Typography variant="body2" color="text.secondary">Order ID: {order.id}</Typography>
                    </CardContent>
                  </Card>
                </Grid>
              );
            })}
          </Grid>
        )}
      </Box>
    </Container>
  );
}