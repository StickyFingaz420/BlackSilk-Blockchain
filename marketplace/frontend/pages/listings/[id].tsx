import { useRouter } from 'next/router';
import { useEffect, useState } from 'react';
import {
  Container,
  Typography,
  Box,
  Card,
  CardContent,
  CardMedia,
  Button,
  Chip,
  Grid,
  Alert,
  CircularProgress,
} from '@mui/material';
import { Listing } from '../../types';
import { useWallet } from '../../components/WalletProvider';

export default function ListingDetail() {
  const router = useRouter();
  const { id } = router.query;
  const { address } = useWallet();
  const [listing, setListing] = useState<Listing | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [orderStatus, setOrderStatus] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    fetch(`/api/listings?query=&page=1&limit=1000`)
      .then(res => res.json())
      .then(data => {
        const found = data.listings.find((l: Listing) => l.id === id);
        setListing(found || null);
        setLoading(false);
      })
      .catch(() => {
        setError('Failed to load listing');
        setLoading(false);
      });
  }, [id]);

  const handleBuy = async () => {
    if (!address || !listing) return;
    setOrderStatus('processing');
    try {
      const res = await fetch('/api/orders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          listing_id: listing.id,
          buyer: address,
          seller: listing.seller,
          amount: listing.price,
        }),
      });
      if (!res.ok) throw new Error('Order creation failed');
      setOrderStatus('success');
    } catch {
      setOrderStatus('error');
    }
  };

  if (loading) return <Box sx={{ textAlign: 'center', py: 8 }}><CircularProgress /></Box>;
  if (error || !listing) return <Alert severity="error">{error || 'Listing not found'}</Alert>;

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Grid container spacing={4}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardMedia
              component="img"
              height="320"
              image={listing.images[0] || '/placeholder.png'}
              alt={listing.title}
            />
            <Box sx={{ display: 'flex', gap: 1, mt: 2, flexWrap: 'wrap' }}>
              {listing.images.slice(1).map((img, idx) => (
                <img key={idx} src={img} alt="" style={{ width: 64, height: 64, objectFit: 'cover', borderRadius: 4, border: '1px solid #eee' }} />
              ))}
            </Box>
          </Card>
        </Grid>
        <Grid item xs={12} md={6}>
          <CardContent>
            <Typography variant="h4" gutterBottom>{listing.title}</Typography>
            <Typography variant="h6" color="primary" gutterBottom>₿{listing.price.toFixed(8)}</Typography>
            <Box sx={{ mb: 2 }}>
              <Chip label={listing.category} sx={{ mr: 1 }} />
              <Chip label={listing.condition} />
            </Box>
            <Typography variant="body1" sx={{ mb: 2 }}>{listing.description}</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>Location: {listing.location}</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>Quantity: {listing.quantity}</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>Seller: {listing.seller}</Typography>
            <Box sx={{ mt: 3 }}>
              {orderStatus === 'success' && <Alert severity="success">Order placed! Check your orders page.</Alert>}
              {orderStatus === 'error' && <Alert severity="error">Order failed. Try again.</Alert>}
              <Button
                variant="contained"
                color="primary"
                size="large"
                disabled={!address || address === listing.seller || orderStatus === 'processing'}
                onClick={handleBuy}
              >
                {address === listing.seller ? 'You are the seller' : address ? 'Buy Now' : 'Connect Wallet to Buy'}
              </Button>
            </Box>
          </CardContent>
        </Grid>
      </Grid>
    </Container>
  );
} 