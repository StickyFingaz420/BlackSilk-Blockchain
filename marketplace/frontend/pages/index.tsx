import { useState, useEffect } from 'react'
import Head from 'next/head'
import { Container, Grid, Card, Typography, Button, Box } from '@mui/material'
import { styled } from '@mui/system'
import { Listing } from '../types'

const StyledCard = styled(Card)(({ theme }) => ({
  height: '100%',
  display: 'flex',
  flexDirection: 'column',
  transition: 'transform 0.2s',
  '&:hover': {
    transform: 'translateY(-4px)',
  },
}))

export default function Home() {
  const [listings, setListings] = useState<Listing[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchListings()
  }, [])

  const fetchListings = async () => {
    try {
      const response = await fetch('/api/listings')
      const data = await response.json()
      setListings(data)
    } catch (error) {
      console.error('Error fetching listings:', error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <Head>
        <title>BlackSilk Marketplace</title>
        <meta name="description" content="Privacy-focused decentralized marketplace" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.ico" />
        
        {/* Security Headers */}
        <meta httpEquiv="Content-Security-Policy" content="default-src 'self'; img-src 'self' https://*; child-src 'none';" />
        <meta httpEquiv="X-Content-Type-Options" content="nosniff" />
        <meta httpEquiv="X-Frame-Options" content="DENY" />
        <meta httpEquiv="X-XSS-Protection" content="1; mode=block" />
        <meta httpEquiv="Referrer-Policy" content="no-referrer" />
        <meta httpEquiv="Permissions-Policy" content="geolocation=(), microphone=(), camera=()" />
      </Head>

      <main>
        <Container maxWidth="lg" sx={{ py: 8 }}>
          <Typography variant="h2" component="h1" gutterBottom align="center" sx={{ mb: 6 }}>
            BlackSilk Marketplace
          </Typography>

          {loading ? (
            <Typography>Loading...</Typography>
          ) : (
            <Grid container spacing={4}>
              {listings.map((listing) => (
                <Grid item key={listing.id} xs={12} sm={6} md={4}>
                  <StyledCard>
                    <Box sx={{ p: 2 }}>
                      <Typography variant="h5" component="h2" gutterBottom>
                        {listing.title}
                      </Typography>
                      <Typography color="text.secondary" paragraph>
                        {listing.description}
                      </Typography>
                      <Typography variant="h6" color="primary">
                        {listing.price} BLK
                      </Typography>
                      <Button
                        variant="contained"
                        color="primary"
                        fullWidth
                        sx={{ mt: 2 }}
                        href={`/listing/${listing.id}`}
                      >
                        View Details
                      </Button>
                    </Box>
                  </StyledCard>
                </Grid>
              ))}
            </Grid>
          )}
        </Container>
      </main>
    </>
  )
} 