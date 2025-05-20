import { useState, useEffect } from 'react'
import Head from 'next/head'
import { Container, Grid, Card, Typography, Button, Box, Pagination, Skeleton, Chip } from '@mui/material'
import { styled } from '@mui/system'
import { Listing, SearchFilters as SearchFiltersType } from '../types'
import AddIcon from '@mui/icons-material/Add'
import { useRouter } from 'next/router'
import Link from 'next/link'
import SearchFilters from '../components/SearchFilters'
import WalletButton from '../components/WalletButton'

const StyledCard = styled(Card)(({ theme }) => ({
  height: '100%',
  display: 'flex',
  flexDirection: 'column',
  transition: 'transform 0.2s',
  '&:hover': {
    transform: 'translateY(-4px)',
  },
}))

export default function Marketplace() {
  const router = useRouter()
  const [listings, setListings] = useState<Listing[]>([])
  const [loading, setLoading] = useState(true)
  const [totalPages, setTotalPages] = useState(1)
  const [filters, setFilters] = useState<SearchFiltersType>({
    query: '',
    sortBy: 'recently_listed',
    page: 1,
    limit: 12,
  })

  useEffect(() => {
    fetchListings()
  }, [filters])

  const fetchListings = async () => {
    try {
      setLoading(true)
      const queryParams = new URLSearchParams()
      
      // Add filters to query params
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined && value !== '') {
          queryParams.append(key, String(value))
        }
      })

      const response = await fetch(`/api/listings?${queryParams.toString()}`)
      const data = await response.json()
      
      setListings(data.listings)
      setTotalPages(data.totalPages)
    } catch (error) {
      console.error('Error fetching listings:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleSearch = (newFilters: SearchFiltersType) => {
    setFilters(prev => ({
      ...prev,
      ...newFilters,
    }))
  }

  const handlePageChange = (_event: React.ChangeEvent<unknown>, page: number) => {
    setFilters(prev => ({
      ...prev,
      page,
    }))
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
        <Container maxWidth="lg" sx={{ py: 4 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
            <Typography variant="h4" component="h1">
              Marketplace
            </Typography>
            <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
              <WalletButton />
              <Button
                variant="contained"
                color="primary"
                startIcon={<AddIcon />}
                onClick={() => router.push('/listings/new')}
              >
                Create Listing
              </Button>
            </Box>
          </Box>

          <SearchFilters onSearch={handleSearch} initialFilters={filters} />

          {loading ? (
            <Grid container spacing={3}>
              {Array.from(new Array(12)).map((_, index) => (
                <Grid item key={index} xs={12} sm={6} md={4} lg={3}>
                  <Card>
                    <Skeleton variant="rectangular" height={200} />
                    <CardContent>
                      <Skeleton />
                      <Skeleton width="60%" />
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          ) : (
            <>
              <Grid container spacing={3}>
                {listings.map((listing) => (
                  <Grid item key={listing.id} xs={12} sm={6} md={4} lg={3}>
                    <Link href={`/listings/${listing.id}`} passHref style={{ textDecoration: 'none' }}>
                      <Card
                        sx={{
                          height: '100%',
                          display: 'flex',
                          flexDirection: 'column',
                          transition: 'transform 0.2s',
                          '&:hover': {
                            transform: 'translateY(-4px)',
                          },
                        }}
                      >
                        <CardMedia
                          component="img"
                          height="200"
                          image={listing.images[0] || '/placeholder.png'}
                          alt={listing.title}
                        />
                        <CardContent sx={{ flexGrow: 1 }}>
                          <Typography gutterBottom variant="h6" component="h2" noWrap>
                            {listing.title}
                          </Typography>
                          <Typography variant="h6" color="primary" gutterBottom>
                            ₿{listing.price.toFixed(8)}
                          </Typography>
                          <Box sx={{ mb: 1 }}>
                            <Chip
                              label={listing.category}
                              size="small"
                              sx={{ mr: 1, mb: 1 }}
                            />
                            <Chip
                              label={listing.condition}
                              size="small"
                              sx={{ mb: 1 }}
                            />
                          </Box>
                          <Typography
                            variant="body2"
                            color="text.secondary"
                            sx={{
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              display: '-webkit-box',
                              WebkitLineClamp: 2,
                              WebkitBoxOrient: 'vertical',
                            }}
                          >
                            {listing.description}
                          </Typography>
                        </CardContent>
                      </Card>
                    </Link>
                  </Grid>
                ))}
              </Grid>

              {listings.length === 0 && (
                <Box sx={{ textAlign: 'center', py: 8 }}>
                  <Typography variant="h6" color="text.secondary" gutterBottom>
                    No listings found
                  </Typography>
                  <Typography color="text.secondary">
                    Try adjusting your search filters or create a new listing
                  </Typography>
                </Box>
              )}

              {totalPages > 1 && (
                <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
                  <Pagination
                    count={totalPages}
                    page={filters.page}
                    onChange={handlePageChange}
                    color="primary"
                  />
                </Box>
              )}
            </>
          )}
        </Container>
      </main>
    </>
  )
} 