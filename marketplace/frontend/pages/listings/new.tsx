import { useState } from 'react';
import { Container, Typography, Box, Alert } from '@mui/material';
import ListingForm from '../../components/ListingForm';
import { Listing } from '../../types';
import { useRouter } from 'next/router';

export default function NewListing() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (data: Partial<Listing>) => {
    try {
      const response = await fetch('/api/listings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });

      if (!response.ok) {
        throw new Error('Failed to create listing');
      }

      const result = await response.json();
      router.push(`/listings/${result.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    }
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Create New Listing
        </Typography>
        <Typography color="text.secondary">
          Fill in the details below to create your listing. All fields marked with * are required.
        </Typography>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 4 }}>
          {error}
        </Alert>
      )}

      <ListingForm onSubmit={handleSubmit} />
    </Container>
  );
} 