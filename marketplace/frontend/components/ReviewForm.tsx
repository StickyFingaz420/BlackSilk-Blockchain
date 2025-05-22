import React, { useState } from 'react';
import { Box, Button, TextField, Rating, Typography, Alert } from '@mui/material';
import { Review } from '../types';

interface ReviewFormProps {
  orderId: string;
  reviewer: string;
  reviewed: string;
  onSubmit: (review: Omit<Review, 'id' | 'created_at'>) => Promise<void>;
}

export default function ReviewForm({ orderId, reviewer, reviewed, onSubmit }: ReviewFormProps) {
  const [rating, setRating] = useState<number | null>(null);
  const [comment, setComment] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(false);
    if (!rating) {
      setError('Please select a rating.');
      return;
    }
    setLoading(true);
    try {
      await onSubmit({ order_id: orderId, reviewer, reviewed, rating, comment });
      setSuccess(true);
      setComment('');
      setRating(null);
    } catch (err) {
      setError('Failed to submit review.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box component="form" onSubmit={handleSubmit} sx={{ mt: 2 }}>
      <Typography variant="h6" gutterBottom>Leave a Review</Typography>
      {error && <Alert severity="error">{error}</Alert>}
      {success && <Alert severity="success">Review submitted!</Alert>}
      <Rating
        value={rating}
        onChange={(_e, value) => setRating(value)}
        size="large"
        sx={{ mb: 2 }}
      />
      <TextField
        label="Comment"
        multiline
        rows={3}
        value={comment}
        onChange={e => setComment(e.target.value)}
        fullWidth
        sx={{ mb: 2 }}
      />
      <Button type="submit" variant="contained" color="primary" disabled={loading}>
        {loading ? 'Submitting...' : 'Submit Review'}
      </Button>
    </Box>
  );
}
