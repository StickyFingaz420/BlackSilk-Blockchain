import React, { useState } from 'react';
import { Box, Button, Typography, Alert } from '@mui/material';
import { DisputeVote } from '../types';

interface DisputeVotingProps {
  contractId: string;
  voter: string;
  onVoted?: () => void;
}

export default function DisputeVoting({ contractId, voter, onVoted }: DisputeVotingProps) {
  const [vote, setVote] = useState<boolean | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleVote = async (voteValue: boolean) => {
    setLoading(true);
    setError(null);
    setStatus(null);
    try {
      const res = await fetch(`/api/escrow/${contractId}/submit_vote`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ voter, vote: voteValue }),
      });
      if (res.ok) {
        setVote(voteValue);
        setStatus('Vote submitted!');
        if (onVoted) onVoted();
      } else {
        setError('Failed to submit vote.');
      }
    } catch {
      setError('Failed to submit vote.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ mt: 2 }}>
      <Typography variant="h6">Dispute Voting</Typography>
      {status && <Alert severity="success">{status}</Alert>}
      {error && <Alert severity="error">{error}</Alert>}
      <Button
        variant="contained"
        color="success"
        onClick={() => handleVote(true)}
        disabled={loading || vote !== null}
        sx={{ mr: 2 }}
      >
        Vote for Buyer
      </Button>
      <Button
        variant="contained"
        color="warning"
        onClick={() => handleVote(false)}
        disabled={loading || vote !== null}
      >
        Vote for Seller
      </Button>
    </Box>
  );
}
