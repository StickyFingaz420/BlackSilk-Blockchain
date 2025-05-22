import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/router';
import {
  Container, Typography, Card, CardContent, Button, Box, Grid, Alert, CircularProgress
} from '@mui/material';
import { EscrowStatus } from '../../types';
import DisputeVoting from '../../components/DisputeVoting';
import { useWallet } from '../../components/WalletProvider';

// For process.env type
// eslint-disable-next-line @typescript-eslint/no-var-requires
// @ts-ignore
const API: string = (typeof process !== 'undefined' && process.env.NEXT_PUBLIC_API_URL) || '';

function toHex(bytes: Uint8Array | number[]) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export default function EscrowPage() {
  const router = useRouter();
  const { contract_id } = router.query;
  const [escrow, setEscrow] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actionMsg, setActionMsg] = useState('');

  // Dummy user for demo (replace with wallet integration)
  const user = {
    pubkey: new Array(32).fill(1), // Replace with real pubkey
    role: 'buyer', // or 'seller' or 'arbiter'
  };

  const { address } = useWallet();

  useEffect(() => {
    if (contract_id) fetchEscrow();
    // eslint-disable-next-line
  }, [contract_id]);

  const fetchEscrow = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API}/escrow/${contract_id}`);
      if (!res.ok) throw new Error('Not found');
      const data = await res.json();
      setEscrow(data);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleAction = async (action: string) => {
    setActionMsg('');
    setError('');
    try {
      const res = await fetch(`${API}/escrow/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contract_id, signer: user.pubkey }),
      });
      if (!res.ok) throw new Error('Action failed');
      setActionMsg(`Action '${action}' successful.`);
      fetchEscrow();
    } catch (e: any) {
      setError(e.message);
    }
  };

  if (loading) return <Container sx={{ py: 8 }}><CircularProgress /></Container>;
  if (error) return <Container sx={{ py: 8 }}><Alert severity="error">{error}</Alert></Container>;
  if (!escrow) return null;

  return (
    <Container maxWidth="sm" sx={{ py: 8 }}>
      <Card>
        <CardContent>
          <Typography variant="h5" gutterBottom>Escrow Contract</Typography>
          <Typography>Status: <b>{escrow.status}</b></Typography>
          <Typography>Amount: {escrow.amount} BLK</Typography>
          <Typography>Buyer: {toHex(escrow.buyer)}</Typography>
          <Typography>Seller: {toHex(escrow.seller)}</Typography>
          <Typography>Arbiter: {toHex(escrow.arbiter)}</Typography>
          <Box sx={{ mt: 2 }}>
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <Button variant="contained" color="primary" fullWidth onClick={() => handleAction('sign')}>Sign for Release</Button>
              </Grid>
              <Grid item xs={6}>
                <Button variant="contained" color="secondary" fullWidth onClick={() => handleAction('refund')}>Sign for Refund</Button>
              </Grid>
              <Grid item xs={12}>
                <Button variant="outlined" color="error" fullWidth onClick={() => handleAction('dispute')}>Raise Dispute</Button>
              </Grid>
            </Grid>
          </Box>
          {actionMsg && <Alert sx={{ mt: 2 }} severity="success">{actionMsg}</Alert>}
          {error && <Alert sx={{ mt: 2 }} severity="error">{error}</Alert>}
        </CardContent>
      </Card>
      {/* Show dispute voting if in Disputed or Voting state */}
      {(escrow.status === 'Disputed' || escrow.status === 'Voting') && address && (
        <DisputeVoting contractId={escrow.contractId} voter={address} />
      )}
      {/* Show voting results if Resolved */}
      {escrow.status === 'Resolved' && (
        <Box sx={{ mt: 2 }}>
          <Typography variant="h6">Dispute Resolved</Typography>
          {/* Optionally show who won based on tally */}
        </Box>
      )}
    </Container>
  );
}