import React from 'react';
import { Button, Chip } from '@mui/material';
import { useWallet } from './WalletProvider';

export default function WalletButton() {
  const { address, connect, disconnect } = useWallet();

  if (address) {
    return (
      <Chip
        label={address.slice(0, 6) + '...' + address.slice(-4)}
        onDelete={disconnect}
        color="primary"
        variant="outlined"
        sx={{ fontWeight: 'bold', fontSize: 16 }}
      />
    );
  }

  return (
    <Button variant="contained" color="primary" onClick={connect}>
      Connect Wallet
    </Button>
  );
} 