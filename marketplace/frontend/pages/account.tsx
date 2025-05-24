import { useState } from 'react';
import { getPublicKey } from '@noble/ed25519';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils';
import { CircularProgress, Alert } from '@mui/material';

export default function AccountPage() {
  const [key, setKey] = useState('');
  const [address, setAddress] = useState('');
  const [error, setError] = useState('');

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    try {
      // Accept either hex private key or mnemonic (stub: treat as hex for now)
      const priv = key.trim();
      if (!priv) throw new Error('Enter a private key or phrase');
      // Convert hex string to Uint8Array
      const privBytes = hexToBytes(priv);
      // Derive public key/address (for demo, just show public key)
      const pub = bytesToHex(await getPublicKey(privBytes));
      setAddress(pub);
      // Store key in-memory (session only)
      sessionStorage.setItem('blacksilk_priv', priv);
    } catch (err: any) {
      setError(err.message || 'Invalid key');
    }
  }

  return (
    <main className="max-w-md mx-auto py-12 px-4">
      <h2 className="text-2xl font-bold mb-4">Login with Private Key or Recovery Phrase</h2>
      <form className="space-y-4" onSubmit={handleLogin}>
        <textarea className="w-full border p-2 rounded" placeholder="Enter your private key or recovery phrase" value={key} onChange={e => setKey(e.target.value)} />
        <button type="submit" className="w-full bg-black text-white py-2 rounded hover:bg-gray-800">
          {address ? 'Logged in' : 'Login'}
        </button>
        {error && <Alert severity="error">{error}</Alert>}
        {address && <Alert severity="success" className="break-all">Wallet address: {address}</Alert>}
      </form>
    </main>
  );
}
