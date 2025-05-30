import React, { useState } from 'react';

const AccountPage = () => {
  const [privateKey, setPrivateKey] = useState('');
  const [recoveryPhrase, setRecoveryPhrase] = useState('');

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();

    if (privateKey) {
      console.log('Logging in with private key:', privateKey);
      // Add logic to handle private key login
    } else if (recoveryPhrase) {
      console.log('Logging in with recovery phrase:', recoveryPhrase);
      // Add logic to handle recovery phrase login
    } else {
      alert('Please enter either a private key or a recovery phrase.');
    }
  };

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-2xl font-bold">Account Login</h1>
      <form onSubmit={handleLogin} className="mt-4">
        <div className="mb-4">
          <label className="block text-sm font-medium">Private Key</label>
          <textarea
            value={privateKey}
            onChange={(e) => setPrivateKey(e.target.value)}
            className="w-full border p-2"
            placeholder="Enter your private key"
          ></textarea>
        </div>
        <div className="mb-4">
          <label className="block text-sm font-medium">Recovery Phrase</label>
          <textarea
            value={recoveryPhrase}
            onChange={(e) => setRecoveryPhrase(e.target.value)}
            className="w-full border p-2"
            placeholder="Enter your recovery phrase"
          ></textarea>
        </div>
        <button type="submit" className="bg-blue-500 text-white px-4 py-2">
          Login
        </button>
      </form>
    </div>
  );
};

export default AccountPage;
