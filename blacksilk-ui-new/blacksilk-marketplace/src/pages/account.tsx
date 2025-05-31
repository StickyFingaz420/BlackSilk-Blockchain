import React, { useState } from 'react';

const AccountPage = () => {
  const [privateKey, setPrivateKey] = useState('');

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    // Handle login logic here
    console.log('Private Key:', privateKey);
  };

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-3xl font-bold mb-4">Account Login</h1>
      <form onSubmit={handleLogin} className="space-y-4">
        <div>
          <label className="block text-lg font-semibold">Private Key / Recovery Phrase</label>
          <textarea
            value={privateKey}
            onChange={(e) => setPrivateKey(e.target.value)}
            className="w-full p-2 border rounded"
            placeholder="Enter your private key or recovery phrase"
            required
          />
        </div>
        <button type="submit" className="px-4 py-2 bg-blue-500 text-white rounded">
          Login
        </button>
      </form>
    </div>
  );
};

export default AccountPage;
