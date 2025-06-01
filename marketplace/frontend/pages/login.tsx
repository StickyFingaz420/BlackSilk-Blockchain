import { useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { Shield, Key, FileText, Eye, EyeOff, Lock, Unlock } from 'lucide-react';
import { useAuth } from '@/hooks';

export default function LoginPage() {
  const router = useRouter();
  const { login, isLoading } = useAuth();
  
  const [loginMethod, setLoginMethod] = useState<'private-key' | 'recovery-phrase'>('private-key');
  const [privateKey, setPrivateKey] = useState('');
  const [recoveryPhrase, setRecoveryPhrase] = useState('');
  const [showPrivateKey, setShowPrivateKey] = useState(false);
  const [error, setError] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (loginMethod === 'private-key' && !privateKey.trim()) {
      setError('Please enter your private key');
      return;
    }

    if (loginMethod === 'recovery-phrase' && !recoveryPhrase.trim()) {
      setError('Please enter your recovery phrase');
      return;
    }

    try {
      const result = await login(
        loginMethod === 'private-key' ? privateKey : recoveryPhrase,
        loginMethod === 'recovery-phrase' ? recoveryPhrase : undefined
      );

      if (result.success) {
        router.push('/dashboard');
      } else {
        setError(result.error || 'Login failed');
      }
    } catch (err) {
      setError('An unexpected error occurred');
    }
  };

  const generateNewWallet = async () => {
    setIsGenerating(true);
    try {
      // Generate new wallet credentials
      const newPrivateKey = generatePrivateKey();
      const newRecoveryPhrase = generateRecoveryPhrase();
      
      setPrivateKey(newPrivateKey);
      setRecoveryPhrase(newRecoveryPhrase);
      setLoginMethod('private-key');
      setShowPrivateKey(true);
      
      // Show success message
      setError('');
    } catch (err) {
      setError('Failed to generate new wallet');
    } finally {
      setIsGenerating(false);
    }
  };

  const generatePrivateKey = (): string => {
    // Generate a secure random private key
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  };

  const generateRecoveryPhrase = (): string => {
    // Simple word list for demonstration
    const words = [
      'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
      'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid',
      'acoustic', 'acquire', 'across', 'act', 'action', 'actor', 'actress', 'actual',
      'adapt', 'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance',
    ];
    
    const phrase = [];
    for (let i = 0; i < 12; i++) {
      phrase.push(words[Math.floor(Math.random() * words.length)]);
    }
    return phrase.join(' ');
  };

  return (
    <>
      <Head>
        <title>Login - BlackSilk Marketplace</title>
        <meta name="description" content="Access your BlackSilk wallet with private key or recovery phrase" />
      </Head>

      <div className="min-h-screen bg-silk-gradient flex items-center justify-center px-4">
        <div className="max-w-md w-full">
          {/* Header */}
          <div className="text-center mb-8">
            <Link href="/" className="inline-flex items-center space-x-2 mb-6">
              <Shield className="h-10 w-10 text-silk-accent" />
              <span className="text-2xl font-bold text-silk-text">BlackSilk</span>
            </Link>
            <h1 className="text-3xl font-bold text-silk-text mb-2">
              Access Your Wallet
            </h1>
            <p className="text-silk-muted">
              No registration required. Just your private key or recovery phrase.
            </p>
          </div>

          {/* Community Warning */}
          <div className="community-warning mb-6">
            <p className="text-sm">
              <strong>Community Standards:</strong> Don't be sick. 
              We maintain zero tolerance for inappropriate content.
            </p>
          </div>

          {/* Login Form */}
          <div className="silk-card">
            <form onSubmit={handleLogin} className="space-y-6">
              {/* Login Method Selector */}
              <div>
                <label className="block text-sm font-medium text-silk-text mb-3">
                  Access Method
                </label>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    type="button"
                    onClick={() => setLoginMethod('private-key')}
                    className={`flex items-center justify-center p-3 rounded-lg border transition-colors ${
                      loginMethod === 'private-key'
                        ? 'border-silk-accent bg-silk-accent/20 text-silk-accent'
                        : 'border-silk-gray bg-silk-gray text-silk-muted hover:border-silk-light'
                    }`}
                  >
                    <Key className="h-4 w-4 mr-2" />
                    Private Key
                  </button>
                  <button
                    type="button"
                    onClick={() => setLoginMethod('recovery-phrase')}
                    className={`flex items-center justify-center p-3 rounded-lg border transition-colors ${
                      loginMethod === 'recovery-phrase'
                        ? 'border-silk-accent bg-silk-accent/20 text-silk-accent'
                        : 'border-silk-gray bg-silk-gray text-silk-muted hover:border-silk-light'
                    }`}
                  >
                    <FileText className="h-4 w-4 mr-2" />
                    Recovery Phrase
                  </button>
                </div>
              </div>

              {/* Private Key Input */}
              {loginMethod === 'private-key' && (
                <div>
                  <label className="block text-sm font-medium text-silk-text mb-2">
                    Private Key
                  </label>
                  <div className="relative">
                    <input
                      type={showPrivateKey ? 'text' : 'password'}
                      value={privateKey}
                      onChange={(e) => setPrivateKey(e.target.value)}
                      placeholder="Enter your 64-character private key"
                      className="silk-input w-full pr-10"
                      maxLength={64}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPrivateKey(!showPrivateKey)}
                      className="absolute right-3 top-1/2 transform -translate-y-1/2 text-silk-muted hover:text-silk-accent"
                    >
                      {showPrivateKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                  <p className="text-xs text-silk-muted mt-1">
                    Your private key is never sent to our servers
                  </p>
                </div>
              )}

              {/* Recovery Phrase Input */}
              {loginMethod === 'recovery-phrase' && (
                <div>
                  <label className="block text-sm font-medium text-silk-text mb-2">
                    Recovery Phrase
                  </label>
                  <textarea
                    value={recoveryPhrase}
                    onChange={(e) => setRecoveryPhrase(e.target.value)}
                    placeholder="Enter your 12-word recovery phrase"
                    className="silk-input w-full h-24 resize-none"
                    rows={3}
                  />
                  <p className="text-xs text-silk-muted mt-1">
                    Enter words separated by spaces
                  </p>
                </div>
              )}

              {/* Error Message */}
              {error && (
                <div className="bg-silk-warning/20 border border-silk-warning/50 text-silk-warning p-3 rounded-lg text-sm">
                  {error}
                </div>
              )}

              {/* Login Button */}
              <button
                type="submit"
                disabled={isLoading}
                className="silk-button w-full flex items-center justify-center"
              >
                {isLoading ? (
                  <div className="loading-spinner mr-2" />
                ) : (
                  <Unlock className="h-4 w-4 mr-2" />
                )}
                {isLoading ? 'Accessing...' : 'Access Wallet'}
              </button>
            </form>

            {/* Generate New Wallet */}
            <div className="mt-6 pt-6 border-t border-silk-gray">
              <div className="text-center">
                <p className="text-silk-muted text-sm mb-4">
                  Don't have a wallet yet?
                </p>
                <button
                  onClick={generateNewWallet}
                  disabled={isGenerating}
                  className="silk-button-secondary w-full flex items-center justify-center"
                >
                  {isGenerating ? (
                    <div className="loading-spinner mr-2" />
                  ) : (
                    <Lock className="h-4 w-4 mr-2" />
                  )}
                  {isGenerating ? 'Generating...' : 'Generate New Wallet'}
                </button>
              </div>
            </div>

            {/* Privacy Notice */}
            <div className="mt-6 pt-6 border-t border-silk-gray">
              <div className="flex items-start space-x-3">
                <Shield className="h-5 w-5 text-silk-accent mt-0.5 flex-shrink-0" />
                <div className="text-xs text-silk-muted">
                  <p className="font-medium text-silk-text mb-1">Privacy First</p>
                  <p>
                    Your credentials are processed locally in your browser. 
                    Enable Tor for maximum anonymity.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Back to Home */}
          <div className="text-center mt-6">
            <Link href="/" className="text-silk-muted hover:text-silk-accent transition-colors text-sm">
              ← Back to Marketplace
            </Link>
          </div>
        </div>
      </div>
    </>
  );
}
