/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    serverComponentsExternalPackages: ['sqlite3'],
  },
  // Enable standalone output for Docker deployment
  output: 'standalone',
  // Custom server configuration
  serverRuntimeConfig: {
    port: process.env.PORT || 3003,
  },
  publicRuntimeConfig: {
    nodeUrl: process.env.NEXT_PUBLIC_NODE_URL || 'http://localhost:19333',
    networkName: process.env.NEXT_PUBLIC_NETWORK_NAME || 'BlackSilk Testnet',
    faucetAmount: process.env.NEXT_PUBLIC_FAUCET_AMOUNT || '10.0',
    cooldownHours: process.env.NEXT_PUBLIC_COOLDOWN_HOURS || '24',
    maxDailyLimit: process.env.NEXT_PUBLIC_MAX_DAILY_LIMIT || '1000',
  },
  // Security headers
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'origin-when-cross-origin',
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=()',
          },
        ],
      },
    ]
  },
  // Rewrites for API routes
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: '/api/:path*',
      },
    ]
  },
}

module.exports = nextConfig
