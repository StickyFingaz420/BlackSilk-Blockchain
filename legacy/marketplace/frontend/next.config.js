/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  trailingSlash: true,
  output: 'export',
  distDir: 'out',
  images: {
    unoptimized: true,
  },
  webpack: (config, { buildId, dev, isServer, defaultLoaders, webpack }) => {
    // Enable WebAssembly support
    config.experiments = { asyncWebAssembly: true };
    
    // Crypto polyfills for browser
    config.resolve.fallback = {
      ...config.resolve.fallback,
      crypto: require.resolve('crypto-browserify'),
      stream: require.resolve('stream-browserify'),
      util: require.resolve('util'),
      buffer: require.resolve('buffer'),
    };

    config.plugins.push(
      new webpack.ProvidePlugin({
        Buffer: ['buffer', 'Buffer'],
        process: 'process/browser',
      })
    );

    return config;
  },
  env: {
    NEXT_PUBLIC_MARKETPLACE_API: process.env.NEXT_PUBLIC_MARKETPLACE_API || 'http://localhost:3000',
    NEXT_PUBLIC_BLACKSILK_NODE: process.env.NEXT_PUBLIC_BLACKSILK_NODE || 'http://localhost:9333',
    NEXT_PUBLIC_IPFS_GATEWAY: process.env.NEXT_PUBLIC_IPFS_GATEWAY || 'https://ipfs.io',
    NEXT_PUBLIC_TOR_PROXY: process.env.NEXT_PUBLIC_TOR_PROXY || 'socks5://127.0.0.1:9050',
  },
};

module.exports = nextConfig;
