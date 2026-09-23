/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    appDir: true,
  },
  images: {
    domains: ['localhost', 'testnet-seed1.blacksilk.io', 'seed1.blacksilk.io'],
  },
  async rewrites() {
    return [
      {
        source: '/api/node/:path*',
        destination: process.env.NODE_URL + '/:path*',
      },
    ];
  },
  webpack: (config) => {
    config.resolve.fallback = {
      ...config.resolve.fallback,
      fs: false,
      net: false,
      dns: false,
      child_process: false,
      tls: false,
    };
    return config;
  },
};

module.exports = nextConfig;
