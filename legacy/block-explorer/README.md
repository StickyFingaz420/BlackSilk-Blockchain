# BlackSilk Block Explorer

A modern, responsive web-based block explorer for the BlackSilk Blockchain. Built with Next.js, TypeScript, and Tailwind CSS.

## Features

### 🔍 **Comprehensive Blockchain Exploration**
- **Real-time Network Statistics**: Live block height, difficulty, hashrate, peer count
- **Block Browser**: Detailed block information with transaction lists
- **Transaction Viewer**: Complete transaction details with privacy features
- **Address Lookup**: Balance and transaction history for addresses
- **Mempool Monitor**: View pending transactions
- **Smart Search**: Search by block height, hash, transaction ID, or address

### 🎨 **Modern User Experience**
- **Responsive Design**: Mobile-first design that works on all devices
- **Dark/Light Theme**: Automatic theme detection with manual toggle
- **Fast Loading**: Optimized performance with skeleton loaders
- **Real-time Updates**: Auto-refreshing data every 30 seconds
- **Intuitive Navigation**: Clean, modern interface with smooth animations

### 🔒 **Privacy-Focused Features**
- **Privacy Transaction Support**: Ring signature and stealth address detection
- **Transaction Type Indicators**: Clear labeling of privacy levels
- **Confidential Amounts**: Support for hidden transaction amounts
- **Security-First**: No private key handling, read-only blockchain access

### 📊 **Advanced Analytics**
- **Network Charts**: Difficulty, hashrate, and block time trends
- **Transaction Statistics**: Volume, fees, and privacy usage
- **Mining Information**: Current rewards, difficulty adjustments
- **Supply Metrics**: Circulating supply, burned coins, halving countdown

## Quick Start

### Prerequisites

- Node.js 18+ and npm/yarn
- BlackSilk node running (testnet or mainnet)
- Git for cloning the repository

### Installation

```bash
# Clone the repository
git clone https://github.com/StickyFingaz420/BlackSilk-Blockchain.git
cd BlackSilk-Blockchain/block-explorer

# Install dependencies
npm install

# Copy environment configuration
cp .env.example .env.local

# Configure your node connection
nano .env.local
```

### Configuration

Edit `.env.local` to match your setup:

```bash
# BlackSilk Node Configuration
NODE_URL=http://localhost:19333                    # Testnet
# NODE_URL=http://localhost:9333                   # Mainnet
NEXT_PUBLIC_NODE_URL=http://localhost:19333

# Network Settings
NEXT_PUBLIC_NETWORK=testnet
NEXT_PUBLIC_NETWORK_NAME=BlackSilk Testnet

# Feature Flags
NEXT_PUBLIC_SHOW_PRIVACY_INFO=true
NEXT_PUBLIC_SHOW_MINING_STATS=true
NEXT_PUBLIC_ENABLE_SEARCH=true

# External Services
NEXT_PUBLIC_FAUCET_URL=http://localhost:3003
NEXT_PUBLIC_GITHUB_URL=https://github.com/blacksilk-org/BlackSilk-Blockchain
```

### Development

```bash
# Start development server
npm run dev

# Open browser
open http://localhost:3002
```

### Production Build

```bash
# Build for production
npm run build

# Start production server
npm start
```

## Architecture

### Technology Stack

- **Frontend Framework**: Next.js 14 (App Router)
- **Language**: TypeScript for type safety
- **Styling**: Tailwind CSS with custom design system
- **State Management**: React hooks and context
- **HTTP Client**: Axios with retry logic
- **Animations**: Framer Motion
- **Icons**: Lucide React
- **Charts**: Recharts for data visualization

### Project Structure

```
block-explorer/
├── src/
│   ├── app/                    # Next.js app router
│   │   ├── layout.tsx          # Root layout
│   │   ├── page.tsx            # Homepage
│   │   ├── globals.css         # Global styles
│   │   └── providers.tsx       # Context providers
│   ├── components/             # React components
│   │   ├── dashboard/          # Dashboard components
│   │   ├── layout/             # Layout components
│   │   └── search/             # Search components
│   ├── lib/                    # Utilities and API
│   │   ├── api.ts              # BlackSilk API client
│   │   └── utils.ts            # Helper functions
│   └── types/                  # TypeScript definitions
│       └── index.ts            # Type definitions
├── public/                     # Static assets
├── package.json                # Dependencies and scripts
├── tailwind.config.js          # Tailwind configuration
├── tsconfig.json               # TypeScript configuration
└── next.config.js              # Next.js configuration
```

### API Integration

The explorer connects to the BlackSilk node's HTTP API:

```typescript
// Core endpoints used:
GET /status                     # Network information
GET /get_blocks                 # Block list with pagination
GET /get_block/{hash|height}    # Specific block details
GET /get_transaction/{txid}     # Transaction details
GET /get_mempool                # Pending transactions
GET /search?q={query}           # Search functionality
```

## Features Documentation

### Search Functionality

The explorer supports multiple search types:

- **Block Height**: Enter a number (e.g., `1000`)
- **Block Hash**: 64-character hex string
- **Transaction Hash**: 64-character hex string
- **Address**: Base58 encoded address
- **Keywords**: `latest`, `mempool`, etc.

### Real-time Updates

Data automatically refreshes:
- **Network stats**: Every 10 seconds
- **Blocks/transactions**: Every 30 seconds
- **Charts**: Every 60 seconds

### Privacy Features

The explorer respects privacy:
- **No tracking**: No analytics or user tracking
- **Read-only**: Never requests private keys
- **Privacy indicators**: Clear labels for private transactions
- **Ring signature support**: Shows ring size and privacy level

### Responsive Design

Optimized for all devices:
- **Mobile-first**: Designed for mobile screens
- **Tablet-friendly**: Optimized layouts for tablets
- **Desktop-enhanced**: Full feature set on desktop
- **Touch-friendly**: Large touch targets

## Deployment

### Docker Deployment

```bash
# Build Docker image
docker build -t blacksilk-explorer .

# Run container
docker run -d \
  --name blacksilk-explorer \
  -p 3002:3002 \
  -e NODE_URL=http://your-node:19333 \
  -e NEXT_PUBLIC_NODE_URL=http://your-node:19333 \
  blacksilk-explorer
```

### Docker Compose

```yaml
version: '3.8'
services:
  explorer:
    build: .
    ports:
      - "3002:3002"
    environment:
      - NODE_URL=http://node:19333
      - NEXT_PUBLIC_NODE_URL=http://localhost:19333
    depends_on:
      - node
```

### Production Considerations

**Performance Optimization:**
- Enable Node.js caching
- Use CDN for static assets
- Configure proper cache headers
- Monitor API response times

**Security:**
- Use HTTPS in production
- Configure CORS properly
- Set security headers
- Monitor for DDoS attacks

**Monitoring:**
- Set up health checks
- Monitor API availability
- Track error rates
- Monitor memory usage

## Development

### Code Standards

```bash
# Linting
npm run lint

# Type checking
npm run type-check

# Format code
npm run format
```

### Testing

```bash
# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# E2E tests
npm run test:e2e
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## API Documentation

### Network Status

```bash
curl http://localhost:19333/status
```

Response:
```json
{
  "version": "1.0.0",
  "network": "testnet",
  "height": 12345,
  "difficulty": 1000000,
  "peers": 8,
  "mempool_size": 5
}
```

### Block Data

```bash
curl http://localhost:19333/get_blocks?limit=10
```

### Search

```bash
curl http://localhost:19333/search?q=1000
curl http://localhost:19333/search?q=abc123...
```

## Troubleshooting

### Common Issues

**Connection Error:**
```
Failed to load network statistics
```
- Check if BlackSilk node is running
- Verify NODE_URL in environment
- Check firewall settings

**Slow Loading:**
```
Long response times
```
- Check node performance
- Verify API rate limits
- Monitor network latency

**Build Errors:**
```
Type errors during build
```
- Run `npm run type-check`
- Check TypeScript configuration
- Update dependencies

### Debug Mode

Enable debug logging:

```bash
DEBUG=* npm run dev
```

Check browser console for client-side errors.

### Performance Monitoring

Monitor API calls:
```bash
# Check API response times
curl -w "%{time_total}" http://localhost:19333/status

# Monitor memory usage
docker stats blacksilk-explorer
```

## Support

- **Documentation**: [docs.blacksilk.io](https://docs.blacksilk.io)
- **Issues**: [GitHub Issues](https://github.com/blacksilk-org/BlackSilk-Blockchain/issues)
- **Community**: [Discord](https://discord.gg/blacksilk)

## License

MIT License - see [LICENSE](../LICENSE) file for details.

---

**Happy Exploring!** 🚀

The BlackSilk Block Explorer makes blockchain data accessible and beautiful. Whether you're a developer, miner, or curious user, explore the privacy-first blockchain with confidence.
