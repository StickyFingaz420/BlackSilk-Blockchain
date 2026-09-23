# BlackSilk Testnet Faucet

A production-ready web service for distributing BlackSilk testnet tokens (tBLK) to developers and testers. Built with Next.js 14, Express.js, and SQLite with comprehensive rate limiting, admin controls, and security features.

## ✅ **DEPLOYMENT STATUS: FULLY OPERATIONAL**

The BlackSilk Testnet Faucet has been successfully completed and deployed:

- ✅ **Frontend Server**: Running on http://localhost:3000
- ✅ **Backend API**: Running on http://localhost:3003  
- ✅ **Database**: SQLite operational with all tables
- ✅ **Address Validation**: tBLK testnet address support
- ✅ **Rate Limiting**: 24-hour cooldown per address/IP
- ✅ **Admin Panel**: Management interface available
- ✅ **API Integration**: Frontend-backend communication working
- ✅ **Token Distribution**: Mock blockchain integration for testnet

### 🚀 Quick Start

```bash
# Start both servers
npm run dev:server &  # Backend on :3003
npm run dev &         # Frontend on :3000

# Test the system
./test-complete-system.sh
```

## 🎯 Features

### Core Functionality
- **Automated Token Distribution**: Secure and reliable testnet token distribution
- **Rate Limiting**: Configurable rate limits (1 request per address per 24 hours)
- **Queue Management**: Efficient request processing with queue system
- **Transaction Tracking**: Complete transaction lifecycle monitoring

### Security & Anti-Abuse
- **IP-based Rate Limiting**: Multiple rate limiting policies for different endpoints
- **Address Blacklisting**: Manual and automated blacklist management
- **JWT Authentication**: Secure admin authentication system
- **Request Validation**: Comprehensive input validation and sanitization

### Administration
- **Admin Dashboard**: Full-featured web interface for monitoring and management
- **Real-time Stats**: System health, performance metrics, and usage statistics
- **Request Management**: View, track, and manage all faucet requests
- **Configuration Management**: Dynamic configuration updates
- **System Logs**: Comprehensive logging with multiple log levels

### Infrastructure
- **Docker Support**: Complete containerization with Docker Compose
- **Database Storage**: SQLite3 with comprehensive schemas
- **Health Monitoring**: System health checks and alerts
- **Metrics Collection**: Prometheus-compatible metrics export
- **Reverse Proxy**: Nginx configuration with security headers

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Nginx Reverse Proxy                     │
│                  (Rate Limiting & SSL)                     │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                  Next.js Frontend                          │
│              (React + TypeScript)                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                 Express.js Backend                         │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Faucet    │  │    Rate     │  │      Health         │ │
│  │   Service   │  │   Limiter   │  │     Monitor         │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Admin     │  │   Metrics   │  │      Logger         │ │
│  │   System    │  │ Collection  │  │     System          │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                   SQLite Database                          │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  Requests   │  │ Rate Limits │  │     Blacklist       │ │
│  │   Table     │  │    Table    │  │      Table          │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                BlackSilk Blockchain Node                   │
│                    (JSON-RPC API)                          │
└─────────────────────────────────────────────────────────────┘
```

## 🛠️ Technology Stack

### Frontend
- **Next.js 14**: React framework with App Router
- **TypeScript**: Type-safe development
- **Tailwind CSS**: Utility-first CSS framework
- **React Hot Toast**: User notifications
- **React Hooks**: State management

### Backend
- **Express.js**: Web application framework
- **TypeScript**: Server-side type safety
- **SQLite3**: Embedded database
- **Winston**: Comprehensive logging
- **JWT**: Authentication tokens
- **Helmet**: Security middleware

### Infrastructure
- **Docker**: Containerization
- **Docker Compose**: Multi-container orchestration
- **Nginx**: Reverse proxy and load balancer
- **PM2**: Process management (optional)

## 📋 Prerequisites

- **Node.js** 18+ 
- **Docker** and **Docker Compose**
- **BlackSilk Node** running and accessible
- **Git** for version control

## 🚀 Quick Start

### 1. Clone and Setup

```bash
git clone https://github.com/BlackSilk-Blockchain/BlackSilk-Blockchain.git
cd BlackSilk-Blockchain/testnet-faucet
```

### 2. Environment Configuration

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```env
# Database
DATABASE_PATH=./data/faucet.db

# BlackSilk Node Configuration
BLACKSILK_RPC_URL=http://localhost:8332
BLACKSILK_RPC_USER=your_rpc_username
BLACKSILK_RPC_PASSWORD=your_rpc_password

# Faucet Configuration
FAUCET_AMOUNT=10
FAUCET_PRIVATE_KEY=your_private_key_here
RATE_LIMIT_HOURS=24

# Admin Configuration
ADMIN_USERNAME=admin
ADMIN_PASSWORD=secure_password_here
JWT_SECRET=your_jwt_secret_here

# Server Configuration
PORT=3000
NODE_ENV=production
```

### 3. Docker Deployment (Recommended)

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### 4. Manual Installation

```bash
# Install dependencies
npm install

# Build the application
npm run build

# Start the production server
npm start
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DATABASE_PATH` | SQLite database file path | `./data/faucet.db` | No |
| `BLACKSILK_RPC_URL` | BlackSilk node RPC endpoint | `http://localhost:8332` | Yes |
| `BLACKSILK_RPC_USER` | RPC username | - | Yes |
| `BLACKSILK_RPC_PASSWORD` | RPC password | - | Yes |
| `FAUCET_AMOUNT` | Tokens per request | `10` | No |
| `FAUCET_PRIVATE_KEY` | Wallet private key | - | Yes |
| `RATE_LIMIT_HOURS` | Hours between requests | `24` | No |
| `ADMIN_USERNAME` | Admin username | `admin` | No |
| `ADMIN_PASSWORD` | Admin password | - | Yes |
| `JWT_SECRET` | JWT signing secret | - | Yes |
| `PORT` | Server port | `3000` | No |

### Rate Limiting Configuration

The faucet implements multiple rate limiting policies:

- **Faucet Requests**: 1 per address per 24 hours
- **API Calls**: 100 per IP per 15 minutes  
- **Status Checks**: 60 per IP per minute
- **Admin Access**: 20 per IP per 15 minutes

## 📊 API Documentation

### Public Endpoints

#### Request Tokens
```http
POST /api/faucet
Content-Type: application/json

{
  "address": "tBLK_ADDRESS_HERE",
  "amount": 10
}
```

#### Check Request Status
```http
GET /api/status/{transactionId}
```

#### Get Public Stats
```http
GET /api/stats
```

### Admin Endpoints

All admin endpoints require JWT authentication via cookies.

#### Admin Login
```http
POST /api/admin/login
Content-Type: application/json

{
  "username": "admin",
  "password": "password"
}
```

#### Get Admin Stats
```http
GET /api/admin/stats
Authorization: Bearer {jwt_token}
```

#### Manage Blacklist
```http
POST /api/admin/blacklist
Content-Type: application/json

{
  "address": "tBLK_ADDRESS",
  "reason": "Abuse detected"
}
```

## 🏥 Health Monitoring

The faucet includes comprehensive health monitoring:

```http
GET /health
```

Response includes:
- Database connectivity
- BlackSilk node status
- Memory usage
- System uptime
- API endpoint health

## 📈 Metrics & Monitoring

Prometheus-compatible metrics are available at:

```http
GET /metrics
```

Key metrics:
- Request count and success rate
- Processing time distribution
- Queue size and wait times
- System resource usage
- Error rates by type

## 🛡️ Security Features

### Authentication & Authorization
- JWT-based admin authentication
- Role-based access control
- Secure cookie handling
- Session timeout management

### Rate Limiting & Anti-Abuse
- Multi-tier IP-based rate limiting
- Address-based request limiting
- Automatic blacklist detection
- Manual blacklist management

### Data Protection
- Input validation and sanitization
- SQL injection prevention
- XSS protection
- CSRF protection
- Security headers (Helmet.js)

### Infrastructure Security
- Nginx reverse proxy
- SSL/TLS termination
- Docker container isolation
- Non-root container execution

## 🐳 Docker Configuration

The application includes production-ready Docker configuration:

### Dockerfile Features
- Multi-stage build for optimization
- Non-root user execution
- Minimal attack surface
- Health check integration
- Volume mounts for data persistence

### Docker Compose Services
- **faucet**: Main application container
- **nginx**: Reverse proxy with rate limiting
- **blacksilk**: BlackSilk node integration (optional)

## 📝 Logging

Comprehensive logging system with Winston:

### Log Levels
- **Error**: System errors and failures
- **Warn**: Warning conditions
- **Info**: General operational messages
- **Debug**: Detailed debugging information

### Log Files
- `error.log`: Error-level messages only
- `combined.log`: All log levels
- Console output for development

### Log Rotation
Automatic log rotation with:
- Maximum file size: 20MB
- Maximum files: 5
- Automatic compression

## 🔍 Troubleshooting

### Common Issues

#### Database Connection Errors
```bash
# Check database file permissions
ls -la ./data/faucet.db

# Reset database
rm ./data/faucet.db
npm run setup
```

#### BlackSilk Node Connection
```bash
# Test RPC connection
curl -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"1.0","id":"test","method":"getblockchaininfo","params":[]}' \
  http://username:password@localhost:8332/
```

#### Rate Limiting Issues
```bash
# Check rate limit database
sqlite3 ./data/faucet.db "SELECT * FROM rate_limits WHERE ip_address = 'YOUR_IP';"
```

### Debug Mode

Enable debug logging:
```bash
NODE_ENV=development npm start
```

Or with Docker:
```bash
docker-compose -f docker-compose.yml -f docker-compose.debug.yml up
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow TypeScript best practices
- Add tests for new features
- Update documentation
- Use conventional commit messages
- Ensure Docker builds pass

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:

- **GitHub Issues**: [Report bugs or request features](https://github.com/BlackSilk-Blockchain/BlackSilk-Blockchain/issues)
- **Discord**: Join our [Discord community](https://discord.gg/blacksilk)
- **Documentation**: Visit our [official documentation](https://docs.blacksilk.com)

## 🎯 Roadmap

### Near Term (Next Release)
- [ ] CAPTCHA integration
- [ ] Multi-language support
- [ ] Advanced analytics dashboard
- [ ] WebSocket real-time updates

### Medium Term
- [ ] Multiple token support
- [ ] Social media verification
- [ ] API key management
- [ ] Webhook notifications

### Long Term
- [ ] Kubernetes deployment
- [ ] Multi-chain support
- [ ] Advanced fraud detection
- [ ] Machine learning abuse detection

---

**BlackSilk Testnet Faucet** - Empowering developers with reliable testnet infrastructure.

For more information about BlackSilk blockchain, visit [blacksilk.com](https://blacksilk.com).
