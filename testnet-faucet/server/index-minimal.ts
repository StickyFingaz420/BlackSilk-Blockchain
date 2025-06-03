import express from 'express';
import cors from 'cors';
import { Database } from './database-new';
import { FaucetService } from './services/faucet-simple';
import { logger } from './logger';

const app = express();
const PORT = process.env.PORT || 3003;

// Middleware
app.use(cors());
app.use(express.json());

// Initialize services
let db: Database;
let faucetService: FaucetService;

async function initializeServices() {
  try {
    db = Database.getInstance();
    await db.initialize();
    faucetService = new FaucetService();
    logger.info('Services initialized successfully');
  } catch (error) {
    logger.error('Failed to initialize services:', error);
    process.exit(1);
  }
}

// Routes
app.post('/api/request', async (req, res) => {
  try {
    const { address, ipAddress } = req.body;
    
    if (!address) {
      return res.status(400).json({ error: 'Address is required' });
    }

    const result = await faucetService.requestTokens(address, ipAddress || req.ip);
    res.json(result);
  } catch (error) {
    logger.error('Request error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/status/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const request = await db.getRequest(id);
    
    if (!request) {
      return res.status(404).json({ error: 'Request not found' });
    }

    res.json({
      id: request.id,
      status: request.status,
      address: request.address,
      amount: request.amount,
      transactionHash: request.transactionHash,
      createdAt: request.createdAt
    });
  } catch (error) {
    logger.error('Status check error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/stats', async (req, res) => {
  try {
    const stats = await db.getStats();
    res.json(stats);
  } catch (error) {
    logger.error('Stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
async function startServer() {
  await initializeServices();
  
  app.listen(PORT, () => {
    logger.info(`Testnet Faucet Server running on port ${PORT}`);
    logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  });
}

if (require.main === module) {
  startServer().catch(error => {
    logger.error('Failed to start server:', error);
    process.exit(1);
  });
}

export default app;
