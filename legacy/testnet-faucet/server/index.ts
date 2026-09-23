#!/usr/bin/env node

import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import path from 'path'
import { createServer } from 'http'
import next from 'next'

import { initializeDatabase } from './database'
import { initializeLogger, logger } from './logger'
import { FaucetService } from './services/faucet'
import { RateLimiter } from './middleware/rateLimiter'
import { errorHandler } from './middleware/errorHandler'
import { healthCheck } from './middleware/healthCheck'
import { metricsCollector } from './services/metrics'
import apiRoutes from './routes/api'
import adminRoutes from './routes/admin'

const dev = process.env.NODE_ENV !== 'production'
const hostname = process.env.HOST || '0.0.0.0'
const port = parseInt(process.env.PORT || '3003', 10)

class FaucetServer {
  private app: express.Application
  private nextApp: any
  private faucetService: FaucetService
  private rateLimiter: RateLimiter

  constructor() {
    this.app = express()
    this.nextApp = next({ dev, hostname, port })
    this.faucetService = new FaucetService()
    this.rateLimiter = new RateLimiter()
  }

  async initialize(): Promise<void> {
    try {
      // Initialize logger
      initializeLogger()
      logger.info('🚀 Starting BlackSilk Testnet Faucet Service...')

      // Initialize database
      await initializeDatabase()
      logger.info('✅ Database initialized')

      // Initialize Next.js
      await this.nextApp.prepare()
      logger.info('✅ Next.js initialized')

      // Initialize faucet service
      await this.faucetService.initialize()
      logger.info('✅ Faucet service initialized')

      // Setup middleware
      this.setupMiddleware()
      logger.info('✅ Middleware configured')

      // Setup routes
      this.setupRoutes()
      logger.info('✅ Routes configured')

      // Start metrics collection
      metricsCollector.start()
      logger.info('✅ Metrics collection started')

    } catch (error) {
      logger.error('❌ Failed to initialize server:', error)
      process.exit(1)
    }
  }

  private setupMiddleware(): void {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'", "https:"],
          scriptSrc: ["'self'", "'unsafe-eval'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'", "ws:", "wss:"],
        },
      },
      crossOriginEmbedderPolicy: false,
    }))

    // CORS configuration
    this.app.use(cors({
      origin: dev ? true : [
        'https://testnet-faucet.blacksilk.io',
        'https://explorer.blacksilk.io',
        'https://blacksilk.io'
      ],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    }))

    // Request parsing
    this.app.use(express.json({ limit: '1mb' }))
    this.app.use(express.urlencoded({ extended: true, limit: '1mb' }))

    // Health check (before rate limiting)
    this.app.use('/health', healthCheck)

    // Rate limiting
    this.app.use('/api/', this.rateLimiter.middleware())

    // Request logging
    this.app.use((req, res, next) => {
      const start = Date.now()
      res.on('finish', () => {
        const duration = Date.now() - start
        logger.info(`${req.method} ${req.path} ${res.statusCode} ${duration}ms`, {
          method: req.method,
          path: req.path,
          statusCode: res.statusCode,
          duration,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
        })
      })
      next()
    })

    // Inject faucet service into request
    this.app.use((req, res, next) => {
      (req as any).faucetService = this.faucetService
      next()
    })
  }

  private setupRoutes(): void {
    const handle = this.nextApp.getRequestHandler()

    // API routes
    this.app.use('/api', apiRoutes)
    this.app.use('/admin', adminRoutes)

    // Metrics endpoint
    this.app.get('/metrics', (req, res) => {
      const metrics = metricsCollector.getMetrics()
      res.json(metrics)
    })

    // Status endpoint
    this.app.get('/status', async (req, res) => {
      try {
        const status = await this.faucetService.getStatus()
        res.json(status)
      } catch (error) {
        logger.error('Status check failed:', error)
        res.status(500).json({ error: 'Status check failed' })
      }
    })

    // Static files for production
    if (!dev) {
      this.app.use('/static', express.static(path.join(__dirname, '../.next/static')))
    }

    // Next.js handler for all other routes
    this.app.all('*', (req, res) => {
      return handle(req, res)
    })

    // Error handling middleware (must be last)
    this.app.use(errorHandler)
  }

  async start(): Promise<void> {
    try {
      const server = createServer(this.app)

      server.listen(port, hostname, () => {
        logger.info(`🎉 BlackSilk Testnet Faucet running on http://${hostname}:${port}`)
        logger.info(`📊 Health check: http://${hostname}:${port}/health`)
        logger.info(`📈 Metrics: http://${hostname}:${port}/metrics`)
        logger.info(`🔧 Admin: http://${hostname}:${port}/admin`)
      })

      // Graceful shutdown
      process.on('SIGTERM', () => this.shutdown(server))
      process.on('SIGINT', () => this.shutdown(server))

    } catch (error) {
      logger.error('❌ Failed to start server:', error)
      process.exit(1)
    }
  }

  private async shutdown(server: any): Promise<void> {
    logger.info('🛑 Shutting down server gracefully...')
    
    server.close(() => {
      logger.info('✅ HTTP server closed')
    })

    await this.faucetService.shutdown()
    metricsCollector.stop()
    
    logger.info('👋 Server shutdown complete')
    process.exit(0)
  }
}

// Start the server
if (require.main === module) {
  const server = new FaucetServer()
  
  server.initialize().then(() => {
    return server.start()
  }).catch((error) => {
    logger.error('❌ Fatal error:', error)
    process.exit(1)
  })
}

export default FaucetServer
