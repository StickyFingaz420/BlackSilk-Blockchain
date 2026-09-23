import { Router, Request, Response } from 'express';
import { Database } from '../database';
import { Logger } from '../logger';
import { FaucetService } from '../services/faucet';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

export class AdminRoutes {
  private router: Router;
  private db: Database;
  private logger: Logger;
  private faucetService: FaucetService;

  constructor(db: Database, logger: Logger, faucetService: FaucetService) {
    this.router = Router();
    this.db = db;
    this.logger = logger;
    this.faucetService = faucetService;
    this.setupRoutes();
  }

  private setupRoutes(): void {
    // Admin authentication
    this.router.post('/auth/login', this.login.bind(this));
    this.router.post('/auth/logout', this.authenticateAdmin.bind(this), this.logout.bind(this));
    this.router.get('/auth/verify', this.authenticateAdmin.bind(this), this.verifyToken.bind(this));

    // Configuration management
    this.router.get('/config', this.authenticateAdmin.bind(this), this.getConfig.bind(this));
    this.router.put('/config', this.authenticateAdmin.bind(this), this.updateConfig.bind(this));

    // Request management
    this.router.get('/requests', this.authenticateAdmin.bind(this), this.getRequests.bind(this));
    this.router.put('/requests/:id/status', this.authenticateAdmin.bind(this), this.updateRequestStatus.bind(this));
    this.router.delete('/requests/:id', this.authenticateAdmin.bind(this), this.deleteRequest.bind(this));

    // System management
    this.router.get('/stats/detailed', this.authenticateAdmin.bind(this), this.getDetailedStats.bind(this));
    this.router.get('/health/system', this.authenticateAdmin.bind(this), this.getSystemHealth.bind(this));
    this.router.post('/system/reset-rates', this.authenticateAdmin.bind(this), this.resetRateLimits.bind(this));
    this.router.post('/system/refill', this.authenticateAdmin.bind(this), this.refillFaucet.bind(this));

    // User management
    this.router.get('/blacklist', this.authenticateAdmin.bind(this), this.getBlacklist.bind(this));
    this.router.post('/blacklist', this.authenticateAdmin.bind(this), this.addToBlacklist.bind(this));
    this.router.delete('/blacklist/:address', this.authenticateAdmin.bind(this), this.removeFromBlacklist.bind(this));

    // Logs
    this.router.get('/logs', this.authenticateAdmin.bind(this), this.getLogs.bind(this));
  }

  private authenticateAdmin(req: Request, res: Response, next: Function): void {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) {
        res.status(401).json({ error: 'No token provided' });
        return;
      }

      const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      
      if (decoded.role !== 'admin') {
        res.status(403).json({ error: 'Admin access required' });
        return;
      }

      req.user = decoded;
      next();
    } catch (error) {
      this.logger.error('Admin authentication failed:', error);
      res.status(401).json({ error: 'Invalid token' });
    }
  }

  private async login(req: Request, res: Response): Promise<void> {
    try {
      const { username, password } = req.body;

      if (!username || !password) {
        res.status(400).json({ error: 'Username and password required' });
        return;
      }

      // Check admin credentials (in production, use proper hashing)
      const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
      const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

      if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
        res.status(401).json({ error: 'Invalid credentials' });
        return;
      }

      // Generate JWT token
      const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
      const token = jwt.sign(
        { username, role: 'admin', timestamp: Date.now() },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      this.logger.info(`Admin login successful: ${username}`);

      res.json({
        success: true,
        token,
        user: { username, role: 'admin' }
      });
    } catch (error) {
      this.logger.error('Admin login error:', error);
      res.status(500).json({ error: 'Login failed' });
    }
  }

  private async logout(req: Request, res: Response): Promise<void> {
    try {
      this.logger.info(`Admin logout: ${req.user?.username}`);
      res.json({ success: true, message: 'Logged out successfully' });
    } catch (error) {
      this.logger.error('Admin logout error:', error);
      res.status(500).json({ error: 'Logout failed' });
    }
  }

  private async verifyToken(req: Request, res: Response): Promise<void> {
    try {
      res.json({
        success: true,
        user: { username: req.user.username, role: 'admin' }
      });
    } catch (error) {
      this.logger.error('Token verification error:', error);
      res.status(500).json({ error: 'Token verification failed' });
    }
  }

  private async getConfig(req: Request, res: Response): Promise<void> {
    try {
      const config = await this.db.getConfig();
      res.json({ success: true, config });
    } catch (error) {
      this.logger.error('Get config error:', error);
      res.status(500).json({ error: 'Failed to get configuration' });
    }
  }

  private async updateConfig(req: Request, res: Response): Promise<void> {
    try {
      const { key, value } = req.body;

      if (!key || value === undefined) {
        res.status(400).json({ error: 'Key and value required' });
        return;
      }

      await this.db.setConfig(key, value);
      this.logger.info(`Admin updated config: ${key} = ${value}`, { admin: req.user.username });

      res.json({ success: true, message: 'Configuration updated' });
    } catch (error) {
      this.logger.error('Update config error:', error);
      res.status(500).json({ error: 'Failed to update configuration' });
    }
  }

  private async getRequests(req: Request, res: Response): Promise<void> {
    try {
      const { page = 1, limit = 50, status, address } = req.query;
      const offset = (Number(page) - 1) * Number(limit);

      let query = `
        SELECT fr.*, rl.ip_address 
        FROM faucet_requests fr
        LEFT JOIN rate_limits rl ON fr.id = rl.id
        WHERE 1=1
      `;
      const params: any[] = [];

      if (status) {
        query += ' AND fr.status = ?';
        params.push(status);
      }

      if (address) {
        query += ' AND fr.address LIKE ?';
        params.push(`%${address}%`);
      }

      query += ' ORDER BY fr.created_at DESC LIMIT ? OFFSET ?';
      params.push(Number(limit), offset);

      const requests = await this.db.query(query, params);

      // Get total count
      let countQuery = 'SELECT COUNT(*) as total FROM faucet_requests WHERE 1=1';
      const countParams: any[] = [];

      if (status) {
        countQuery += ' AND status = ?';
        countParams.push(status);
      }

      if (address) {
        countQuery += ' AND address LIKE ?';
        countParams.push(`%${address}%`);
      }

      const [{ total }] = await this.db.query(countQuery, countParams);

      res.json({
        success: true,
        requests,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit))
        }
      });
    } catch (error) {
      this.logger.error('Get requests error:', error);
      res.status(500).json({ error: 'Failed to get requests' });
    }
  }

  private async updateRequestStatus(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { status, admin_notes } = req.body;

      if (!['pending', 'completed', 'failed', 'cancelled'].includes(status)) {
        res.status(400).json({ error: 'Invalid status' });
        return;
      }

      await this.db.query(
        'UPDATE faucet_requests SET status = ?, admin_notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [status, admin_notes || null, id]
      );

      this.logger.info(`Admin updated request ${id} status to ${status}`, { 
        admin: req.user.username,
        notes: admin_notes 
      });

      res.json({ success: true, message: 'Request status updated' });
    } catch (error) {
      this.logger.error('Update request status error:', error);
      res.status(500).json({ error: 'Failed to update request status' });
    }
  }

  private async deleteRequest(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      await this.db.query('DELETE FROM faucet_requests WHERE id = ?', [id]);

      this.logger.info(`Admin deleted request ${id}`, { admin: req.user.username });

      res.json({ success: true, message: 'Request deleted' });
    } catch (error) {
      this.logger.error('Delete request error:', error);
      res.status(500).json({ error: 'Failed to delete request' });
    }
  }

  private async getDetailedStats(req: Request, res: Response): Promise<void> {
    try {
      const stats = await this.faucetService.getDetailedStatistics();
      res.json({ success: true, stats });
    } catch (error) {
      this.logger.error('Get detailed stats error:', error);
      res.status(500).json({ error: 'Failed to get detailed statistics' });
    }
  }

  private async getSystemHealth(req: Request, res: Response): Promise<void> {
    try {
      const health = await this.faucetService.getSystemHealth();
      res.json({ success: true, health });
    } catch (error) {
      this.logger.error('Get system health error:', error);
      res.status(500).json({ error: 'Failed to get system health' });
    }
  }

  private async resetRateLimits(req: Request, res: Response): Promise<void> {
    try {
      await this.db.query('DELETE FROM rate_limits');
      
      this.logger.info('Admin reset all rate limits', { admin: req.user.username });

      res.json({ success: true, message: 'Rate limits reset' });
    } catch (error) {
      this.logger.error('Reset rate limits error:', error);
      res.status(500).json({ error: 'Failed to reset rate limits' });
    }
  }

  private async refillFaucet(req: Request, res: Response): Promise<void> {
    try {
      const { amount } = req.body;

      if (!amount || isNaN(Number(amount))) {
        res.status(400).json({ error: 'Valid amount required' });
        return;
      }

      // This would typically trigger a refill transaction
      this.logger.info(`Admin requested faucet refill: ${amount} BSK`, { 
        admin: req.user.username 
      });

      res.json({ 
        success: true, 
        message: `Refill request logged for ${amount} BSK` 
      });
    } catch (error) {
      this.logger.error('Refill faucet error:', error);
      res.status(500).json({ error: 'Failed to process refill request' });
    }
  }

  private async getBlacklist(req: Request, res: Response): Promise<void> {
    try {
      const blacklist = await this.db.query(
        'SELECT * FROM blacklist ORDER BY created_at DESC'
      );

      res.json({ success: true, blacklist });
    } catch (error) {
      this.logger.error('Get blacklist error:', error);
      res.status(500).json({ error: 'Failed to get blacklist' });
    }
  }

  private async addToBlacklist(req: Request, res: Response): Promise<void> {
    try {
      const { address, reason } = req.body;

      if (!address) {
        res.status(400).json({ error: 'Address required' });
        return;
      }

      await this.db.query(
        'INSERT OR REPLACE INTO blacklist (address, reason, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)',
        [address, reason || 'Admin blacklisted']
      );

      this.logger.info(`Admin blacklisted address: ${address}`, { 
        admin: req.user.username,
        reason 
      });

      res.json({ success: true, message: 'Address blacklisted' });
    } catch (error) {
      this.logger.error('Add to blacklist error:', error);
      res.status(500).json({ error: 'Failed to blacklist address' });
    }
  }

  private async removeFromBlacklist(req: Request, res: Response): Promise<void> {
    try {
      const { address } = req.params;

      await this.db.query('DELETE FROM blacklist WHERE address = ?', [address]);

      this.logger.info(`Admin removed from blacklist: ${address}`, { 
        admin: req.user.username 
      });

      res.json({ success: true, message: 'Address removed from blacklist' });
    } catch (error) {
      this.logger.error('Remove from blacklist error:', error);
      res.status(500).json({ error: 'Failed to remove from blacklist' });
    }
  }

  private async getLogs(req: Request, res: Response): Promise<void> {
    try {
      const { level = 'info', limit = 100, page = 1 } = req.query;
      
      // This would typically read from log files
      // For now, return a placeholder response
      res.json({ 
        success: true, 
        logs: [],
        message: 'Log retrieval not yet implemented - check log files directly'
      });
    } catch (error) {
      this.logger.error('Get logs error:', error);
      res.status(500).json({ error: 'Failed to get logs' });
    }
  }

  public getRouter(): Router {
    return this.router;
  }
}
