import { Request, Response, NextFunction } from 'express';
import { Database } from '../database';
import { Logger } from '../logger';

export interface RateLimitConfig {
  windowMs: number;  // Time window in milliseconds
  maxRequests: number;  // Maximum requests per window
  blockDurationMs: number;  // Block duration if limit exceeded
  skipSuccessfulRequests: boolean;  // Don't count successful requests
  skipFailedRequests: boolean;  // Don't count failed requests
  keyGenerator?: (req: Request) => string;  // Custom key generator
}

export interface RateLimitInfo {
  totalHits: number;
  totalRequests: number;
  resetTime: Date;
  remaining: number;
  limit: number;
  windowStart: Date;
}

export class RateLimiter {
  private db: Database;
  private logger: Logger;
  private config: RateLimitConfig;

  constructor(db: Database, logger: Logger, config: RateLimitConfig) {
    this.db = db;
    this.logger = logger;
    this.config = {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 5,
      blockDurationMs: 60 * 60 * 1000, // 1 hour
      skipSuccessfulRequests: false,
      skipFailedRequests: false,
      ...config
    };
  }

  /**
   * Create rate limiting middleware
   */
  public middleware() {
    return async (req: Request, res: Response, next: NextFunction) => {
      try {
        const key = this.getKey(req);
        const rateLimitInfo = await this.checkRateLimit(key);

        // Add rate limit headers
        res.set({
          'X-RateLimit-Limit': rateLimitInfo.limit.toString(),
          'X-RateLimit-Remaining': rateLimitInfo.remaining.toString(),
          'X-RateLimit-Reset': Math.ceil(rateLimitInfo.resetTime.getTime() / 1000).toString(),
          'X-RateLimit-Window': this.config.windowMs.toString()
        });

        // Check if blocked
        const blockInfo = await this.isBlocked(key);
        if (blockInfo.blocked) {
          this.logger.warn(`Rate limit exceeded for ${key}`, {
            ip: this.getClientIP(req),
            path: req.path,
            blockUntil: blockInfo.blockUntil
          });

          res.status(429).json({
            error: 'Too many requests',
            message: `Rate limit exceeded. Try again after ${new Date(blockInfo.blockUntil!).toISOString()}`,
            retryAfter: Math.ceil((blockInfo.blockUntil! - Date.now()) / 1000)
          });
          return;
        }

        // Record this request
        await this.recordRequest(key);

        // Check if this request exceeds the limit
        if (rateLimitInfo.remaining <= 0) {
          await this.blockKey(key);
          
          this.logger.warn(`Rate limit triggered for ${key}`, {
            ip: this.getClientIP(req),
            path: req.path,
            requests: rateLimitInfo.totalHits
          });

          res.status(429).json({
            error: 'Rate limit exceeded',
            message: `Too many requests. Blocked for ${this.config.blockDurationMs / 1000 / 60} minutes`,
            retryAfter: Math.ceil(this.config.blockDurationMs / 1000)
          });
          return;
        }

        next();
      } catch (error) {
        this.logger.error('Rate limiter error:', error);
        // Don't block requests on rate limiter errors
        next();
      }
    };
  }

  /**
   * Get the key to use for rate limiting
   */
  private getKey(req: Request): string {
    if (this.config.keyGenerator) {
      return this.config.keyGenerator(req);
    }

    const ip = this.getClientIP(req);
    const path = req.path;
    return `${ip}:${path}`;
  }

  /**
   * Get client IP address
   */
  private getClientIP(req: Request): string {
    const forwarded = req.headers['x-forwarded-for'] as string;
    const realIP = req.headers['x-real-ip'] as string;
    
    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }
    
    if (realIP) {
      return realIP;
    }
    
    return req.connection.remoteAddress || req.socket.remoteAddress || 'unknown';
  }

  /**
   * Check current rate limit status for a key
   */
  private async checkRateLimit(key: string): Promise<RateLimitInfo> {
    const windowStart = new Date(Date.now() - this.config.windowMs);
    const resetTime = new Date(Date.now() + this.config.windowMs);

    // Clean up old entries
    await this.db.query(
      'DELETE FROM rate_limits WHERE key = ? AND created_at < ?',
      [key, windowStart.toISOString()]
    );

    // Count current requests
    const result = await this.db.query(
      'SELECT COUNT(*) as count FROM rate_limits WHERE key = ? AND created_at >= ?',
      [key, windowStart.toISOString()]
    );

    const totalHits = result[0]?.count || 0;
    const remaining = Math.max(0, this.config.maxRequests - totalHits);

    return {
      totalHits,
      totalRequests: totalHits,
      resetTime,
      remaining,
      limit: this.config.maxRequests,
      windowStart
    };
  }

  /**
   * Record a request for rate limiting
   */
  private async recordRequest(key: string): Promise<void> {
    await this.db.query(
      'INSERT INTO rate_limits (key, ip_address, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)',
      [key, key.split(':')[0]] // Extract IP from key
    );
  }

  /**
   * Check if a key is currently blocked
   */
  private async isBlocked(key: string): Promise<{ blocked: boolean; blockUntil?: number }> {
    const result = await this.db.query(
      'SELECT block_until FROM rate_limit_blocks WHERE key = ? AND block_until > ?',
      [key, Date.now()]
    );

    if (result.length > 0) {
      return {
        blocked: true,
        blockUntil: result[0].block_until
      };
    }

    return { blocked: false };
  }

  /**
   * Block a key for the configured duration
   */
  private async blockKey(key: string): Promise<void> {
    const blockUntil = Date.now() + this.config.blockDurationMs;
    
    await this.db.query(
      'INSERT OR REPLACE INTO rate_limit_blocks (key, block_until, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)',
      [key, blockUntil]
    );
  }

  /**
   * Clear rate limit for a specific key (admin function)
   */
  public async clearRateLimit(key: string): Promise<void> {
    await this.db.query('DELETE FROM rate_limits WHERE key = ?', [key]);
    await this.db.query('DELETE FROM rate_limit_blocks WHERE key = ?', [key]);
    
    this.logger.info(`Rate limit cleared for key: ${key}`);
  }

  /**
   * Get rate limit statistics
   */
  public async getStats(): Promise<any> {
    const stats = await this.db.query(`
      SELECT 
        COUNT(*) as total_requests,
        COUNT(DISTINCT ip_address) as unique_ips,
        COUNT(CASE WHEN created_at >= datetime('now', '-1 hour') THEN 1 END) as requests_last_hour,
        COUNT(CASE WHEN created_at >= datetime('now', '-1 day') THEN 1 END) as requests_last_day
      FROM rate_limits
    `);

    const blocks = await this.db.query(`
      SELECT 
        COUNT(*) as total_blocks,
        COUNT(CASE WHEN block_until > ? THEN 1 END) as active_blocks
      FROM rate_limit_blocks
    `, [Date.now()]);

    return {
      requests: stats[0] || {},
      blocks: blocks[0] || {}
    };
  }

  /**
   * Clean up expired rate limit data
   */
  public async cleanup(): Promise<void> {
    const cutoff = new Date(Date.now() - (this.config.windowMs * 2)); // Keep extra history
    
    await this.db.query(
      'DELETE FROM rate_limits WHERE created_at < ?',
      [cutoff.toISOString()]
    );

    await this.db.query(
      'DELETE FROM rate_limit_blocks WHERE block_until < ?',
      [Date.now()]
    );

    this.logger.debug('Rate limit cleanup completed');
  }
}

/**
 * Create different rate limiters for different endpoints
 */
export class RateLimitFactory {
  private db: Database;
  private logger: Logger;

  constructor(db: Database, logger: Logger) {
    this.db = db;
    this.logger = logger;
  }

  /**
   * Rate limiter for faucet requests (strict)
   */
  public createFaucetLimiter(): RateLimiter {
    return new RateLimiter(this.db, this.logger, {
      windowMs: 24 * 60 * 60 * 1000, // 24 hours
      maxRequests: 1, // 1 request per day
      blockDurationMs: 24 * 60 * 60 * 1000, // 24 hour block
      skipSuccessfulRequests: false,
      skipFailedRequests: true,
      keyGenerator: (req) => `faucet:${this.getClientIP(req)}`
    });
  }

  /**
   * Rate limiter for API endpoints (moderate)
   */
  public createAPILimiter(): RateLimiter {
    return new RateLimiter(this.db, this.logger, {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 100, // 100 requests per 15 minutes
      blockDurationMs: 60 * 60 * 1000, // 1 hour block
      skipSuccessfulRequests: false,
      skipFailedRequests: false,
      keyGenerator: (req) => `api:${this.getClientIP(req)}`
    });
  }

  /**
   * Rate limiter for status checks (lenient)
   */
  public createStatusLimiter(): RateLimiter {
    return new RateLimiter(this.db, this.logger, {
      windowMs: 60 * 1000, // 1 minute
      maxRequests: 60, // 60 requests per minute
      blockDurationMs: 5 * 60 * 1000, // 5 minute block
      skipSuccessfulRequests: false,
      skipFailedRequests: false,
      keyGenerator: (req) => `status:${this.getClientIP(req)}`
    });
  }

  /**
   * Rate limiter for admin endpoints (very strict)
   */
  public createAdminLimiter(): RateLimiter {
    return new RateLimiter(this.db, this.logger, {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 20, // 20 requests per 15 minutes
      blockDurationMs: 60 * 60 * 1000, // 1 hour block
      skipSuccessfulRequests: false,
      skipFailedRequests: false,
      keyGenerator: (req) => `admin:${this.getClientIP(req)}`
    });
  }

  private getClientIP(req: Request): string {
    const forwarded = req.headers['x-forwarded-for'] as string;
    const realIP = req.headers['x-real-ip'] as string;
    
    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }
    
    if (realIP) {
      return realIP;
    }
    
    return req.connection.remoteAddress || req.socket.remoteAddress || 'unknown';
  }
}
