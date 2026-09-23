import { Request, Response, NextFunction } from 'express';
import { Logger } from '../logger';

export interface ErrorDetails {
  message: string;
  stack?: string;
  code?: string | number;
  statusCode: number;
  timestamp: string;
  path: string;
  method: string;
  ip: string;
  userAgent?: string;
  requestId?: string;
}

export class AppError extends Error {
  public statusCode: number;
  public code?: string | number;
  public isOperational: boolean;

  constructor(message: string, statusCode: number = 500, code?: string | number) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = true;
    
    Error.captureStackTrace(this, this.constructor);
  }
}

export class ValidationError extends AppError {
  constructor(message: string, field?: string) {
    super(`Validation Error: ${message}`, 400, 'VALIDATION_ERROR');
    this.name = 'ValidationError';
  }
}

export class RateLimitError extends AppError {
  constructor(message: string = 'Rate limit exceeded') {
    super(message, 429, 'RATE_LIMIT_ERROR');
    this.name = 'RateLimitError';
  }
}

export class FaucetError extends AppError {
  constructor(message: string, code?: string) {
    super(message, 400, code || 'FAUCET_ERROR');
    this.name = 'FaucetError';
  }
}

export class NodeConnectionError extends AppError {
  constructor(message: string = 'BlackSilk node connection failed') {
    super(message, 503, 'NODE_CONNECTION_ERROR');
    this.name = 'NodeConnectionError';
  }
}

export class InsufficientFundsError extends AppError {
  constructor(message: string = 'Insufficient funds in faucet') {
    super(message, 503, 'INSUFFICIENT_FUNDS');
    this.name = 'InsufficientFundsError';
  }
}

export class ErrorHandler {
  private logger: Logger;

  constructor(logger: Logger) {
    this.logger = logger;
  }

  /**
   * Express error handling middleware
   */
  public middleware() {
    return (error: Error, req: Request, res: Response, next: NextFunction) => {
      const errorDetails = this.createErrorDetails(error, req);
      
      // Log the error
      this.logError(error, errorDetails);

      // Don't expose internal errors in production
      const isProduction = process.env.NODE_ENV === 'production';
      const response = this.createErrorResponse(error, errorDetails, isProduction);

      res.status(errorDetails.statusCode).json(response);
    };
  }

  /**
   * Async error wrapper for route handlers
   */
  public wrapAsync(fn: (req: Request, res: Response, next: NextFunction) => Promise<any>) {
    return (req: Request, res: Response, next: NextFunction) => {
      Promise.resolve(fn(req, res, next)).catch(next);
    };
  }

  /**
   * Handle unhandled promise rejections
   */
  public handleUnhandledRejection(): void {
    process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
      this.logger.error('Unhandled Promise Rejection:', {
        reason: reason instanceof Error ? reason.message : reason,
        stack: reason instanceof Error ? reason.stack : undefined,
        promise: promise.toString()
      });

      // Graceful shutdown
      process.exit(1);
    });
  }

  /**
   * Handle uncaught exceptions
   */
  public handleUncaughtException(): void {
    process.on('uncaughtException', (error: Error) => {
      this.logger.error('Uncaught Exception:', {
        message: error.message,
        stack: error.stack,
        name: error.name
      });

      // Graceful shutdown
      process.exit(1);
    });
  }

  /**
   * Create detailed error information
   */
  private createErrorDetails(error: Error, req: Request): ErrorDetails {
    const statusCode = this.getStatusCode(error);
    const code = this.getErrorCode(error);

    return {
      message: error.message,
      stack: error.stack,
      code,
      statusCode,
      timestamp: new Date().toISOString(),
      path: req.path,
      method: req.method,
      ip: this.getClientIP(req),
      userAgent: req.headers['user-agent'],
      requestId: req.headers['x-request-id'] as string
    };
  }

  /**
   * Log error with appropriate level
   */
  private logError(error: Error, details: ErrorDetails): void {
    const logData = {
      message: details.message,
      statusCode: details.statusCode,
      code: details.code,
      path: details.path,
      method: details.method,
      ip: details.ip,
      userAgent: details.userAgent,
      requestId: details.requestId,
      stack: details.stack
    };

    if (details.statusCode >= 500) {
      // Server errors
      this.logger.error('Server Error:', logData);
    } else if (details.statusCode >= 400) {
      // Client errors (less critical)
      this.logger.warn('Client Error:', logData);
    } else {
      // Other errors
      this.logger.info('Request Error:', logData);
    }
  }

  /**
   * Create error response for client
   */
  private createErrorResponse(error: Error, details: ErrorDetails, isProduction: boolean): any {
    const baseResponse = {
      success: false,
      error: {
        message: details.message,
        code: details.code,
        timestamp: details.timestamp
      }
    };

    // Add additional details in development
    if (!isProduction) {
      return {
        ...baseResponse,
        error: {
          ...baseResponse.error,
          stack: details.stack,
          path: details.path,
          method: details.method
        }
      };
    }

    // In production, sanitize error messages for certain types
    if (details.statusCode >= 500) {
      return {
        ...baseResponse,
        error: {
          ...baseResponse.error,
          message: 'Internal server error'
        }
      };
    }

    return baseResponse;
  }

  /**
   * Get HTTP status code from error
   */
  private getStatusCode(error: Error): number {
    if (error instanceof AppError) {
      return error.statusCode;
    }

    // Handle specific error types
    if (error.name === 'ValidationError') return 400;
    if (error.name === 'UnauthorizedError') return 401;
    if (error.name === 'ForbiddenError') return 403;
    if (error.name === 'NotFoundError') return 404;
    if (error.name === 'ConflictError') return 409;
    if (error.name === 'TooManyRequestsError') return 429;

    // Default to 500 for unknown errors
    return 500;
  }

  /**
   * Get error code from error
   */
  private getErrorCode(error: Error): string | number | undefined {
    if (error instanceof AppError) {
      return error.code;
    }

    return error.name;
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
   * Handle 404 errors (route not found)
   */
  public notFoundHandler() {
    return (req: Request, res: Response, next: NextFunction) => {
      const error = new AppError(`Route ${req.method} ${req.path} not found`, 404, 'ROUTE_NOT_FOUND');
      next(error);
    };
  }

  /**
   * Request timeout handler
   */
  public timeoutHandler(timeoutMs: number = 30000) {
    return (req: Request, res: Response, next: NextFunction) => {
      const timeout = setTimeout(() => {
        const error = new AppError('Request timeout', 408, 'REQUEST_TIMEOUT');
        next(error);
      }, timeoutMs);

      // Clear timeout when response is finished
      res.on('finish', () => {
        clearTimeout(timeout);
      });

      next();
    };
  }

  /**
   * Validation middleware for request body
   */
  public validateBody(schema: any) {
    return (req: Request, res: Response, next: NextFunction) => {
      try {
        // Simple validation - in production use a proper validation library
        if (!req.body) {
          throw new ValidationError('Request body is required');
        }

        // Add your validation logic here
        next();
      } catch (error) {
        next(error);
      }
    };
  }

  /**
   * CORS error handler
   */
  public corsErrorHandler() {
    return (req: Request, res: Response, next: NextFunction) => {
      res.header('Access-Control-Allow-Origin', process.env.CORS_ORIGIN || '*');
      res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');

      if (req.method === 'OPTIONS') {
        res.sendStatus(200);
        return;
      }

      next();
    };
  }

  /**
   * Security headers middleware
   */
  public securityHeaders() {
    return (req: Request, res: Response, next: NextFunction) => {
      // Remove server header
      res.removeHeader('X-Powered-By');
      
      // Add security headers
      res.header('X-Content-Type-Options', 'nosniff');
      res.header('X-Frame-Options', 'DENY');
      res.header('X-XSS-Protection', '1; mode=block');
      res.header('Referrer-Policy', 'strict-origin-when-cross-origin');
      
      next();
    };
  }

  /**
   * Request logging middleware
   */
  public requestLogger() {
    return (req: Request, res: Response, next: NextFunction) => {
      const start = Date.now();
      const requestId = req.headers['x-request-id'] || this.generateRequestId();
      
      // Add request ID to request object
      req.headers['x-request-id'] = requestId as string;

      // Log request
      this.logger.info('Incoming request:', {
        requestId,
        method: req.method,
        path: req.path,
        ip: this.getClientIP(req),
        userAgent: req.headers['user-agent']
      });

      // Log response when finished
      res.on('finish', () => {
        const duration = Date.now() - start;
        
        this.logger.info('Request completed:', {
          requestId,
          method: req.method,
          path: req.path,
          statusCode: res.statusCode,
          duration: `${duration}ms`,
          ip: this.getClientIP(req)
        });
      });

      next();
    };
  }

  /**
   * Generate unique request ID
   */
  private generateRequestId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
}

// Export error classes for use in other modules
export {
  AppError,
  ValidationError,
  RateLimitError,
  FaucetError,
  NodeConnectionError,
  InsufficientFundsError
};
