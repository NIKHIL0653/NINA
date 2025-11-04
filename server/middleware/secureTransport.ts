import { Request, Response, NextFunction } from 'express';
import https from 'https';
import { AuthenticatedRequest } from './auth';

// Force HTTPS in production
export const forceHTTPS = (req: Request, res: Response, next: NextFunction) => {
  if (process.env.NODE_ENV === 'production' && req.header('x-forwarded-proto') !== 'https') {
    res.redirect(`https://${req.header('host')}${req.url}`);
  } else {
    next();
  }
};

// Security headers middleware
export const securityHeaders = (req: Request, res: Response, next: NextFunction) => {
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');

  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Enable XSS protection
  res.setHeader('X-XSS-Protection', '1; mode=block');

  // Referrer policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Content Security Policy
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https: blob:",
    "connect-src 'self' https://*.supabase.co https://openrouter.ai wss://*.supabase.co",
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'"
  ].join('; '));

  // HSTS (HTTP Strict Transport Security)
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }

  next();
};

// Request size limits for PHI data
export const phiDataLimits = (req: Request, res: Response, next: NextFunction) => {
  const phiEndpoints = [
    '/api/medical-records',
    '/api/prescriptions',
    '/api/medical-history',
    '/api/vital-signs'
  ];

  if (phiEndpoints.some(endpoint => req.path.startsWith(endpoint))) {
    // Limit PHI data uploads to 50MB
    const maxSize = 50 * 1024 * 1024; // 50MB

    if (req.headers['content-length'] && parseInt(req.headers['content-length']) > maxSize) {
      return res.status(413).json({
        error: 'Payload Too Large',
        message: 'PHI data upload exceeds maximum allowed size'
      });
    }
  }

  next();
};

// Request logging for security events
export const securityLogger = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  const startTime = Date.now();

  // Log security-relevant requests
  const securityEndpoints = [
    '/api/auth',
    '/api/mfa',
    '/api/users',
    '/api/audit'
  ];

  const isSecurityEndpoint = securityEndpoints.some(endpoint => req.path.startsWith(endpoint));

  if (isSecurityEndpoint || req.user) {
    res.on('finish', () => {
      const duration = Date.now() - startTime;
      const logData = {
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.user?.id,
        statusCode: res.statusCode,
        duration,
        userRole: req.user?.role
      };

      // Log to security log (in production, use dedicated security logging)
      if (res.statusCode >= 400) {
        console.warn('[SECURITY EVENT]', JSON.stringify(logData));
      } else if (isSecurityEndpoint) {
        console.info('[SECURITY ACCESS]', JSON.stringify(logData));
      }
    });
  }

  next();
};

// Rate limiting for sensitive operations
export const sensitiveOperationLimiter = (req: Request, res: Response, next: NextFunction) => {
  const sensitiveOperations = [
    'DELETE /api/medical-records',
    'DELETE /api/prescriptions',
    'POST /api/auth/logout',
    'PUT /api/users'
  ];

  const operation = `${req.method} ${req.route?.path || req.path}`;

  if (sensitiveOperations.some(op => operation.includes(op.split(' ')[1]))) {
    // Add additional delay for sensitive operations (simple implementation)
    // In production, use more sophisticated rate limiting
    setTimeout(() => next(), 100); // 100ms delay
  } else {
    next();
  }
};

// Input sanitization middleware
export const sanitizeInput = (req: Request, res: Response, next: NextFunction) => {
  // Sanitize query parameters
  for (const [key, value] of Object.entries(req.query)) {
    if (typeof value === 'string') {
      req.query[key] = sanitizeString(value);
    }
  }

  // Sanitize body parameters (for non-file uploads)
  if (req.body && typeof req.body === 'object' && !req.is('multipart/form-data')) {
    req.body = sanitizeObject(req.body);
  }

  next();
};

// Basic string sanitization
function sanitizeString(str: string): string {
  return str
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+\s*=/gi, '') // Remove event handlers
    .trim();
}

// Recursive object sanitization
function sanitizeObject(obj: any): any {
  if (typeof obj === 'string') {
    return sanitizeString(obj);
  }

  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item));
  }

  if (typeof obj === 'object' && obj !== null) {
    const sanitized: any = {};
    for (const [key, value] of Object.entries(obj)) {
      sanitized[key] = sanitizeObject(value);
    }
    return sanitized;
  }

  return obj;
}

// Certificate validation for external requests
export class CertificateValidator {
  static async validateCertificate(hostname: string): Promise<boolean> {
    return new Promise((resolve) => {
      const options = {
        hostname,
        port: 443,
        method: 'GET',
        rejectUnauthorized: true
      };

      const req = https.request(options, (res) => {
        // Certificate is valid if we get here
        resolve(true);
        req.destroy();
      });

      req.on('error', (err) => {
        console.warn(`Certificate validation failed for ${hostname}:`, err.message);
        resolve(false);
      });

      req.setTimeout(5000, () => {
        console.warn(`Certificate validation timeout for ${hostname}`);
        resolve(false);
        req.destroy();
      });

      req.end();
    });
  }
}

// Secure cookie settings
export const secureCookies = (req: Request, res: Response, next: NextFunction) => {
  // Override res.cookie to force secure settings
  const originalCookie = res.cookie;
  res.cookie = function(name: string, value: any, options: any = {}) {
    // Force secure settings in production
    if (process.env.NODE_ENV === 'production') {
      options.secure = true;
      options.httpOnly = true;
      options.sameSite = 'strict';
    }

    return originalCookie.call(this, name, value, options);
  };

  next();
};