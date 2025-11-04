import rateLimit from 'express-rate-limit';
import { AuthenticatedRequest } from './auth';
import { supabase } from '@shared/supabase';

// General API rate limiter
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests',
    message: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Stricter limiter for authentication endpoints
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 auth attempts per windowMs
  message: {
    error: 'Too many authentication attempts',
    message: 'Too many login attempts, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Healthcare data specific limiter (more restrictive)
export const healthcareDataLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // limit each user to 10 healthcare data operations per minute
  keyGenerator: (req: AuthenticatedRequest) => {
    // Use user ID if authenticated, otherwise use IP
    if (req.user?.id) {
      return req.user.id;
    }
    // For unauthenticated requests, use a simple key to avoid IPv6 issues
    return 'anonymous';
  },
  message: {
    error: 'Rate limit exceeded',
    message: 'Too many healthcare data operations. Please wait before making more requests.',
    retryAfter: '1 minute'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// File upload limiter
export const fileUploadLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 3, // limit each user to 3 file uploads per minute
  keyGenerator: (req: AuthenticatedRequest) => {
    // Use user ID if authenticated, otherwise use IP
    if (req.user?.id) {
      return req.user.id;
    }
    // For unauthenticated requests, use a simple key to avoid IPv6 issues
    return 'anonymous';
  },
  message: {
    error: 'Upload limit exceeded',
    message: 'Too many file uploads. Please wait before uploading more files.',
    retryAfter: '1 minute'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// AI/chat endpoint limiter
export const aiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // limit each user to 5 AI requests per minute
  keyGenerator: (req: AuthenticatedRequest) => {
    // Use user ID if authenticated, otherwise use IP
    if (req.user?.id) {
      return req.user.id;
    }
    // For unauthenticated requests, use a simple key to avoid IPv6 issues
    return 'anonymous';
  },
  message: {
    error: 'AI request limit exceeded',
    message: 'Too many AI requests. Please wait before making more requests.',
    retryAfter: '1 minute'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Emergency access limiter (higher limits for urgent situations)
export const emergencyLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20, // Allow more requests during emergencies
  keyGenerator: (req: AuthenticatedRequest) => {
    if (req.user?.id) {
      return `emergency_${req.user.id}`;
    }
    return 'emergency_anonymous';
  },
  message: {
    error: 'Emergency access rate limit',
    message: 'Emergency access rate limit exceeded. Please contact support if this is a genuine emergency.',
    retryAfter: '5 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Admin operations limiter (stricter for security)
export const adminLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // limit admin operations
  keyGenerator: (req: AuthenticatedRequest) => {
    if (req.user?.id) {
      return `admin_${req.user.id}`;
    }
    return 'admin_anonymous';
  },
  message: {
    error: 'Admin operation limit exceeded',
    message: 'Too many admin operations. Please wait before performing more administrative tasks.',
    retryAfter: '1 minute'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Audit log access limiter
export const auditLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // limit audit log queries
  keyGenerator: (req: AuthenticatedRequest) => {
    if (req.user?.id) {
      return `audit_${req.user.id}`;
    }
    return 'audit_anonymous';
  },
  message: {
    error: 'Audit log access limit exceeded',
    message: 'Too many audit log queries. Please wait before accessing logs again.',
    retryAfter: '1 minute'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Dynamic rate limiter based on user role and risk level
export const createDynamicLimiter = (baseLimit: number, windowMs: number) => {
  return rateLimit({
    windowMs,
    max: (req: AuthenticatedRequest, res) => {
      let limit = baseLimit;

      // Adjust limit based on user role
      if (req.user?.role === 'admin') {
        limit = Math.floor(limit * 2); // Admins get higher limits
      } else if (req.user?.role === 'healthcare_provider') {
        limit = Math.floor(limit * 1.5); // Providers get slightly higher limits
      }

      // Could add risk-based adjustments here in the future
      // based on user behavior, failed requests, etc.

      return limit;
    },
    keyGenerator: (req: AuthenticatedRequest) => {
      if (req.user?.id) {
        return req.user.id;
      }
      return req.ip || 'anonymous';
    },
    message: {
      error: 'Rate limit exceeded',
      message: 'Request rate limit exceeded. Please try again later.',
      retryAfter: `${windowMs / 1000} seconds`
    },
    standardHeaders: true,
    legacyHeaders: false,
    // Skip custom store for now - use default memory store
    // In production, implement proper store interface
  });
};