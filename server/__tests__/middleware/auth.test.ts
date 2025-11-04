import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Request, Response, NextFunction } from 'express';
import { createAuthMiddleware, requireRole } from '../../middleware/auth';
import { supabase } from '@shared/supabase';

// Mock Supabase
vi.mock('@shared/supabase', () => ({
  supabase: {
    auth: {
      getUser: vi.fn()
    }
  }
}));

// Mock jsonwebtoken
vi.mock('jsonwebtoken', () => ({
  default: {
    verify: vi.fn(),
    sign: vi.fn()
  },
  verify: vi.fn(),
  sign: vi.fn()
}));

describe('Authentication Middleware', () => {
  let mockReq: Partial<Request> & { user?: any };
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockReq = {
      headers: {},
      ip: '127.0.0.1'
    };
    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis()
    };
    mockNext = vi.fn();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('createAuthMiddleware', () => {
    it('should authenticate valid JWT token', async () => {
      const middleware = createAuthMiddleware();
      mockReq.headers = {
        authorization: 'Bearer valid-token'
      };

      // Mock JWT verification
      const jwt = await import('jsonwebtoken');
      vi.mocked(jwt.verify).mockImplementation(() => ({
        userId: 'user-123',
        email: 'test@example.com',
        role: 'patient',
        sessionId: 'session-123',
        type: 'access',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + (15 * 60)
      }));

      // Mock session validation
      const auth = await import('../../middleware/auth');
      vi.mocked(auth.validateSession).mockImplementation(() => ({
        userId: 'user-123',
        email: 'test@example.com',
        role: 'patient',
        lastActivity: new Date(),
        expiresAt: new Date(Date.now() + 30 * 60 * 1000)
      }));

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.user).toEqual({
        id: 'user-123',
        email: 'test@example.com',
        role: 'patient',
        sessionId: 'session-123',
        lastActivity: expect.any(Date)
      });
      expect(mockNext).toHaveBeenCalled();
    });

    it('should reject missing authorization header', async () => {
      const middleware = createAuthMiddleware();

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Missing or invalid authorization header'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject invalid JWT token', async () => {
      const middleware = createAuthMiddleware();
      mockReq.headers = {
        authorization: 'Bearer invalid-token'
      };

      // Mock JWT verification to throw error
      const jwt = await import('jsonwebtoken');
      vi.mocked(jwt.verify).mockImplementation(() => {
        throw new Error('Invalid token');
      });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Invalid or expired token'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should handle authentication service errors', async () => {
      const middleware = createAuthMiddleware();
      mockReq.headers = {
        authorization: 'Bearer token'
      };

      // Mock JWT verification to succeed
      const jwt = await import('jsonwebtoken');
      vi.mocked(jwt.verify).mockImplementation(() => ({
        userId: 'user-123',
        email: 'test@example.com',
        role: 'patient',
        sessionId: 'session-123',
        type: 'access',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + (15 * 60)
      }));

      // Mock session validation to return null (service error scenario)
      const auth = await import('../../middleware/auth');
      vi.mocked(auth.validateSession).mockImplementation(() => null);

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Session expired or invalid'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('requireRole', () => {
    it('should allow access for user with correct role', () => {
      const middleware = requireRole(['admin']);
      mockReq.user = { id: 'user-123', role: 'admin' };

      middleware(mockReq as any, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should deny access for user without required role', () => {
      const middleware = requireRole(['admin']);
      mockReq.user = { id: 'user-123', role: 'patient' };

      middleware(mockReq as any, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Forbidden',
        message: 'Insufficient permissions'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should deny access for unauthenticated user', () => {
      const middleware = requireRole(['admin']);

      middleware(mockReq as any, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });
});