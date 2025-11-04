import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { supabase } from '@shared/supabase';
import { RoleManager } from './roleManager';

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    role?: string;
    sessionId?: string;
    lastActivity?: Date;
  };
}

// Session store (in production, use Redis or database)
interface SessionData {
  userId: string;
  email: string;
  role: string;
  lastActivity: Date;
  expiresAt: Date;
}

const sessions = new Map<string, SessionData>();
const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes
const REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60 * 1000; // 7 days

// Generate secure session ID
function generateSessionId(): string {
  return require('crypto').randomBytes(32).toString('hex');
}

// Clean up expired sessions
function cleanupExpiredSessions(): void {
  const now = new Date();
  for (const [sessionId, session] of sessions.entries()) {
    if (session.expiresAt < now) {
      sessions.delete(sessionId);
    }
  }
}

// Run cleanup every 5 minutes
setInterval(cleanupExpiredSessions, 5 * 60 * 1000);

// Generate JWT access token
export function generateAccessToken(userId: string, email: string, role: string, sessionId: string): string {
  const payload = {
    userId,
    email,
    role,
    sessionId,
    type: 'access',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (15 * 60) // 15 minutes
  };

  return jwt.sign(payload, process.env.JWT_SECRET || 'fallback-secret');
}

// Generate JWT refresh token
export function generateRefreshToken(userId: string, sessionId: string): string {
  const payload = {
    userId,
    sessionId,
    type: 'refresh',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (REFRESH_TOKEN_EXPIRY / 1000)
  };

  return jwt.sign(payload, process.env.JWT_SECRET || 'fallback-secret');
}

// Create new session
export function createSession(userId: string, email: string, role: string): string {
  const sessionId = generateSessionId();
  const now = new Date();

  sessions.set(sessionId, {
    userId,
    email,
    role,
    lastActivity: now,
    expiresAt: new Date(now.getTime() + SESSION_TIMEOUT)
  });

  return sessionId;
}

// Update session activity
export function updateSessionActivity(sessionId: string): boolean {
  const session = sessions.get(sessionId);
  if (!session) return false;

  const now = new Date();
  if (session.expiresAt < now) {
    sessions.delete(sessionId);
    return false;
  }

  session.lastActivity = now;
  session.expiresAt = new Date(now.getTime() + SESSION_TIMEOUT);
  return true;
}

// Validate session
export function validateSession(sessionId: string): SessionData | null {
  const session = sessions.get(sessionId);
  if (!session) return null;

  const now = new Date();
  if (session.expiresAt < now) {
    sessions.delete(sessionId);
    return null;
  }

  return session;
}

// Destroy session
export function destroySession(sessionId: string): void {
  sessions.delete(sessionId);
}

export const createAuthMiddleware = () => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Missing or invalid authorization header'
        });
      }

      const token = authHeader.substring(7); // Remove 'Bearer ' prefix

      // Verify JWT token
      let decoded: any;
      try {
        decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
      } catch (jwtError) {
        console.warn('JWT verification failed:', jwtError);
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Invalid or expired token'
        });
      }

      // Validate session
      const session = validateSession(decoded.sessionId);
      if (!session) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Session expired or invalid'
        });
      }

      // Update session activity
      updateSessionActivity(decoded.sessionId);

      // Get user role from database if not in session
      let userRole = session.role;
      if (!userRole) {
        userRole = await RoleManager.getUserRole(session.userId) || ROLES.PATIENT;
        // Update session with role
        session.role = userRole;
      }

      // Attach user info to request
      req.user = {
        id: session.userId,
        email: session.email,
        role: userRole,
        sessionId: decoded.sessionId,
        lastActivity: session.lastActivity
      };

      next();
    } catch (error) {
      console.error('Auth middleware error:', error);
      return res.status(500).json({
        error: 'Internal Server Error',
        message: 'Authentication service temporarily unavailable'
      });
    }
  };
};

// Role-based authorization middleware
export const requireRole = (allowedRoles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }

    if (!allowedRoles.includes(req.user.role || '')) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Insufficient permissions'
      });
    }

    next();
  };
};

// Healthcare role definitions
export const ROLES = {
  PATIENT: 'patient',
  HEALTHCARE_PROVIDER: 'healthcare_provider',
  ADMIN: 'admin'
} as const;

export type UserRole = typeof ROLES[keyof typeof ROLES];

// Role hierarchy for permission escalation
const ROLE_HIERARCHY = {
  [ROLES.PATIENT]: 1,
  [ROLES.HEALTHCARE_PROVIDER]: 2,
  [ROLES.ADMIN]: 3
};

// Check if user has required role level or higher
export const requireRoleLevel = (minimumRole: UserRole) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }

    const userRoleLevel = ROLE_HIERARCHY[req.user.role as UserRole] || 0;
    const requiredLevel = ROLE_HIERARCHY[minimumRole] || 0;

    if (userRoleLevel < requiredLevel) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Insufficient permissions'
      });
    }

    next();
  };
};

// Resource ownership middleware - ensures users can only access their own data
export const requireOwnership = (resourceUserIdParam: string = 'userId') => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }

    const resourceUserId = req.params[resourceUserIdParam] || req.body.user_id || req.query.userId;

    // Admins can access any resource
    if (req.user.role === ROLES.ADMIN) {
      return next();
    }

    // Healthcare providers can access patient data they have permission for
    if (req.user.role === ROLES.HEALTHCARE_PROVIDER) {
      // In production, check provider-patient relationship
      // For now, allow access to any patient data
      return next();
    }

    // Patients can only access their own data
    if (req.user.role === ROLES.PATIENT && req.user.id !== resourceUserId) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Access denied: can only access own data'
      });
    }

    next();
  };
};

// Refresh token endpoint handler
export const refreshToken = async (req: Request, res: Response) => {
  try {
    const { refreshToken: token } = req.body;

    if (!token) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Refresh token required'
      });
    }

    // Verify refresh token
    let decoded: any;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
    } catch (jwtError) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid refresh token'
      });
    }

    if (decoded.type !== 'refresh') {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid token type'
      });
    }

    // Validate session
    const session = validateSession(decoded.sessionId);
    if (!session) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Session expired'
      });
    }

    // Generate new tokens
    const newAccessToken = generateAccessToken(session.userId, session.email, session.role, decoded.sessionId);
    const newRefreshToken = generateRefreshToken(session.userId, decoded.sessionId);

    // Update session activity
    updateSessionActivity(decoded.sessionId);

    res.json({
      success: true,
      data: {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresIn: 15 * 60 // 15 minutes
      }
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Token refresh failed'
    });
  }
};

// Logout handler
export const logout = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (req.user?.sessionId) {
      destroySession(req.user.sessionId);
    }

    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Logout failed'
    });
  }
};

// Optional auth middleware (doesn't fail if no token)
export const optionalAuth = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);

      // Verify JWT token
      let decoded: any;
      try {
        decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
      } catch (jwtError) {
        // Invalid token, continue without auth
        next();
        return;
      }

      // Validate session
      const session = validateSession(decoded.sessionId);
      if (session) {
        // Update session activity
        updateSessionActivity(decoded.sessionId);

        // Get user role from database for optional auth
        const userRole = await RoleManager.getUserRole(session.userId) || ROLES.PATIENT;

        req.user = {
          id: session.userId,
          email: session.email,
          role: userRole,
          sessionId: decoded.sessionId,
          lastActivity: session.lastActivity
        };
      }
    }

    next();
  } catch (error) {
    // Don't fail, just continue without auth
    next();
  }
};

// Session timeout middleware
export const sessionTimeoutMiddleware = () => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (req.user?.sessionId) {
      const session = sessions.get(req.user.sessionId);
      if (session) {
        const now = new Date();
        const timeSinceActivity = now.getTime() - session.lastActivity.getTime();

        // Check if session should timeout (30 minutes of inactivity)
        if (timeSinceActivity > SESSION_TIMEOUT) {
          destroySession(req.user.sessionId);
          return res.status(401).json({
            error: 'Unauthorized',
            message: 'Session expired due to inactivity'
          });
        }
      }
    }
    next();
  };
};