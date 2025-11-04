import { Request, Response, NextFunction } from 'express';
import { AuthenticatedRequest } from './auth';
import { supabase } from '@shared/supabase';

// MFA configuration
interface MFAConfig {
  enabled: boolean;
  requiredForRoles: string[];
  methods: ('totp' | 'sms' | 'email')[];
  backupCodesCount: number;
}

// Default MFA configuration
const DEFAULT_MFA_CONFIG: MFAConfig = {
  enabled: true,
  requiredForRoles: ['healthcare_provider', 'admin'],
  methods: ['totp', 'sms'],
  backupCodesCount: 10
};

// MFA session data
interface MFASession {
  userId: string;
  method: 'totp' | 'sms' | 'email';
  code: string;
  expiresAt: Date;
  attempts: number;
}

// In-memory MFA sessions (in production, use Redis/database)
const mfaSessions = new Map<string, MFASession>();
const MFA_CODE_EXPIRY = 5 * 60 * 1000; // 5 minutes
const MAX_ATTEMPTS = 3;

// Generate secure MFA code
function generateMFACode(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Generate backup codes
function generateBackupCodes(count: number): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    codes.push(require('crypto').randomBytes(4).toString('hex').toUpperCase());
  }
  return codes;
}

// Clean up expired MFA sessions
function cleanupExpiredMFASessions(): void {
  const now = new Date();
  for (const [sessionId, session] of mfaSessions.entries()) {
    if (session.expiresAt < now) {
      mfaSessions.delete(sessionId);
    }
  }
}

// Run cleanup every 5 minutes
setInterval(cleanupExpiredMFASessions, 5 * 60 * 1000);

// Check if MFA is required for user
export async function isMFARequired(userId: string, role: string): Promise<boolean> {
  if (!DEFAULT_MFA_CONFIG.enabled) return false;

  // Check if role requires MFA
  if (DEFAULT_MFA_CONFIG.requiredForRoles.includes(role)) {
    return true;
  }

  // Check user-specific MFA settings (future enhancement)
  try {
    const { data } = await supabase
      .from('user_mfa_settings')
      .select('enabled')
      .eq('user_id', userId)
      .single();

    return data?.enabled || false;
  } catch (error) {
    console.warn('Failed to check user MFA settings:', error);
    return false;
  }
}

// Initiate MFA challenge
export async function initiateMFA(userId: string, method: 'totp' | 'sms' | 'email' = 'totp'): Promise<{sessionId: string, message: string}> {
  const sessionId = require('crypto').randomBytes(16).toString('hex');
  const code = generateMFACode();
  const expiresAt = new Date(Date.now() + MFA_CODE_EXPIRY);

  mfaSessions.set(sessionId, {
    userId,
    method,
    code,
    expiresAt,
    attempts: 0
  });

  let message = 'MFA code sent';

  // Send MFA code based on method
  switch (method) {
    case 'sms':
      // In production, integrate with SMS service (Twilio, etc.)
      console.log(`[MFA] SMS code ${code} sent to user ${userId}`);
      message = 'MFA code sent via SMS';
      break;
    case 'email':
      // In production, send email
      console.log(`[MFA] Email code ${code} sent to user ${userId}`);
      message = 'MFA code sent via email';
      break;
    case 'totp':
      // TOTP is handled client-side
      message = 'Please enter your TOTP code';
      break;
  }

  return { sessionId, message };
}

// Verify MFA code
export function verifyMFA(sessionId: string, code: string): boolean {
  const session = mfaSessions.get(sessionId);
  if (!session) return false;

  const now = new Date();
  if (session.expiresAt < now) {
    mfaSessions.delete(sessionId);
    return false;
  }

  if (session.attempts >= MAX_ATTEMPTS) {
    mfaSessions.delete(sessionId);
    return false;
  }

  session.attempts++;

  if (session.code === code) {
    mfaSessions.delete(sessionId);
    return true;
  }

  return false;
}

// MFA middleware
export const requireMFA = () => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const mfaRequired = await isMFARequired(req.user.id, req.user.role || '');

      if (!mfaRequired) {
        return next();
      }

      // Check if MFA has been completed for this session
      const mfaVerified = req.headers['x-mfa-verified'] === 'true' ||
                         req.body.mfaVerified === true;

      if (mfaVerified) {
        return next();
      }

      // MFA required but not verified
      return res.status(403).json({
        error: 'MFA Required',
        message: 'Multi-factor authentication is required',
        mfaRequired: true,
        methods: DEFAULT_MFA_CONFIG.methods
      });

    } catch (error) {
      console.error('MFA middleware error:', error);
      return res.status(500).json({
        error: 'Internal Server Error',
        message: 'MFA verification failed'
      });
    }
  };
};

// MFA setup for users
export const setupMFA = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }

    const { method } = req.body;

    if (!DEFAULT_MFA_CONFIG.methods.includes(method)) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Invalid MFA method'
      });
    }

    // Generate backup codes
    const backupCodes = generateBackupCodes(DEFAULT_MFA_CONFIG.backupCodesCount);

    // Store MFA settings (in production, hash backup codes)
    const { error } = await supabase
      .from('user_mfa_settings')
      .upsert({
        user_id: req.user.id,
        method,
        enabled: true,
        backup_codes: backupCodes, // In production, hash these
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });

    if (error) {
      console.error('Failed to setup MFA:', error);
      return res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to setup MFA'
      });
    }

    res.json({
      success: true,
      message: 'MFA setup completed',
      data: {
        method,
        backupCodes // In production, don't return these - show once and hash
      }
    });

  } catch (error) {
    console.error('MFA setup error:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'MFA setup failed'
    });
  }
};

// Verify MFA during authentication
export const verifyMFACode = async (req: Request, res: Response) => {
  try {
    const { sessionId, code } = req.body;

    if (!sessionId || !code) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Session ID and code required'
      });
    }

    const verified = verifyMFA(sessionId, code);

    if (!verified) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid or expired MFA code'
      });
    }

    res.json({
      success: true,
      message: 'MFA verification successful'
    });

  } catch (error) {
    console.error('MFA verification error:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'MFA verification failed'
    });
  }
};