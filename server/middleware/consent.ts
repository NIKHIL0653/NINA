import { Request, Response, NextFunction } from 'express';
import { AuthenticatedRequest } from './auth';
import { supabase } from '@shared/supabase';

// Consent types
export enum ConsentType {
  DATA_PROCESSING = 'data_processing',
  MEDICAL_DATA_SHARING = 'medical_data_sharing',
  ANALYTICS = 'analytics',
  MARKETING = 'marketing',
  RESEARCH = 'research',
  EMERGENCY_ACCESS = 'emergency_access',
  THIRD_PARTY_SHARING = 'third_party_sharing'
}

// Consent status
export enum ConsentStatus {
  GRANTED = 'granted',
  DENIED = 'denied',
  REVOKED = 'revoked',
  EXPIRED = 'expired'
}

// Consent record interface
interface ConsentRecord {
  id?: string;
  user_id: string;
  consent_type: ConsentType;
  status: ConsentStatus;
  granted_at: string;
  expires_at?: string;
  revoked_at?: string;
  consent_version: string;
  ip_address: string;
  user_agent: string;
  purpose: string;
  data_scope?: string[];
  third_party_recipients?: string[];
}

// Consent management class
export class ConsentManager {
  private static readonly CONSENT_VERSIONS = {
    [ConsentType.DATA_PROCESSING]: '1.2',
    [ConsentType.MEDICAL_DATA_SHARING]: '1.1',
    [ConsentType.ANALYTICS]: '1.0',
    [ConsentType.MARKETING]: '1.3',
    [ConsentType.RESEARCH]: '1.0',
    [ConsentType.EMERGENCY_ACCESS]: '1.1',
    [ConsentType.THIRD_PARTY_SHARING]: '1.2'
  };

  // Check if user has given consent for specific type
  static async hasConsent(userId: string, consentType: ConsentType): Promise<boolean> {
    try {
      const { data, error } = await supabase
        .from('user_consents')
        .select('*')
        .eq('user_id', userId)
        .eq('consent_type', consentType)
        .eq('status', ConsentStatus.GRANTED)
        .order('granted_at', { ascending: false })
        .limit(1)
        .single();

      if (error || !data) return false;

      // Check if consent has expired
      if (data.expires_at) {
        const now = new Date();
        const expiry = new Date(data.expires_at);
        if (now > expiry) {
          // Auto-expire the consent
          await this.revokeConsent(userId, consentType, 'system', 'Consent expired');
          return false;
        }
      }

      return true;
    } catch (error) {
      console.error('Error checking consent:', error);
      return false;
    }
  }

  // Grant consent
  static async grantConsent(
    userId: string,
    consentType: ConsentType,
    purpose: string,
    options: {
      expiresAt?: Date;
      dataScope?: string[];
      thirdPartyRecipients?: string[];
      ipAddress: string;
      userAgent: string;
    }
  ): Promise<boolean> {
    try {
      const consentRecord: Omit<ConsentRecord, 'id'> = {
        user_id: userId,
        consent_type: consentType,
        status: ConsentStatus.GRANTED,
        granted_at: new Date().toISOString(),
        expires_at: options.expiresAt?.toISOString(),
        consent_version: this.CONSENT_VERSIONS[consentType],
        ip_address: options.ipAddress,
        user_agent: options.userAgent,
        purpose,
        data_scope: options.dataScope,
        third_party_recipients: options.thirdPartyRecipients
      };

      const { error } = await supabase
        .from('user_consents')
        .insert(consentRecord);

      if (error) {
        console.error('Failed to grant consent:', error);
        return false;
      }

      return true;
    } catch (error) {
      console.error('Error granting consent:', error);
      return false;
    }
  }

  // Revoke consent
  static async revokeConsent(
    userId: string,
    consentType: ConsentType,
    revokedBy: string,
    reason?: string
  ): Promise<boolean> {
    try {
      const { error } = await supabase
        .from('user_consents')
        .update({
          status: ConsentStatus.REVOKED,
          revoked_at: new Date().toISOString(),
          revocation_reason: reason,
          revoked_by: revokedBy
        })
        .eq('user_id', userId)
        .eq('consent_type', consentType)
        .eq('status', ConsentStatus.GRANTED);

      if (error) {
        console.error('Failed to revoke consent:', error);
        return false;
      }

      return true;
    } catch (error) {
      console.error('Error revoking consent:', error);
      return false;
    }
  }

  // Get user's consent history
  static async getConsentHistory(userId: string): Promise<ConsentRecord[]> {
    try {
      const { data, error } = await supabase
        .from('user_consents')
        .select('*')
        .eq('user_id', userId)
        .order('granted_at', { ascending: false });

      if (error) {
        console.error('Failed to get consent history:', error);
        return [];
      }

      return data || [];
    } catch (error) {
      console.error('Error getting consent history:', error);
      return [];
    }
  }

  // Get active consents for user
  static async getActiveConsents(userId: string): Promise<ConsentRecord[]> {
    try {
      const { data, error } = await supabase
        .from('user_consents')
        .select('*')
        .eq('user_id', userId)
        .eq('status', ConsentStatus.GRANTED)
        .order('granted_at', { ascending: false });

      if (error) {
        console.error('Failed to get active consents:', error);
        return [];
      }

      // Filter out expired consents
      const now = new Date();
      return (data || []).filter(consent => {
        if (!consent.expires_at) return true;
        return new Date(consent.expires_at) > now;
      });
    } catch (error) {
      console.error('Error getting active consents:', error);
      return [];
    }
  }

  // Check if consent is required for operation
  static isConsentRequired(operation: string, dataType?: string): ConsentType | null {
    const consentMappings: Record<string, ConsentType> = {
      'share_medical_data': ConsentType.MEDICAL_DATA_SHARING,
      'use_analytics': ConsentType.ANALYTICS,
      'send_marketing': ConsentType.MARKETING,
      'use_for_research': ConsentType.RESEARCH,
      'emergency_access': ConsentType.EMERGENCY_ACCESS,
      'third_party_sharing': ConsentType.THIRD_PARTY_SHARING
    };

    return consentMappings[operation] || null;
  }

  // Validate consent scope
  static validateConsentScope(
    userId: string,
    consentType: ConsentType,
    requiredScope?: string[]
  ): Promise<boolean> {
    return this.hasConsent(userId, consentType);
  }
}

// Consent middleware
export const requireConsent = (consentType: ConsentType) => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const hasConsent = await ConsentManager.hasConsent(req.user.id, consentType);

      if (!hasConsent) {
        return res.status(403).json({
          error: 'Consent Required',
          message: `User consent required for ${consentType.replace('_', ' ')}`,
          consentType,
          required: true
        });
      }

      next();
    } catch (error) {
      console.error('Consent middleware error:', error);
      return res.status(500).json({
        error: 'Internal Server Error',
        message: 'Consent verification failed'
      });
    }
  };
};

// Emergency access consent (bypasses normal consent for emergencies)
export const emergencyConsentOverride = () => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    // Check if this is marked as an emergency request
    const isEmergency = req.headers['x-emergency-access'] === 'true' ||
                       req.body.emergencyAccess === true;

    if (isEmergency && req.user) {
      // Log emergency access
      console.warn(`[EMERGENCY ACCESS] User: ${req.user.id} - ${req.method} ${req.path}`);

      // Grant temporary emergency consent
      const emergencyConsentGranted = await ConsentManager.grantConsent(
        req.user.id,
        ConsentType.EMERGENCY_ACCESS,
        'Emergency medical access',
        {
          ipAddress: req.ip || '',
          userAgent: req.get('User-Agent') || '',
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
        }
      );

      if (emergencyConsentGranted) {
        // Add emergency flag to request for audit logging
        (req as any).emergencyAccess = true;
      }
    }

    next();
  };
};

// Data sharing consent validation
export const validateDataSharingConsent = (recipientType: string) => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        return next(); // Let auth middleware handle this
      }

      const consentType = recipientType === 'research' ? ConsentType.RESEARCH :
                          recipientType === 'third_party' ? ConsentType.THIRD_PARTY_SHARING :
                          ConsentType.MEDICAL_DATA_SHARING;

      const hasConsent = await ConsentManager.hasConsent(req.user.id, consentType);

      if (!hasConsent) {
        return res.status(403).json({
          error: 'Data Sharing Not Authorized',
          message: `User has not consented to share data with ${recipientType}`,
          consentType,
          recipientType
        });
      }

      next();
    } catch (error) {
      console.error('Data sharing consent validation error:', error);
      return res.status(500).json({
        error: 'Internal Server Error',
        message: 'Consent validation failed'
      });
    }
  };
};