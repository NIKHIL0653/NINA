import { Request, Response, NextFunction } from 'express';
import { AuthenticatedRequest } from './auth';
import { supabase } from '@shared/supabase';

// Emergency access levels
export enum EmergencyLevel {
  LOW = 'low',           // Minor emergency, limited access
  MEDIUM = 'medium',     // Moderate emergency, standard access
  HIGH = 'high',         // Critical emergency, full access
  CRITICAL = 'critical'  // Life-threatening, override all restrictions
}

// Emergency access request interface
interface EmergencyAccessRequest {
  id?: string;
  patient_id: string;
  requester_id: string;
  requester_role: string;
  emergency_level: EmergencyLevel;
  reason: string;
  approved_by?: string;
  approved_at?: string;
  expires_at: string;
  status: 'pending' | 'approved' | 'denied' | 'expired' | 'revoked';
  access_scope: string[]; // What data can be accessed
  ip_address: string;
  user_agent: string;
  created_at: string;
}

// Emergency access manager
export class EmergencyAccessManager {
  // Emergency access duration by level (in hours)
  private static readonly ACCESS_DURATIONS = {
    [EmergencyLevel.LOW]: 4,
    [EmergencyLevel.MEDIUM]: 12,
    [EmergencyLevel.HIGH]: 24,
    [EmergencyLevel.CRITICAL]: 72
  };

  // Maximum concurrent emergency accesses per patient
  private static readonly MAX_CONCURRENT_ACCESSES = 3;

  // Create emergency access request
  static async createEmergencyRequest(
    patientId: string,
    requesterId: string,
    requesterRole: string,
    emergencyLevel: EmergencyLevel,
    reason: string,
    accessScope: string[],
    ipAddress: string,
    userAgent: string
  ): Promise<{ success: boolean; requestId?: string; autoApproved?: boolean }> {
    try {
      // Check if auto-approval is possible
      const autoApproved = await this.shouldAutoApprove(requesterRole, emergencyLevel);

      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + this.ACCESS_DURATIONS[emergencyLevel]);

      const request: Omit<EmergencyAccessRequest, 'id'> = {
        patient_id: patientId,
        requester_id: requesterId,
        requester_role: requesterRole,
        emergency_level: emergencyLevel,
        reason,
        status: autoApproved ? 'approved' : 'pending',
        access_scope: accessScope,
        expires_at: expiresAt.toISOString(),
        ip_address: ipAddress,
        user_agent: userAgent,
        created_at: new Date().toISOString(),
        ...(autoApproved && {
          approved_by: 'system',
          approved_at: new Date().toISOString()
        })
      };

      const { data, error } = await supabase
        .from('emergency_access_requests')
        .insert(request)
        .select('id')
        .single();

      if (error) {
        console.error('Failed to create emergency access request:', error);
        return { success: false };
      }

      // Log emergency access creation
      console.warn(`[EMERGENCY ACCESS] ${emergencyLevel.toUpperCase()} access requested for patient ${patientId} by ${requesterRole} ${requesterId}`);

      return {
        success: true,
        requestId: data.id,
        autoApproved
      };
    } catch (error) {
      console.error('Error creating emergency access request:', error);
      return { success: false };
    }
  }

  // Approve emergency access request
  static async approveEmergencyRequest(
    requestId: string,
    approverId: string,
    approverRole: string
  ): Promise<boolean> {
    try {
      // Verify approver has permission
      if (!this.canApproveEmergency(approverRole)) {
        throw new Error('Insufficient permissions to approve emergency access');
      }

      const { error } = await supabase
        .from('emergency_access_requests')
        .update({
          status: 'approved',
          approved_by: approverId,
          approved_at: new Date().toISOString()
        })
        .eq('id', requestId)
        .eq('status', 'pending');

      if (error) {
        console.error('Failed to approve emergency access:', error);
        return false;
      }

      return true;
    } catch (error) {
      console.error('Error approving emergency access:', error);
      return false;
    }
  }

  // Check if user has active emergency access to patient data
  static async hasEmergencyAccess(
    requesterId: string,
    patientId: string,
    requiredScope?: string[]
  ): Promise<{ hasAccess: boolean; level?: EmergencyLevel; scope?: string[] }> {
    try {
      const now = new Date().toISOString();

      const { data, error } = await supabase
        .from('emergency_access_requests')
        .select('*')
        .eq('requester_id', requesterId)
        .eq('patient_id', patientId)
        .eq('status', 'approved')
        .gt('expires_at', now)
        .order('created_at', { ascending: false })
        .limit(1)
        .single();

      if (error || !data) {
        return { hasAccess: false };
      }

      // Check if required scope is covered
      if (requiredScope && !this.scopeCovers(data.access_scope, requiredScope)) {
        return { hasAccess: false };
      }

      return {
        hasAccess: true,
        level: data.emergency_level,
        scope: data.access_scope
      };
    } catch (error) {
      console.error('Error checking emergency access:', error);
      return { hasAccess: false };
    }
  }

  // Revoke emergency access
  static async revokeEmergencyAccess(
    requestId: string,
    revokerId: string,
    reason?: string
  ): Promise<boolean> {
    try {
      const { error } = await supabase
        .from('emergency_access_requests')
        .update({
          status: 'revoked',
          revoked_at: new Date().toISOString(),
          revocation_reason: reason,
          revoked_by: revokerId
        })
        .eq('id', requestId)
        .in('status', ['approved', 'pending']);

      if (error) {
        console.error('Failed to revoke emergency access:', error);
        return false;
      }

      return true;
    } catch (error) {
      console.error('Error revoking emergency access:', error);
      return false;
    }
  }

  // Get active emergency accesses for a patient
  static async getActiveEmergencyAccesses(patientId: string): Promise<EmergencyAccessRequest[]> {
    try {
      const now = new Date().toISOString();

      const { data, error } = await supabase
        .from('emergency_access_requests')
        .select('*')
        .eq('patient_id', patientId)
        .eq('status', 'approved')
        .gt('expires_at', now)
        .order('created_at', { ascending: false });

      if (error) {
        console.error('Failed to get active emergency accesses:', error);
        return [];
      }

      return data || [];
    } catch (error) {
      console.error('Error getting active emergency accesses:', error);
      return [];
    }
  }

  // Check if emergency level should be auto-approved
  private static async shouldAutoApprove(requesterRole: string, emergencyLevel: EmergencyLevel): Promise<boolean> {
    // Critical emergencies are always auto-approved for authorized roles
    if (emergencyLevel === EmergencyLevel.CRITICAL) {
      return ['healthcare_provider', 'admin'].includes(requesterRole);
    }

    // High priority for healthcare providers
    if (emergencyLevel === EmergencyLevel.HIGH && requesterRole === 'healthcare_provider') {
      return true;
    }

    // Medium priority requires manual approval
    return false;
  }

  // Check if role can approve emergency access
  private static canApproveEmergency(role: string): boolean {
    return ['admin', 'healthcare_provider'].includes(role);
  }

  // Check if access scope covers required scope
  private static scopeCovers(grantedScope: string[], requiredScope: string[]): boolean {
    return requiredScope.every(scope => grantedScope.includes(scope) || grantedScope.includes('*'));
  }

  // Clean up expired emergency accesses
  static async cleanupExpiredAccesses(): Promise<number> {
    try {
      const now = new Date().toISOString();

      const { data, error } = await supabase
        .from('emergency_access_requests')
        .update({ status: 'expired' })
        .eq('status', 'approved')
        .lt('expires_at', now)
        .select('id');

      if (error) {
        console.error('Failed to cleanup expired accesses:', error);
        return 0;
      }

      return data?.length || 0;
    } catch (error) {
      console.error('Error cleaning up expired accesses:', error);
      return 0;
    }
  }
}

// Emergency access middleware
export const emergencyAccessMiddleware = (requiredScope?: string[]) => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      // Extract patient ID from request
      const patientId = req.params.userId || req.params.patientId || req.params.id;

      if (!patientId) {
        return next(); // Not a patient-specific request
      }

      // Check if user has emergency access
      const emergencyAccess = await EmergencyAccessManager.hasEmergencyAccess(
        req.user.id,
        patientId,
        requiredScope
      );

      if (emergencyAccess.hasAccess) {
        // Add emergency access flag to request
        (req as any).emergencyAccess = {
          level: emergencyAccess.level,
          scope: emergencyAccess.scope
        };

        // Log emergency access usage
        console.warn(`[EMERGENCY ACCESS] ${emergencyAccess.level?.toUpperCase()} access used by ${req.user.role} ${req.user.id} for patient ${patientId}`);

        return next();
      }

      next();
    } catch (error) {
      console.error('Emergency access middleware error:', error);
      return res.status(500).json({
        error: 'Internal Server Error',
        message: 'Emergency access check failed'
      });
    }
  };
};

// Emergency override for critical situations
export const emergencyOverride = () => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    // Check for emergency override header
    const emergencyOverride = req.headers['x-emergency-override'] === process.env.EMERGENCY_OVERRIDE_KEY;

    if (emergencyOverride && req.user) {
      // Log emergency override
      console.error(`[EMERGENCY OVERRIDE] Used by ${req.user.role} ${req.user.id} for ${req.method} ${req.path}`);

      // Grant full access for emergency override
      (req as any).emergencyOverride = true;

      return next();
    }

    next();
  };
};