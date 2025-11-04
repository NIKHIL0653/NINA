import { Router } from 'express';
import { AuthenticatedRequest } from '../middleware/auth';
import { EmergencyAccessManager, EmergencyLevel } from '../middleware/emergencyAccess';
import { auditMiddleware } from '../middleware/audit';

const router = Router();

// Request emergency access
router.post('/request',
  auditMiddleware('CREATE', 'emergency_access'),
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const { patientId, emergencyLevel, reason, accessScope } = req.body;

      if (!patientId || !emergencyLevel || !reason) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Patient ID, emergency level, and reason are required'
        });
      }

      if (!Object.values(EmergencyLevel).includes(emergencyLevel)) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid emergency level'
        });
      }

      // Default access scope if not provided
      const scope = accessScope || ['medical_records', 'emergency_contacts'];

      const result = await EmergencyAccessManager.createEmergencyRequest(
        patientId,
        req.user.id,
        req.user.role || 'unknown',
        emergencyLevel,
        reason,
        scope,
        req.ip || '',
        req.get('User-Agent') || ''
      );

      if (!result.success) {
        return res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to create emergency access request'
        });
      }

      res.status(201).json({
        success: true,
        message: result.autoApproved
          ? 'Emergency access granted automatically'
          : 'Emergency access request submitted for approval',
        data: {
          requestId: result.requestId,
          autoApproved: result.autoApproved,
          emergencyLevel
        }
      });
    } catch (error) {
      console.error('Failed to request emergency access:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to request emergency access'
      });
    }
  }
);

// Approve emergency access request (admin/healthcare provider only)
router.post('/:requestId/approve',
  auditMiddleware('UPDATE', 'emergency_access'),
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const { requestId } = req.params;

      const success = await EmergencyAccessManager.approveEmergencyRequest(
        requestId,
        req.user.id,
        req.user.role || 'unknown'
      );

      if (!success) {
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Cannot approve emergency access request'
        });
      }

      res.json({
        success: true,
        message: 'Emergency access request approved'
      });
    } catch (error) {
      console.error('Failed to approve emergency access:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to approve emergency access'
      });
    }
  }
);

// Revoke emergency access
router.post('/:requestId/revoke',
  auditMiddleware('UPDATE', 'emergency_access'),
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const { requestId } = req.params;
      const { reason } = req.body;

      const success = await EmergencyAccessManager.revokeEmergencyAccess(
        requestId,
        req.user.id,
        reason
      );

      if (!success) {
        return res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to revoke emergency access'
        });
      }

      res.json({
        success: true,
        message: 'Emergency access revoked'
      });
    } catch (error) {
      console.error('Failed to revoke emergency access:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to revoke emergency access'
      });
    }
  }
);

// Get active emergency accesses for a patient
router.get('/patient/:patientId/active',
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const { patientId } = req.params;

      // Check if user can view emergency accesses for this patient
      if (req.user.role !== 'admin' && req.user.id !== patientId) {
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Cannot view emergency accesses for this patient'
        });
      }

      const accesses = await EmergencyAccessManager.getActiveEmergencyAccesses(patientId);

      res.json({
        success: true,
        data: accesses.map(access => ({
          id: access.id,
          requesterId: access.requester_id,
          requesterRole: access.requester_role,
          emergencyLevel: access.emergency_level,
          reason: access.reason,
          approvedBy: access.approved_by,
          approvedAt: access.approved_at,
          expiresAt: access.expires_at,
          accessScope: access.access_scope
        }))
      });
    } catch (error) {
      console.error('Failed to get active emergency accesses:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve emergency accesses'
      });
    }
  }
);

// Check if user has emergency access to patient
router.get('/check/:patientId',
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const { patientId } = req.params;
      const { scope } = req.query;

      const accessCheck = await EmergencyAccessManager.hasEmergencyAccess(
        req.user.id,
        patientId,
        scope ? (scope as string).split(',') : undefined
      );

      res.json({
        success: true,
        data: {
          hasAccess: accessCheck.hasAccess,
          level: accessCheck.level,
          scope: accessCheck.scope
        }
      });
    } catch (error) {
      console.error('Failed to check emergency access:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to check emergency access'
      });
    }
  }
);

// Get emergency access options
router.get('/options',
  async (req, res) => {
    try {
      const levels = Object.values(EmergencyLevel);
      const scopes = [
        'medical_records',
        'prescriptions',
        'emergency_contacts',
        'vital_signs',
        'appointments',
        'medical_history',
        '*'
      ];

      const levelDescriptions = {
        [EmergencyLevel.LOW]: 'Minor emergency - limited access for 4 hours',
        [EmergencyLevel.MEDIUM]: 'Moderate emergency - standard access for 12 hours',
        [EmergencyLevel.HIGH]: 'Critical emergency - full access for 24 hours',
        [EmergencyLevel.CRITICAL]: 'Life-threatening emergency - override access for 72 hours'
      };

      res.json({
        success: true,
        data: {
          levels: levels.map(level => ({
            value: level,
            label: level.charAt(0).toUpperCase() + level.slice(1),
            description: levelDescriptions[level]
          })),
          scopes: scopes.map(scope => ({
            value: scope,
            label: scope === '*' ? 'All Data' : scope.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
          }))
        }
      });
    } catch (error) {
      console.error('Failed to get emergency access options:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve emergency access options'
      });
    }
  }
);

// Cleanup expired emergency accesses (admin only)
router.post('/cleanup',
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Admin access required'
        });
      }

      const cleanedCount = await EmergencyAccessManager.cleanupExpiredAccesses();

      res.json({
        success: true,
        message: `Cleaned up ${cleanedCount} expired emergency accesses`
      });
    } catch (error) {
      console.error('Failed to cleanup emergency accesses:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to cleanup emergency accesses'
      });
    }
  }
);

export { router as emergencyAccessRoutes };