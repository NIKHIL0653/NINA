import { Router } from 'express';
import { requireRole, ROLES, AuthenticatedRequest } from '../middleware/auth';
import { DataRetentionManager, RetentionScheduler } from '../middleware/dataRetention';
import { auditMiddleware } from '../middleware/audit';
import { supabase } from '@shared/supabase';

const router = Router();

// Get data retention policies (admin only)
router.get('/policies',
  requireRole([ROLES.ADMIN]),
  auditMiddleware('READ', 'data_retention'),
  async (req: AuthenticatedRequest, res) => {
    try {
      const policies = Object.entries(DataRetentionManager['RETENTION_POLICIES']).map(([type, days]) => ({
        dataType: type,
        retentionDays: days,
        retentionYears: Math.round(days / 365 * 10) / 10
      }));

      res.json({
        success: true,
        data: policies
      });
    } catch (error) {
      console.error('Failed to get retention policies:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve retention policies'
      });
    }
  }
);

// Get retention report (admin only)
router.get('/report',
  requireRole([ROLES.ADMIN]),
  auditMiddleware('READ', 'data_retention'),
  async (req: AuthenticatedRequest, res) => {
    try {
      const report = await DataRetentionManager.getRetentionReport();

      res.json({
        success: true,
        data: report
      });
    } catch (error) {
      console.error('Failed to get retention report:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve retention report'
      });
    }
  }
);

// User data deletion request (GDPR right to be forgotten)
router.delete('/user-data',
  auditMiddleware('DELETE', 'user_data'),
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const { confirmDeletion } = req.body;

      if (!confirmDeletion) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Deletion confirmation required'
        });
      }

      // Schedule user data deletion (don't delete immediately for safety)
      const deletionDate = new Date();
      deletionDate.setDate(deletionDate.getDate() + 30); // 30 days grace period

      const scheduled = await DataRetentionManager.scheduleDeletion('user_data', req.user.id, deletionDate);

      if (!scheduled) {
        return res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to schedule data deletion'
        });
      }

      res.json({
        success: true,
        message: 'Data deletion scheduled',
        data: {
          scheduledDeletionDate: deletionDate.toISOString(),
          gracePeriodDays: 30
        }
      });
    } catch (error) {
      console.error('Failed to schedule user data deletion:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to schedule data deletion'
      });
    }
  }
);

// Cancel scheduled deletion
router.delete('/user-data/cancel',
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      // Remove from deletion schedule
      const { error } = await supabase
        .from('data_deletion_schedule')
        .delete()
        .eq('data_type', 'user_data')
        .eq('record_id', req.user.id)
        .eq('status', 'scheduled');

      if (error) {
        console.error('Failed to cancel deletion:', error);
        return res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to cancel deletion'
        });
      }

      res.json({
        success: true,
        message: 'Data deletion cancelled'
      });
    } catch (error) {
      console.error('Failed to cancel deletion:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to cancel deletion'
      });
    }
  }
);

// Manual cleanup trigger (admin only)
router.post('/cleanup',
  requireRole([ROLES.ADMIN]),
  auditMiddleware('EXECUTE', 'data_retention'),
  async (req: AuthenticatedRequest, res) => {
    try {
      const result = await RetentionScheduler.triggerManualCleanup();

      res.json({
        success: true,
        message: 'Manual cleanup completed',
        data: result
      });
    } catch (error) {
      console.error('Manual cleanup failed:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Manual cleanup failed'
      });
    }
  }
);

// Get user's data summary before deletion
router.get('/user-data/summary',
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      // Mock data summary (in production, query actual data counts)
      const dataSummary = {
        medicalRecords: 15,
        prescriptions: 8,
        emergencyContacts: 3,
        appointments: 12,
        chatHistory: 245,
        vitalSigns: 67,
        auditLogs: 156,
        totalDataPoints: 506
      };

      // Check if deletion is already scheduled
      const { data: scheduledDeletion } = await supabase
        .from('data_deletion_schedule')
        .select('scheduled_deletion_date')
        .eq('data_type', 'user_data')
        .eq('record_id', req.user.id)
        .eq('status', 'scheduled')
        .single();

      res.json({
        success: true,
        data: {
          ...dataSummary,
          scheduledDeletion: scheduledDeletion?.scheduled_deletion_date || null
        }
      });
    } catch (error) {
      console.error('Failed to get data summary:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve data summary'
      });
    }
  }
);

// Export user data before deletion (data portability)
router.get('/user-data/export',
  auditMiddleware('EXPORT', 'user_data'),
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      // Mock data export (in production, gather actual user data)
      const exportData = {
        userId: req.user.id,
        exportDate: new Date().toISOString(),
        data: {
          profile: {
            id: req.user.id,
            role: req.user.role,
            created_at: '2024-01-15T10:00:00Z'
          },
          medicalRecords: [
            {
              id: 'mr_001',
              diagnosis: 'Hypertension',
              created_at: '2024-02-01T09:00:00Z'
            }
          ],
          prescriptions: [],
          emergencyContacts: [],
          appointments: [],
          disclaimer: 'This data export is provided for your records. Some sensitive information may be redacted for privacy.'
        }
      };

      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="user-data-export-${req.user.id}.json"`);
      res.json(exportData);
    } catch (error) {
      console.error('Failed to export user data:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to export user data'
      });
    }
  }
);

export { router as dataRetentionRoutes };