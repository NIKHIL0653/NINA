import { Router } from 'express';
import { AuthenticatedRequest } from '../middleware/auth';
import { PrivacyManager, PrivacyCategory, PrivacyLevel } from '../middleware/privacy';
import { auditMiddleware } from '../middleware/audit';

const router = Router();

// Get user's privacy settings
router.get('/settings',
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const settings = await PrivacyManager.getPrivacySettings(req.user.id);

      // Convert to client-friendly format
      const formattedSettings = Object.entries(settings).map(([category, setting]) => ({
        category,
        level: setting.level,
        allowedUsers: setting.allowed_users || [],
        allowedRoles: setting.allowed_roles || [],
        restrictions: setting.restrictions,
        updatedAt: setting.updated_at
      }));

      res.json({
        success: true,
        data: formattedSettings
      });
    } catch (error) {
      console.error('Failed to get privacy settings:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve privacy settings'
      });
    }
  }
);

// Update privacy setting
router.put('/settings/:category',
  auditMiddleware('UPDATE', 'privacy_settings'),
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const { category } = req.params;
      const { level, allowedUsers, allowedRoles, restrictions } = req.body;

      if (!Object.values(PrivacyCategory).includes(category as PrivacyCategory)) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid privacy category'
        });
      }

      if (!Object.values(PrivacyLevel).includes(level)) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid privacy level'
        });
      }

      const success = await PrivacyManager.updatePrivacySetting(
        req.user.id,
        category as PrivacyCategory,
        level,
        {
          allowedUsers,
          allowedRoles,
          restrictions
        }
      );

      if (!success) {
        return res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to update privacy setting'
        });
      }

      res.json({
        success: true,
        message: 'Privacy setting updated successfully',
        data: {
          category,
          level,
          allowedUsers: allowedUsers || [],
          allowedRoles: allowedRoles || [],
          restrictions
        }
      });
    } catch (error) {
      console.error('Failed to update privacy setting:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to update privacy setting'
      });
    }
  }
);

// Bulk update privacy settings
router.put('/settings',
  auditMiddleware('UPDATE', 'privacy_settings'),
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const { settings } = req.body;

      if (!Array.isArray(settings)) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Settings must be an array'
        });
      }

      const updates = settings.map(setting => ({
        category: setting.category,
        level: setting.level,
        allowedUsers: setting.allowedUsers,
        allowedRoles: setting.allowedRoles,
        restrictions: setting.restrictions
      }));

      const result = await PrivacyManager.bulkUpdateSettings(req.user.id, updates);

      res.json({
        success: result.success,
        message: `Updated ${result.updated} settings, ${result.failed} failed`,
        data: result
      });
    } catch (error) {
      console.error('Failed to bulk update privacy settings:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to update privacy settings'
      });
    }
  }
);

// Reset privacy settings to defaults
router.post('/settings/reset',
  auditMiddleware('UPDATE', 'privacy_settings'),
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const success = await PrivacyManager.resetToDefaults(req.user.id);

      if (!success) {
        return res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to reset privacy settings'
        });
      }

      res.json({
        success: true,
        message: 'Privacy settings reset to defaults'
      });
    } catch (error) {
      console.error('Failed to reset privacy settings:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to reset privacy settings'
      });
    }
  }
);

// Get privacy options (available categories and levels)
router.get('/options',
  async (req, res) => {
    try {
      const categories = Object.values(PrivacyCategory);
      const levels = Object.values(PrivacyLevel);

      const categoryDescriptions = {
        [PrivacyCategory.PROFILE_VISIBILITY]: 'Who can see your basic profile information',
        [PrivacyCategory.MEDICAL_DATA_SHARING]: 'Who can access your medical records and data',
        [PrivacyCategory.CONTACT_PREFERENCES]: 'How and when you can be contacted',
        [PrivacyCategory.ANALYTICS_OPT_IN]: 'Use of anonymized data for service improvement',
        [PrivacyCategory.MARKETING_OPT_IN]: 'Receive health-related communications',
        [PrivacyCategory.RESEARCH_PARTICIPATION]: 'Participation in medical research',
        [PrivacyCategory.EMERGENCY_ACCESS]: 'Emergency access to your medical information',
        [PrivacyCategory.DATA_RETENTION]: 'How long your data is retained',
        [PrivacyCategory.AUDIT_LOG_ACCESS]: 'Who can view your activity logs'
      };

      const levelDescriptions = {
        [PrivacyLevel.PUBLIC]: 'Anyone can access',
        [PrivacyLevel.HEALTHCARE_PROVIDERS]: 'Only healthcare providers',
        [PrivacyLevel.EMERGENCY_CONTACTS]: 'Only emergency contacts',
        [PrivacyLevel.PRIVATE]: 'Only you'
      };

      res.json({
        success: true,
        data: {
          categories: categories.map(cat => ({
            value: cat,
            label: cat.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
            description: categoryDescriptions[cat]
          })),
          levels: levels.map(level => ({
            value: level,
            label: level.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
            description: levelDescriptions[level]
          }))
        }
      });
    } catch (error) {
      console.error('Failed to get privacy options:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve privacy options'
      });
    }
  }
);

// Check access for specific operation (for frontend validation)
router.post('/check-access',
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const { targetUserId, category, context } = req.body;

      if (!targetUserId || !category) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Target user ID and category are required'
        });
      }

      const accessCheck = await PrivacyManager.checkAccess(
        targetUserId,
        req.user.id,
        req.user.role || 'patient',
        category,
        context
      );

      res.json({
        success: true,
        data: {
          allowed: accessCheck.allowed,
          reason: accessCheck.reason
        }
      });
    } catch (error) {
      console.error('Failed to check access:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to check access'
      });
    }
  }
);

export { router as privacyRoutes };