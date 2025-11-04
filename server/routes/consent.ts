import { Router } from 'express';
import { AuthenticatedRequest } from '../middleware/auth';
import { ConsentManager, ConsentType, ConsentStatus } from '../middleware/consent';
import { auditMiddleware } from '../middleware/audit';

const router = Router();

// Get user's consent status
router.get('/status',
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const activeConsents = await ConsentManager.getActiveConsents(req.user.id);

      // Check status for all consent types
      const consentStatus = Object.values(ConsentType).reduce((acc, type) => {
        const hasConsent = activeConsents.some(consent => consent.consent_type === type);
        acc[type] = hasConsent ? ConsentStatus.GRANTED : ConsentStatus.DENIED;
        return acc;
      }, {} as Record<ConsentType, ConsentStatus>);

      res.json({
        success: true,
        data: {
          consents: consentStatus,
          activeConsents: activeConsents.map(consent => ({
            type: consent.consent_type,
            grantedAt: consent.granted_at,
            expiresAt: consent.expires_at,
            version: consent.consent_version
          }))
        }
      });
    } catch (error) {
      console.error('Failed to get consent status:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve consent status'
      });
    }
  }
);

// Grant consent
router.post('/grant',
  auditMiddleware('CREATE', 'consent'),
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const { consentType, purpose, expiresAt, dataScope, thirdPartyRecipients } = req.body;

      if (!consentType || !Object.values(ConsentType).includes(consentType)) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid consent type'
        });
      }

      if (!purpose) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Purpose is required'
        });
      }

      const options = {
        ipAddress: req.ip || '',
        userAgent: req.get('User-Agent') || '',
        expiresAt: expiresAt ? new Date(expiresAt) : undefined,
        dataScope,
        thirdPartyRecipients
      };

      const success = await ConsentManager.grantConsent(
        req.user.id,
        consentType,
        purpose,
        options
      );

      if (!success) {
        return res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to grant consent'
        });
      }

      res.json({
        success: true,
        message: 'Consent granted successfully',
        data: {
          consentType,
          grantedAt: new Date().toISOString(),
          expiresAt: options.expiresAt?.toISOString()
        }
      });
    } catch (error) {
      console.error('Failed to grant consent:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to grant consent'
      });
    }
  }
);

// Revoke consent
router.post('/revoke',
  auditMiddleware('UPDATE', 'consent'),
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const { consentType, reason } = req.body;

      if (!consentType || !Object.values(ConsentType).includes(consentType)) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid consent type'
        });
      }

      const success = await ConsentManager.revokeConsent(
        req.user.id,
        consentType,
        req.user.id,
        reason
      );

      if (!success) {
        return res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to revoke consent'
        });
      }

      res.json({
        success: true,
        message: 'Consent revoked successfully',
        data: { consentType }
      });
    } catch (error) {
      console.error('Failed to revoke consent:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to revoke consent'
      });
    }
  }
);

// Get consent history
router.get('/history',
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const history = await ConsentManager.getConsentHistory(req.user.id);

      res.json({
        success: true,
        data: history.map(consent => ({
          id: consent.id,
          type: consent.consent_type,
          status: consent.status,
          grantedAt: consent.granted_at,
          expiresAt: consent.expires_at,
          revokedAt: consent.revoked_at,
          version: consent.consent_version,
          purpose: consent.purpose,
          dataScope: consent.data_scope,
          thirdPartyRecipients: consent.third_party_recipients
        }))
      });
    } catch (error) {
      console.error('Failed to get consent history:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve consent history'
      });
    }
  }
);

// Get consent requirements for operations
router.get('/requirements',
  async (req: AuthenticatedRequest, res) => {
    try {
      const { operation, dataType } = req.query;

      const requiredConsent = ConsentManager.isConsentRequired(operation as string, dataType as string);

      res.json({
        success: true,
        data: {
          operation,
          dataType,
          requiredConsent,
          consentDescription: requiredConsent ? getConsentDescription(requiredConsent) : null
        }
      });
    } catch (error) {
      console.error('Failed to get consent requirements:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve consent requirements'
      });
    }
  }
);

// Bulk consent operations
router.post('/bulk',
  auditMiddleware('UPDATE', 'consent'),
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const { operations } = req.body; // Array of {consentType, action: 'grant'|'revoke', ...}

      if (!Array.isArray(operations)) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Operations must be an array'
        });
      }

      const results = [];

      for (const op of operations) {
        try {
          let success = false;

          if (op.action === 'grant') {
            success = await ConsentManager.grantConsent(
              req.user.id,
              op.consentType,
              op.purpose || 'Bulk consent operation',
              {
                ipAddress: req.ip || '',
                userAgent: req.get('User-Agent') || '',
                expiresAt: op.expiresAt ? new Date(op.expiresAt) : undefined
              }
            );
          } else if (op.action === 'revoke') {
            success = await ConsentManager.revokeConsent(
              req.user.id,
              op.consentType,
              req.user.id,
              op.reason
            );
          }

          results.push({
            consentType: op.consentType,
            action: op.action,
            success
          });
        } catch (error) {
          results.push({
            consentType: op.consentType,
            action: op.action,
            success: false,
            error: error.message
          });
        }
      }

      res.json({
        success: true,
        data: results
      });
    } catch (error) {
      console.error('Bulk consent operation failed:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Bulk consent operation failed'
      });
    }
  }
);

// Helper function to get consent descriptions
function getConsentDescription(consentType: ConsentType): string {
  const descriptions = {
    [ConsentType.DATA_PROCESSING]: 'Processing of personal health information for service provision',
    [ConsentType.MEDICAL_DATA_SHARING]: 'Sharing medical data with healthcare providers',
    [ConsentType.ANALYTICS]: 'Use of anonymized data for service improvement',
    [ConsentType.MARKETING]: 'Receiving health-related communications and updates',
    [ConsentType.RESEARCH]: 'Participation in medical research studies',
    [ConsentType.EMERGENCY_ACCESS]: 'Emergency access to medical information',
    [ConsentType.THIRD_PARTY_SHARING]: 'Sharing data with third-party healthcare services'
  };

  return descriptions[consentType] || 'Unknown consent type';
}

export { router as consentRoutes };