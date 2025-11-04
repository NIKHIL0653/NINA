import { Router } from 'express';
import { requireMFA, setupMFA, verifyMFACode, initiateMFA } from '../middleware/mfa';
import { AuthenticatedRequest } from '../middleware/auth';
import { supabase } from '@shared/supabase';

const router = Router();

// Setup MFA for user
router.post('/setup', setupMFA);

// Initiate MFA challenge
router.post('/initiate', async (req: AuthenticatedRequest, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }

    const { method } = req.body;
    const result = await initiateMFA(req.user.id, method);

    res.json({
      success: true,
      data: {
        sessionId: result.sessionId,
        message: result.message
      }
    });
  } catch (error) {
    console.error('MFA initiation error:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to initiate MFA'
    });
  }
});

// Verify MFA code
router.post('/verify', verifyMFACode);

// Get MFA status for user
router.get('/status', async (req: AuthenticatedRequest, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }

    // Check MFA settings
    const { data, error } = await supabase
      .from('user_mfa_settings')
      .select('enabled, method')
      .eq('user_id', req.user.id)
      .single();

    const mfaEnabled = !error && data?.enabled;

    res.json({
      success: true,
      data: {
        enabled: mfaEnabled,
        method: data?.method || null
      }
    });
  } catch (error) {
    console.error('MFA status error:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to get MFA status'
    });
  }
});

// Disable MFA (requires current MFA verification)
router.delete('/disable', requireMFA(), async (req: AuthenticatedRequest, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }

    const { error } = await supabase
      .from('user_mfa_settings')
      .update({
        enabled: false,
        updated_at: new Date().toISOString()
      })
      .eq('user_id', req.user.id);

    if (error) {
      console.error('Failed to disable MFA:', error);
      return res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to disable MFA'
      });
    }

    res.json({
      success: true,
      message: 'MFA disabled successfully'
    });
  } catch (error) {
    console.error('MFA disable error:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to disable MFA'
    });
  }
});

export { router as mfaRoutes };