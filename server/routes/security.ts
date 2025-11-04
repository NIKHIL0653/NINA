import { Router } from 'express';
import { AuthenticatedRequest } from '../middleware/auth';
import { SecurityMonitor, SecurityEventType, SecuritySeverity } from '../middleware/securityMonitoring';
import { requireRole, ROLES } from '../middleware/auth';

const router = Router();

// Get security dashboard (admin only)
router.get('/dashboard',
  requireRole([ROLES.ADMIN]),
  async (req: AuthenticatedRequest, res) => {
    try {
      const dashboard = await SecurityMonitor.getSecurityDashboard();

      if (!dashboard) {
        return res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to retrieve security dashboard'
        });
      }

      res.json({
        success: true,
        data: dashboard
      });
    } catch (error) {
      console.error('Failed to get security dashboard:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve security dashboard'
      });
    }
  }
);

// Get recent security events
router.get('/events',
  requireRole([ROLES.ADMIN]),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { limit = 50, severity, eventType, startDate, endDate } = req.query;

      // This would need to be implemented in SecurityMonitor
      // For now, return mock data
      const events = [
        {
          id: '1',
          event_type: SecurityEventType.FAILED_LOGIN,
          severity: SecuritySeverity.MEDIUM,
          user_id: 'user123',
          ip_address: '192.168.1.1',
          timestamp: new Date().toISOString(),
          details: { attempts: 3 }
        }
      ];

      res.json({
        success: true,
        data: events,
        total: events.length
      });
    } catch (error) {
      console.error('Failed to get security events:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve security events'
      });
    }
  }
);

// Report suspicious activity
router.post('/report',
  async (req: AuthenticatedRequest, res) => {
    try {
      const { eventType, severity, details, ipAddress, userAgent } = req.body;

      if (!eventType || !Object.values(SecurityEventType).includes(eventType)) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid event type'
        });
      }

      if (!severity || !Object.values(SecuritySeverity).includes(severity)) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid severity level'
        });
      }

      await SecurityMonitor.logSecurityEvent(
        eventType,
        severity,
        details,
        req.user?.id,
        ipAddress || req.ip,
        userAgent || req.get('User-Agent')
      );

      res.json({
        success: true,
        message: 'Security event reported successfully'
      });
    } catch (error) {
      console.error('Failed to report security event:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to report security event'
      });
    }
  }
);

// Check IP reputation
router.get('/ip-check/:ipAddress',
  requireRole([ROLES.ADMIN]),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { ipAddress } = req.params;

      const isSuspicious = await SecurityMonitor.isSuspiciousIP(ipAddress);

      res.json({
        success: true,
        data: {
          ipAddress,
          isSuspicious,
          status: isSuspicious ? 'suspicious' : 'clean'
        }
      });
    } catch (error) {
      console.error('Failed to check IP reputation:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to check IP reputation'
      });
    }
  }
);

// Get security alerts
router.get('/alerts',
  requireRole([ROLES.ADMIN]),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { resolved = false } = req.query;

      // Mock alerts - in production, fetch from database
      const alerts = [
        {
          id: 'alert1',
          type: 'brute_force_attempt',
          severity: SecuritySeverity.HIGH,
          description: 'Multiple failed login attempts detected',
          ip_address: '192.168.1.100',
          timestamp: new Date().toISOString(),
          resolved: false
        }
      ].filter(alert => alert.resolved === (resolved === 'true'));

      res.json({
        success: true,
        data: alerts
      });
    } catch (error) {
      console.error('Failed to get security alerts:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve security alerts'
      });
    }
  }
);

// Resolve security alert
router.post('/alerts/:alertId/resolve',
  requireRole([ROLES.ADMIN]),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { alertId } = req.params;
      const { resolution } = req.body;

      // In production, update alert status in database
      console.log(`Security alert ${alertId} resolved by ${req.user?.id}: ${resolution}`);

      res.json({
        success: true,
        message: 'Security alert resolved'
      });
    } catch (error) {
      console.error('Failed to resolve security alert:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to resolve security alert'
      });
    }
  }
);

// Get security metrics
router.get('/metrics',
  requireRole([ROLES.ADMIN]),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { period = '24h' } = req.query;

      // Mock metrics - in production, calculate from database
      const metrics = {
        period,
        totalEvents: 150,
        criticalEvents: 2,
        highEvents: 8,
        mediumEvents: 25,
        lowEvents: 115,
        topEventTypes: [
          { type: SecurityEventType.FAILED_LOGIN, count: 45 },
          { type: SecurityEventType.UNAUTHORIZED_ACCESS, count: 23 },
          { type: SecurityEventType.SUSPICIOUS_ACTIVITY, count: 18 }
        ],
        topIPs: [
          { ip: '192.168.1.100', events: 12 },
          { ip: '10.0.0.50', events: 8 }
        ]
      };

      res.json({
        success: true,
        data: metrics
      });
    } catch (error) {
      console.error('Failed to get security metrics:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve security metrics'
      });
    }
  }
);

// Security incident response
router.post('/incident',
  requireRole([ROLES.ADMIN]),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { incidentType, description, affectedUsers, severity } = req.body;

      // Log critical security incident
      await SecurityMonitor.logSecurityEvent(
        SecurityEventType.DATA_BREACH_ATTEMPT,
        severity || SecuritySeverity.CRITICAL,
        {
          incidentType,
          description,
          affectedUsers,
          reportedBy: req.user?.id
        },
        req.user?.id,
        req.ip || '',
        req.get('User-Agent') || ''
      );

      // In production, trigger incident response procedures
      console.error('🚨 SECURITY INCIDENT REPORTED:', {
        type: incidentType,
        description,
        affectedUsers,
        reportedBy: req.user?.id,
        timestamp: new Date().toISOString()
      });

      res.json({
        success: true,
        message: 'Security incident reported and incident response initiated'
      });
    } catch (error) {
      console.error('Failed to report security incident:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to report security incident'
      });
    }
  }
);

export { router as securityRoutes };