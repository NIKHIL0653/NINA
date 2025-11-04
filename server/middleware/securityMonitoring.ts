import { Request, Response, NextFunction } from 'express';
import { AuthenticatedRequest } from './auth';
import { supabase } from '@shared/supabase';

// Security event types
export enum SecurityEventType {
  FAILED_LOGIN = 'failed_login',
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  UNAUTHORIZED_ACCESS = 'unauthorized_access',
  DATA_BREACH_ATTEMPT = 'data_breach_attempt',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
  SUSPICIOUS_IP = 'suspicious_ip',
  ACCOUNT_LOCKOUT = 'account_lockout',
  PASSWORD_RESET = 'password_reset',
  MFA_FAILURE = 'mfa_failure',
  EMERGENCY_ACCESS = 'emergency_access',
  PRIVACY_VIOLATION = 'privacy_violation',
  CONSENT_VIOLATION = 'consent_violation'
}

// Security event severity
export enum SecuritySeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

// Security event interface
interface SecurityEvent {
  id?: string;
  event_type: SecurityEventType;
  severity: SecuritySeverity;
  user_id?: string;
  ip_address: string;
  user_agent: string;
  location?: string;
  details: any;
  timestamp: string;
  resolved?: boolean;
  resolved_at?: string;
  resolved_by?: string;
}

// Security monitoring thresholds
const MONITORING_THRESHOLDS = {
  FAILED_LOGINS_PER_HOUR: 5,
  SUSPICIOUS_REQUESTS_PER_MINUTE: 10,
  RATE_LIMIT_VIOLATIONS_PER_HOUR: 20,
  MFA_FAILURES_PER_HOUR: 3
};

// Security monitoring manager
export class SecurityMonitor {
  private static alertQueue: SecurityEvent[] = [];
  private static readonly ALERT_BATCH_SIZE = 5;

  // Log security event
  static async logSecurityEvent(
    eventType: SecurityEventType,
    severity: SecuritySeverity,
    details: any,
    userId?: string,
    ipAddress?: string,
    userAgent?: string,
    location?: string
  ): Promise<void> {
    try {
      const event: Omit<SecurityEvent, 'id'> = {
        event_type: eventType,
        severity,
        user_id: userId,
        ip_address: ipAddress || 'unknown',
        user_agent: userAgent || 'unknown',
        location,
        details,
        timestamp: new Date().toISOString()
      };

      // Add to alert queue for batch processing
      this.alertQueue.push(event as SecurityEvent);

      // Process alerts if queue is full
      if (this.alertQueue.length >= this.ALERT_BATCH_SIZE) {
        await this.processAlertQueue();
      }

      // Immediate alerts for critical events
      if (severity === SecuritySeverity.CRITICAL) {
        await this.sendImmediateAlert(event as SecurityEvent);
      }

      // Log to console for immediate visibility
      console.error(`[SECURITY ${severity.toUpperCase()}] ${eventType}:`, {
        userId,
        ipAddress,
        details
      });

    } catch (error) {
      console.error('Failed to log security event:', error);
    }
  }

  // Process queued alerts
  private static async processAlertQueue(): Promise<void> {
    if (this.alertQueue.length === 0) return;

    try {
      const events = [...this.alertQueue];
      this.alertQueue = [];

      // Store in database
      const { error } = await supabase
        .from('security_events')
        .insert(events);

      if (error) {
        console.error('Failed to store security events:', error);
        // Re-queue failed events
        this.alertQueue.unshift(...events);
      }

      // Check for patterns and send alerts
      await this.analyzeSecurityPatterns(events);

    } catch (error) {
      console.error('Error processing alert queue:', error);
    }
  }

  // Send immediate alert for critical events
  private static async sendImmediateAlert(event: SecurityEvent): Promise<void> {
    // In production, integrate with alerting systems (email, SMS, Slack, etc.)
    console.error('🚨 CRITICAL SECURITY ALERT:', {
      type: event.event_type,
      user: event.user_id,
      ip: event.ip_address,
      details: event.details,
      timestamp: event.timestamp
    });

    // TODO: Send alerts to security team
  }

  // Analyze security patterns
  private static async analyzeSecurityPatterns(events: SecurityEvent[]): Promise<void> {
    try {
      // Group events by type and time window
      const patterns = this.detectPatterns(events);

      for (const pattern of patterns) {
        if (pattern.severity === SecuritySeverity.HIGH || pattern.severity === SecuritySeverity.CRITICAL) {
          await this.sendPatternAlert(pattern);
        }
      }
    } catch (error) {
      console.error('Error analyzing security patterns:', error);
    }
  }

  // Detect security patterns
  private static detectPatterns(events: SecurityEvent[]): any[] {
    const patterns: any[] = [];
    const now = new Date();

    // Failed login attempts from same IP
    const failedLogins = events.filter(e =>
      e.event_type === SecurityEventType.FAILED_LOGIN &&
      new Date(e.timestamp) > new Date(now.getTime() - 60 * 60 * 1000) // Last hour
    );

    const failedLoginByIP = this.groupBy(failedLogins, 'ip_address');
    for (const [ip, loginEvents] of Object.entries(failedLoginByIP)) {
      if ((loginEvents as SecurityEvent[]).length >= MONITORING_THRESHOLDS.FAILED_LOGINS_PER_HOUR) {
        patterns.push({
          type: 'brute_force_attempt',
          severity: SecuritySeverity.HIGH,
          description: `Multiple failed login attempts from IP ${ip}`,
          events: loginEvents,
          ip_address: ip
        });
      }
    }

    // Rate limit violations
    const rateLimitViolations = events.filter(e =>
      e.event_type === SecurityEventType.RATE_LIMIT_EXCEEDED &&
      new Date(e.timestamp) > new Date(now.getTime() - 60 * 60 * 1000)
    );

    if (rateLimitViolations.length >= MONITORING_THRESHOLDS.RATE_LIMIT_VIOLATIONS_PER_HOUR) {
      patterns.push({
        type: 'rate_limit_abuse',
        severity: SecuritySeverity.MEDIUM,
        description: 'High number of rate limit violations detected',
        events: rateLimitViolations
      });
    }

    // Suspicious activity from same user
    const suspiciousByUser = this.groupBy(
      events.filter(e => e.severity === SecuritySeverity.HIGH || e.severity === SecuritySeverity.CRITICAL),
      'user_id'
    );

    for (const [userId, userEvents] of Object.entries(suspiciousByUser)) {
      if ((userEvents as SecurityEvent[]).length >= 3) {
        patterns.push({
          type: 'suspicious_user_activity',
          severity: SecuritySeverity.HIGH,
          description: `Multiple suspicious activities from user ${userId}`,
          events: userEvents,
          user_id: userId
        });
      }
    }

    return patterns;
  }

  // Send pattern-based alert
  private static async sendPatternAlert(pattern: any): Promise<void> {
    console.warn(`[SECURITY PATTERN] ${pattern.type}: ${pattern.description}`);

    // TODO: Send to security monitoring system
  }

  // Group array by key
  private static groupBy<T>(array: T[], key: keyof T): Record<string, T[]> {
    return array.reduce((groups, item) => {
      const groupKey = String(item[key]);
      if (!groups[groupKey]) {
        groups[groupKey] = [];
      }
      groups[groupKey].push(item);
      return groups;
    }, {} as Record<string, T[]>);
  }

  // Check if IP is suspicious
  static async isSuspiciousIP(ipAddress: string): Promise<boolean> {
    try {
      // Check against known malicious IPs (in production, use threat intelligence feeds)
      const recentEvents = await this.getRecentEventsForIP(ipAddress, 24 * 60 * 60 * 1000); // 24 hours

      const suspiciousCount = recentEvents.filter(event =>
        [SecurityEventType.FAILED_LOGIN, SecurityEventType.UNAUTHORIZED_ACCESS, SecurityEventType.SUSPICIOUS_ACTIVITY].includes(event.event_type)
      ).length;

      return suspiciousCount >= 3;
    } catch (error) {
      console.error('Error checking suspicious IP:', error);
      return false;
    }
  }

  // Get recent events for IP
  private static async getRecentEventsForIP(ipAddress: string, timeWindowMs: number): Promise<SecurityEvent[]> {
    try {
      const cutoffTime = new Date(Date.now() - timeWindowMs).toISOString();

      const { data, error } = await supabase
        .from('security_events')
        .select('*')
        .eq('ip_address', ipAddress)
        .gte('timestamp', cutoffTime)
        .order('timestamp', { ascending: false });

      if (error) {
        console.error('Failed to get recent events for IP:', error);
        return [];
      }

      return data || [];
    } catch (error) {
      console.error('Error getting recent events for IP:', error);
      return [];
    }
  }

  // Get security dashboard data
  static async getSecurityDashboard(): Promise<any> {
    try {
      const now = new Date();
      const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
      const last7d = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();

      // Get event counts
      const { data: events24h, error: error24h } = await supabase
        .from('security_events')
        .select('event_type, severity')
        .gte('timestamp', last24h);

      const { data: events7d, error: error7d } = await supabase
        .from('security_events')
        .select('event_type, severity')
        .gte('timestamp', last7d);

      if (error24h || error7d) {
        console.error('Failed to get security dashboard data');
        return null;
      }

      // Calculate statistics
      const stats24h = this.calculateEventStats(events24h || []);
      const stats7d = this.calculateEventStats(events7d || []);

      return {
        last24Hours: stats24h,
        last7Days: stats7d,
        topThreats: await this.getTopThreats(),
        recentEvents: await this.getRecentSecurityEvents(10)
      };
    } catch (error) {
      console.error('Error getting security dashboard:', error);
      return null;
    }
  }

  // Calculate event statistics
  private static calculateEventStats(events: any[]): any {
    const stats = {
      total: events.length,
      byType: {} as Record<string, number>,
      bySeverity: {} as Record<string, number>,
      criticalCount: 0,
      highCount: 0
    };

    events.forEach(event => {
      // Count by type
      stats.byType[event.event_type] = (stats.byType[event.event_type] || 0) + 1;

      // Count by severity
      stats.bySeverity[event.severity] = (stats.bySeverity[event.severity] || 0) + 1;

      // Count critical/high
      if (event.severity === SecuritySeverity.CRITICAL) stats.criticalCount++;
      if (event.severity === SecuritySeverity.HIGH) stats.highCount++;
    });

    return stats;
  }

  // Get top threats
  private static async getTopThreats(): Promise<any[]> {
    try {
      const last7d = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();

      // Note: Supabase doesn't support GROUP BY in the same way as raw SQL
      // This would need to be implemented differently or use a view
      const { data, error } = await supabase
        .from('security_events')
        .select('ip_address, event_type')
        .gte('timestamp', last7d);

      if (error) {
        console.error('Failed to get top threats:', error);
        return [];
      }

      // Manual grouping (simplified)
      const threatCounts: Record<string, number> = {};
      (data || []).forEach(event => {
        const key = `${event.ip_address}:${event.event_type}`;
        threatCounts[key] = (threatCounts[key] || 0) + 1;
      });

      return Object.entries(threatCounts)
        .map(([key, count]) => {
          const [ip, type] = key.split(':');
          return { ip_address: ip, event_type: type, count };
        })
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);

      if (error) {
        console.error('Failed to get top threats:', error);
        return [];
      }

      return data || [];
    } catch (error) {
      console.error('Error getting top threats:', error);
      return [];
    }
  }

  // Get recent security events
  private static async getRecentSecurityEvents(limit: number): Promise<SecurityEvent[]> {
    try {
      const { data, error } = await supabase
        .from('security_events')
        .select('*')
        .order('timestamp', { ascending: false })
        .limit(limit);

      if (error) {
        console.error('Failed to get recent security events:', error);
        return [];
      }

      return data || [];
    } catch (error) {
      console.error('Error getting recent security events:', error);
      return [];
    }
  }
}

// Security monitoring middleware
export const securityMonitoring = () => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const startTime = Date.now();
    const originalSend = res.send;
    let responseSent = false;

    // Override res.send to capture response
    res.send = function(data: any) {
      responseSent = true;
      return originalSend.call(this, data);
    };

    // Monitor after response
    res.on('finish', async () => {
      try {
        const responseTime = Date.now() - startTime;
        const ipAddress = req.ip || req.connection.remoteAddress || '';
        const userAgent = req.get('User-Agent') || '';

        // Check for suspicious patterns
        if (responseTime > 30000) { // Very slow response
          await SecurityMonitor.logSecurityEvent(
            SecurityEventType.SUSPICIOUS_ACTIVITY,
            SecuritySeverity.LOW,
            { reason: 'slow_response', responseTime },
            req.user?.id,
            ipAddress,
            userAgent
          );
        }

        // Check for unauthorized access attempts
        if (res.statusCode === 401 || res.statusCode === 403) {
          await SecurityMonitor.logSecurityEvent(
            SecurityEventType.UNAUTHORIZED_ACCESS,
            SecuritySeverity.MEDIUM,
            {
              url: req.url,
              method: req.method,
              statusCode: res.statusCode
            },
            req.user?.id,
            ipAddress,
            userAgent
          );
        }

        // Check for potential data exfiltration
        if (req.method === 'GET' && res.get('Content-Length') &&
            parseInt(res.get('Content-Length')!) > 10000000) { // 10MB
          await SecurityMonitor.logSecurityEvent(
            SecurityEventType.SUSPICIOUS_ACTIVITY,
            SecuritySeverity.MEDIUM,
            {
              reason: 'large_response',
              contentLength: res.get('Content-Length'),
              url: req.url
            },
            req.user?.id,
            ipAddress,
            userAgent
          );
        }

      } catch (error) {
        console.error('Security monitoring error:', error);
      }
    });

    next();
  };
};

// Suspicious activity detection
export const detectSuspiciousActivity = () => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const ipAddress = req.ip || req.connection.remoteAddress || '';
    const userAgent = req.get('User-Agent') || '';

    // Check if IP is suspicious
    const isSuspiciousIP = await SecurityMonitor.isSuspiciousIP(ipAddress);
    if (isSuspiciousIP) {
      await SecurityMonitor.logSecurityEvent(
        SecurityEventType.SUSPICIOUS_IP,
        SecuritySeverity.HIGH,
        { reason: 'suspicious_ip_detected' },
        req.user?.id,
        ipAddress,
        userAgent
      );
    }

    // Check for unusual request patterns
    const suspiciousPatterns = [
      /\.\./,  // Directory traversal
      /<script/i,  // XSS attempts
      /union.*select/i,  // SQL injection
      /eval\(/i,  // Code injection
      /base64/i  // Potential encoded attacks
    ];

    const requestData = JSON.stringify({
      url: req.url,
      query: req.query,
      body: req.body,
      headers: req.headers
    });

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(requestData)) {
        await SecurityMonitor.logSecurityEvent(
          SecurityEventType.SUSPICIOUS_ACTIVITY,
          SecuritySeverity.HIGH,
          {
            reason: 'suspicious_pattern_detected',
            pattern: pattern.source,
            url: req.url
          },
          req.user?.id,
          ipAddress,
          userAgent
        );
        break;
      }
    }

    next();
  };
};