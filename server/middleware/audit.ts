import { Request, Response, NextFunction } from 'express';
import { AuthenticatedRequest } from './auth';
import { supabase } from '@shared/supabase';

// Audit log entry interface
interface AuditEntry {
  id?: string;
  timestamp: string;
  userId?: string;
  userRole?: string;
  action: string;
  resource: string;
  resourceId?: string;
  method: string;
  ip: string;
  userAgent: string;
  success: boolean;
  details?: any;
  error?: string;
  sessionId?: string;
  location?: string;
  deviceInfo?: any;
}

// Audit log storage (in production, use database)
class AuditLogger {
  private static instance: AuditLogger;
  private auditBuffer: AuditEntry[] = [];
  private readonly BATCH_SIZE = 10; // Batch size for database writes
  private readonly FLUSH_INTERVAL = 30000; // 30 seconds

  private constructor() {
    // Auto-flush buffer periodically
    setInterval(() => this.flushBuffer(), this.FLUSH_INTERVAL);
  }

  static getInstance(): AuditLogger {
    if (!AuditLogger.instance) {
      AuditLogger.instance = new AuditLogger();
    }
    return AuditLogger.instance;
  }

  async log(entry: Omit<AuditEntry, 'id'>): Promise<void> {
    const auditEntry: AuditEntry = {
      ...entry,
      id: require('crypto').randomUUID()
    };

    this.auditBuffer.push(auditEntry);

    // Flush if buffer is full
    if (this.auditBuffer.length >= this.BATCH_SIZE) {
      await this.flushBuffer();
    }
  }

  private async flushBuffer(): Promise<void> {
    if (this.auditBuffer.length === 0) return;

    try {
      const entries = [...this.auditBuffer];
      this.auditBuffer = [];

      // Insert into database
      const { error } = await supabase
        .from('audit_logs')
        .insert(entries.map(entry => ({
          id: entry.id,
          timestamp: entry.timestamp,
          user_id: entry.userId,
          user_role: entry.userRole,
          action: entry.action,
          resource: entry.resource,
          resource_id: entry.resourceId,
          method: entry.method,
          ip: entry.ip,
          user_agent: entry.userAgent,
          success: entry.success,
          details: entry.details,
          error: entry.error,
          session_id: entry.sessionId,
          location: entry.location,
          device_info: entry.deviceInfo
        })));

      if (error) {
        console.error('Failed to save audit logs:', error);
        // Re-queue failed entries
        this.auditBuffer.unshift(...entries);
      }
    } catch (error) {
      console.error('Audit logging error:', error);
      // Keep entries in buffer for retry
    }
  }

  async query(options: {
    userId?: string;
    resource?: string;
    action?: string;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
    offset?: number;
  }): Promise<{ logs: AuditEntry[]; total: number }> {
    try {
      let query = supabase
        .from('audit_logs')
        .select('*', { count: 'exact' });

      if (options.userId) {
        query = query.eq('user_id', options.userId);
      }
      if (options.resource) {
        query = query.eq('resource', options.resource);
      }
      if (options.action) {
        query = query.eq('action', options.action);
      }
      if (options.startDate) {
        query = query.gte('timestamp', options.startDate.toISOString());
      }
      if (options.endDate) {
        query = query.lte('timestamp', options.endDate.toISOString());
      }

      query = query
        .order('timestamp', { ascending: false })
        .range(options.offset || 0, (options.offset || 0) + (options.limit || 100) - 1);

      const { data, error, count } = await query;

      if (error) {
        console.error('Audit query error:', error);
        return { logs: [], total: 0 };
      }

      const logs: AuditEntry[] = (data || []).map(row => ({
        id: row.id,
        timestamp: row.timestamp,
        userId: row.user_id,
        userRole: row.user_role,
        action: row.action,
        resource: row.resource,
        resourceId: row.resource_id,
        method: row.method,
        ip: row.ip,
        userAgent: row.user_agent,
        success: row.success,
        details: row.details,
        error: row.error,
        sessionId: row.session_id,
        location: row.location,
        deviceInfo: row.device_info
      }));

      return { logs, total: count || 0 };
    } catch (error) {
      console.error('Audit query failed:', error);
      return { logs: [], total: 0 };
    }
  }
}

const auditLogger = AuditLogger.getInstance();

// Helper functions for audit logging
function sanitizeBodyForAudit(body: any): any {
  if (!body || typeof body !== 'object') return body;

  const sanitized = { ...body };

  // Remove sensitive fields from audit
  const sensitiveFields = ['password', 'token', 'secret', 'key', 'ssn', 'credit_card'];
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  });

  // Limit body size for audit logs
  const bodyString = JSON.stringify(sanitized);
  if (bodyString.length > 1000) {
    return { truncated: true, size: bodyString.length };
  }

  return sanitized;
}

function extractDeviceInfo(req: Request): any {
  const userAgent = req.get('User-Agent') || '';

  return {
    userAgent,
    platform: req.get('Sec-Ch-Ua-Platform') || 'unknown',
    mobile: /mobile/i.test(userAgent),
    browser: extractBrowser(userAgent),
    os: extractOS(userAgent)
  };
}

function extractLocationInfo(req: Request): string {
  // In production, use IP geolocation service
  // For now, return IP-based location hint
  const ip = req.ip || req.connection.remoteAddress || '';
  return ip ? `IP: ${ip}` : 'unknown';
}

function extractBrowser(userAgent: string): string {
  if (userAgent.includes('Chrome')) return 'Chrome';
  if (userAgent.includes('Firefox')) return 'Firefox';
  if (userAgent.includes('Safari')) return 'Safari';
  if (userAgent.includes('Edge')) return 'Edge';
  return 'unknown';
}

function extractOS(userAgent: string): string {
  if (userAgent.includes('Windows')) return 'Windows';
  if (userAgent.includes('Mac')) return 'macOS';
  if (userAgent.includes('Linux')) return 'Linux';
  if (userAgent.includes('Android')) return 'Android';
  if (userAgent.includes('iOS')) return 'iOS';
  return 'unknown';
}

// Audit middleware
export const auditMiddleware = (action: string, resource: string) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const startTime = Date.now();
    const originalSend = res.send;
    let responseSent = false;

    // Override res.send to capture response
    res.send = function(data: any) {
      responseSent = true;
      return originalSend.call(this, data);
    };

    // Log after response is sent
    res.on('finish', async () => {
      const auditEntry: Omit<AuditEntry, 'id'> = {
        timestamp: new Date().toISOString(),
        userId: req.user?.id,
        userRole: req.user?.role,
        action,
        resource,
        resourceId: req.params.id || req.params.recordId,
        method: req.method,
        ip: req.ip || req.connection.remoteAddress || '',
        userAgent: req.get('User-Agent') || '',
        success: res.statusCode >= 200 && res.statusCode < 400,
        sessionId: req.user?.sessionId,
        details: {
          url: req.url,
          query: req.query,
          body: sanitizeBodyForAudit(req.body),
          responseTime: Date.now() - startTime,
          statusCode: res.statusCode,
          contentLength: res.get('Content-Length')
        },
        deviceInfo: extractDeviceInfo(req),
        location: extractLocationInfo(req)
      };

      // Add error details if request failed
      if (!auditEntry.success && res.statusCode >= 400) {
        auditEntry.error = `HTTP ${res.statusCode}`;
      }

      // Log to database
      await auditLogger.log(auditEntry);

      // Log HIPAA-relevant actions to console
      if (isHIPAASensitive(resource, action)) {
        console.log(`[HIPAA AUDIT] ${auditEntry.timestamp} - User: ${auditEntry.userId} (${auditEntry.userRole}) - ${auditEntry.action} ${auditEntry.resource}${auditEntry.resourceId ? `:${auditEntry.resourceId}` : ''} - Success: ${auditEntry.success}`);
      }
    });

    next();
  };
};

// Check if action is HIPAA-sensitive
function isHIPAASensitive(resource: string, action: string): boolean {
  const sensitiveResources = [
    'medical-records',
    'prescriptions',
    'medical-history',
    'vital-signs',
    'health-profile'
  ];

  const sensitiveActions = [
    'CREATE',
    'READ',
    'UPDATE',
    'DELETE'
  ];

  return sensitiveResources.includes(resource) && sensitiveActions.includes(action.toUpperCase());
}

// Get audit logs (admin only)
export const getAuditLogs = async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { userId, resource, action, limit = 100, offset = 0, startDate, endDate } = req.query;

  try {
    const options: any = {
      limit: parseInt(limit as string),
      offset: parseInt(offset as string)
    };

    if (userId) options.userId = userId;
    if (resource) options.resource = resource;
    if (action) options.action = action;
    if (startDate) options.startDate = new Date(startDate as string);
    if (endDate) options.endDate = new Date(endDate as string);

    const { logs, total } = await auditLogger.query(options);

    res.json({
      success: true,
      data: logs,
      total,
      limit: options.limit,
      offset: options.offset
    });
  } catch (error) {
    console.error('Failed to get audit logs:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve audit logs'
    });
  }
};

// Get audit logs for current user
export const getUserAuditLogs = async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const { logs } = await auditLogger.query({
      userId: req.user.id,
      limit: 50
    });

    res.json({
      success: true,
      data: logs
    });
  } catch (error) {
    console.error('Failed to get user audit logs:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve audit logs'
    });
  }
};

// Export audit log for compliance (CSV format)
export const exportAuditLog = async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const { startDate, endDate, userId, resource } = req.query;

    const options: any = {
      limit: 10000 // Export up to 10k records
    };

    if (userId) options.userId = userId;
    if (resource) options.resource = resource;
    if (startDate) options.startDate = new Date(startDate as string);
    if (endDate) options.endDate = new Date(endDate as string);

    const { logs } = await auditLogger.query(options);

    const csvHeader = 'Timestamp,User ID,User Role,Action,Resource,Resource ID,Method,IP,User Agent,Success,Session ID,Location,Details\n';
    const csvRows = logs.map(entry =>
      `"${entry.timestamp}","${entry.userId}","${entry.userRole}","${entry.action}","${entry.resource}","${entry.resourceId}","${entry.method}","${entry.ip}","${entry.userAgent}","${entry.success}","${entry.sessionId}","${entry.location}","${JSON.stringify(entry.details).replace(/"/g, '""')}"`
    ).join('\n');

    const csv = csvHeader + csvRows;

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="audit-log-${new Date().toISOString().split('T')[0]}.csv"`);
    res.send(csv);
  } catch (error) {
    console.error('Failed to export audit log:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to export audit log'
    });
  }
};