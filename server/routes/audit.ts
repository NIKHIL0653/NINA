import { Router } from 'express';
import { requireRole } from '../middleware/auth';
import { getAuditLogs, getUserAuditLogs, exportAuditLog } from '../middleware/audit';

const router = Router();

// Get audit logs for current user
router.get('/user', getUserAuditLogs);

// Admin routes (require admin role in production)
router.get('/', requireRole(['admin']), getAuditLogs);
router.get('/export', requireRole(['admin']), exportAuditLog);

export { router as auditRoutes };