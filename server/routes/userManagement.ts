import { Router } from 'express';
import { requireRole, ROLES, AuthenticatedRequest } from '../middleware/auth';
import { RoleManager } from '../middleware/roleManager';
import { auditMiddleware } from '../middleware/audit';

const router = Router();

// Get all users (admin only)
router.get('/users',
  requireRole([ROLES.ADMIN]),
  auditMiddleware('LIST', 'user_management'),
  async (req: AuthenticatedRequest, res) => {
    try {
      const users = await RoleManager.getAllUsersWithRoles();

      res.json({
        success: true,
        data: users
      });
    } catch (error) {
      console.error('Failed to get users:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve users'
      });
    }
  }
);

// Update user role (admin only)
router.put('/users/:userId/role',
  requireRole([ROLES.ADMIN]),
  auditMiddleware('UPDATE', 'user_management'),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { userId } = req.params;
      const { role } = req.body;

      if (!role || !Object.values(ROLES).includes(role)) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid role specified'
        });
      }

      if (!req.user?.id) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Admin authentication required'
        });
      }

      // Validate role transition
      const currentRole = await RoleManager.getUserRole(userId);
      if (currentRole && !RoleManager.validateRoleTransition(currentRole, role)) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid role transition'
        });
      }

      const success = await RoleManager.setUserRole(userId, role, req.user.id);

      if (!success) {
        return res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to update user role'
        });
      }

      res.json({
        success: true,
        message: 'User role updated successfully',
        data: { userId, role }
      });
    } catch (error) {
      console.error('Failed to update user role:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to update user role'
      });
    }
  }
);

// Get user permissions
router.get('/permissions',
  async (req: AuthenticatedRequest, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      const permissions = {
        role: req.user.role,
        canAccessMedicalRecords: RoleManager.hasPermission(req.user.role as any, 'read', 'medical_records'),
        canCreateMedicalRecords: RoleManager.hasPermission(req.user.role as any, 'create', 'medical_records'),
        canUpdateMedicalRecords: RoleManager.hasPermission(req.user.role as any, 'update', 'medical_records'),
        canDeleteMedicalRecords: RoleManager.hasPermission(req.user.role as any, 'delete', 'medical_records'),
        canAccessPrescriptions: RoleManager.hasPermission(req.user.role as any, 'read', 'prescriptions'),
        canCreatePrescriptions: RoleManager.hasPermission(req.user.role as any, 'create', 'prescriptions'),
        canAccessEmergencyContacts: RoleManager.hasPermission(req.user.role as any, 'read', 'emergency_contacts'),
        canCreateEmergencyContacts: RoleManager.hasPermission(req.user.role as any, 'create', 'emergency_contacts'),
        canAccessAppointments: RoleManager.hasPermission(req.user.role as any, 'read', 'appointments'),
        canCreateAppointments: RoleManager.hasPermission(req.user.role as any, 'create', 'appointments'),
        canAccessAuditLogs: RoleManager.hasPermission(req.user.role as any, 'read', 'audit_logs'),
        canManageUsers: RoleManager.hasPermission(req.user.role as any, 'read', 'user_management'),
        isAdmin: req.user.role === ROLES.ADMIN,
        isHealthcareProvider: req.user.role === ROLES.HEALTHCARE_PROVIDER,
        isPatient: req.user.role === ROLES.PATIENT
      };

      res.json({
        success: true,
        data: permissions
      });
    } catch (error) {
      console.error('Failed to get permissions:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve permissions'
      });
    }
  }
);

export { router as userManagementRoutes };