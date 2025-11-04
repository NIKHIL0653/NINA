import { supabase } from '@shared/supabase';
import { ROLES, UserRole } from './auth';

// Role management utilities
export class RoleManager {
  // Get user role from database
  static async getUserRole(userId: string): Promise<UserRole | null> {
    try {
      const { data, error } = await supabase
        .from('profiles')
        .select('role')
        .eq('id', userId)
        .single();

      if (error || !data) {
        console.warn('Failed to get user role:', error?.message);
        return null;
      }

      return data.role as UserRole;
    } catch (error) {
      console.error('Error getting user role:', error);
      return null;
    }
  }

  // Set user role (admin only)
  static async setUserRole(userId: string, role: UserRole, adminUserId: string): Promise<boolean> {
    try {
      // Verify admin has permission
      const adminRole = await this.getUserRole(adminUserId);
      if (adminRole !== ROLES.ADMIN) {
        throw new Error('Insufficient permissions to set user role');
      }

      const { error } = await supabase
        .from('profiles')
        .update({
          role,
          updated_at: new Date().toISOString()
        })
        .eq('id', userId);

      if (error) {
        console.error('Failed to set user role:', error);
        return false;
      }

      return true;
    } catch (error) {
      console.error('Error setting user role:', error);
      return false;
    }
  }

  // Initialize user profile with default role
  static async initializeUserProfile(userId: string, email: string, fullName?: string): Promise<UserRole> {
    try {
      // Check if profile already exists
      const { data: existingProfile } = await supabase
        .from('profiles')
        .select('role')
        .eq('id', userId)
        .single();

      if (existingProfile) {
        return existingProfile.role as UserRole;
      }

      // Create new profile with default role
      const defaultRole = ROLES.PATIENT;
      const { error } = await supabase
        .from('profiles')
        .insert({
          id: userId,
          email,
          full_name: fullName,
          role: defaultRole,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        });

      if (error) {
        console.error('Failed to create user profile:', error);
        throw error;
      }

      return defaultRole;
    } catch (error) {
      console.error('Error initializing user profile:', error);
      throw error;
    }
  }

  // Validate role transition (business logic rules)
  static validateRoleTransition(currentRole: UserRole, newRole: UserRole): boolean {
    // Define allowed transitions
    const allowedTransitions: Record<UserRole, UserRole[]> = {
      [ROLES.PATIENT]: [ROLES.HEALTHCARE_PROVIDER], // Patients can become providers
      [ROLES.HEALTHCARE_PROVIDER]: [ROLES.PATIENT, ROLES.ADMIN], // Providers can become patients or admins
      [ROLES.ADMIN]: [ROLES.HEALTHCARE_PROVIDER, ROLES.PATIENT] // Admins can become providers or patients
    };

    return allowedTransitions[currentRole]?.includes(newRole) || false;
  }

  // Get all users with their roles (admin only)
  static async getAllUsersWithRoles(): Promise<Array<{id: string, email: string, role: UserRole, created_at: string}>> {
    try {
      const { data, error } = await supabase
        .from('profiles')
        .select('id, email, role, created_at')
        .order('created_at', { ascending: false });

      if (error) {
        console.error('Failed to get users with roles:', error);
        return [];
      }

      return data || [];
    } catch (error) {
      console.error('Error getting users with roles:', error);
      return [];
    }
  }

  // Check if user has permission for action on resource
  static hasPermission(userRole: UserRole, action: string, resource: string): boolean {
    // Define permissions matrix
    const permissions: Record<UserRole, Record<string, string[]>> = {
      [ROLES.PATIENT]: {
        'medical_records': ['read', 'create'],
        'prescriptions': ['read'],
        'emergency_contacts': ['read', 'create', 'update', 'delete'],
        'appointments': ['read', 'create', 'update'],
        'vital_signs': ['read', 'create'],
        'health_profile': ['read', 'update']
      },
      [ROLES.HEALTHCARE_PROVIDER]: {
        'medical_records': ['read', 'create', 'update'],
        'prescriptions': ['read', 'create', 'update'],
        'emergency_contacts': ['read'],
        'appointments': ['read', 'create', 'update', 'delete'],
        'vital_signs': ['read', 'create', 'update'],
        'health_profile': ['read', 'update'],
        'audit_logs': ['read']
      },
      [ROLES.ADMIN]: {
        'medical_records': ['read', 'create', 'update', 'delete'],
        'prescriptions': ['read', 'create', 'update', 'delete'],
        'emergency_contacts': ['read', 'create', 'update', 'delete'],
        'appointments': ['read', 'create', 'update', 'delete'],
        'vital_signs': ['read', 'create', 'update', 'delete'],
        'health_profile': ['read', 'create', 'update', 'delete'],
        'audit_logs': ['read', 'create', 'update', 'delete'],
        'user_management': ['read', 'create', 'update', 'delete']
      }
    };

    const rolePermissions = permissions[userRole];
    if (!rolePermissions) return false;

    const resourcePermissions = rolePermissions[resource];
    if (!resourcePermissions) return false;

    return resourcePermissions.includes(action.toLowerCase());
  }
}