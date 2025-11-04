import { Request, Response, NextFunction } from 'express';
import { AuthenticatedRequest } from './auth';
import { supabase } from '@shared/supabase';

// Privacy settings categories
export enum PrivacyCategory {
  PROFILE_VISIBILITY = 'profile_visibility',
  MEDICAL_DATA_SHARING = 'medical_data_sharing',
  CONTACT_PREFERENCES = 'contact_preferences',
  ANALYTICS_OPT_IN = 'analytics_opt_in',
  MARKETING_OPT_IN = 'marketing_opt_in',
  RESEARCH_PARTICIPATION = 'research_participation',
  EMERGENCY_ACCESS = 'emergency_access',
  DATA_RETENTION = 'data_retention',
  AUDIT_LOG_ACCESS = 'audit_log_access'
}

// Privacy setting levels
export enum PrivacyLevel {
  PUBLIC = 'public',
  HEALTHCARE_PROVIDERS = 'healthcare_providers',
  EMERGENCY_CONTACTS = 'emergency_contacts',
  PRIVATE = 'private'
}

// Privacy settings interface
interface PrivacySettings {
  user_id: string;
  category: PrivacyCategory;
  level: PrivacyLevel;
  allowed_users?: string[]; // Specific user IDs
  allowed_roles?: string[]; // Specific roles
  restrictions?: {
    exclude_fields?: string[];
    time_restrictions?: {
      start_time?: string;
      end_time?: string;
      days_of_week?: number[];
    };
    geographic_restrictions?: string[];
  };
  updated_at: string;
  updated_by: string;
}

// Privacy controls class
export class PrivacyManager {
  // Default privacy settings for new users
  private static readonly DEFAULT_SETTINGS: Record<PrivacyCategory, PrivacyLevel> = {
    [PrivacyCategory.PROFILE_VISIBILITY]: PrivacyLevel.PRIVATE,
    [PrivacyCategory.MEDICAL_DATA_SHARING]: PrivacyLevel.HEALTHCARE_PROVIDERS,
    [PrivacyCategory.CONTACT_PREFERENCES]: PrivacyLevel.PRIVATE,
    [PrivacyCategory.ANALYTICS_OPT_IN]: PrivacyLevel.PRIVATE,
    [PrivacyCategory.MARKETING_OPT_IN]: PrivacyLevel.PRIVATE,
    [PrivacyCategory.RESEARCH_PARTICIPATION]: PrivacyLevel.PRIVATE,
    [PrivacyCategory.EMERGENCY_ACCESS]: PrivacyLevel.EMERGENCY_CONTACTS,
    [PrivacyCategory.DATA_RETENTION]: PrivacyLevel.PRIVATE,
    [PrivacyCategory.AUDIT_LOG_ACCESS]: PrivacyLevel.PRIVATE
  };

  // Get user's privacy settings
  static async getPrivacySettings(userId: string): Promise<Record<PrivacyCategory, PrivacySettings>> {
    try {
      const { data, error } = await supabase
        .from('user_privacy_settings')
        .select('*')
        .eq('user_id', userId);

      if (error) {
        console.error('Failed to get privacy settings:', error);
        return this.getDefaultSettings(userId);
      }

      // Convert array to object keyed by category
      const settings: Record<PrivacyCategory, PrivacySettings> = { ...this.getDefaultSettings(userId) };

      (data || []).forEach(setting => {
        settings[setting.category] = setting;
      });

      return settings;
    } catch (error) {
      console.error('Error getting privacy settings:', error);
      return this.getDefaultSettings(userId);
    }
  }

  // Update privacy setting
  static async updatePrivacySetting(
    userId: string,
    category: PrivacyCategory,
    level: PrivacyLevel,
    additionalOptions?: {
      allowedUsers?: string[];
      allowedRoles?: string[];
      restrictions?: PrivacySettings['restrictions'];
    }
  ): Promise<boolean> {
    try {
      const setting: Omit<PrivacySettings, 'updated_at'> = {
        user_id: userId,
        category,
        level,
        allowed_users: additionalOptions?.allowedUsers,
        allowed_roles: additionalOptions?.allowedRoles,
        restrictions: additionalOptions?.restrictions,
        updated_by: userId
      };

      const { error } = await supabase
        .from('user_privacy_settings')
        .upsert(setting, {
          onConflict: 'user_id,category'
        });

      if (error) {
        console.error('Failed to update privacy setting:', error);
        return false;
      }

      return true;
    } catch (error) {
      console.error('Error updating privacy setting:', error);
      return false;
    }
  }

  // Check if access is allowed based on privacy settings
  static async checkAccess(
    targetUserId: string,
    requestingUserId: string,
    requestingUserRole: string,
    category: PrivacyCategory,
    context?: {
      field?: string;
      time?: Date;
      location?: string;
    }
  ): Promise<{ allowed: boolean; reason?: string }> {
    try {
      const settings = await this.getPrivacySettings(targetUserId);
      const setting = settings[category];

      if (!setting) {
        return { allowed: false, reason: 'No privacy setting found' };
      }

      // Check time restrictions
      if (setting.restrictions?.time_restrictions && context?.time) {
        const timeAllowed = this.checkTimeRestrictions(setting.restrictions.time_restrictions, context.time);
        if (!timeAllowed) {
          return { allowed: false, reason: 'Access restricted by time settings' };
        }
      }

      // Check field restrictions
      if (setting.restrictions?.exclude_fields && context?.field) {
        if (setting.restrictions.exclude_fields.includes(context.field)) {
          return { allowed: false, reason: 'Field access restricted' };
        }
      }

      // Check geographic restrictions
      if (setting.restrictions?.geographic_restrictions && context?.location) {
        if (setting.restrictions.geographic_restrictions.includes(context.location)) {
          return { allowed: false, reason: 'Geographic access restricted' };
        }
      }

      // Check privacy level
      switch (setting.level) {
        case PrivacyLevel.PUBLIC:
          return { allowed: true };

        case PrivacyLevel.HEALTHCARE_PROVIDERS:
          if (requestingUserRole === 'healthcare_provider' || requestingUserRole === 'admin') {
            return { allowed: true };
          }
          break;

        case PrivacyLevel.EMERGENCY_CONTACTS:
          // Check if requesting user is an emergency contact
          const isEmergencyContact = await this.isEmergencyContact(targetUserId, requestingUserId);
          if (isEmergencyContact) {
            return { allowed: true };
          }
          break;

        case PrivacyLevel.PRIVATE:
          // Only allow access to own data
          if (targetUserId === requestingUserId) {
            return { allowed: true };
          }
          break;
      }

      // Check specific allowed users/roles
      if (setting.allowed_users?.includes(requestingUserId)) {
        return { allowed: true };
      }

      if (setting.allowed_roles?.includes(requestingUserRole)) {
        return { allowed: true };
      }

      return { allowed: false, reason: 'Access denied by privacy settings' };
    } catch (error) {
      console.error('Error checking privacy access:', error);
      return { allowed: false, reason: 'Privacy check failed' };
    }
  }

  // Check if user is an emergency contact
  private static async isEmergencyContact(targetUserId: string, requestingUserId: string): Promise<boolean> {
    try {
      const { data, error } = await supabase
        .from('emergency_contacts')
        .select('id')
        .eq('user_id', targetUserId)
        .eq('contact_user_id', requestingUserId) // Assuming we store user IDs for contacts
        .limit(1);

      return !error && (data?.length || 0) > 0;
    } catch (error) {
      console.error('Error checking emergency contact:', error);
      return false;
    }
  }

  // Check time-based restrictions
  private static checkTimeRestrictions(timeRestrictions: any, currentTime: Date): boolean {
    if (timeRestrictions.start_time && timeRestrictions.end_time) {
      const start = new Date(`1970-01-01T${timeRestrictions.start_time}`);
      const end = new Date(`1970-01-01T${timeRestrictions.end_time}`);
      const now = new Date(`1970-01-01T${currentTime.toTimeString().split(' ')[0]}`);

      if (now < start || now > end) {
        return false;
      }
    }

    if (timeRestrictions.days_of_week) {
      const currentDay = currentTime.getDay(); // 0 = Sunday, 6 = Saturday
      if (!timeRestrictions.days_of_week.includes(currentDay)) {
        return false;
      }
    }

    return true;
  }

  // Get default settings
  private static getDefaultSettings(userId: string): Record<PrivacyCategory, PrivacySettings> {
    const settings: Record<PrivacyCategory, PrivacySettings> = {} as any;

    Object.entries(this.DEFAULT_SETTINGS).forEach(([category, level]) => {
      settings[category as PrivacyCategory] = {
        user_id: userId,
        category: category as PrivacyCategory,
        level,
        updated_at: new Date().toISOString(),
        updated_by: 'system'
      };
    });

    return settings;
  }

  // Bulk update privacy settings
  static async bulkUpdateSettings(
    userId: string,
    updates: Array<{
      category: PrivacyCategory;
      level: PrivacyLevel;
      allowedUsers?: string[];
      allowedRoles?: string[];
      restrictions?: PrivacySettings['restrictions'];
    }>
  ): Promise<{ success: boolean; updated: number; failed: number }> {
    let updated = 0;
    let failed = 0;

    for (const update of updates) {
      try {
        const success = await this.updatePrivacySetting(
          userId,
          update.category,
          update.level,
          {
            allowedUsers: update.allowedUsers,
            allowedRoles: update.allowedRoles,
            restrictions: update.restrictions
          }
        );

        if (success) {
          updated++;
        } else {
          failed++;
        }
      } catch (error) {
        console.error(`Failed to update ${update.category}:`, error);
        failed++;
      }
    }

    return { success: failed === 0, updated, failed };
  }

  // Reset to default settings
  static async resetToDefaults(userId: string): Promise<boolean> {
    try {
      // Delete all existing settings
      await supabase
        .from('user_privacy_settings')
        .delete()
        .eq('user_id', userId);

      // The getPrivacySettings method will return defaults when none exist
      return true;
    } catch (error) {
      console.error('Error resetting privacy settings:', error);
      return false;
    }
  }
}

// Privacy middleware
export const enforcePrivacy = (category: PrivacyCategory, context?: any) => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      // Extract target user ID from request
      const targetUserId = req.params.userId || req.params.id || req.user.id;

      const accessCheck = await PrivacyManager.checkAccess(
        targetUserId,
        req.user.id,
        req.user.role || 'patient',
        category,
        {
          field: req.params.field,
          time: new Date(),
          location: req.get('CF-IPCountry') || req.get('X-Forwarded-For')?.split(',')[0]
        }
      );

      if (!accessCheck.allowed) {
        return res.status(403).json({
          error: 'Privacy Restriction',
          message: accessCheck.reason || 'Access denied by privacy settings',
          category
        });
      }

      next();
    } catch (error) {
      console.error('Privacy enforcement error:', error);
      return res.status(500).json({
        error: 'Internal Server Error',
        message: 'Privacy check failed'
      });
    }
  };
};

// Data filtering based on privacy settings
export const filterDataByPrivacy = (category: PrivacyCategory) => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const originalJson = res.json;

    res.json = function(data: any) {
      // Apply privacy filtering to response data
      const filteredData = filterDataForPrivacy(data, req.user?.id || '', category);
      return originalJson.call(this, filteredData);
    };

    next();
  };
};

// Data filtering function
function filterDataForPrivacy(data: any, requestingUserId: string, category: PrivacyCategory): any {
  // Implement data filtering logic based on privacy settings
  // This would recursively filter object properties based on privacy rules
  return data; // Placeholder - implement actual filtering
}