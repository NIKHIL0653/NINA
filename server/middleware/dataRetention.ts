import { supabase } from '@shared/supabase';

// Data retention policies (HIPAA compliant)
export class DataRetentionManager {
  // Retention periods in days (based on HIPAA guidelines)
  private static readonly RETENTION_POLICIES = {
    // Medical records: 7 years after last patient encounter
    medical_records: 7 * 365,

    // Audit logs: 7 years minimum
    audit_logs: 7 * 365,

    // User profiles: Retain while account active + 7 years
    user_profiles: 7 * 365,

    // Chat history: 7 years
    chat_history: 7 * 365,

    // Emergency contacts: 7 years after last update
    emergency_contacts: 7 * 365,

    // Prescriptions: 7 years
    prescriptions: 7 * 365,

    // Appointments: 7 years
    appointments: 7 * 365,

    // Vital signs: 7 years
    vital_signs: 7 * 365,

    // Medical history: 7 years
    medical_history: 7 * 365,

    // Session data: 30 days (shorter for security)
    sessions: 30,

    // Failed login attempts: 1 year
    failed_logins: 365,

    // MFA attempts: 90 days
    mfa_attempts: 90,

    // Analytics data: 7 years
    analytics: 7 * 365,

    // Backup data: 7 years
    backups: 7 * 365
  };

  // Check if data should be retained
  static shouldRetain(dataType: keyof typeof DataRetentionManager.RETENTION_POLICIES, lastModified: Date): boolean {
    const retentionDays = this.RETENTION_POLICIES[dataType];
    if (!retentionDays) return true; // Unknown data type, retain

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    return lastModified > cutoffDate;
  }

  // Get retention policy for data type
  static getRetentionPolicy(dataType: string): number {
    return this.RETENTION_POLICIES[dataType as keyof typeof DataRetentionManager.RETENTION_POLICIES] || (7 * 365);
  }

  // Schedule data for deletion (mark as pending deletion)
  static async scheduleDeletion(dataType: string, recordId: string, deletionDate: Date): Promise<boolean> {
    try {
      const { error } = await supabase
        .from('data_deletion_schedule')
        .insert({
          data_type: dataType,
          record_id: recordId,
          scheduled_deletion_date: deletionDate.toISOString(),
          status: 'scheduled',
          created_at: new Date().toISOString()
        });

      if (error) {
        console.error('Failed to schedule deletion:', error);
        return false;
      }

      return true;
    } catch (error) {
      console.error('Error scheduling deletion:', error);
      return false;
    }
  }

  // Execute pending deletions
  static async executePendingDeletions(): Promise<{ deleted: number; failed: number }> {
    try {
      const now = new Date().toISOString();

      // Get pending deletions
      const { data: pendingDeletions, error: fetchError } = await supabase
        .from('data_deletion_schedule')
        .select('*')
        .eq('status', 'scheduled')
        .lte('scheduled_deletion_date', now);

      if (fetchError) {
        console.error('Failed to fetch pending deletions:', fetchError);
        return { deleted: 0, failed: 0 };
      }

      let deleted = 0;
      let failed = 0;

      for (const deletion of pendingDeletions || []) {
        try {
          await this.deleteRecord(deletion.data_type, deletion.record_id);
          await this.markDeletionComplete(deletion.id);
          deleted++;
        } catch (error) {
          console.error(`Failed to delete ${deletion.data_type}:${deletion.record_id}:`, error);
          await this.markDeletionFailed(deletion.id, error);
          failed++;
        }
      }

      return { deleted, failed };
    } catch (error) {
      console.error('Error executing pending deletions:', error);
      return { deleted: 0, failed: 1 };
    }
  }

  // Delete specific record based on type
  private static async deleteRecord(dataType: string, recordId: string): Promise<void> {
    let tableName: string;

    switch (dataType) {
      case 'medical_records':
        tableName = 'medical_records';
        break;
      case 'audit_logs':
        tableName = 'audit_logs';
        break;
      case 'user_profiles':
        tableName = 'profiles';
        break;
      case 'chat_history':
        tableName = 'chat_history';
        break;
      case 'emergency_contacts':
        tableName = 'emergency_contacts';
        break;
      case 'prescriptions':
        tableName = 'prescriptions';
        break;
      case 'appointments':
        tableName = 'appointments';
        break;
      default:
        throw new Error(`Unknown data type: ${dataType}`);
    }

    const { error } = await supabase
      .from(tableName)
      .delete()
      .eq('id', recordId);

    if (error) {
      throw error;
    }
  }

  // Mark deletion as complete
  private static async markDeletionComplete(deletionId: string): Promise<void> {
    const { error } = await supabase
      .from('data_deletion_schedule')
      .update({
        status: 'completed',
        completed_at: new Date().toISOString()
      })
      .eq('id', deletionId);

    if (error) {
      console.error('Failed to mark deletion complete:', error);
    }
  }

  // Mark deletion as failed
  private static async markDeletionFailed(deletionId: string, error: any): Promise<void> {
    const { error: updateError } = await supabase
      .from('data_deletion_schedule')
      .update({
        status: 'failed',
        error_message: error?.message || 'Unknown error',
        failed_at: new Date().toISOString()
      })
      .eq('id', deletionId);

    if (updateError) {
      console.error('Failed to mark deletion failed:', updateError);
    }
  }

  // Check and schedule deletions for expired data
  static async checkAndScheduleDeletions(): Promise<{ scheduled: number }> {
    try {
      let scheduled = 0;

      // Check each data type
      for (const [dataType, retentionDays] of Object.entries(this.RETENTION_POLICIES)) {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

        // Get records older than retention period
        const records = await this.getExpiredRecords(dataType, cutoffDate);

        for (const record of records) {
          const deletionDate = new Date();
          deletionDate.setDate(deletionDate.getDate() + 30); // Schedule deletion in 30 days

          await this.scheduleDeletion(dataType, record.id, deletionDate);
          scheduled++;
        }
      }

      return { scheduled };
    } catch (error) {
      console.error('Error checking and scheduling deletions:', error);
      return { scheduled: 0 };
    }
  }

  // Get expired records for a data type
  private static async getExpiredRecords(dataType: string, cutoffDate: Date): Promise<any[]> {
    let tableName: string;
    let dateField: string;

    switch (dataType) {
      case 'medical_records':
        tableName = 'medical_records';
        dateField = 'created_at';
        break;
      case 'audit_logs':
        tableName = 'audit_logs';
        dateField = 'timestamp';
        break;
      case 'user_profiles':
        tableName = 'profiles';
        dateField = 'created_at';
        break;
      case 'chat_history':
        tableName = 'chat_history';
        dateField = 'created_at';
        break;
      case 'emergency_contacts':
        tableName = 'emergency_contacts';
        dateField = 'updated_at';
        break;
      case 'prescriptions':
        tableName = 'prescriptions';
        dateField = 'created_at';
        break;
      case 'appointments':
        tableName = 'appointments';
        dateField = 'created_at';
        break;
      default:
        return [];
    }

    try {
      const { data, error } = await supabase
        .from(tableName)
        .select('id, ' + dateField)
        .lt(dateField, cutoffDate.toISOString());

      if (error) {
        console.error(`Failed to get expired ${dataType}:`, error);
        return [];
      }

      return data || [];
    } catch (error) {
      console.error(`Error getting expired ${dataType}:`, error);
      return [];
    }
  }

  // User-initiated data deletion (right to be forgotten)
  static async deleteUserData(userId: string): Promise<{ success: boolean; deletedRecords: number }> {
    try {
      let deletedRecords = 0;

      // Delete from all user-related tables
      const tables = [
        'medical_records',
        'prescriptions',
        'emergency_contacts',
        'appointments',
        'chat_history',
        'vital_signs'
      ];

      for (const table of tables) {
        const { data, error } = await supabase
          .from(table)
          .delete()
          .eq('user_id', userId)
          .select('id');

        if (error) {
          console.error(`Failed to delete from ${table}:`, error);
        } else {
          deletedRecords += data?.length || 0;
        }
      }

      // Anonymize audit logs instead of deleting (for compliance)
      await supabase
        .from('audit_logs')
        .update({
          user_id: null,
          details: { deleted: true, deletion_date: new Date().toISOString() }
        })
        .eq('user_id', userId);

      // Mark user profile as deleted (don't actually delete for audit purposes)
      await supabase
        .from('profiles')
        .update({
          full_name: '[DELETED]',
          email: `[DELETED_${userId}]`,
          deleted_at: new Date().toISOString()
        })
        .eq('id', userId);

      return { success: true, deletedRecords };
    } catch (error) {
      console.error('Error deleting user data:', error);
      return { success: false, deletedRecords: 0 };
    }
  }

  // Get data retention report
  static async getRetentionReport(): Promise<any> {
    try {
      const report = {
        policies: this.RETENTION_POLICIES,
        scheduledDeletions: 0,
        completedDeletions: 0,
        failedDeletions: 0,
        lastCleanup: new Date().toISOString()
      };

      // Get deletion statistics
      const { data: stats } = await supabase
        .from('data_deletion_schedule')
        .select('status')
        .in('status', ['scheduled', 'completed', 'failed']);

      if (stats) {
        for (const stat of stats) {
          if (stat.status === 'scheduled') report.scheduledDeletions++;
          if (stat.status === 'completed') report.completedDeletions++;
          if (stat.status === 'failed') report.failedDeletions++;
        }
      }

      return report;
    } catch (error) {
      console.error('Error getting retention report:', error);
      return null;
    }
  }
}

// Automated cleanup scheduler
export class RetentionScheduler {
  private static intervalId: NodeJS.Timeout | null = null;

  // Start automated retention management
  static startAutomatedCleanup(): void {
    // Check for expired data daily
    this.intervalId = setInterval(async () => {
      try {
        console.log('[RETENTION] Running automated cleanup...');

        // Check and schedule deletions
        const { scheduled } = await DataRetentionManager.checkAndScheduleDeletions();
        console.log(`[RETENTION] Scheduled ${scheduled} records for deletion`);

        // Execute pending deletions
        const { deleted, failed } = await DataRetentionManager.executePendingDeletions();
        console.log(`[RETENTION] Deleted ${deleted} records, ${failed} failed`);

      } catch (error) {
        console.error('[RETENTION] Automated cleanup failed:', error);
      }
    }, 24 * 60 * 60 * 1000); // Daily
  }

  // Stop automated cleanup
  static stopAutomatedCleanup(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  // Manual cleanup trigger
  static async triggerManualCleanup(): Promise<{ scheduled: number; deleted: number; failed: number }> {
    try {
      const { scheduled } = await DataRetentionManager.checkAndScheduleDeletions();
      const { deleted, failed } = await DataRetentionManager.executePendingDeletions();

      return { scheduled, deleted, failed };
    } catch (error) {
      console.error('Manual cleanup failed:', error);
      return { scheduled: 0, deleted: 0, failed: 1 };
    }
  }
}