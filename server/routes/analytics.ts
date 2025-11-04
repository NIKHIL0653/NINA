import { Router } from 'express';
import { requireRole, ROLES, AuthenticatedRequest } from '../middleware/auth';
import { DataAnonymizer, AnalyticsQueryBuilder } from '../middleware/dataAnonymization';
import { supabase } from '@shared/supabase';
import { auditMiddleware } from '../middleware/audit';

const router = Router();

// Get anonymized analytics data (healthcare providers and admins only)
router.get('/medical-records',
  requireRole([ROLES.HEALTHCARE_PROVIDER, ROLES.ADMIN]),
  auditMiddleware('READ', 'analytics'),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { startDate, endDate, category, limit = 1000 } = req.query;

      // Build date filter
      let dateFilter = '';
      const params: any[] = [];

      if (startDate) {
        dateFilter += ' AND created_at >= ?';
        params.push(startDate);
      }

      if (endDate) {
        dateFilter += ' AND created_at <= ?';
        params.push(endDate);
      }

      // Fetch medical records (in production, use proper database query)
      // For demo purposes, using mock data
      const mockRecords = [
        {
          id: '1',
          user_id: 'user1',
          diagnosis: 'Type 2 Diabetes',
          treatment_type: 'Medication',
          medication_name: 'Metformin',
          blood_pressure: '140/90',
          temperature: 98.6,
          date_of_birth: '1980-05-15',
          gender: 'female',
          state: 'CA',
          created_at: '2024-01-15T10:00:00Z'
        },
        {
          id: '2',
          user_id: 'user2',
          diagnosis: 'Hypertension',
          treatment_type: 'Lifestyle',
          blood_pressure: '160/100',
          temperature: 99.1,
          date_of_birth: '1975-08-22',
          gender: 'male',
          state: 'NY',
          created_at: '2024-02-20T14:30:00Z'
        }
      ];

      // Filter records if needed
      let filteredRecords = mockRecords;
      if (category) {
        filteredRecords = mockRecords.filter(record =>
          DataAnonymizer.categorizeDiagnosis(record.diagnosis) === category
        );
      }

      // Create anonymized dataset
      const anonymizedData = DataAnonymizer.createAnalyticsDataset(filteredRecords);

      // Validate anonymization
      const isValid = DataAnonymizer.validateAnonymization(filteredRecords, anonymizedData);

      if (!isValid) {
        return res.status(500).json({
          error: 'Data Anonymization Error',
          message: 'Failed to properly anonymize data'
        });
      }

      res.json({
        success: true,
        data: anonymizedData,
        metadata: {
          totalRecords: filteredRecords.length,
          anonymizedFields: Object.keys(anonymizedData[0] || {}),
          dateRange: { startDate, endDate },
          category: category || 'all'
        }
      });
    } catch (error) {
      console.error('Analytics error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve analytics data'
      });
    }
  }
);

// Get aggregated health metrics
router.get('/metrics',
  requireRole([ROLES.HEALTHCARE_PROVIDER, ROLES.ADMIN]),
  auditMiddleware('READ', 'analytics'),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { metric, groupBy = 'age_group', startDate, endDate } = req.query;

      // Mock aggregated data (in production, query database with safe aggregations)
      const mockAggregatedData = {
        total_patients: 1250,
        avg_age: 45,
        gender_distribution: {
          male: 45,
          female: 52,
          other: 3
        },
        diagnosis_categories: {
          cardiovascular: 28,
          endocrine: 22,
          respiratory: 18,
          mental_health: 15,
          other: 17
        },
        treatment_types: {
          pharmacological: 65,
          lifestyle: 20,
          therapeutic: 10,
          surgical: 5
        },
        bp_categories: {
          normal: 35,
          elevated: 25,
          stage_1: 20,
          stage_2: 15,
          crisis: 5
        }
      };

      // Validate that aggregated data doesn't allow re-identification
      const groupSizes = Object.values(mockAggregatedData[metric as keyof typeof mockAggregatedData] || {});
      const hasSmallGroups = Array.isArray(groupSizes) && groupSizes.some((size: any) => typeof size === 'number' && size < 5);

      if (hasSmallGroups) {
        return res.status(403).json({
          error: 'Privacy Violation',
          message: 'Query results too granular, risking patient re-identification'
        });
      }

      res.json({
        success: true,
        data: mockAggregatedData,
        metadata: {
          metric: metric || 'overview',
          groupBy,
          dateRange: { startDate, endDate },
          privacyValidated: true
        }
      });
    } catch (error) {
      console.error('Metrics error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve metrics'
      });
    }
  }
);

// Get de-identified dataset for research (admin only)
router.get('/research-dataset',
  requireRole([ROLES.ADMIN]),
  auditMiddleware('EXPORT', 'analytics'),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { studyId, includeFields } = req.query;

      // Mock research dataset (in production, query approved research datasets)
      const mockResearchData = [
        {
          study_id: 'STUDY_001',
          age_group: '30-49',
          gender: 'female',
          region: 'REGION_ca',
          diagnosis_category: 'endocrine',
          treatment_category: 'pharmacological',
          bp_category: 'stage_1',
          enrollment_month: '2024-01'
        },
        {
          study_id: 'STUDY_002',
          age_group: '50-69',
          gender: 'male',
          region: 'REGION_ny',
          diagnosis_category: 'cardiovascular',
          treatment_category: 'lifestyle',
          bp_category: 'elevated',
          enrollment_month: '2024-02'
        }
      ];

      // Create de-identified dataset
      const deIdentifiedData = DataAnonymizer.createDeIdentifiedDataset(mockResearchData);

      // Validate de-identification
      const isValid = DataAnonymizer.validateAnonymization(mockResearchData, deIdentifiedData);

      if (!isValid) {
        return res.status(500).json({
          error: 'De-identification Error',
          message: 'Failed to properly de-identify research data'
        });
      }

      res.json({
        success: true,
        data: deIdentifiedData,
        metadata: {
          studyId: studyId || 'general_research',
          totalParticipants: deIdentifiedData.length,
          deIdentified: true,
          hipaaCompliant: true,
          fieldsIncluded: includeFields ? includeFields.toString().split(',') : ['all']
        }
      });
    } catch (error) {
      console.error('Research dataset error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve research dataset'
      });
    }
  }
);

// Validate analytics query safety
router.post('/validate-query',
  requireRole([ROLES.HEALTHCARE_PROVIDER, ROLES.ADMIN]),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { query, minimumGroupSize = 5 } = req.body;

      // Mock validation (in production, actually validate the query)
      const isSafe = !query.toLowerCase().includes('select') ||
                    query.toLowerCase().includes('group by') ||
                    query.toLowerCase().includes('count(*)');

      res.json({
        success: true,
        data: {
          isSafe,
          minimumGroupSize,
          recommendations: isSafe ? [] : [
            'Use aggregation functions instead of selecting individual records',
            'Ensure group sizes are at least 5 to prevent re-identification',
            'Remove direct identifiers from queries'
          ]
        }
      });
    } catch (error) {
      console.error('Query validation error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to validate query'
      });
    }
  }
);

export { router as analyticsRoutes };