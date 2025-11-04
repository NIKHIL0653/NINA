import { createHash } from 'crypto';

// Data anonymization utilities for HIPAA compliance
export class DataAnonymizer {
  // Salt for hashing (should be environment-specific)
  private static readonly HASH_SALT = process.env.ANONYMIZATION_SALT || 'default-anonymization-salt';

  // Fields that should be anonymized for analytics
  private static readonly SENSITIVE_FIELDS = [
    'first_name',
    'last_name',
    'full_name',
    'email',
    'phone',
    'address',
    'city',
    'state',
    'zip_code',
    'ssn',
    'medical_record_number',
    'insurance_id',
    'emergency_contact_name',
    'emergency_contact_phone',
    'emergency_contact_email',
    'date_of_birth',
    'diagnosis_details',
    'treatment_notes',
    'medication_history',
    'allergy_details'
  ];

  // Create anonymized hash of sensitive data
  static anonymizeField(value: string): string {
    if (!value || typeof value !== 'string') return '';

    const saltedValue = value + this.HASH_SALT;
    return createHash('sha256').update(saltedValue).digest('hex');
  }

  // Anonymize an entire object for analytics
  static anonymizeObject(data: any): any {
    if (!data || typeof data !== 'object') return data;

    const anonymized = { ...data };

    // Anonymize direct sensitive fields
    for (const field of this.SENSITIVE_FIELDS) {
      if (anonymized[field]) {
        anonymized[field] = this.anonymizeField(String(anonymized[field]));
      }
    }

    // Handle nested objects
    for (const [key, value] of Object.entries(anonymized)) {
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        anonymized[key] = this.anonymizeObject(value);
      }
    }

    return anonymized;
  }

  // Create anonymized dataset for analytics
  static createAnalyticsDataset(records: any[]): any[] {
    return records.map(record => ({
      // Keep non-sensitive identifiers
      id: this.anonymizeField(record.id || ''),
      user_id: this.anonymizeField(record.user_id || ''),

      // Demographic data (generalized)
      age_group: this.categorizeAge(record.date_of_birth),
      gender: record.gender, // Assuming gender is not sensitive
      location_general: this.generalizeLocation(record),

      // Medical data (anonymized)
      ...this.anonymizeMedicalData(record),

      // Temporal data
      created_at_month: this.extractMonth(record.created_at),
      created_at_year: this.extractYear(record.created_at),

      // Aggregated metrics
      record_count: 1, // For counting purposes
    }));
  }

  // Categorize age into groups
  private static categorizeAge(dateOfBirth?: string): string {
    if (!dateOfBirth) return 'unknown';

    try {
      const birthDate = new Date(dateOfBirth);
      const today = new Date();
      const age = today.getFullYear() - birthDate.getFullYear();

      if (age < 18) return '0-17';
      if (age < 30) return '18-29';
      if (age < 50) return '30-49';
      if (age < 70) return '50-69';
      return '70+';
    } catch {
      return 'unknown';
    }
  }

  // Generalize location data
  private static generalizeLocation(record: any): string {
    // Only keep state/region level, not specific addresses
    if (record.state) return `state_${this.anonymizeField(record.state)}`;
    if (record.city) return `city_${this.anonymizeField(record.city)}`;
    return 'unknown';
  }

  // Anonymize medical data while preserving analytical value
  private static anonymizeMedicalData(record: any): any {
    const medicalData: any = {};

    // Diagnosis categories (group similar diagnoses)
    if (record.diagnosis) {
      medicalData.diagnosis_category = this.categorizeDiagnosis(record.diagnosis);
    }

    // Treatment types
    if (record.treatment_type) {
      medicalData.treatment_category = this.categorizeTreatment(record.treatment_type);
    }

    // Medication classes (not specific medications)
    if (record.medication_name) {
      medicalData.medication_class = this.categorizeMedication(record.medication_name);
    }

    // Vital signs ranges
    if (record.blood_pressure) {
      medicalData.bp_category = this.categorizeBloodPressure(record.blood_pressure);
    }

    if (record.temperature) {
      medicalData.temperature_range = this.categorizeTemperature(record.temperature);
    }

    return medicalData;
  }

  // Categorize diagnoses
  static categorizeDiagnosis(diagnosis: string): string {
    const diagnosisLower = diagnosis.toLowerCase();

    if (diagnosisLower.includes('diabetes')) return 'endocrine';
    if (diagnosisLower.includes('hypertension') || diagnosisLower.includes('blood pressure')) return 'cardiovascular';
    if (diagnosisLower.includes('asthma') || diagnosisLower.includes('copd')) return 'respiratory';
    if (diagnosisLower.includes('depression') || diagnosisLower.includes('anxiety')) return 'mental_health';
    if (diagnosisLower.includes('cancer') || diagnosisLower.includes('tumor')) return 'oncology';
    if (diagnosisLower.includes('arthritis') || diagnosisLower.includes('joint')) return 'musculoskeletal';
    if (diagnosisLower.includes('infection')) return 'infectious';

    return 'other';
  }

  // Categorize treatments
  private static categorizeTreatment(treatment: string): string {
    const treatmentLower = treatment.toLowerCase();

    if (treatmentLower.includes('surgery')) return 'surgical';
    if (treatmentLower.includes('medication') || treatmentLower.includes('drug')) return 'pharmacological';
    if (treatmentLower.includes('therapy') || treatmentLower.includes('counseling')) return 'therapeutic';
    if (treatmentLower.includes('lifestyle') || treatmentLower.includes('diet')) return 'lifestyle';

    return 'other';
  }

  // Categorize medications
  private static categorizeMedication(medication: string): string {
    const medLower = medication.toLowerCase();

    if (medLower.includes('insulin')) return 'antidiabetic';
    if (medLower.includes('statin')) return 'cholesterol';
    if (medLower.includes('beta') || medLower.includes('ace') || medLower.includes('arb')) return 'cardiovascular';
    if (medLower.includes('antibiotic')) return 'antibiotic';
    if (medLower.includes('antidepressant') || medLower.includes('anxiolytic')) return 'psychiatric';
    if (medLower.includes('pain') || medLower.includes('ibuprofen') || medLower.includes('acetaminophen')) return 'analgesic';

    return 'other';
  }

  // Categorize blood pressure
  private static categorizeBloodPressure(bp: string): string {
    try {
      const [systolic] = bp.split('/').map(Number);
      if (systolic < 120) return 'normal';
      if (systolic < 130) return 'elevated';
      if (systolic < 140) return 'stage_1';
      if (systolic < 180) return 'stage_2';
      return 'crisis';
    } catch {
      return 'unknown';
    }
  }

  // Categorize temperature
  private static categorizeTemperature(temp: number): string {
    if (temp < 95) return 'hypothermia';
    if (temp < 97) return 'low';
    if (temp < 99) return 'normal';
    if (temp < 101) return 'low_fever';
    if (temp < 103) return 'fever';
    return 'high_fever';
  }

  // Extract month from date
  private static extractMonth(dateString?: string): string {
    if (!dateString) return 'unknown';
    try {
      return new Date(dateString).toISOString().substring(0, 7); // YYYY-MM
    } catch {
      return 'unknown';
    }
  }

  // Extract year from date
  private static extractYear(dateString?: string): string {
    if (!dateString) return 'unknown';
    try {
      return new Date(dateString).getFullYear().toString();
    } catch {
      return 'unknown';
    }
  }

  // Create de-identified dataset for research/analytics
  static createDeIdentifiedDataset(records: any[]): any[] {
    return records.map((record, index) => ({
      // Replace with study ID
      study_id: `STUDY_${index + 1}`,

      // Anonymized demographics
      age_group: this.categorizeAge(record.date_of_birth),
      gender: record.gender,

      // Generalized location (remove specific identifiers)
      region: record.state ? `REGION_${this.anonymizeField(record.state).substring(0, 8)}` : 'unknown',

      // Medical data (categorized, not specific)
      ...this.anonymizeMedicalData(record),

      // Temporal data (remove specific dates)
      enrollment_month: this.extractMonth(record.created_at),
      enrollment_year: this.extractYear(record.created_at),

      // Remove all direct identifiers
      // Note: In production, ensure no combination of fields can re-identify individuals
    }));
  }

  // Validate that anonymized data cannot be re-identified
  static validateAnonymization(originalRecords: any[], anonymizedRecords: any[]): boolean {
    // Check that no direct identifiers remain
    const directIdentifiers = ['email', 'phone', 'name', 'ssn', 'address'];

    for (const record of anonymizedRecords) {
      for (const identifier of directIdentifiers) {
        if (record[identifier] && typeof record[identifier] === 'string' &&
            !record[identifier].match(/^[a-f0-9]{64}$/)) { // Not a hash
          return false;
        }
      }
    }

    // Check for potential re-identification through combination of fields
    // This is a simplified check - in production, use more sophisticated methods
    const uniqueCombinations = new Set();
    for (const record of anonymizedRecords) {
      const combination = `${record.age_group}-${record.gender}-${record.region}`;
      if (uniqueCombinations.has(combination)) {
        // Potential re-identification risk if combinations aren't unique enough
        console.warn('Potential re-identification risk detected in anonymized data');
      }
      uniqueCombinations.add(combination);
    }

    return true;
  }
}

// Utility for creating safe analytics queries
export class AnalyticsQueryBuilder {
  // Build safe aggregation queries that don't expose individual records
  static buildSafeAggregationQuery(collection: string, groupBy: string[], metrics: string[]): any {
    // This would integrate with your database to create safe aggregation queries
    // Example structure for MongoDB/SQL aggregation

    const query = {
      collection,
      pipeline: [
        // Only include anonymized fields
        {
          $project: {
            ...groupBy.reduce((acc, field) => ({ ...acc, [field]: 1 }), {}),
            ...metrics.reduce((acc, metric) => ({ ...acc, [metric]: 1 }), {}),
            _id: 0
          }
        },
        // Group by specified fields
        {
          $group: {
            _id: groupBy.reduce((acc, field) => ({ ...acc, [field]: `$${field}` }), {}),
            count: { $sum: 1 },
            ...metrics.reduce((acc, metric) => ({
              ...acc,
              [`avg_${metric}`]: { $avg: `$${metric}` },
              [`min_${metric}`]: { $min: `$${metric}` },
              [`max_${metric}`]: { $max: `$${metric}` }
            }), {})
          }
        }
      ]
    };

    return query;
  }

  // Validate that query results don't allow re-identification
  static validateQueryResults(results: any[], minimumGroupSize: number = 5): boolean {
    for (const result of results) {
      if (result.count < minimumGroupSize) {
        return false; // Group too small, could allow re-identification
      }
    }
    return true;
  }
}