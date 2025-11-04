import { body, param, query, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';
import { AuthenticatedRequest } from './auth';

// Validation middleware
export const handleValidationErrors = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      message: 'Invalid input data',
      details: errors.array()
    });
  }
  next();
};

// Healthcare data validation rules
export const medicalRecordValidation = [
  body('test_type')
    .isString()
    .isLength({ min: 1, max: 100 })
    .withMessage('Test type must be 1-100 characters')
    .matches(/^[a-zA-Z0-9\s\-_]+$/)
    .withMessage('Test type contains invalid characters'),

  body('test_data')
    .optional()
    .isObject()
    .withMessage('Test data must be a valid object'),

  handleValidationErrors
];

export const prescriptionValidation = [
  body('medication_name')
    .isString()
    .isLength({ min: 1, max: 200 })
    .withMessage('Medication name must be 1-200 characters')
    .matches(/^[a-zA-Z0-9\s\-\(\)\[\]\+\.]+$/)
    .withMessage('Medication name contains invalid characters'),

  body('dosage')
    .isString()
    .isLength({ min: 1, max: 50 })
    .withMessage('Dosage must be 1-50 characters'),

  body('frequency')
    .isString()
    .isLength({ min: 1, max: 100 })
    .withMessage('Frequency must be 1-100 characters'),

  body('prescribing_doctor')
    .isString()
    .isLength({ min: 1, max: 100 })
    .withMessage('Doctor name must be 1-100 characters')
    .matches(/^[a-zA-Z\s\.\-]+$/)
    .withMessage('Doctor name contains invalid characters'),

  body('start_date')
    .isISO8601()
    .withMessage('Start date must be a valid ISO date'),

  body('end_date')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO date'),

  body('instructions')
    .optional()
    .isString()
    .isLength({ max: 1000 })
    .withMessage('Instructions must be less than 1000 characters'),

  handleValidationErrors
];

export const appointmentValidation = [
  body('provider_name')
    .isString()
    .isLength({ min: 1, max: 100 })
    .withMessage('Provider name must be 1-100 characters'),

  body('appointment_date')
    .isISO8601()
    .withMessage('Appointment date must be a valid ISO date'),

  body('appointment_type')
    .isString()
    .isLength({ min: 1, max: 50 })
    .withMessage('Appointment type must be 1-50 characters'),

  body('location')
    .optional()
    .isString()
    .isLength({ max: 200 })
    .withMessage('Location must be less than 200 characters'),

  body('notes')
    .optional()
    .isString()
    .isLength({ max: 1000 })
    .withMessage('Notes must be less than 1000 characters'),

  handleValidationErrors
];

export const emergencyContactValidation = [
  body('name')
    .isString()
    .isLength({ min: 1, max: 100 })
    .withMessage('Name must be 1-100 characters')
    .matches(/^[a-zA-Z\s\.\-]+$/)
    .withMessage('Name contains invalid characters'),

  body('relationship')
    .isString()
    .isLength({ min: 1, max: 50 })
    .withMessage('Relationship must be 1-50 characters'),

  body('phone')
    .matches(/^[\+]?[1-9][\d]{0,15}$/)
    .withMessage('Phone number must be valid'),

  body('email')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Email must be valid'),

  body('address')
    .optional()
    .isString()
    .isLength({ max: 300 })
    .withMessage('Address must be less than 300 characters'),

  handleValidationErrors
];

// User input validation
export const userProfileValidation = [
  body('full_name')
    .optional()
    .isString()
    .isLength({ min: 1, max: 100 })
    .withMessage('Full name must be 1-100 characters')
    .matches(/^[a-zA-Z\s\.\-]+$/)
    .withMessage('Full name contains invalid characters'),

  body('email')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Email must be valid'),

  handleValidationErrors
];

// Authentication validation
export const loginValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Email must be valid'),

  body('password')
    .isString()
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters'),

  handleValidationErrors
];

export const registerValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Email must be valid'),

  body('password')
    .isString()
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number'),

  body('full_name')
    .optional()
    .isString()
    .isLength({ min: 1, max: 100 })
    .withMessage('Full name must be 1-100 characters'),

  handleValidationErrors
];

// MFA validation
export const mfaValidation = [
  body('method')
    .isIn(['totp', 'sms', 'email'])
    .withMessage('MFA method must be totp, sms, or email'),

  handleValidationErrors
];

export const mfaVerifyValidation = [
  body('sessionId')
    .isString()
    .isLength({ min: 1, max: 100 })
    .withMessage('Session ID is required'),

  body('code')
    .isString()
    .isLength({ min: 6, max: 6 })
    .isNumeric()
    .withMessage('MFA code must be 6 digits'),

  handleValidationErrors
];

// Query parameter validation
export const paginationValidation = [
  query('limit')
    .optional()
    .isInt({ min: 1, max: 1000 })
    .withMessage('Limit must be between 1 and 1000'),

  query('offset')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Offset must be non-negative'),

  handleValidationErrors
];

export const dateRangeValidation = [
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO date'),

  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO date'),

  handleValidationErrors
];

// ID parameter validation
export const idValidation = [
  param('id')
    .isUUID()
    .withMessage('ID must be a valid UUID'),

  handleValidationErrors
];

// File upload validation
export const fileUploadValidation = [
  // File validation is handled by multer configuration
  // This is for additional metadata validation
  body('fileName')
    .optional()
    .isString()
    .isLength({ max: 255 })
    .withMessage('File name must be less than 255 characters'),

  body('fileType')
    .optional()
    .isIn(['medical_record', 'prescription', 'lab_result', 'imaging', 'other'])
    .withMessage('File type must be valid'),

  handleValidationErrors
];

// Search validation
export const searchValidation = [
  query('q')
    .isString()
    .isLength({ min: 1, max: 200 })
    .withMessage('Search query must be 1-200 characters'),

  query('type')
    .optional()
    .isIn(['medical_records', 'prescriptions', 'appointments', 'all'])
    .withMessage('Search type must be valid'),

  handleValidationErrors
];

// Custom validators for healthcare data
export const healthcareDataValidators = {
  // Validate medical license number format
  medicalLicense: (value: string) => {
    const licenseRegex = /^[A-Z]{2}\d{6,8}$/; // e.g., MD123456
    return licenseRegex.test(value);
  },

  // Validate NPI number (National Provider Identifier)
  npi: (value: string) => {
    const npiRegex = /^\d{10}$/;
    return npiRegex.test(value) && value.length === 10;
  },

  // Validate ICD-10 code
  icd10: (value: string) => {
    const icd10Regex = /^[A-Z]\d{2}(\.\d{1,3})?$/;
    return icd10Regex.test(value);
  },

  // Validate medication dosage format
  dosage: (value: string) => {
    const dosageRegex = /^\d+(\.\d+)?\s*(mg|g|ml|mcg|units?|tablets?|capsules?)$/i;
    return dosageRegex.test(value);
  },

  // Validate phone number (US format with extensions)
  phoneNumber: (value: string) => {
    const phoneRegex = /^[\+]?[1-9][\d]{0,15}(\s?x\d+)?$/;
    return phoneRegex.test(value);
  },

  // Validate date is not in future (for medical events)
  notFutureDate: (value: string) => {
    const date = new Date(value);
    const now = new Date();
    return date <= now;
  },

  // Validate age is reasonable
  reasonableAge: (dateOfBirth: string) => {
    try {
      const birth = new Date(dateOfBirth);
      const now = new Date();
      const age = now.getFullYear() - birth.getFullYear();
      return age >= 0 && age <= 150;
    } catch {
      return false;
    }
  }
};

// SQL injection prevention (additional layer)
export const sqlInjectionCheck = (req: Request, res: Response, next: NextFunction) => {
  const checkValue = (value: any): boolean => {
    if (typeof value === 'string') {
      // Check for common SQL injection patterns
      const sqlPatterns = [
        /(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bCREATE\b|\bALTER\b)/i,
        /(-{2}|\/\*|\*\/)/, // Comments
        /('|(\\x27)|(\\x2D))/, // Quotes and dashes
        /(<script|javascript:|vbscript:|onload=|onerror=)/i // XSS
      ];

      return !sqlPatterns.some(pattern => pattern.test(value));
    }

    if (Array.isArray(value)) {
      return value.every(item => checkValue(item));
    }

    if (typeof value === 'object' && value !== null) {
      return Object.values(value).every(val => checkValue(val));
    }

    return true;
  };

  // Check all request data
  const allData = {
    ...req.body,
    ...req.query,
    ...req.params
  };

  if (!checkValue(allData)) {
    return res.status(400).json({
      error: 'Bad Request',
      message: 'Invalid characters detected in request'
    });
  }

  next();
};

// HIPAA compliance validation
export const hipaaComplianceCheck = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  // Ensure user has proper authorization for PHI access
  const phiEndpoints = [
    '/api/medical-records',
    '/api/prescriptions',
    '/api/medical-history',
    '/api/vital-signs'
  ];

  const isPHIEndpoint = phiEndpoints.some(endpoint => req.path.startsWith(endpoint));

  if (isPHIEndpoint && (!req.user || !['patient', 'healthcare_provider', 'admin'].includes(req.user.role || ''))) {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Access to PHI requires proper authorization'
    });
  }

  // Log PHI access for audit
  if (isPHIEndpoint && req.user) {
    console.log(`[PHI ACCESS] User: ${req.user.id} (${req.user.role}) - ${req.method} ${req.path}`);
  }

  next();
};