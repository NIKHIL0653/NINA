import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import rateLimit from "express-rate-limit";
import { forceHTTPS, securityHeaders, phiDataLimits, securityLogger, sensitiveOperationLimiter, sanitizeInput, secureCookies } from "./middleware/secureTransport";
import { securityMonitoring, detectSuspiciousActivity } from "./middleware/securityMonitoring";
import { sqlInjectionCheck, hipaaComplianceCheck } from "./middleware/validation";
import { handleDemo } from "./routes/demo";
import { createAuthMiddleware, sessionTimeoutMiddleware } from "./middleware/auth";
import { errorHandler } from "./middleware/errorHandler";
import { apiLimiter, authLimiter, healthcareDataLimiter, fileUploadLimiter, aiLimiter, emergencyLimiter, adminLimiter, auditLimiter } from "./middleware/rateLimit";
import { healthRoutes } from "./routes/health";
import { auditRoutes } from "./routes/audit";
import { authRoutes } from "./routes/auth";
import { medicalRecordsRoutes } from "./routes/medicalRecords";
import { appointmentsRoutes } from "./routes/appointments";
import { prescriptionDocumentsRoutes } from "./routes/prescriptionDocuments";
import { medicalHistoryRoutes } from "./routes/medicalHistory";
import { vitalSignsRoutes } from "./routes/vitalSigns";
import { userHealthProfileRoutes } from "./routes/userHealthProfile";
import { userManagementRoutes } from "./routes/userManagement";
import { mfaRoutes } from "./routes/mfa";
import { analyticsRoutes } from "./routes/analytics";
import { dataRetentionRoutes } from "./routes/dataRetention";
import { consentRoutes } from "./routes/consent";
import { privacyRoutes } from "./routes/privacy";
import { emergencyAccessRoutes } from "./routes/emergencyAccess";
import { securityRoutes } from "./routes/security";
import { complianceRoutes } from "./routes/compliance";

export function createServer() {
  const app = express();

  // Force HTTPS in production
  app.use(forceHTTPS);

  // Security headers
  app.use(securityHeaders);

  // Security monitoring
  app.use(securityMonitoring());
  app.use(detectSuspiciousActivity());

  // Security middleware
  app.use(helmet({
    contentSecurityPolicy: false, // Disabled because we set it in securityHeaders
  }));

  // Secure cookies
  app.use(secureCookies);

  // Rate limiting - general API limiter
  app.use(apiLimiter);

  // CORS configuration
  app.use(cors({
    origin: process.env.NODE_ENV === 'production'
      ? ['https://yourdomain.com'] // Replace with your actual domain
      : ['http://localhost:5173', 'http://localhost:3000'],
    credentials: true,
  }));

  // Security logging
  app.use(securityLogger);

  // Input sanitization and validation
  app.use(sanitizeInput);
  app.use(sqlInjectionCheck);

  // PHI data size limits
  app.use(phiDataLimits);

  // Logging
  app.use(morgan('combined'));

  // Body parsing middleware
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Health check (no auth required)
  app.use('/api/health', healthRoutes);

  // Auth routes (no auth required for login/refresh)
  app.use('/api/auth', authRoutes);

  // MFA routes
  app.use('/api/mfa', mfaRoutes);

  // Analytics routes (anonymized data for healthcare providers)
  app.use('/api/analytics', analyticsRoutes);

  // Data retention routes
  app.use('/api/retention', dataRetentionRoutes);

  // Consent management routes
  app.use('/api/consent', consentRoutes);

  // Privacy settings routes
  app.use('/api/privacy', privacyRoutes);

  // Emergency access routes
  app.use('/api/emergency-access', emergencyAccessRoutes);

  // Security monitoring routes
  app.use('/api/security', securityRoutes);

  // Compliance reporting routes
  app.use('/api/compliance', complianceRoutes);

  // Auth middleware for protected routes
  app.use('/api', createAuthMiddleware(), sessionTimeoutMiddleware(), sensitiveOperationLimiter, hipaaComplianceCheck);

  // API routes
  app.get("/api/ping", (req, res) => {
    res.json({
      message: "Hello from Express server v2!",
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development'
    });
  });

  app.get("/api/demo", handleDemo);

  // Audit routes (with audit-specific rate limiting)
  app.use('/api/audit', auditLimiter, auditRoutes);

  // User management routes (admin operations)
  app.use('/api/users', adminLimiter, userManagementRoutes);

  // Healthcare API routes with specific rate limiting
  app.use('/api/medical-records', healthcareDataLimiter, medicalRecordsRoutes);
  app.use('/api/appointments', healthcareDataLimiter, appointmentsRoutes);
  app.use('/api/prescription-documents', fileUploadLimiter, prescriptionDocumentsRoutes);
  app.use('/api/medical-history', healthcareDataLimiter, medicalHistoryRoutes);
  app.use('/api/vital-signs', healthcareDataLimiter, vitalSignsRoutes);
  app.use('/api/health-profile', healthcareDataLimiter, userHealthProfileRoutes);

  // Error handling middleware (must be last)
  app.use(errorHandler);

  return app;
}
