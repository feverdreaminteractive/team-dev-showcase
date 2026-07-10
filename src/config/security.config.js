// Security Configuration
// Author: Alex Chen (Tech Lead)
// Issue: #20

export const securityConfig = {
  // Authentication
  auth: {
    jwtAccessExpiry: '15m',
    jwtRefreshExpiry: '7d',
    passwordMinLength: 12,
    passwordRequireUppercase: true,
    passwordRequireNumbers: true,
    passwordRequireSymbols: true,
    maxLoginAttempts: 5,
    lockoutDuration: 15 * 60 * 1000, // 15 minutes
    enable2FA: true,
  },

  // Rate Limiting
  rateLimit: {
    windowMs: 15 * 60 * 1000,
    maxRequests: 100,
    apiMaxRequests: 50,
    skipSuccessfulRequests: false,
    skipFailedRequests: false,
  },

  // CORS
  cors: {
    credentials: true,
    maxAge: 86400, // 24 hours
    preflightContinue: false,
  },

  // Session
  session: {
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      sameSite: 'strict',
    },
  },

  // Data Protection
  dataProtection: {
    encryptionAlgorithm: 'aes-256-gcm',
    hashAlgorithm: 'sha256',
    saltRounds: 12,
    sensitiveFields: [
      'password',
      'email',
      'phone',
      'ssn',
      'creditCard',
      'apiKey',
      'token',
    ],
  },

  // GDPR Compliance
  gdpr: {
    dataRetentionDays: 365,
    anonymizeAfterDays: 730,
    allowDataExport: true,
    allowDataDeletion: true,
    requireConsent: true,
    consentTypes: [
      'necessary',
      'preferences',
      'statistics',
      'marketing',
    ],
  },

  // Security Headers
  headers: {
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    csp: {
      reportUri: '/api/csp-report',
      upgradeInsecureRequests: true,
    },
  },

  // Monitoring
  monitoring: {
    enableSecurityLogs: true,
    logLevel: 'info',
    alertOnSuspiciousActivity: true,
    alertChannels: ['email', 'slack'],
    metricsEnabled: true,
  },

  // Validation Rules
  validation: {
    maxRequestSize: '10mb',
    maxUploadSize: '50mb',
    allowedFileTypes: [
      '.jpg', '.jpeg', '.png', '.gif', '.pdf',
      '.doc', '.docx', '.txt', '.csv',
    ],
    sanitizeInput: true,
    validateEmail: true,
    validateUrl: true,
  },
};

export default securityConfig;