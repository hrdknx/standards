# Security Best Practices for Web Applications

This document outlines essential security practices for building secure web applications. Following these guidelines will help protect your application and users from common vulnerabilities.

## 1. Authentication

### Secret Management
- **Never use hardcoded secret fallbacks** for JWT/session secrets
- **Throw errors** if required secrets are not configured - fail fast rather than running insecurely
- Use environment variables for all sensitive configuration

### Password Security
- Use **bcrypt** or **argon2** for password hashing (never MD5, SHA1, or plain SHA256)
- Use appropriate cost factors (bcrypt: 10-12 rounds)
- Never store passwords in plain text or reversible encryption

### Multi-Factor Authentication (MFA)
- Implement **TOTP-based MFA** for sensitive applications
- Use established libraries (e.g., `otplib`, `speakeasy`)
- Provide backup codes for account recovery
- Rate limit MFA verification attempts

### Session Security
- Set secure cookie flags:
  - `HttpOnly`: Prevents JavaScript access to cookies
  - `Secure`: Only transmit over HTTPS (enable in production)
  - `SameSite=Lax` or `SameSite=Strict`: Prevents CSRF attacks
- Use short token expiration times:
  - 24 hours for general sessions
  - Shorter durations for sensitive operations
- Implement secure session invalidation on logout

```typescript
// Example secure cookie configuration
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax' as const,
  maxAge: 24 * 60 * 60 * 1000, // 24 hours
  path: '/',
};
```

## 2. Rate Limiting

### Why Rate Limit
Rate limiting protects against brute force attacks, credential stuffing, and denial of service.

### Implementation Guidelines
- **Always rate limit authentication endpoints**: login, MFA verification, password reset
- **Recommended limit**: 5 attempts per 15 minutes for auth routes
- Track by IP address using headers: `x-forwarded-for`, `x-real-ip`
- Return **429 Too Many Requests** status when limit exceeded
- Include `Retry-After` header with seconds until reset

### Response Headers
Include rate limit information in responses:
- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Requests remaining in window
- `X-RateLimit-Reset`: Unix timestamp when limit resets

```typescript
// Example rate limiter configuration
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      error: 'Too many attempts. Please try again later.',
    });
  },
});
```

## 3. Input Validation

### Core Principles
- **Validate ALL user input** with schemas (Zod recommended)
- **Validate on the server** - never trust client-side validation alone
- Use **strict types**: enums, regex patterns for dates, positive numbers, etc.
- **Limit string lengths** to prevent abuse and buffer overflows
- Return **descriptive but safe** error messages (don't leak implementation details)

### Zod Example
```typescript
import { z } from 'zod';

const userSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(8).max(128),
  name: z.string().min(1).max(100),
  age: z.number().int().positive().max(150).optional(),
  role: z.enum(['user', 'admin', 'moderator']),
  birthDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
});

// Always validate before processing
const result = userSchema.safeParse(req.body);
if (!result.success) {
  return res.status(400).json({ error: 'Invalid input' });
}
```

## 4. Security Headers

Configure these headers on all responses to protect against common attacks:

| Header | Value | Purpose |
|--------|-------|---------|
| `Content-Security-Policy` | Restrict resource loading | Prevents XSS and injection attacks |
| `X-Frame-Options` | `DENY` | Prevents clickjacking |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME type sniffing |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Enforces HTTPS |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controls referrer information |
| `Permissions-Policy` | Disable unused features | Restricts browser feature access |
| `X-XSS-Protection` | `1; mode=block` | Legacy XSS protection |

### Next.js Example
```typescript
// next.config.js
const securityHeaders = [
  {
    key: 'X-Frame-Options',
    value: 'DENY',
  },
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff',
  },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=31536000; includeSubDomains',
  },
  {
    key: 'Referrer-Policy',
    value: 'strict-origin-when-cross-origin',
  },
  {
    key: 'X-XSS-Protection',
    value: '1; mode=block',
  },
];

module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
    ];
  },
};
```

## 5. API Security

### API Key Best Practices
- Use **cryptographically secure random tokens** for API keys (not UUIDs or user IDs)
- **Prefix API keys** for easy identification: `hdk_xxx`, `sk_xxx`, `pk_xxx`
- **Store API keys hashed** or use constant-time comparison to prevent timing attacks
- Implement proper authentication on **all endpoints**
- **Scope data access** by user/account ID in all database queries

### Key Generation Example
```typescript
import crypto from 'crypto';

function generateApiKey(prefix: string = 'sk'): string {
  const randomBytes = crypto.randomBytes(32).toString('hex');
  return `${prefix}_${randomBytes}`;
}

// For storage, hash the key
function hashApiKey(key: string): string {
  return crypto.createHash('sha256').update(key).digest('hex');
}
```

### Data Access Control
```typescript
// Always scope queries by user/account
const userData = await prisma.resource.findMany({
  where: {
    userId: authenticatedUser.id, // Always include ownership check
    // ... other filters
  },
});
```

## 6. Database Security

### Query Safety
- **Use parameterized queries** - ORMs like Prisma handle this automatically
- **Never concatenate** user input into SQL strings
- Use **prepared statements** for raw queries when necessary

### Connection Security
- Use **SSL/TLS connections** in production
- Configure connection pooling appropriately
- Use least-privilege database accounts

### Data Protection
- Implement **row-level security** where possible
- Encrypt sensitive data at rest
- **Regular backups** with encryption
- Test backup restoration periodically

```typescript
// Prisma SSL configuration example
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
  // In production, DATABASE_URL should include ?sslmode=require
}
```

## 7. Secrets Management

### Core Rules
- **Never commit secrets** to version control
- Use `.env` files locally with proper `.gitignore` entries
- Create `.env.example` with placeholder values for documentation
- **Throw errors** if required environment variables are missing
- **Rotate secrets** regularly, especially after team member departures

### Environment Variable Validation
```typescript
// Validate required environment variables at startup
function validateEnv() {
  const required = [
    'DATABASE_URL',
    'JWT_SECRET',
    'SESSION_SECRET',
  ];

  const missing = required.filter(key => !process.env[key]);

  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(', ')}`
    );
  }
}

// Call at application startup
validateEnv();
```

### .gitignore Example
```
# Environment files
.env
.env.local
.env.*.local

# Never commit these
*.pem
*.key
credentials.json
```

## 8. Environment Configuration

### Production Checklist
- Set `NODE_ENV=production`
- Enable SSL/TLS for all database connections
- Set `Secure` cookie flag to `true`
- Disable debug logging and verbose error messages
- Enable HTTPS only (redirect HTTP to HTTPS)
- Configure proper CORS origins

### Environment-Aware Configuration
```typescript
const config = {
  isProduction: process.env.NODE_ENV === 'production',
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax' as const,
  },
  logging: {
    level: process.env.NODE_ENV === 'production' ? 'error' : 'debug',
  },
};
```

## 9. File Uploads

### Validation Requirements
- **Validate file types** - don't trust MIME type alone, check magic bytes
- Set **file size limits** appropriate to your use case
- **Scan for malware** if possible (ClamAV, cloud scanning services)
- **Generate random filenames** - never use user-provided names directly

### Storage Best Practices
- Store files **outside the web root** or use signed URLs
- Use cloud storage (S3, GCS) with proper access controls
- Set appropriate Content-Disposition headers for downloads

```typescript
import crypto from 'crypto';
import path from 'path';

function generateSafeFilename(originalName: string): string {
  const ext = path.extname(originalName).toLowerCase();
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf'];

  if (!allowedExtensions.includes(ext)) {
    throw new Error('File type not allowed');
  }

  const randomName = crypto.randomBytes(16).toString('hex');
  return `${randomName}${ext}`;
}
```

## 10. Error Handling

### Security Principles
- **Never expose stack traces** to users in production
- **Log errors server-side** with full details for debugging
- Return **generic error messages** to clients
- Use **consistent error response format**
- Use `try/catch` blocks consistently

### Implementation Example
```typescript
// Error handler middleware
function errorHandler(err: Error, req: Request, res: Response, next: NextFunction) {
  // Log full error details server-side
  console.error('Error:', {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString(),
  });

  // Return safe error to client
  const isProduction = process.env.NODE_ENV === 'production';

  res.status(500).json({
    error: isProduction
      ? 'An unexpected error occurred'
      : err.message,
  });
}
```

---

## Quick Reference Checklist

- [ ] JWT/session secrets are required (no fallbacks)
- [ ] Passwords hashed with bcrypt/argon2
- [ ] Secure cookie flags configured
- [ ] Rate limiting on auth endpoints
- [ ] All input validated with Zod schemas
- [ ] Security headers configured
- [ ] API keys use secure random generation
- [ ] Database queries use parameterized statements
- [ ] All secrets in environment variables
- [ ] .env files in .gitignore
- [ ] Production environment properly configured
- [ ] File uploads validated and stored securely
- [ ] Error messages don't leak sensitive info

---

*Last updated: January 2026*
