# Security Best Practices for Web Applications

This document outlines essential security practices for building secure web applications. Following these guidelines will help protect your application and users from common vulnerabilities.

## 1. Authentication

### Secret Management
- **Never use hardcoded secret fallbacks** for JWT/session secrets
- **Throw errors** if required secrets are not configured - fail fast rather than running insecurely
- Use environment variables for all sensitive configuration
- **Minimum secret length**: 32 characters for JWT secrets

```typescript
// Validate secrets at startup - fail fast if missing or weak
function validateSecret(name: string, value: string | undefined): string {
  if (!value) {
    throw new Error(
      `${name} environment variable is required.\n` +
      `Generate a secure secret with: openssl rand -base64 32`
    );
  }
  if (value.length < 32) {
    throw new Error(`${name} must be at least 32 characters for security.`);
  }
  return value;
}

const JWT_SECRET = validateSecret('JWT_SECRET', process.env.JWT_SECRET);
```

### Password Security
- Use **bcrypt** or **argon2** for password hashing (never MD5, SHA1, or plain SHA256)
- Use appropriate cost factors (bcrypt: 10-12 rounds)
- Never store passwords in plain text or reversible encryption

### Multi-Factor Authentication (MFA)
- Implement **TOTP-based MFA** for sensitive applications
- Use established libraries (e.g., `otplib`, `speakeasy`)
- Provide backup codes for account recovery
- Rate limit MFA verification attempts
- **Enforce MFA completion** - verify `mfaVerified` flag before granting access to protected resources

```typescript
// In middleware - enforce MFA completion for admin routes
if (adminPayload && !adminPayload.mfaVerified) {
  return NextResponse.json(
    { error: 'MFA verification required' },
    { status: 401 }
  );
}
```

### Session Security
- Set secure cookie flags:
  - `HttpOnly`: Prevents JavaScript access to cookies
  - `Secure`: Only transmit over HTTPS (enable in production)
  - `SameSite=Lax` or `SameSite=Strict`: Prevents CSRF attacks
- Use short token expiration times:
  - **2 hours** for regular user sessions
  - **30 minutes** for admin/sensitive sessions
  - Shorter durations for MFA pending states (5 minutes)
- **Align cookie maxAge with JWT expiry** - mismatched values cause auth issues
- Implement secure session invalidation on logout

```typescript
// Export constants to ensure consistency
export const TOKEN_EXPIRY = '2h';
export const COOKIE_MAX_AGE = 2 * 60 * 60; // 2 hours in seconds

// Always use the same constant for both
const token = await generateToken(payload, secret, TOKEN_EXPIRY);
response.headers.set('Set-Cookie',
  createAuthCookie(COOKIE_NAME, token, COOKIE_MAX_AGE)
);
```

### Token Refresh (Sliding Window)
Implement automatic token refresh to maintain security while preserving user experience:

- **Shorten base token expiry** (2h instead of 7d)
- **Auto-refresh in middleware** when token approaches expiry
- Define refresh windows (e.g., refresh when <1h remaining)

```typescript
// Check if token should be refreshed
export function shouldRefreshToken(
  payload: { exp?: number },
  refreshWindowSeconds: number
): boolean {
  if (!payload.exp) return false;
  const now = Math.floor(Date.now() / 1000);
  const timeRemaining = payload.exp - now;
  return timeRemaining > 0 && timeRemaining < refreshWindowSeconds;
}

// In middleware - refresh approaching-expiry tokens
if (shouldRefreshToken(payload, REFRESH_WINDOW)) {
  const newToken = await refreshToken(payload);
  response.headers.set('Set-Cookie',
    createAuthCookie(COOKIE_NAME, newToken, COOKIE_MAX_AGE)
  );
}
```

## 2. Rate Limiting

### Why Rate Limit
Rate limiting protects against brute force attacks, credential stuffing, and denial of service.

### Implementation Guidelines
- **Always rate limit authentication endpoints**: login, MFA verification, password reset
- **Rate limit ALL API endpoints** - not just auth (prevents DoS on data endpoints)
- **Stricter limits for expensive operations**: exports, bulk operations, file uploads
- Track by IP address using headers: `x-forwarded-for`, `x-real-ip`
- Return **429 Too Many Requests** status when limit exceeded
- Include `Retry-After` header with seconds until reset

### Recommended Limits

| Endpoint Type | Limit | Window |
|---------------|-------|--------|
| Auth (login, MFA) | 5 requests | 15 minutes |
| Magic link / password reset | 5 per email, 20 per IP | 15 minutes |
| General API endpoints | 100 requests | 1 minute |
| Export / heavy operations | 10 requests | 1 minute |

### Response Headers
Include rate limit information in responses:
- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Requests remaining in window
- `X-RateLimit-Reset`: Unix timestamp when limit resets

```typescript
// In-memory sliding window rate limiter
class RateLimiter {
  private store: Map<string, number[]> = new Map();

  constructor(
    private maxRequests: number,
    private windowMs: number
  ) {}

  check(key: string): { allowed: boolean; retryAfter?: number } {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    let timestamps = this.store.get(key) || [];
    timestamps = timestamps.filter(ts => ts > windowStart);

    if (timestamps.length >= this.maxRequests) {
      const retryAfter = Math.ceil((timestamps[0] + this.windowMs - now) / 1000);
      return { allowed: false, retryAfter };
    }

    timestamps.push(now);
    this.store.set(key, timestamps);
    return { allowed: true };
  }
}

// Create rate limiters for different endpoint types
export const authLimiter = new RateLimiter(5, 15 * 60 * 1000);
export const apiLimiter = new RateLimiter(100, 60 * 1000);
export const exportLimiter = new RateLimiter(10, 60 * 1000);
```

### In-Memory vs Distributed Rate Limiting

The examples above use in-memory storage. Choose your approach based on your deployment:

#### In-Memory (Simple)
```typescript
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
```

| Pros | Cons |
|------|------|
| Zero configuration | Resets on server restart |
| Fastest (no network call) | Doesn't work across multiple instances |
| No external dependencies | Uses application memory |

**Use when**: Single server instance, internal tools, rate limit reset on restart is acceptable.

#### Distributed (Redis)
```typescript
import Redis from 'ioredis';
const redis = new Redis(process.env.REDIS_URL);

async function rateLimit(key: string, max: number, windowSec: number) {
  const count = await redis.incr(key);
  if (count === 1) await redis.expire(key, windowSec);
  return { allowed: count <= max, remaining: Math.max(0, max - count) };
}
```

| Pros | Cons |
|------|------|
| Survives restarts | Requires Redis infrastructure |
| Works across instances | Network latency per request |
| Shared state | Additional cost/complexity |

**Use when**: Multiple servers (load balanced), public APIs, high-security requirements, serverless deployments.

#### Decision Guide

| Scenario | Recommendation |
|----------|----------------|
| Personal/internal app, single PM2 process | In-memory |
| Production API, single server, can tolerate restart reset | In-memory |
| Load-balanced, multiple instances | Redis required |
| Public API with strict security requirements | Redis required |
| Serverless (Vercel, Lambda) | Redis required (no persistent memory) |

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
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Restricts browser feature access |

### Next.js Example
```typescript
// next.config.ts
const securityHeaders = [
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob: https://*.s3.*.amazonaws.com",
      "connect-src 'self' https://*.s3.*.amazonaws.com",
      "frame-ancestors 'none'",
    ].join('; '),
  },
];

export default {
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};
```

### CSP Nonces (Recommended)

Using `'unsafe-inline'` in CSP defeats XSS protection. The proper solution is **nonces** - random tokens that mark trusted scripts.

#### How It Works
1. Generate a random nonce per request
2. Add nonce to CSP header: `script-src 'self' 'nonce-abc123'`
3. Add nonce attribute to trusted scripts: `<script nonce="abc123">`
4. Browser blocks any script without the matching nonce

#### Next.js Implementation

**Middleware** - Generate nonce and set CSP header:
```typescript
// middleware.ts
function generateCspHeader(nonce: string): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    "style-src 'self' 'unsafe-inline'",  // Keep for Tailwind/CSS-in-JS
    "img-src 'self' data: blob: https:",
    "font-src 'self' data:",
    "connect-src 'self' https:",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; ");
}

export async function middleware(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');

  const response = NextResponse.next();
  response.headers.set('Content-Security-Policy', generateCspHeader(nonce));
  response.headers.set('x-nonce', nonce);
  return response;
}
```

**Layout** - Read nonce for scripts:
```typescript
// app/layout.tsx
import { headers } from 'next/headers';

export default async function RootLayout({ children }) {
  const headersList = await headers();
  const nonce = headersList.get('x-nonce') || '';

  return (
    <html>
      <body data-nonce={nonce}>{children}</body>
    </html>
  );
}
```

**Note**: Keep `'unsafe-inline'` for `style-src` - removing it requires complex style nonce injection that breaks most CSS-in-JS libraries and Tailwind.

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

### API Route-Level Authentication

**Middleware alone is not enough.** While middleware can protect page routes, API routes should also verify authentication at the handler level. This provides defense in depth and ensures APIs return proper 401 responses instead of redirects.

#### Auth Helper Pattern
```typescript
// lib/auth.ts
import { cookies } from 'next/headers';
import { jwtVerify } from 'jose';
import { NextResponse } from 'next/server';

export async function requireAuth(): Promise<JWTPayload | NextResponse> {
  const cookieStore = await cookies();
  const token = cookieStore.get('auth-token')?.value;

  if (!token) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const secret = new TextEncoder().encode(process.env.JWT_SECRET);
    const { payload } = await jwtVerify(token, secret);

    if (!payload.mfaVerified) {
      return NextResponse.json({ error: 'MFA required' }, { status: 401 });
    }

    return payload as JWTPayload;
  } catch {
    return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
  }
}

export function isAuthError(result: unknown): result is NextResponse {
  return result instanceof NextResponse;
}
```

#### Usage in API Routes
```typescript
// app/api/clients/route.ts
import { requireAuth, isAuthError } from '@/lib/auth';

export async function GET() {
  const auth = await requireAuth();
  if (isAuthError(auth)) return auth;  // Returns 401

  // auth is now the verified JWT payload
  const clients = await db.query('SELECT * FROM clients');
  return NextResponse.json(clients);
}
```

Apply this pattern to **every** API route except `/api/auth/*` endpoints.

## 6. Database Security

### Query Safety
- **Use parameterized queries** - ORMs like Prisma handle this automatically
- **Never concatenate** user input into SQL strings
- Use **prepared statements** for raw queries when necessary

### Connection Security
- Use **SSL/TLS connections** for remote databases
- **Smart SSL configuration** - disable for localhost, enable for remote
- Configure **connection pooling** to prevent resource exhaustion
- Use least-privilege database accounts

```typescript
// Smart SSL configuration based on environment
function getSslConfig() {
  const dbUrl = process.env.DATABASE_URL || '';
  const isLocalhost = dbUrl.includes('localhost') || dbUrl.includes('127.0.0.1');

  // No SSL for local development
  if (isLocalhost) return undefined;

  // Strict SSL for production, relaxed for dev with remote DB
  return process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: true }
    : { rejectUnauthorized: false };
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: getSslConfig(),
  max: 20,                    // Maximum connections
  min: 2,                     // Minimum idle connections
  idleTimeoutMillis: 30000,   // Close idle connections after 30s
});
```

### Data Protection
- Implement **row-level security** where possible
- Encrypt sensitive data at rest
- **Regular backups** with encryption
- Test backup restoration periodically

## 7. Secrets Management

### Core Rules
- **Never commit secrets** to version control
- Use `.env` files locally with proper `.gitignore` entries
- Create `.env.example` with placeholder values for documentation
- **Throw errors** if required environment variables are missing
- **Rotate secrets** regularly, especially after team member departures

### Environment Variable Validation
Validate ALL critical service credentials at startup:

```typescript
function validateEnvVar(name: string): string {
  const value = process.env[name];
  if (!value || value.trim() === '') {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

// Validate at module load time - fail fast
const DATABASE_URL = validateEnvVar('DATABASE_URL');
const JWT_SECRET = validateEnvVar('JWT_SECRET');
const AWS_ACCESS_KEY_ID = validateEnvVar('AWS_ACCESS_KEY_ID');
const AWS_SECRET_ACCESS_KEY = validateEnvVar('AWS_SECRET_ACCESS_KEY');
const AWS_S3_BUCKET = validateEnvVar('AWS_S3_BUCKET');
const SENDGRID_API_KEY = validateEnvVar('SENDGRID_API_KEY');
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
- **Validate file types using magic bytes** - don't trust MIME type or extension alone
- Set **file size limits** appropriate to your use case
- **Scan for malware** if possible (ClamAV, cloud scanning services)
- **Generate random filenames** - never use user-provided names directly

### Magic Byte Verification
Use the `file-type` package to verify actual file content:

```typescript
import { fileTypeFromBuffer } from 'file-type';

const ALLOWED_MIME_TYPES = new Set([
  'application/pdf',
  'image/png',
  'image/jpeg',
]);

async function verifyFileType(buffer: Buffer): Promise<{
  valid: boolean;
  detectedType?: string;
  error?: string;
}> {
  // Check for PDF magic bytes manually (file-type can miss some PDFs)
  const pdfMagic = Buffer.from([0x25, 0x50, 0x44, 0x46]); // %PDF
  if (buffer.length >= 4 && buffer.subarray(0, 4).equals(pdfMagic)) {
    return { valid: true, detectedType: 'application/pdf' };
  }

  const fileType = await fileTypeFromBuffer(buffer);

  if (!fileType) {
    return { valid: false, error: 'Unable to determine file type' };
  }

  if (!ALLOWED_MIME_TYPES.has(fileType.mime)) {
    return {
      valid: false,
      detectedType: fileType.mime,
      error: `Invalid file type: ${fileType.mime}`
    };
  }

  return { valid: true, detectedType: fileType.mime };
}
```

### S3 Storage Best Practices
- **Store S3 keys, not public URLs** - generate presigned URLs on demand
- Use **presigned URLs** for both uploads and downloads
- Set appropriate bucket policies (private by default)
- Verify files server-side after upload before storing references

```typescript
// Extract S3 key from URL for verification
function extractS3KeyFromUrl(fileUrl: string): string | null {
  try {
    const url = new URL(fileUrl);
    return url.pathname.startsWith('/') ? url.pathname.slice(1) : url.pathname;
  } catch {
    return null;
  }
}

// Download partial file for verification (first 8KB is enough for magic bytes)
async function getFileHead(fileKey: string, bytes: number = 8192): Promise<Buffer> {
  const command = new GetObjectCommand({
    Bucket: AWS_S3_BUCKET,
    Key: fileKey,
    Range: `bytes=0-${bytes - 1}`,
  });
  const response = await s3Client.send(command);
  // Convert stream to buffer...
}
```

## 10. Error Handling

### Security Principles
- **Never expose stack traces** to users in production
- **Log errors server-side** with full details for debugging
- Return **generic error messages** to clients
- Use **consistent error response format**
- Use `try/catch` blocks consistently
- **Sanitize logged data** - don't log passwords, tokens, or full query parameters

### Implementation Example
```typescript
// Error handler middleware
function errorHandler(err: Error, req: Request, res: Response, next: NextFunction) {
  // Log full error details server-side (sanitized)
  console.error('Error:', {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString(),
    // Don't log: req.body, req.headers.authorization, etc.
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

## 11. Email Security

### HTML Content Escaping
Always escape user-provided content before inserting into HTML emails to prevent XSS in email clients:

```typescript
function escapeHtml(text: string): string {
  const htmlEntities: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  };
  return text.replace(/[&<>"']/g, (char) => htmlEntities[char]);
}

// Use in email templates
const emailHtml = `
  <p>Hello ${escapeHtml(companyName)},</p>
  <p>Invoice ${escapeHtml(invoiceNumber)} has been ${escapeHtml(status)}.</p>
  ${notes ? `<p>Notes: ${escapeHtml(notes)}</p>` : ''}
`;
```

### Email Best Practices
- Validate email service credentials at startup
- Use established email services (SendGrid, AWS SES, Postmark)
- Implement proper SPF, DKIM, and DMARC records
- Rate limit email sending to prevent abuse

---

## Quick Reference Checklist

### Authentication & Sessions
- [ ] JWT/session secrets are required (no fallbacks, min 32 chars)
- [ ] Passwords hashed with bcrypt/argon2
- [ ] Secure cookie flags configured (HttpOnly, Secure, SameSite)
- [ ] Cookie maxAge matches JWT expiry
- [ ] Token refresh (sliding window) implemented
- [ ] MFA completion enforced before resource access

### Rate Limiting
- [ ] Auth endpoints rate limited (5/15min)
- [ ] All API endpoints rate limited (100/min)
- [ ] Export/heavy operations stricter limits (10/min)
- [ ] 429 response with Retry-After header
- [ ] Appropriate storage chosen (in-memory vs Redis based on deployment)

### Input & Output
- [ ] All input validated with Zod schemas
- [ ] Security headers configured
- [ ] CSP with nonces (no unsafe-inline for scripts)
- [ ] Error messages don't leak sensitive info
- [ ] User content escaped in HTML emails

### Infrastructure
- [ ] All secrets in environment variables
- [ ] All critical env vars validated at startup
- [ ] .env files in .gitignore
- [ ] SSL enabled for remote databases
- [ ] Database connection pool configured
- [ ] Production environment properly configured

### File Handling
- [ ] File types verified with magic bytes
- [ ] S3 keys stored (not public URLs)
- [ ] Presigned URLs used for access
- [ ] File size limits enforced server-side

### API Security
- [ ] API keys use secure random generation
- [ ] Database queries use parameterized statements
- [ ] Data access scoped by user/account
- [ ] API routes verify auth at handler level (not just middleware)

---

*Last updated: January 16, 2026*
