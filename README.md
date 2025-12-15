# @phishdirectory/core

The core phishing detection API and dashboard. Aggregates threat intelligence from multiple sources to identify malicious domains and URLs.

## Features

- **Multi-Source Detection**: Aggregates verdicts from Google Safe Browsing, VirusTotal, PhishTank, URLScan.io, and Walshy API
- **Weighted Scoring**: Combines results using confidence-weighted aggregation for accurate verdicts
- **RESTful API**: Clean JSON API for domain and URL checking with bulk support
- **Passwordless Auth**: Secure magic link authentication (no passwords to leak)
- **Service-to-Service**: Dedicated API keys for external service integration
- **Webhooks**: Real-time notifications for phishing verdicts
- **Admin Dashboard**: Manage users, services, and monitor activity
- **Feature Flags**: Flipper integration for gradual rollouts

## Quick Start

### Prerequisites

- Ruby 3.4+
- PostgreSQL 14+
- Redis (optional, for caching)

### Installation

```bash
# Clone the repository
git clone https://github.com/phishdirectory/core.git
cd core

# Install dependencies
bundle install

# Setup database
bin/rails db:create db:migrate

# Start the server
bin/rails server
```

### Configuration

Generate credentials:

```bash
bin/rails credentials:edit
```

Add required keys:

```yaml
lockbox:
  master_key: <64-char hex string>

blind_index:
  master_key: <64-char hex string>

google_safe_browsing:
  api_key: <your-api-key>

virustotal:
  api_key: <your-api-key>

urlscan:
  api_key: <your-api-key>

phishtank:
  api_key: <your-api-key>

slack:
  browser_token: <token>
  cookie: <cookie>

ops:
  email: ops@yourdomain.com
```

## API Usage

### Authentication

All API requests (except health check) require authentication via:

- **Header**: `Authorization: Bearer <api_key>`
- **Header**: `X-API-Key: <api_key>`

User API keys start with `pdat_` prefix.

### Endpoints

#### Health Check
```bash
GET /api/v1/health

# Response
{
  "status": "ok",
  "timestamp": "2025-01-15T10:30:00Z",
  "version": "1.0.0"
}
```

#### Check Domain
```bash
GET /api/v1/domain/check?domain=suspicious-site.com

# Response
{
  "domain": "suspicious-site.com",
  "verdict": "phishing",
  "confidence": 0.92,
  "last_checked": "2025-01-15T10:30:00Z",
  "created_at": "2025-01-15T10:30:00Z"
}
```

#### Bulk Check Domains
```bash
POST /api/v1/domain/bulk
Content-Type: application/json

{
  "domains": ["site1.com", "site2.com", "site3.com"]
}

# Response
{
  "results": [
    { "domain": "site1.com", "verdict": "clean", "confidence": 0.85 },
    { "domain": "site2.com", "verdict": "phishing", "confidence": 0.94 },
    { "domain": "site3.com", "verdict": "unknown", "confidence": 0.0 }
  ],
  "count": 3
}
```

#### Check URL
```bash
GET /api/v1/url/check?url=https://suspicious-site.com/login

# Response
{
  "url": "https://suspicious-site.com/login",
  "verdict": "phishing",
  "confidence": 0.89,
  "last_checked": "2025-01-15T10:30:00Z"
}
```

#### Current User
```bash
GET /api/v1/user/me

# Response
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "username": "johndoe",
    "access_level": "user",
    "status": "active"
  }
}
```

### Verdicts

| Verdict | Description |
|---------|-------------|
| `clean` | No threats detected |
| `phishing` | Confirmed phishing/malicious |
| `suspicious` | Potentially malicious, needs review |
| `unknown` | Not enough data to determine |
| `pending` | Analysis in progress |

### Rate Limits

- **User API Keys**: 1000 requests/hour
- **Service Keys**: 10000 requests/hour
- **Bulk Endpoints**: Max 100 items per request

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     @phishdirectory/core                     │
├─────────────────────────────────────────────────────────────┤
│  Web UI (Dashboard)          │  JSON API (/api/v1/*)        │
│  - Magic Link Auth           │  - User API Keys             │
│  - User Dashboard            │  - Service API Keys          │
│  - Admin Panel               │  - Domain/URL Checking       │
├─────────────────────────────────────────────────────────────┤
│                    Detection Services                        │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────┐ │
│  │ Google  │ │ Virus   │ │ Phish   │ │ URLScan │ │Walshy │ │
│  │ Safe    │ │ Total   │ │ Tank    │ │   .io   │ │  API  │ │
│  │Browsing │ │         │ │         │ │         │ │       │ │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └───┬───┘ │
│       └───────────┴──────────┬┴───────────┴─────────┘      │
│                              ▼                              │
│                    Aggregator Service                       │
│                  (Weighted Confidence)                      │
├─────────────────────────────────────────────────────────────┤
│  Background Jobs (Solid Queue)  │  Webhooks                 │
│  - Async phish checks           │  - Verdict notifications  │
│  - Session cleanup              │  - Signed payloads        │
│  - Metrics aggregation          │  - Retry with backoff     │
└─────────────────────────────────────────────────────────────┘
```

## Admin Dashboard

Access admin features at `/admin` (requires admin role):

- **Users**: View, edit, suspend, impersonate users
- **Services**: Manage external service integrations
- **Feature Flags**: `/admin/flipper`
- **Background Jobs**: `/admin/jobs`
- **Analytics**: `/admin/blazer`

## Development

### Running Tests

```bash
bin/rails test
```

### Console

```bash
bin/rails console
```

### Background Jobs

Jobs are processed by Solid Queue. In development, they run inline by default.

## Webhook Events

Services can register webhooks to receive real-time notifications:

```json
{
  "event": "domain.verdict",
  "payload": {
    "domain": "malicious-site.com",
    "classification": "phishing",
    "confidence": 0.95,
    "checked_at": "2025-01-15T10:30:00Z"
  },
  "signature": "sha256=..."
}
```

Verify webhook signatures using the secret provided during registration.

## Security

- **Encryption**: All sensitive data encrypted at rest (Lockbox)
- **Passwordless**: No password database to breach
- **Session Security**: Encrypted tokens with device fingerprinting
- **Rate Limiting**: Rack::Attack for abuse prevention
- **Audit Logging**: Paper Trail for all model changes

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Support

- **Issues**: [GitHub Issues](https://github.com/phishdirectory/core/issues)
- **Email**: support@phish.directory
