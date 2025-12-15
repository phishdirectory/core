# @phishdirectory/core

The core phishing detection API and dashboard, merged from the original `core` and `veritas` applications.

## Architecture

**Rails 8.1 Hybrid Application** - Serves both web UI and JSON API.

### Key Decisions
- **Primary Keys**: UUID everywhere
- **User Auth**: Magic links only (passwordless)
- **Service Auth**: API keys with hash verification
- **Encryption**: Lockbox for at-rest encryption, BlindIndex for searchable fields
- **Background Jobs**: Solid Queue
- **Feature Flags**: Flipper with role-based groups

## Authentication

### User Authentication (Web + API)
- **Web**: Magic link → Session cookie → `User::Session` record
- **API**: User API keys (prefix `pdat_`) via `Authorization: Bearer` or `X-API-Key` header

### Service Authentication (API only)
- Service API keys (no prefix) for service-to-service communication
- Keys have `api_key` (public) and `hash_key` (verification) components

## Directory Structure

```
app/
├── controllers/
│   ├── admin/           # Admin CRUD (users, services, webhooks)
│   ├── api/v1/          # JSON API endpoints
│   │   ├── auth/        # Service authentication
│   │   ├── domain/      # Domain checking
│   │   ├── url/         # URL checking
│   │   └── user/        # Current user
│   └── dashboard/       # User dashboard
├── jobs/
│   ├── phish_*_job.rb   # Phishing check jobs
│   ├── *_cleanup_job.rb # Maintenance jobs
│   └── notify_*.rb      # Notification jobs
├── mailers/
│   ├── user_mailer.rb   # User emails (magic link, welcome)
│   └── ops_mailer.rb    # Ops alerts (security, errors)
├── models/
│   ├── user.rb          # User with AASM states
│   ├── user/session.rb  # Encrypted session tokens
│   ├── service.rb       # External services
│   ├── service/         # Key, KeyUsage, Webhook
│   └── phish/           # Domain, Url models
└── services/
    ├── phish/           # Detection services
    │   ├── aggregator_service.rb
    │   ├── walshy_service.rb
    │   ├── google_safe_browsing_service.rb
    │   └── ...
    ├── webhook_service.rb
    └── api_metrics_service.rb
```

## API Endpoints

### Public (No Auth)
- `GET /api/v1/health` - Health check

### User Auth Required
- `GET /api/v1/user/me` - Current user info
- `PUT /api/v1/user/me` - Update profile
- `GET/POST /api/v1/domain/check` - Check single domain
- `GET/POST /api/v1/domain/bulk` - Check multiple domains (max 100)
- `GET/POST /api/v1/url/check` - Check single URL
- `GET/POST /api/v1/url/bulk` - Check multiple URLs (max 100)

### Service Auth Required
- `POST /api/v1/auth/authenticate` - Verify service key
- `GET /api/v1/webhooks` - List webhooks
- `POST /api/v1/webhooks` - Create webhook
- `DELETE /api/v1/webhooks/:id` - Delete webhook

## Models

### User States (AASM)
- `pending` → `active` → `suspended` / `deactivated` / `locked`

### Service States (AASM)
- `active` → `suspended` / `decommissioned`

### Service Key States
- `active` → `deprecated` → `revoked`

## Configuration

### Required Credentials
```yaml
lockbox:
  master_key: <32-byte hex>
blind_index:
  master_key: <32-byte hex>
google_safe_browsing:
  api_key: <key>
virustotal:
  api_key: <key>
urlscan:
  api_key: <key>
phishtank:
  api_key: <key>
slack:
  browser_token: <token>
  cookie: <cookie>
ops:
  email: ops@phish.directory
```

### Feature Flags (Flipper)
Groups defined in `config/initializers/flipper.rb`:
- `:admins` - Admin+ users
- `:trusted` - Trusted+ users
- `:staff` - All staff

## Development

```bash
# Setup
bin/rails db:create db:migrate

# Run server
bin/rails server

# Run tests
bin/rails test

# Console
bin/rails console
```

## Monitoring

- **Health Checks**: `/health` (OkComputer)
- **Feature Flags**: `/admin/flipper`
- **Background Jobs**: `/admin/jobs` (Mission Control)
- **Analytics**: `/admin/blazer`
- **Console Audits**: `/admin/console_audits`

## Code Style

- Use `has_encrypted` for Lockbox (not Rails 8 `encrypts`)
- Prefer Faraday for HTTP clients (per CLAUDE.md convention)
- Use AASM for state machines
- Use Paper Trail for audit logging
- use tailwind for css