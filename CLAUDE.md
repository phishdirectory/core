# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
# Full development environment (web + CSS watcher + background jobs)
bin/dev

# Individual components
bin/rails server                    # Web server only
bin/rails solid_queue:start         # Background job worker
bin/rails tailwindcss:watch         # CSS watcher

# Setup
bin/setup                           # Install deps + prepare database
bin/setup --reset                   # Reset database from scratch

# Testing
bin/rails test                      # All tests
bin/rails test test/models/user_test.rb           # Single file
bin/rails test test/models/user_test.rb:42        # Single test by line

# Code quality (all run via bin/ci)
bin/rubocop                         # Ruby style (Rails Omakase)
bin/brakeman --quiet --no-pager     # Security analysis
bin/bundler-audit                   # Gem vulnerability audit
bin/ci                              # Run all checks
```

## Architecture

**Rails 8.1 Hybrid Application** - Serves both web UI and JSON API.

### Key Technical Decisions
- **Primary Keys**: UUID everywhere with Base62-encoded public IDs (e.g., `usr_4k8xJm2pN9qW`)
- **User Auth**: Magic links only (passwordless) → `User::Session` records
- **API Auth**: User keys (`pdat_*` prefix) or service keys (no prefix)
- **Encryption**: Lockbox for at-rest encryption, BlindIndex for searchable encrypted fields
- **Background Jobs**: Solid Queue with 5 priority levels (critical → low_priority)
- **State Machines**: AASM for User, Service, Service::Key states
- **Soft Deletes**: Discard gem via `SoftDeletable` concern
- **Audit Logging**: Paper Trail for model changes

### Core Patterns

**Public IDs**: All major models use `PublicIdentifiable` concern for API-friendly IDs:
```ruby
class User < ApplicationRecord
  include PublicIdentifiable
  set_public_id_prefix "usr"  # → user.public_id = "usr_4k8xJm2pN9qW"
end
```

**Phishing Detection Flow**:
1. API request → `Api::V1::Domain::DomainsController#check`
2. Find or create `Phish::Domain` record
3. `AggregatorService.check_domain` orchestrates multiple services
4. Authoritative sources (Fish Fish, Sinking Yachts) override weighted scoring
5. Rate-limited services schedule `PhishServiceRetryJob` for later
6. `Verdict` record stores final classification

**Service Layer** (`app/services/phish/`):
- `BaseService`: Faraday HTTP client, error handling, rate limit tracking
- Individual services extend BaseService: `GoogleSafeBrowsingService`, `VirustotalService`, etc.
- `AggregatorService`: Orchestrates all services, weighted scoring, authoritative source logic

**Job Queue Priorities** (`config/solid_queue.yml`):
1. `critical` - Security incidents, ops alerts
2. `webhooks` - External notifications
3. `default` - Normal operations (phish checks, emails)
4. `maintenance` - Cleanup jobs
5. `low_priority` - Retries, background processing

### Directory Structure

```
app/
├── controllers/
│   ├── admin/              # Admin CRUD (users, services, webhooks)
│   ├── api/v1/             # JSON API endpoints
│   │   ├── base_controller.rb  # Dual auth (user/service), request logging
│   │   ├── domain/         # Domain checking
│   │   ├── url/            # URL checking
│   │   └── user/           # Current user
│   └── dashboard/          # User dashboard
├── models/
│   ├── concerns/
│   │   ├── public_identifiable.rb  # Prefixed public IDs
│   │   ├── soft_deletable.rb       # Discard-based soft delete
│   │   └── protectable.rb          # Protection system
│   ├── user.rb             # AASM: active/suspended/deactivated
│   ├── user/session.rb     # Encrypted session tokens
│   ├── service.rb          # External services
│   ├── service/            # Key, KeyUsage, Webhook
│   ├── phish/              # Domain, Url, Verdict, Tld, Protection
│   └── verdict.rb          # Classifications: phishing/suspicious/clean/unknown/protected
├── services/
│   └── phish/
│       ├── base_service.rb         # HTTP client, error handling
│       ├── aggregator_service.rb   # Multi-service orchestration
│       └── *_service.rb            # Individual detection services
└── jobs/
    ├── phish_*_job.rb      # Phishing check jobs
    ├── *_sync_job.rb       # Feed syncing jobs
    └── *_cleanup_job.rb    # Maintenance jobs
```

## API Endpoints

### Public
- `GET /api/v1/health`

### User Auth Required (pdat_* keys)
- `GET/POST /api/v1/domain/check` - Single domain
- `GET/POST /api/v1/domain/bulk` - Multiple domains (max 100)
- `GET/POST /api/v1/url/check` - Single URL
- `GET/POST /api/v1/url/bulk` - Multiple URLs (max 100)
- `GET /api/v1/user/me` - Current user

### Service Auth Required
- `POST /api/v1/auth/authenticate` - Verify service key
- `CRUD /api/v1/webhooks` - Webhook management

## Configuration

### Required Credentials (`bin/rails credentials:edit`)
```yaml
lockbox:
  master_key: <64-char hex>
blind_index:
  master_key: <64-char hex>

# Optional - services skip if unconfigured
google_safe_browsing:
  api_key: <key>
virustotal:
  api_key: <key>
urlscan:
  api_key: <key>

# Optional - scoring weights (see credentials for values)
scoring:
  min_confidence: <threshold>
  default_weight: <weight>
  weights: { ... }
```

## Admin & Monitoring

- **Feature Flags**: `/admin/flipper`
- **Background Jobs**: `/admin/jobs` (Mission Control)
- **Analytics**: `/admin/blazer`
- **Console Audits**: `/admin/console_audits`
- **Health**: `/health` (OkComputer)

## Code Style

- Use `has_encrypted` for Lockbox (not Rails 8 `encrypts`)
- Prefer Faraday for HTTP clients
- Use AASM for state machines
- Use Paper Trail for audit logging
- Use Tailwind CSS for styling
- Use Discard (`discard`/`undiscard`) for soft deletes
