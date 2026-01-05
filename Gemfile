source "https://rubygems.org"

# Core Rails
gem "rails", "~> 8.1.1"
gem "logger"                        # Required for Ruby 3.4+ (bundled gem)
gem "ostruct"                       # Required for Ruby 3.5+ (bundled gem)
gem "pg", "~> 1.6"
gem "puma", ">= 5.0"

# Windows timezone data
gem "tzinfo-data", platforms: %i[windows jruby]

# Rails 8 Solid gems
gem "solid_cache"
gem "solid_queue"
gem "solid_cable"

# Performance
gem "bootsnap", require: false
gem "thruster", require: false

# Asset Pipeline (required for admin UIs: mission_control, flipper-ui, blazer)
gem "sprockets-rails"

# Active Storage
gem "image_processing", "~> 1.2"
gem "active_storage_validations"

# ============================================
# Authentication & Security
# ============================================
gem "doorkeeper"                    # OAuth 2.0 provider
gem "lockbox"                       # Encryption
gem "blind_index"                   # Searchable encrypted fields
gem "rack-attack"                   # Rate limiting
gem "rack-cors"                     # CORS handling
gem "geocoder"                      # IP geolocation for sessions
gem "bcrypt"                        # Password hashing (has_secure_password)

# SAML 2.0 Identity Provider
gem "ruby-saml", "~> 1.17"          # SAML core library
gem "saml_idp", "~> 0.16"           # SAML IdP functionality

# ============================================
# Database & Models
# ============================================
gem "paper_trail"                   # Audit trail / versioning
gem "friendly_id"                   # Human-readable slugs
gem "hashid-rails"                  # Obfuscated public IDs
gem "pg_search"                     # Full-text search
gem "strong_migrations"             # Safe migrations
gem "aasm"                          # State machines
gem "kaminari"                      # Pagination
gem "validates_email_format_of"     # Email format validation
gem "valid_email2"                  # Disposable email checking
gem "discard"                       # Soft delete with recovery
gem "phonelib"                      # Phone number parsing & E.164 validation

# ============================================
# API & HTTP
# ============================================
gem "faraday"                       # HTTP client (per CLAUDE.md)
gem "faraday-retry"                 # Retry middleware
gem "rswag-api"                     # Serve OpenAPI JSON
gem "rswag-ui"                      # Swagger UI for API docs
gem "whois"                         # WHOIS lookups for domain info
gem "whois-parser"                  # Parse WHOIS responses
gem "rdap"                          # RDAP lookups (newer WHOIS replacement)
gem "public_suffix"                 # TLD parsing for compound TLDs (.co.uk, etc.)

# ============================================
# Browser Automation (for web form submissions)
# ============================================
gem "ferrum"                        # Headless Chrome driver

# ============================================
# PDF Generation
# ============================================
gem "wicked_pdf"                    # PDF generation from HTML
gem "wkhtmltopdf-binary"            # wkhtmltopdf binary

# ============================================
# Email
# ============================================
gem "postmark-rails"                # Postmark email delivery

# ============================================
# Background Jobs
# ============================================
gem "mission_control-jobs"          # Job dashboard

# ============================================
# Monitoring & Analytics
# ============================================
gem "ahoy_matey"                    # Analytics tracking
gem "blazer"                        # BI dashboards
gem "flipper"                       # Feature flags
gem "flipper-active_record"         # Flipper ActiveRecord adapter
gem "flipper-ui"                    # Flipper web UI
gem "statsd-instrument"             # Metrics collection
gem "okcomputer"                    # Health checks
gem "rollup"                        # Time-series rollups
gem "pghero"                        # PostgreSQL monitoring
gem "lograge"                       # Structured JSON logging
gem "logstop"                       # PII filtering in logs

# ============================================
# Console Auditing (Production Security)
# ============================================
gem "console1984"                   # Console session auditing
gem "audits1984"                    # Console audit management UI

# ============================================
# Development & Test
# ============================================
group :development, :test do
  gem "debug", platforms: %i[mri windows], require: "debug/prelude"
  gem "bundler-audit", require: false
  gem "brakeman", require: false
  gem "rubocop-rails-omakase", require: false
  gem "dotenv-rails"                # Environment variables
  gem "webmock"                     # HTTP request stubbing
end

group :development do
  gem "letter_opener"               # Preview emails in development
  gem "letter_opener_web"           # Web UI for letter_opener
  gem "annotaterb"                  # Annotate models with schema
end

gem "tailwindcss-rails", "~> 4.4"
