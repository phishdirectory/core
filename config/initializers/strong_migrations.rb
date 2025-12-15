# Strong Migrations configuration
# Prevents dangerous migrations in production

StrongMigrations.start_after = 20251215160011  # Allow all initial migrations

# Additional safety settings (uncomment in production)
# StrongMigrations.lock_timeout = 10.seconds
# StrongMigrations.statement_timeout = 1.hour

# Target PostgreSQL version for checks
StrongMigrations.target_postgresql_version = "17"
