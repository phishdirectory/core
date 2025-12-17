# frozen_string_literal: true

# PgHero: PostgreSQL monitoring and insights
# Provides query stats, index usage, database size, and more
#
# Dashboard available at /admin/pghero (protected by AdminConstraint)
#
# Prerequisites for full functionality:
#   1. Enable pg_stat_statements extension in PostgreSQL:
#      CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
#
#   2. Add to postgresql.conf:
#      shared_preload_libraries = 'pg_stat_statements'
#
#   3. Restart PostgreSQL after changes

# Disable PgHero's built-in HTTP Basic Auth
# Authentication is handled by AdminConstraint in routes.rb
ENV["PGHERO_USERNAME"] = nil
ENV["PGHERO_PASSWORD"] = nil
