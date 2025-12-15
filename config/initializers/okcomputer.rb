# frozen_string_literal: true

# OkComputer health checks configuration
# Documentation: https://github.com/sportngin/okcomputer

OkComputer.mount_at = "health"

# Require authentication for certain checks in production
# OkComputer.require_authentication(
#   ENV.fetch("HEALTH_CHECK_USER", "admin"),
#   ENV.fetch("HEALTH_CHECK_PASSWORD", "password"),
#   except: %w[default]
# )

# Default check (always runs)
OkComputer::Registry.register "default", OkComputer::DefaultCheck.new

# Database check
OkComputer::Registry.register "database", OkComputer::ActiveRecordCheck.new

# Redis/Cache check (if using Redis)
# OkComputer::Registry.register "cache", OkComputer::RedisCheck.new(url: ENV["REDIS_URL"])

# Solid Queue check
OkComputer::Registry.register "queue", OkComputer::SidekiqLatencyCheck.new("default", 100) rescue OkComputer::DefaultCheck.new

# Custom app version check
class AppVersionCheck < OkComputer::Check
  def check
    version = ENV.fetch("RELEASE_VERSION") { `git rev-parse --short HEAD`.strip rescue "unknown" }
    mark_message "Version: #{version}"
  end
end
OkComputer::Registry.register "version", AppVersionCheck.new

# Custom database migrations check
class MigrationCheck < OkComputer::Check
  def check
    if ActiveRecord::Base.connection.migration_context.needs_migration?
      mark_failure
      mark_message "Pending migrations"
    else
      mark_message "Migrations up to date"
    end
  end
end
OkComputer::Registry.register "migrations", MigrationCheck.new

# Deferred check for memory usage
class MemoryCheck < OkComputer::Check
  THRESHOLD_MB = 512

  def check
    memory_mb = `ps -o rss= -p #{Process.pid}`.to_i / 1024
    if memory_mb > THRESHOLD_MB
      mark_failure
      mark_message "Memory usage high: #{memory_mb}MB"
    else
      mark_message "Memory usage: #{memory_mb}MB"
    end
  end
end
OkComputer::Registry.register "memory", MemoryCheck.new

# Make memory check optional (don't fail deploy)
OkComputer.make_optional %w[memory]
