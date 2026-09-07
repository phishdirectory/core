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

# Solid Queue check.
#
# This used to register a *Sidekiq* latency check on an app that has never run
# Sidekiq, guarded by a `rescue` modifier covering the whole statement: when
# the check raised, the registration never happened and the fallback was
# discarded, so there was effectively no queue check at all.
class SolidQueueCheck < OkComputer::Check
  MAX_LATENCY_SECONDS = 300
  MAX_FAILED_JOBS = 100

  def check
    oldest = SolidQueue::ReadyExecution.minimum(:created_at)
    latency = oldest ? (Time.current - oldest).to_i : 0
    failures = SolidQueue::FailedExecution.count

    if latency > MAX_LATENCY_SECONDS
      mark_failure
      mark_message "Queue backed up: oldest ready job is #{latency}s old"
    elsif failures > MAX_FAILED_JOBS
      mark_failure
      mark_message "#{failures} failed jobs waiting"
    else
      mark_message "Queue healthy: #{latency}s latency, #{failures} failed"
    end
  rescue StandardError => e
    mark_failure
    mark_message "Could not read queue state: #{e.class}"
  end
end
OkComputer::Registry.register "queue", SolidQueueCheck.new

# Custom app version check
# Resolved once at boot rather than shelling out per request. `git` is not
# installed in the production image, so the old fallback spawned a process that
# could only ever fail.
APP_VERSION = ENV["RELEASE_VERSION"].presence || "unknown"

class AppVersionCheck < OkComputer::Check
  def check
    mark_message "Version: #{APP_VERSION}"
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

  # Read from procfs where it exists. Shelling out to `ps` on every health
  # poll spawns a process per request, which is a strange thing for a liveness
  # endpoint to do.
  def check
    memory_mb = resident_set_size_mb
    return mark_message("Memory usage unavailable") if memory_mb.nil?

    if memory_mb > THRESHOLD_MB
      mark_failure
      mark_message "Memory usage high: #{memory_mb}MB"
    else
      mark_message "Memory usage: #{memory_mb}MB"
    end
  end

  private

  def resident_set_size_mb
    statm = "/proc/#{Process.pid}/statm"
    return nil unless File.readable?(statm)

    pages = File.read(statm).split[1].to_i
    (pages * 4096) / 1_048_576
  rescue StandardError
    nil
  end
end
OkComputer::Registry.register "memory", MemoryCheck.new

# Make memory check optional (don't fail deploy)
OkComputer.make_optional %w[memory]
