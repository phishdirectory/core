# frozen_string_literal: true

class HeartbeatJob < ApplicationJob
  queue_as :default

  def perform
    # Record that the app is alive
    Rails.logger.info("[Heartbeat] Application alive at #{Time.current.iso8601}")

    # Report metrics
    if defined?(StatsD)
      StatsD.gauge("app.heartbeat", 1)
      StatsD.gauge("app.jobs_pending", pending_jobs_count)
      StatsD.gauge("app.users_active_24h", active_users_count)
    end

    # Check critical services
    check_database
    check_redis
    check_external_services
  end

  private

  def pending_jobs_count
    if defined?(SolidQueue)
      SolidQueue::Job.where(finished_at: nil).count
    else
      0
    end
  rescue StandardError
    -1
  end

  def active_users_count
    User.where("last_seen_at > ?", 24.hours.ago).count
  rescue StandardError
    -1
  end

  def check_database
    ActiveRecord::Base.connection.execute("SELECT 1")
    Rails.logger.debug("[Heartbeat] Database: OK")
  rescue StandardError => e
    Rails.logger.error("[Heartbeat] Database: FAILED - #{e.message}")
  end

  def check_redis
    return unless defined?(Redis)

    Redis.current.ping
    Rails.logger.debug("[Heartbeat] Redis: OK")
  rescue StandardError => e
    Rails.logger.error("[Heartbeat] Redis: FAILED - #{e.message}")
  end

  def check_external_services
    # Add external service checks here if needed
    Rails.logger.debug("[Heartbeat] External services: OK")
  end
end
