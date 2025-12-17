# frozen_string_literal: true

class ApiMetricsBatchJob < ApplicationJob
  queue_as QUEUE_DEFAULT

  def perform
    # Flush any batched metrics
    ApiMetricsService.flush

    # Record aggregate stats
    record_daily_stats
    record_service_stats
  end

  private

  def record_daily_stats
    today = Date.current

    # API key usage
    api_key_count = UserApiKey.where(active: true).count
    api_keys_used_today = UserApiKey.where("last_used_at > ?", today.beginning_of_day).count

    if defined?(StatsD)
      StatsD.gauge("api.keys.total", api_key_count)
      StatsD.gauge("api.keys.used_today", api_keys_used_today)
    end

    Rails.logger.info("[ApiMetricsBatch] API Keys: #{api_key_count} total, #{api_keys_used_today} used today")
  end

  def record_service_stats
    # Service key usage
    service_count = Service.where(status: :active).count
    service_key_count = Service::Key.where(status: :active).count

    if defined?(StatsD)
      StatsD.gauge("services.total", service_count)
      StatsD.gauge("services.keys.total", service_key_count)
    end

    Rails.logger.info("[ApiMetricsBatch] Services: #{service_count} active, #{service_key_count} active keys")
  end
end
