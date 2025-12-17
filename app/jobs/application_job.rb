# frozen_string_literal: true

class ApplicationJob < ActiveJob::Base
  # Queue priority constants (highest to lowest priority)
  #
  # Usage:
  #   class MyJob < ApplicationJob
  #     queue_as QUEUE_CRITICAL
  #   end
  #
  # Queue Descriptions:
  #   CRITICAL     - Security incidents, ops alerts. Processed immediately.
  #   WEBHOOKS     - External notifications. Time-sensitive delivery.
  #   DEFAULT      - Normal operations (phish checks, emails, metrics).
  #   MAINTENANCE  - Cleanup jobs. Can be delayed during high load.
  #   LOW_PRIORITY - Retry jobs, background processing. Lowest urgency.
  #
  QUEUE_CRITICAL     = :critical
  QUEUE_WEBHOOKS     = :webhooks
  QUEUE_DEFAULT      = :default
  QUEUE_MAINTENANCE  = :maintenance
  QUEUE_LOW_PRIORITY = :low_priority

  # Automatically retry jobs that encountered a deadlock
  retry_on ActiveRecord::Deadlocked, wait: :polynomially_longer, attempts: 5

  # Most jobs are safe to ignore if the underlying records are no longer available
  discard_on ActiveJob::DeserializationError

  # Retry on network errors (common with external API calls)
  retry_on Faraday::Error, wait: :polynomially_longer, attempts: 3

  # Retry on transient connection issues
  retry_on ActiveRecord::ConnectionNotEstablished, wait: 5.seconds, attempts: 3

  # Log job execution with timing
  around_perform :log_job_execution

  private

  def log_job_execution
    job_info = "[#{self.class.name}] [#{job_id[0..7]}]"
    start_time = Time.current

    Rails.logger.info("#{job_info} Starting with args: #{redacted_arguments}")

    yield

    duration = ((Time.current - start_time) * 1000).round(2)
    Rails.logger.info("#{job_info} Completed in #{duration}ms")
  rescue StandardError => e
    duration = ((Time.current - start_time) * 1000).round(2)
    Rails.logger.error("#{job_info} Failed after #{duration}ms: #{e.class} - #{e.message}")
    raise
  end

  # Redact sensitive arguments from logs
  def redacted_arguments
    arguments.map do |arg|
      case arg
      when Hash
        arg.transform_values { |v| sensitive_key?(arg, v) ? "[REDACTED]" : v }
      else
        arg
      end
    end.inspect
  end

  def sensitive_key?(hash, _value)
    sensitive_keys = %w[password token api_key secret key credential]
    hash.keys.any? { |k| sensitive_keys.any? { |s| k.to_s.downcase.include?(s) } }
  end
end
