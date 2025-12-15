# frozen_string_literal: true

class ApplicationJob < ActiveJob::Base
  # Automatically retry jobs that encountered a deadlock
  retry_on ActiveRecord::Deadlocked, wait: :polynomially_longer, attempts: 5

  # Most jobs are safe to ignore if the underlying records are no longer available
  discard_on ActiveJob::DeserializationError

  # Retry on network errors
  retry_on Faraday::Error, wait: :polynomially_longer, attempts: 3

  # Log job execution
  around_perform :log_job_execution

  private

  def log_job_execution
    start_time = Time.current
    Rails.logger.info("[#{self.class.name}] Starting job with args: #{arguments.inspect}")

    yield

    duration = ((Time.current - start_time) * 1000).round(2)
    Rails.logger.info("[#{self.class.name}] Completed in #{duration}ms")
  rescue StandardError => e
    Rails.logger.error("[#{self.class.name}] Failed: #{e.message}")
    raise
  end
end
