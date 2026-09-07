# frozen_string_literal: true

class PhishUrlCheckJob < ApplicationJob
  queue_as QUEUE_DEFAULT

  # Retry with exponential backoff for transient errors
  retry_on Phish::BaseService::RateLimitError, wait: :polynomially_longer, attempts: 5
  retry_on Faraday::TimeoutError, wait: 30.seconds, attempts: 3
  retry_on Faraday::ConnectionFailed, wait: 1.minute, attempts: 3

  # Don't retry on auth errors - those need manual intervention
  discard_on Phish::BaseService::AuthenticationError
  discard_on ActiveRecord::RecordNotFound

  def perform(url_id)
    phish_url = Phish::Url.find(url_id)

    Rails.logger.info("[PhishCheck] Checking URL: #{phish_url.url}")

    # Use VerdictService to check and update atomically
    result = VerdictService.check_url!(phish_url)

    # Record metrics
    ApiMetricsService.record_phish_check(
      type: "url",
      verdict: result[:verdict],
      cached: false
    )

    # Notify webhooks if phishing detected
    if result[:verdict] == "phishing"
      WebhookService.notify_url_verdict(phish_url, phish_url.verdict)

      # Trigger automated reporting if enabled
      if Flipper.enabled?(:auto_reporting)
        Report::CreateCaseJob.perform_later("Phish::Url", phish_url.id)
      end
    end

    result
  end
end
