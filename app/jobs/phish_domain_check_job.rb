# frozen_string_literal: true

class PhishDomainCheckJob < ApplicationJob
  queue_as QUEUE_DEFAULT

  # Retry with exponential backoff for transient errors
  retry_on Phish::BaseService::RateLimitError, wait: :polynomially_longer, attempts: 5
  retry_on Faraday::TimeoutError, wait: 30.seconds, attempts: 3
  retry_on Faraday::ConnectionFailed, wait: 1.minute, attempts: 3

  # Don't retry on auth errors - those need manual intervention
  discard_on Phish::BaseService::AuthenticationError
  discard_on ActiveRecord::RecordNotFound

  def perform(domain_id)
    domain = Phish::Domain.find(domain_id)

    Rails.logger.info("[PhishCheck] Checking domain: #{domain.domain}")

    # Use VerdictService to check and update atomically
    result = VerdictService.check_domain!(domain)

    # Record metrics
    ApiMetricsService.record_phish_check(
      type: "domain",
      verdict: result[:verdict],
      cached: false
    )

    # Notify webhooks if phishing detected
    if result[:verdict] == "phishing"
      WebhookService.notify_domain_verdict(domain, domain.verdict)

      # Trigger automated reporting if enabled
      if Flipper.enabled?(:auto_reporting)
        Report::CreateCaseJob.perform_later("Phish::Domain", domain.id)
      end
    end

    result
  end
end
