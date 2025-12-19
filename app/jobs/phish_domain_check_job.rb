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

    # Use the aggregator service to check multiple sources
    service = Phish::AggregatorService.new
    result = service.check_domain(domain.domain)

    # Update or create verdict
    verdict = domain.verdict || Verdict.new
    verdict.update!(
      classification: result[:verdict],
      confidence_score: result[:confidence],
      sources: result[:details]&.dig(:service_results) || [],
      metadata: result[:details] || {}
    )
    domain.update!(verdict: verdict) unless domain.verdict_id == verdict.id

    # Update last_checked_at
    domain.update!(last_checked_at: Time.current)

    # Record metrics
    ApiMetricsService.record_phish_check(
      type: "domain",
      verdict: result[:verdict],
      cached: false
    )

    # Notify webhooks if phishing detected
    if result[:verdict] == "phishing"
      WebhookService.notify_domain_verdict(domain, verdict)

      # Trigger automated reporting if enabled
      if Flipper.enabled?(:auto_reporting)
        Report::CreateCaseJob.perform_later("Phish::Domain", domain.id)
      end
    end

    result
  end
end
