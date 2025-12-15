# frozen_string_literal: true

class PhishDomainCheckJob < ApplicationJob
  queue_as :default

  def perform(domain_id)
    domain = Phish::Domain.find_by(id: domain_id)
    return unless domain

    Rails.logger.info("[PhishCheck] Checking domain: #{domain.domain}")

    # Use the aggregator service to check multiple sources
    service = Phish::AggregatorService.new
    result = service.check_domain(domain.domain)

    # Update or create verdict
    verdict = domain.verdict || domain.build_verdict
    verdict.update!(
      verdict: result[:verdict],
      confidence: result[:confidence],
      details: result[:details]
    )

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
    end

    result
  end
end
