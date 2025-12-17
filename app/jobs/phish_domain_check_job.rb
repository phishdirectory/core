# frozen_string_literal: true

class PhishDomainCheckJob < ApplicationJob
  queue_as QUEUE_DEFAULT

  def perform(domain_id)
    domain = Phish::Domain.find_by(id: domain_id)
    return unless domain

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
    end

    result
  end
end
