# frozen_string_literal: true

class PhishUrlCheckJob < ApplicationJob
  queue_as QUEUE_DEFAULT

  def perform(url_id)
    phish_url = Phish::Url.find_by(id: url_id)
    return unless phish_url

    Rails.logger.info("[PhishCheck] Checking URL: #{phish_url.url}")

    # Use the aggregator service to check multiple sources
    service = Phish::AggregatorService.new
    result = service.check_url(phish_url.url)

    # Update or create verdict
    verdict = phish_url.verdict || phish_url.build_verdict
    verdict.update!(
      verdict: result[:verdict],
      confidence: result[:confidence],
      details: result[:details]
    )

    # Update last_checked_at
    phish_url.update!(last_checked_at: Time.current)

    # Record metrics
    ApiMetricsService.record_phish_check(
      type: "url",
      verdict: result[:verdict],
      cached: false
    )

    result
  end
end
