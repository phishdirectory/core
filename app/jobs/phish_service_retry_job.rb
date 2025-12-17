# frozen_string_literal: true

# Retries a specific phishing detection service that was previously rate-limited.
# This job is automatically scheduled by the aggregator when a service returns
# a rate limit error, ensuring we eventually get data from all sources.
#
# @example Scheduled automatically by aggregator
#   PhishServiceRetryJob.set(wait: 60.seconds).perform_later(
#     record_type: "domain",
#     record_id: domain.id,
#     service_name: "virustotal"
#   )
#
class PhishServiceRetryJob < ApplicationJob
  queue_as QUEUE_LOW_PRIORITY

  # Retry with exponential backoff if the service is still rate-limited
  retry_on Phish::BaseService::RateLimitError, wait: :polynomially_longer, attempts: 3

  # Don't retry on auth errors - those need manual intervention
  discard_on Phish::BaseService::AuthenticationError

  def perform(record_type:, record_id:, service_name:)
    record = find_record(record_type, record_id)
    return unless record

    service = instantiate_service(service_name)
    return unless service

    Rails.logger.info("[PhishRetry] Retrying #{service_name} for #{record_type}: #{record_identifier(record)}")

    # Check the domain/URL with the specific service
    result = case record_type
    when "domain"
      service.check_domain(record.domain)
    when "url"
      service.check_url(record.url)
    end

    return unless result

    # Merge the result into the existing verdict
    merge_result_into_verdict(record, result)

    Rails.logger.info("[PhishRetry] Successfully updated #{record_type} with #{service_name} result: #{result[:verdict]}")
  end

  private

  def find_record(record_type, record_id)
    case record_type
    when "domain"
      Phish::Domain.find_by(id: record_id)
    when "url"
      Phish::Url.find_by(id: record_id)
    end
  end

  def record_identifier(record)
    record.respond_to?(:domain) ? record.domain : record.url
  end

  def instantiate_service(service_name)
    case service_name.to_sym
    when :virustotal then Phish::VirustotalService.new
    when :urlscan then Phish::UrlscanService.new
    when :google_safe_browsing then Phish::GoogleSafeBrowsingService.new
    when :walshy then Phish::WalshyService.new
    else
      Rails.logger.warn("[PhishRetry] Unknown service: #{service_name}")
      nil
    end
  end

  def merge_result_into_verdict(record, new_result)
    verdict = record.verdict || Verdict.new

    # Add this source's result
    verdict.add_source(new_result[:service], new_result)

    # Recalculate the overall verdict if this result is more severe
    if should_upgrade_verdict?(verdict.classification, new_result[:verdict])
      verdict.classification = new_result[:verdict]
      verdict.confidence_score = new_result[:confidence]
    elsif verdict.classification == new_result[:verdict]
      # Same classification - take the higher confidence
      if new_result[:confidence] && new_result[:confidence] > (verdict.confidence_score || 0)
        verdict.confidence_score = new_result[:confidence]
      end
    end

    # Update metadata with retry info
    verdict.set_metadata(:last_retry_service, new_result[:service])
    verdict.set_metadata(:last_retry_at, Time.current.iso8601)

    verdict.save!

    # Associate verdict with record if new
    record.update!(verdict: verdict) unless record.verdict_id == verdict.id

    # Notify webhooks if verdict changed to phishing
    if new_result[:verdict] == "phishing" && verdict.phishing?
      notify_verdict_change(record, verdict)
    end
  end

  # Determine if new verdict should upgrade the existing one
  # Severity order: unknown < clean < suspicious < phishing
  def should_upgrade_verdict?(current, new_verdict)
    severity = { "unknown" => 0, "clean" => 1, "suspicious" => 2, "phishing" => 3 }
    (severity[new_verdict] || 0) > (severity[current] || 0)
  end

  def notify_verdict_change(record, verdict)
    if record.is_a?(Phish::Domain)
      WebhookService.notify_domain_verdict(record, verdict)
    else
      WebhookService.notify_url_verdict(record, verdict)
    end
  rescue StandardError => e
    Rails.logger.error("[PhishRetry] Failed to notify webhook: #{e.message}")
  end
end
