# frozen_string_literal: true

# One-time job to backfill all existing phishing domains to OTX pulse
# Run with: OtxBackfillJob.perform_later
class OtxBackfillJob < ApplicationJob
  queue_as QUEUE_LOW_PRIORITY

  # OTX API has rate limits, so we batch conservatively
  BATCH_SIZE = 100
  # Delay between batches to avoid rate limiting
  BATCH_DELAY = 5.seconds

  def perform(batch_offset: 0, include_urls: false)
    otx_service = Phish::OtxService.new
    unless otx_service.configured?
      Rails.logger.error("[OtxBackfillJob] OTX not configured, aborting")
      return
    end

    Rails.logger.info("[OtxBackfillJob] Starting backfill (offset: #{batch_offset})...")

    # Get batch of phishing domains
    domains = Phish::Domain.phishing
                           .order(:created_at)
                           .offset(batch_offset)
                           .limit(BATCH_SIZE)
                           .pluck(:domain)

    if domains.empty?
      finalize_backfill(include_urls)
      return
    end

    # Add domains to OTX in bulk
    result = otx_service.add_domains(domains)

    if result[:success]
      Rails.logger.info("[OtxBackfillJob] Added #{result[:added]} domains to OTX pulse")
    else
      Rails.logger.error("[OtxBackfillJob] Failed to add domains: #{result[:error]}")
    end

    # Schedule next batch
    if domains.size == BATCH_SIZE
      OtxBackfillJob.set(wait: BATCH_DELAY).perform_later(
        batch_offset: batch_offset + BATCH_SIZE,
        include_urls: include_urls
      )
    else
      finalize_backfill(include_urls)
    end
  end

  private

  def finalize_backfill(include_urls)
    if include_urls
      Rails.logger.info("[OtxBackfillJob] Domain backfill complete, starting URL backfill...")
      OtxUrlBackfillJob.perform_later
    else
      Rails.logger.info("[OtxBackfillJob] Backfill complete!")
    end
  end
end
