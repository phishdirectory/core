# frozen_string_literal: true

# One-time job to backfill all existing phishing URLs to OTX pulse
# Usually run after OtxBackfillJob with include_urls: true
# Or manually: OtxUrlBackfillJob.perform_later
class OtxUrlBackfillJob < ApplicationJob
  queue_as QUEUE_LOW_PRIORITY

  BATCH_SIZE = 100
  BATCH_DELAY = 5.seconds

  def perform(batch_offset: 0)
    otx_service = Phish::OtxService.new
    unless otx_service.configured?
      Rails.logger.error("[OtxUrlBackfillJob] OTX not configured, aborting")
      return
    end

    Rails.logger.info("[OtxUrlBackfillJob] Starting URL backfill (offset: #{batch_offset})...")

    # Get batch of phishing URLs
    urls = Phish::Url.phishing
                     .order(:created_at)
                     .offset(batch_offset)
                     .limit(BATCH_SIZE)
                     .pluck(:url)

    if urls.empty?
      Rails.logger.info("[OtxUrlBackfillJob] URL backfill complete!")
      return
    end

    # Add URLs to OTX in bulk
    result = otx_service.add_urls(urls)

    if result[:success]
      Rails.logger.info("[OtxUrlBackfillJob] Added #{result[:added]} URLs to OTX pulse")
    else
      Rails.logger.error("[OtxUrlBackfillJob] Failed to add URLs: #{result[:error]}")
    end

    # Schedule next batch
    if urls.size == BATCH_SIZE
      OtxUrlBackfillJob.set(wait: BATCH_DELAY).perform_later(
        batch_offset: batch_offset + BATCH_SIZE
      )
    else
      Rails.logger.info("[OtxUrlBackfillJob] URL backfill complete!")
    end
  end
end
