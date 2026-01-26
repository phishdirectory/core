# frozen_string_literal: true

# Syncs the PhishDestroy phishing feed
# Runs every 6 hours (real-time feed but we rate limit ourselves)
class PhishdestroySyncJob < ApplicationJob
  queue_as QUEUE_MAINTENANCE

  def perform
    Rails.logger.info("[PhishdestroySyncJob] Starting PhishDestroy feed sync...")

    service = Phish::PhishdestroyService.new
    result = service.sync_feed

    if result[:success]
      Rails.logger.info(
        "[PhishdestroySyncJob] Sync complete: #{result[:domains]} domains"
      )
    else
      Rails.logger.error("[PhishdestroySyncJob] Sync failed: #{result[:error]}")
    end
  end
end
