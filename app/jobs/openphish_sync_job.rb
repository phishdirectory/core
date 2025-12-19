# frozen_string_literal: true

# Syncs the OpenPhish community phishing feed
# Runs every 12 hours (matches feed update frequency)
class OpenphishSyncJob < ApplicationJob
  queue_as QUEUE_MAINTENANCE

  def perform
    Rails.logger.info("[OpenphishSyncJob] Starting OpenPhish feed sync...")

    service = Phish::OpenphishService.new
    result = service.sync_feed

    if result[:success]
      Rails.logger.info(
        "[OpenphishSyncJob] Sync complete: #{result[:urls]} URLs, #{result[:domains]} domains"
      )
    else
      Rails.logger.error("[OpenphishSyncJob] Sync failed: #{result[:error]}")
    end
  end
end
