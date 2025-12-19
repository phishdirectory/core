# frozen_string_literal: true

# Syncs recent changes from Sinking Yachts phishing feed
# Runs every 10 minutes to get near-real-time updates
class SinkingYachtsSyncJob < ApplicationJob
  queue_as QUEUE_MAINTENANCE

  def perform(full_sync: false)
    Rails.logger.info("[SinkingYachtsSyncJob] Starting sync (full: #{full_sync})...")

    service = Phish::SinkingYachtsService.new

    # Use 660 seconds (11 mins) overlap to ensure no gaps between 10-min runs
    result = full_sync ? service.sync_all : service.sync_recent(seconds: 660)

    if result[:success]
      if full_sync
        Rails.logger.info("[SinkingYachtsSyncJob] Full sync complete: #{result[:count]} domains")
      else
        Rails.logger.info("[SinkingYachtsSyncJob] Sync complete: #{result[:added]} added, #{result[:removed]} removed")
      end
    else
      Rails.logger.error("[SinkingYachtsSyncJob] Sync failed: #{result[:error]}")
    end
  end
end
