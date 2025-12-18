# frozen_string_literal: true

# Syncs the full FishFish domain list to local cache
# Run weekly to ensure we have the latest phishing domains
class FishFishSyncJob < ApplicationJob
  queue_as QUEUE_MAINTENANCE

  def perform
    Rails.logger.info("[FishFishSyncJob] Starting FishFish sync...")

    service = Phish::FishFishService.new
    result = service.sync_domain_list

    if result[:success]
      Rails.logger.info("[FishFishSyncJob] Sync complete: #{result[:count]} domains cached")
    else
      Rails.logger.error("[FishFishSyncJob] Sync failed: #{result[:error]}")
    end
  end
end
