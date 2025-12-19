# frozen_string_literal: true

# Syncs TLD support data from CleanDNS API
# Run daily to keep TLD support status current
class CleandnsTldSyncJob < ApplicationJob
  queue_as QUEUE_MAINTENANCE

  def perform
    Rails.logger.info("[CleandnsTldSyncJob] Starting CleanDNS TLD sync...")

    service = Phish::CleandnsTldService.new
    result = service.sync

    if result[:success]
      Rails.logger.info(
        "[CleandnsTldSyncJob] Sync complete: " \
        "#{result[:created]} created, #{result[:updated]} updated, " \
        "#{result[:supported_tlds]} TLDs supported"
      )
    else
      Rails.logger.error("[CleandnsTldSyncJob] Sync failed: #{result[:error]}")
    end
  end
end
