# frozen_string_literal: true

# Syncs the IOK indicator corpus from phish-report/IOK.
# Runs daily; the upstream repository changes a few times a month.
class IokSyncJob < ApplicationJob
  queue_as QUEUE_MAINTENANCE

  def perform
    Rails.logger.info("[IokSyncJob] Starting IOK indicator sync...")

    result = Iok::SyncService.new.sync

    if result[:success]
      Rails.logger.info(
        "[IokSyncJob] Sync complete: #{result[:created]} created, #{result[:updated]} updated, " \
        "#{result[:unchanged]} unchanged, #{result[:invalid]} invalid, #{result[:removed]} removed"
      )
    else
      Rails.logger.error("[IokSyncJob] Sync failed: #{result[:error]}")
    end
  end
end
