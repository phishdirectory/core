# frozen_string_literal: true

# Refreshes the IP ranges on the DigitalOcean abuse contact.
# DigitalOcean reallocates blocks, so a stale list makes the report pipeline
# miss sites it should report.
class DigitalOceanRangeSyncJob < ApplicationJob
  queue_as QUEUE_MAINTENANCE

  def perform
    Rails.logger.info("[DigitalOceanRangeSyncJob] Starting DigitalOcean IP range sync...")

    result = Report::DigitalOceanRangeService.new.sync

    if result[:success]
      Rails.logger.info("[DigitalOceanRangeSyncJob] Sync complete: #{result[:ranges]} ranges stored")
    else
      Rails.logger.error("[DigitalOceanRangeSyncJob] Sync failed: #{result[:error]}")
    end
  end
end
