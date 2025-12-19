# frozen_string_literal: true

# Backfills TLD associations for existing domains
# Run once after migration, or periodically to catch any missed domains
class TldBackfillJob < ApplicationJob
  queue_as QUEUE_MAINTENANCE

  BATCH_SIZE = 1000

  def perform(batch_offset: 0)
    Rails.logger.info("[TldBackfillJob] Starting TLD backfill (offset: #{batch_offset})...")

    domains = Phish::Domain.without_tld
                           .order(:created_at)
                           .offset(batch_offset)
                           .limit(BATCH_SIZE)

    if domains.empty?
      finalize_backfill
      return
    end

    processed = 0
    errors = 0

    domains.each do |domain|
      tld = Phish::Tld.find_or_create_from_domain(domain.domain)
      if tld
        domain.update_column(:tld_id, tld.id)
        processed += 1
      else
        errors += 1
      end
    rescue StandardError => e
      Rails.logger.error("[TldBackfillJob] Error processing #{domain.domain}: #{e.message}")
      errors += 1
    end

    Rails.logger.info("[TldBackfillJob] Processed #{processed} domains, #{errors} errors")

    # Schedule next batch if there might be more
    if domains.size == BATCH_SIZE
      TldBackfillJob.perform_later(batch_offset: batch_offset + BATCH_SIZE)
    else
      finalize_backfill
    end
  end

  private

  def finalize_backfill
    # Update counter caches after backfill completes
    Rails.logger.info("[TldBackfillJob] Updating counter caches...")

    Phish::Tld.find_each do |tld|
      Phish::Tld.reset_counters(tld.id, :domains)
    end

    Rails.logger.info("[TldBackfillJob] Backfill complete, counter caches updated!")
  end
end
