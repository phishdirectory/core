# frozen_string_literal: true

class BulkDomainImportJob < ApplicationJob
  queue_as QUEUE_LOW_PRIORITY

  def perform(domains, user_id)
    user = User.find(user_id)
    Rails.logger.info("[BulkDomainImport] Processing #{domains.size} domains for user #{user.pd_id}")

    imported = 0
    skipped = 0
    invalid = 0

    domains.each do |domain|
      normalized = normalize_domain(domain)

      unless valid_domain?(normalized)
        invalid += 1
        next
      end

      phish_domain = Phish::Domain.create_or_find_by!(domain: normalized)
      phish_domain.touch_last_seen!

      # Queue individual check if needed
      if phish_domain.needs_recheck?
        PhishDomainCheckJob.perform_later(phish_domain.id)
        imported += 1
      else
        skipped += 1
      end
    rescue ActiveRecord::RecordInvalid => e
      Rails.logger.warn("[BulkDomainImport] Invalid domain #{domain}: #{e.message}")
      invalid += 1
    end

    Rails.logger.info("[BulkDomainImport] Complete: #{imported} queued, #{skipped} skipped, #{invalid} invalid")

    { imported: imported, skipped: skipped, invalid: invalid }
  end

  private

  def normalize_domain(domain)
    domain = domain.sub(%r{\Ahttps?://}, "")
    domain = domain.split("/").first
    domain = domain.split(":").first
    domain
  end

  def valid_domain?(domain)
    domain.present? && domain.match?(/\A[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}\z/i)
  end
end
