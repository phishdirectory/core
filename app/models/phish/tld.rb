# frozen_string_literal: true

class Phish::Tld < ApplicationRecord
  include SoftDeletable
  include PublicIdentifiable

  self.table_name = "phish_tlds"
  set_public_id_prefix "tld"

  # Associations
  has_many :domains, class_name: "Phish::Domain", foreign_key: :tld_id, dependent: :nullify

  # Validations
  validates :name, presence: true, uniqueness: true
  validates :name, format: {
    with: /\A[a-z0-9]+([\-\.][a-z0-9]+)*\z/,
    message: "must be a valid TLD format (lowercase)"
  }

  # Normalizations
  normalizes :name, with: ->(name) { name.strip.downcase }

  # Scopes
  scope :cleandns_supported, -> { where(cleandns_supported: true) }
  scope :cleandns_unsupported, -> { where(cleandns_supported: false) }
  scope :with_domains, -> { where("domains_count > 0") }
  scope :by_domain_count, -> { order(domains_count: :desc) }
  scope :recently_synced, ->(threshold = 24.hours) { where("cleandns_synced_at > ?", threshold.ago) }
  scope :needs_sync, ->(threshold = 24.hours) {
    where("cleandns_synced_at IS NULL OR cleandns_synced_at < ?", threshold.ago)
  }

  # ===========================================
  # Class methods
  # ===========================================

  class << self
    # Extract TLD from a domain string using PublicSuffix
    # Handles compound TLDs like .co.uk, .com.au correctly
    def extract_from_domain(domain_string)
      return nil if domain_string.blank?

      normalized = domain_string.to_s.strip.downcase

      begin
        parsed = PublicSuffix.parse(normalized)
        parsed.tld
      rescue PublicSuffix::DomainNotAllowed, PublicSuffix::DomainInvalid
        # Fallback to naive extraction for invalid/unknown TLDs
        parts = normalized.split(".")
        parts.length > 1 ? parts.last : nil
      end
    end

    # Find or create TLD record from domain string
    def find_or_create_from_domain(domain_string)
      tld_name = extract_from_domain(domain_string)
      return nil if tld_name.blank?

      find_or_create_by!(name: tld_name)
    rescue ActiveRecord::RecordInvalid, ActiveRecord::RecordNotUnique
      # Handle race condition - another thread created it
      find_by(name: tld_name)
    end
  end

  # ===========================================
  # Instance methods
  # ===========================================

  def supported_by_cleandns?
    cleandns_supported?
  end

  def sync_needed?(threshold = 24.hours)
    cleandns_synced_at.nil? || cleandns_synced_at < threshold.ago
  end

  def update_from_cleandns!(registrars_list: [], resellers_list: [], supported: true)
    update!(
      cleandns_supported: supported,
      registrars: registrars_list,
      resellers: resellers_list,
      cleandns_synced_at: Time.current
    )
  end
end
