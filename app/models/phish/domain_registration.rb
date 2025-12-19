# frozen_string_literal: true

class Phish::DomainRegistration < ApplicationRecord
  include SoftDeletable
  include PublicIdentifiable

  self.table_name = "phish_domain_registrations"
  set_public_id_prefix "dreg"

  # Cache TTL for fresh data
  CACHE_TTL = 24.hours

  # Validations
  validates :domain, presence: true, uniqueness: true
  validates :domain, format: {
    with: /\A[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}\z/i,
    message: "must be a valid domain format"
  }
  validates :queried_at, presence: true
  validates :source, inclusion: { in: %w[rdap whois], allow_nil: true }

  # Normalizations
  normalizes :domain, with: ->(domain) { domain.strip.downcase }

  # Scopes
  scope :fresh, ->(threshold = CACHE_TTL) { where("queried_at > ?", threshold.ago) }
  scope :stale, ->(threshold = CACHE_TTL) { where("queried_at <= ?", threshold.ago) }
  scope :expiring_soon, ->(days = 30) { where("expires_at < ?", days.days.from_now).where("expires_at > ?", Time.current) }
  scope :expired, -> { where("expires_at < ?", Time.current) }
  scope :recently_registered, ->(days = 30) { where("registered_at > ?", days.days.ago) }

  # ===========================================
  # Cache management
  # ===========================================

  def fresh?(threshold = CACHE_TTL)
    queried_at > threshold.ago
  end

  def stale?(threshold = CACHE_TTL)
    !fresh?(threshold)
  end

  # ===========================================
  # Calculated fields
  # ===========================================

  def domain_age_days
    return nil unless registered_at

    ((Time.current - registered_at) / 1.day).to_i
  end

  def days_until_expiry
    return nil unless expires_at

    ((expires_at - Time.current) / 1.day).to_i
  end

  def expired?
    expires_at.present? && expires_at < Time.current
  end

  def expiring_soon?(days = 30)
    return false unless expires_at

    expires_at > Time.current && expires_at < days.days.from_now
  end

  def recently_registered?(days = 30)
    return false unless registered_at

    registered_at > days.days.ago
  end

  # ===========================================
  # Class methods
  # ===========================================

  class << self
    def find_fresh(domain)
      find_by(domain: domain.strip.downcase)&.then { |r| r.fresh? ? r : nil }
    end

    def cache_key_for(domain)
      "phish/domain_registration/#{domain.strip.downcase}"
    end
  end
end
