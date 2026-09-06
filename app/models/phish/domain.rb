# frozen_string_literal: true

class Phish::Domain < ApplicationRecord
  include SoftDeletable
  include EncodedIds::UuidIdentifiable
  include Protectable
  include Classifiable

  self.table_name = "phish_domains"
  set_public_id_prefix "dom"

  # Associations
  belongs_to :verdict, optional: true
  belongs_to :tld, class_name: "Phish::Tld", optional: true, counter_cache: :domains_count

  # Validations
  validates :domain, presence: true, uniqueness: true
  validates :domain, format: {
    with: /\A[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}\z/i,
    message: "must be a valid domain format"
  }

  # Normalizations
  normalizes :domain, with: ->(domain) { domain.strip.downcase }

  # Callbacks
  before_validation :associate_tld, on: [ :create, :update ], if: :domain_changed?

  # Scopes
  scope :checked, -> { where.not(last_checked_at: nil) }
  scope :unchecked, -> { where(last_checked_at: nil) }
  scope :stale, ->(threshold = 24.hours) { where("last_checked_at < ?", threshold.ago) }
  scope :needs_check, -> { unchecked.or(stale) }
  scope :with_verdict, -> { where.not(verdict_id: nil) }
  scope :phishing, -> { joins(:verdict).where(verdicts: { classification: "phishing" }) }
  scope :suspicious, -> { joins(:verdict).where(verdicts: { classification: "suspicious" }) }
  scope :clean, -> { joins(:verdict).where(verdicts: { classification: "clean" }) }

  # Availability tracking scopes
  scope :seen_recently, ->(threshold = 7.days) { where("last_seen_at > ?", threshold.ago) }
  scope :not_seen_recently, ->(threshold = 7.days) { where("last_seen_at IS NULL OR last_seen_at <= ?", threshold.ago) }
  scope :needs_availability_check, ->(threshold = 1.hour) {
    where("availability_checked_at IS NULL OR availability_checked_at < ?", threshold.ago)
  }
  scope :resolvable, -> { where(dns_resolvable: true) }
  scope :reachable, -> { where(http_reachable: true) }
  scope :active_domains, -> { resolvable.reachable }

  # TLD-related scopes
  scope :with_tld, -> { where.not(tld_id: nil) }
  scope :without_tld, -> { where(tld_id: nil) }
  scope :cleandns_reportable, -> { joins(:tld).where(phish_tlds: { cleandns_supported: true }) }

  # Delegations
  delegate :classification, :confidence_score, :phishing?, :suspicious?, :clean?, :dangerous?, :safe?,
           to: :verdict, allow_nil: true
  delegate :cleandns_supported?, to: :tld, allow_nil: true, prefix: true

  # ===========================================
  # Check status helpers
  # ===========================================

  def checked?
    last_checked_at.present?
  end

  def stale?(threshold = 24.hours)
    last_checked_at.nil? || last_checked_at < threshold.ago
  end

  def needs_check?(threshold = 24.hours)
    !checked? || stale?(threshold)
  end

  # Returns true if domain has been checked before but verdict may need refreshing.
  # Uses a shorter threshold than needs_check? since this is for actively-queried domains.
  def needs_recheck?(threshold = 4.hours)
    checked? && stale?(threshold)
  end

  # ===========================================
  # Verdict management
  # ===========================================

  def update_verdict!(new_verdict)
    update!(verdict: new_verdict, last_checked_at: Time.current)
  end

  def mark_checked!
    update!(last_checked_at: Time.current)
  end

  # ===========================================
  # Availability tracking
  # ===========================================

  def touch_last_seen!
    update!(last_seen_at: Time.current)
  end

  def update_availability!(dns_resolvable:, http_reachable:)
    update!(
      dns_resolvable: dns_resolvable,
      http_reachable: http_reachable,
      availability_checked_at: Time.current
    )
  end

  def available?
    dns_resolvable? && http_reachable?
  end

  def needs_availability_check?(threshold = 1.hour)
    availability_checked_at.nil? || availability_checked_at < threshold.ago
  end

  # ===========================================
  # TLD helpers
  # ===========================================

  def tld_name
    tld&.name || Phish::Tld.extract_from_domain(domain)
  end

  # ===========================================
  # Class methods
  # ===========================================

  class << self
    def find_or_create_for_check(domain_string)
      find_or_create_by!(domain: domain_string.strip.downcase)
    end

    def extract_domain(url_or_domain)
      return url_or_domain if url_or_domain !~ %r{://}

      URI.parse(url_or_domain).host
    rescue URI::InvalidURIError
      url_or_domain
    end
  end

  private

  def associate_tld
    return if domain.blank?

    self.tld = Phish::Tld.find_or_create_from_domain(domain)
  end

  # Required by Protectable concern
  def protectable_value
    domain
  end
end
