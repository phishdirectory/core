# frozen_string_literal: true

class Report::DomainLookup < ApplicationRecord
  self.table_name = "report_domain_lookups"

  CACHE_TTL = 24.hours

  # Associations
  belongs_to :matched_hosting_contact, class_name: "Report::AbuseContact", optional: true
  belongs_to :matched_registrar_contact, class_name: "Report::AbuseContact", optional: true

  # Validations
  validates :domain, presence: true, uniqueness: true

  # Scopes
  scope :fresh, -> { where("expires_at > ?", Time.current) }
  scope :stale, -> { where("expires_at <= ? OR expires_at IS NULL", Time.current) }
  scope :with_registrar, -> { where.not(registrar_name: nil) }
  scope :with_hosting, -> { where.not(hosting_provider: nil) }

  # Class methods
  class << self
    # Find or create a lookup for a domain
    def for_domain(domain)
      find_by(domain: normalize_domain(domain))
    end

    # Check if we have a fresh lookup for a domain
    def fresh_for?(domain)
      fresh.exists?(domain: normalize_domain(domain))
    end

    # Normalize domain for storage
    def normalize_domain(domain)
      domain.to_s.downcase.strip
    end
  end

  # Instance methods

  def fresh?
    expires_at.present? && expires_at > Time.current
  end

  def stale?
    !fresh?
  end

  def refresh_needed?
    stale? || looked_up_at.nil?
  end

  # Mark lookup as complete
  def mark_looked_up!(source: nil)
    update!(
      looked_up_at: Time.current,
      expires_at: CACHE_TTL.from_now,
      lookup_source: source
    )
  end

  # Update matched contacts based on patterns
  def match_contacts!
    self.matched_registrar_contact = Report::AbuseContact.find_for_registrar(registrar_name)
    self.matched_hosting_contact = Report::AbuseContact.find_for_nameservers(nameservers)
    save!
  end

  # Get all matched contacts
  def matched_contacts
    [ matched_registrar_contact, matched_hosting_contact ].compact.uniq
  end

  # Check if we found any abuse contacts
  def has_contacts?
    matched_registrar_contact_id.present? || matched_hosting_contact_id.present?
  end

  # Summary for case domain_info
  def to_summary
    {
      registrar_name: registrar_name,
      registrar_abuse_email: registrar_abuse_email,
      nameservers: nameservers,
      hosting_provider: hosting_provider,
      domain_created_at: domain_created_at&.iso8601,
      domain_expires_at: domain_expires_at&.iso8601,
      lookup_source: lookup_source,
      looked_up_at: looked_up_at&.iso8601
    }.compact
  end
end
