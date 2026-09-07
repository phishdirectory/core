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
  #
  # Hosting is matched strongest signal first:
  #
  #   1. CNAME and reverse lookups name the platform or machine serving the
  #      page. A site on platform hosting resolves to a shared anycast address
  #      that belongs to a CDN, so these are often the only records that name
  #      the party who can take it down.
  #   2. The addresses name the network that owns them.
  #   3. Nameservers name only the DNS operator, which is frequently a
  #      different company: github.com delegates to Route 53 but is served by
  #      GitHub, so matching here first would report to the wrong party.
  #
  # MX is deliberately absent. It names who carries the mail, not who serves
  # the page; mail_hosts surfaces it for a human to route by hand.
  def match_contacts!
    self.matched_registrar_contact = Report::AbuseContact.find_for_registrar(registrar_name)
    self.matched_hosting_contact =
      Report::AbuseContact.find_for_hostnames(serving_hostnames) ||
      Report::AbuseContact.find_for_ip(resolved_addresses) ||
      Report::AbuseContact.find_for_hostnames(nameserver_hostnames)
    self.hosting_provider = matched_hosting_contact.name if matched_hosting_contact
    save!
  end

  # Every address the domain resolves to, both families
  #
  # @return [Array<String>]
  def resolved_addresses
    Array(a_records) + Array(aaaa_records)
  end

  # Hostnames naming the party that serves the page
  #
  # @return [Array<String>]
  def serving_hostnames
    Report::DnsSweepService.serving_hostnames(dns_records || {})
  end

  # Hostnames naming the DNS operator, from the zone and from the registry
  #
  # @return [Array<String>]
  def nameserver_hostnames
    registry = Array(nameservers).map { |ns| ns.to_s.downcase.chomp(".") }

    (Report::DnsSweepService.nameserver_hostnames(dns_records || {}) + registry)
      .compact_blank.uniq
  end

  # Every hostname the zone points at, registry nameservers included
  #
  # @return [Array<String>]
  def resolved_hostnames
    (serving_hostnames + nameserver_hostnames).uniq
  end

  # The mail hosts for the domain, for routing the mail side of a report by hand
  #
  # @return [Array<String>]
  def mail_hosts
    Array((dns_records || {})["MX"]).filter_map do |mx|
      (mx.is_a?(Hash) ? mx["exchange"] : mx).to_s.downcase.chomp(".").presence
    end
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
      a_records: a_records,
      aaaa_records: aaaa_records,
      dns_records: dns_records,
      mail_hosts: mail_hosts,
      hosting_provider: hosting_provider,
      domain_created_at: domain_created_at&.iso8601,
      domain_expires_at: domain_expires_at&.iso8601,
      lookup_source: lookup_source,
      looked_up_at: looked_up_at&.iso8601
    }.compact
  end
end
