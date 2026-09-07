# frozen_string_literal: true

class Report::AbuseContact < ApplicationRecord
  self.table_name = "report_abuse_contacts"

  include SoftDeletable
  include EncodedIds::UuidIdentifiable

  set_public_id_prefix "rac"

  has_paper_trail

  # Lockbox encryption for API credentials
  has_encrypted :api_endpoint, :api_key

  # Associations
  has_many :submissions, class_name: "Report::Submission",
           foreign_key: :abuse_contact_id,
           dependent: :restrict_with_error,
           inverse_of: :abuse_contact

  has_many :matched_as_hosting, class_name: "Report::DomainLookup",
           foreign_key: :matched_hosting_contact_id,
           dependent: :nullify,
           inverse_of: :matched_hosting_contact

  has_many :matched_as_registrar, class_name: "Report::DomainLookup",
           foreign_key: :matched_registrar_contact_id,
           dependent: :nullify,
           inverse_of: :matched_registrar_contact

  # Enums
  enum :contact_type, {
    registrar: "registrar",
    hosting: "hosting",
    security_vendor: "security_vendor",
    other: "other"
  }, prefix: true

  enum :method, {
    email: "email",
    web_form: "web_form",
    api: "api"
  }, prefix: :contact

  # Validations
  validates :name, presence: true
  validates :contact_type, presence: true
  validates :method, presence: true
  validates :email, presence: true, if: -> { contact_email? }
  validates :web_form_url, presence: true, if: -> { contact_web_form? }
  validates :email, format: { with: URI::MailTo::EMAIL_REGEXP }, allow_blank: true
  validates :web_form_url, format: { with: URI::DEFAULT_PARSER.make_regexp(%w[http https]) }, allow_blank: true
  validates :priority, numericality: { only_integer: true, greater_than: 0 }

  # Scopes
  scope :active, -> { where(active: true) }
  scope :inactive, -> { where(active: false) }
  scope :registrars, -> { where(contact_type: "registrar") }
  scope :hosting_providers, -> { where(contact_type: "hosting") }
  scope :security_vendors, -> { where(contact_type: "security_vendor") }
  scope :trusted, -> { where(trusted_reporter: true) }
  scope :by_priority, -> { order(priority: :asc) }
  scope :with_ip_ranges, -> { where("jsonb_array_length(ip_ranges) > 0") }

  # Class methods
  class << self
    # Find contact matching a registrar name
    def find_for_registrar(registrar_name)
      return nil if registrar_name.blank?

      active.registrars.find do |contact|
        patterns = contact.registrar_patterns || []
        patterns.any? { |p| registrar_name.downcase.include?(p.downcase) }
      end
    end

    # Find contact matching any hostname the domain's zone points at
    #
    # Nameservers, CNAME targets, reverse lookups and MX exchanges all name a
    # provider the same way, so one list of globs per contact matches all of
    # them. A CNAME is often the only record that names the platform serving a
    # phishing page, because its addresses are shared anycast ones.
    #
    # @param hostnames [Array<String>] hostnames from the zone
    # @return [Report::AbuseContact, nil]
    def find_for_hostnames(hostnames)
      hostnames = Array(hostnames).compact_blank
      return nil if hostnames.empty?

      active.by_priority.find { |contact| contact.matches_hostname?(hostnames) }
    end
    alias_method :find_for_nameservers, :find_for_hostnames

    # Find contact whose published IP ranges cover any of the given addresses
    #
    # Nameserver patterns only identify a host when the site also uses that
    # host's DNS, which phishing sites usually do not. Matching the addresses a
    # domain actually resolves to is what finds the provider serving the page.
    #
    # @param addresses [Array<String>] IP addresses the domain resolves to
    # @return [Report::AbuseContact, nil]
    def find_for_ip(addresses)
      ips = Array(addresses).filter_map { |address| parse_ip(address) }
      return nil if ips.empty?

      active.with_ip_ranges.by_priority.find { |contact| contact.covers_ip?(ips) }
    end

    # Get all contacts that should always receive reports
    def always_report_to
      active.trusted.by_priority
    end

    private

    def parse_ip(address)
      IPAddr.new(address.to_s)
    rescue IPAddr::InvalidAddressError
      nil
    end
  end

  # Instance methods

  # Check whether any of the given hostnames matches this contact's patterns
  #
  # A bare pattern also matches its own subdomains, so "digitalocean.com"
  # covers "ns1.digitalocean.com" without every entry needing a glob.
  #
  # @param hostnames [Array<String>] hostnames from the zone
  # @return [Boolean]
  def matches_hostname?(hostnames)
    patterns = Array(hostname_patterns).compact_blank
    return false if patterns.empty?

    names = Array(hostnames).map { |name| name.to_s.downcase.chomp(".") }

    patterns.any? do |pattern|
      pattern = pattern.to_s.downcase.chomp(".")

      names.any? do |name|
        File.fnmatch?(pattern, name, File::FNM_CASEFOLD) ||
          name == pattern ||
          name.end_with?(".#{pattern}")
      end
    end
  end

  # Check whether any of the given addresses falls inside this contact's ranges
  #
  # @param addresses [Array<IPAddr>] parsed addresses
  # @return [Boolean]
  def covers_ip?(addresses)
    return false if cidr_ranges.empty?

    Array(addresses).any? do |address|
      cidr_ranges.any? { |range| range.include?(address) }
    end
  end

  def operational?
    active? && kept?
  end

  def record_submission_sent!
    increment!(:reports_sent)
  end

  def record_acknowledgment!
    increment!(:reports_acknowledged)
    update_response_stats!
  end

  # Display name with organization
  def display_name
    organization.present? ? "#{name} (#{organization})" : name
  end

  private

  # DigitalOcean publishes around 1200 ranges, so parse them once per record.
  def cidr_ranges
    @cidr_ranges ||= Array(ip_ranges).filter_map do |range|
      IPAddr.new(range.to_s)
    rescue IPAddr::InvalidAddressError
      nil
    end
  end

  def update_response_stats!
    acknowledged = submissions.where.not(acknowledged_at: nil)
    return if acknowledged.empty?

    avg_hours = acknowledged.average(
      Arel.sql("EXTRACT(EPOCH FROM (acknowledged_at - sent_at)) / 3600")
    )
    update!(avg_response_hours: avg_hours) if avg_hours
  end
end
