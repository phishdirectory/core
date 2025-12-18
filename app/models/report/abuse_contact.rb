# frozen_string_literal: true

class Report::AbuseContact < ApplicationRecord
  self.table_name = "report_abuse_contacts"

  include SoftDeletable
  include PublicIdentifiable

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

    # Find contact matching nameservers
    def find_for_nameservers(nameservers)
      return nil if nameservers.blank?

      active.find do |contact|
        patterns = contact.nameserver_patterns || []
        patterns.any? do |pattern|
          nameservers.any? { |ns| File.fnmatch?(pattern, ns, File::FNM_CASEFOLD) }
        end
      end
    end

    # Get all contacts that should always receive reports
    def always_report_to
      active.trusted.by_priority
    end
  end

  # Instance methods
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

  def update_response_stats!
    acknowledged = submissions.where.not(acknowledged_at: nil)
    return if acknowledged.empty?

    avg_hours = acknowledged.average(
      Arel.sql("EXTRACT(EPOCH FROM (acknowledged_at - sent_at)) / 3600")
    )
    update!(avg_response_hours: avg_hours) if avg_hours
  end
end
