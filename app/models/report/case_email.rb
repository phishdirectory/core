# frozen_string_literal: true

class Report::CaseEmail < ApplicationRecord
  self.table_name = "report_case_emails"

  include PublicIdentifiable

  set_public_id_prefix "rce"

  # Associations
  belongs_to :case, class_name: "Report::Case"
  belongs_to :submission, class_name: "Report::Submission", optional: true
  belongs_to :action_mailbox_inbound_email,
             class_name: "ActionMailbox::InboundEmail",
             optional: true

  # Enum
  enum :direction, {
    inbound: "inbound",
    outbound: "outbound"
  }, prefix: true

  # Validations
  validates :direction, presence: true

  # Scopes
  scope :inbound, -> { where(direction: "inbound") }
  scope :outbound, -> { where(direction: "outbound") }
  scope :recent, -> { order(received_at: :desc, created_at: :desc) }
  scope :for_submission, ->(submission_id) { where(submission_id: submission_id) }

  # Callbacks
  before_validation :set_received_at, on: :create

  # Instance methods

  # Check if this is an inbound reply
  def reply?
    direction_inbound? && from_address.present?
  end

  # Get a preview of the body
  def body_preview(length: 200)
    text = body_text.presence || ActionController::Base.helpers.strip_tags(body_html)
    text&.truncate(length)
  end

  # Parse ticket/reference numbers from the email
  def extract_reference_numbers
    text = [subject, body_text].compact.join(" ")

    # Common patterns for ticket numbers
    patterns = [
      /ticket[:\s#]*(\w+-?\d+)/i,
      /case[:\s#]*(\w+-?\d+)/i,
      /ref[:\s#]*(\w+-?\d+)/i,
      /incident[:\s#]*(\w+-?\d+)/i,
      /#(\d{5,})/
    ]

    references = patterns.flat_map do |pattern|
      text.scan(pattern).flatten
    end

    references.uniq
  end

  # Update submission with extracted reference
  def update_submission_reference!
    return unless submission && direction_inbound?

    refs = extract_reference_numbers
    return if refs.empty?

    submission.update!(submission_reference: refs.first) unless submission.submission_reference.present?
  end

  # Create from an outbound mailer
  def self.create_from_outbound!(case_record:, submission: nil, mail:)
    create!(
      case: case_record,
      submission: submission,
      direction: :outbound,
      from_address: mail.from&.first,
      to_addresses: Array(mail.to),
      cc_addresses: Array(mail.cc),
      subject: mail.subject,
      body_text: mail.text_part&.body&.decoded,
      body_html: mail.html_part&.body&.decoded,
      received_at: Time.current
    )
  end

  # Create from an inbound Action Mailbox email
  def self.create_from_inbound!(case_record:, submission: nil, inbound_email:)
    mail = inbound_email.mail

    email = create!(
      case: case_record,
      submission: submission,
      action_mailbox_inbound_email: inbound_email,
      direction: :inbound,
      from_address: mail.from&.first,
      to_addresses: Array(mail.to),
      cc_addresses: Array(mail.cc),
      subject: mail.subject,
      body_text: mail.text_part&.body&.decoded || mail.body&.decoded,
      body_html: mail.html_part&.body&.decoded,
      received_at: mail.date || Time.current
    )

    email.update_submission_reference!
    email
  end

  private

  def set_received_at
    self.received_at ||= Time.current
  end
end
