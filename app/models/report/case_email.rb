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

  # Attachments - preserved before Action Mailbox incineration
  has_many_attached :attachments

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
  scope :with_attachments, -> { joins(:attachments_attachments).distinct }

  # Callbacks
  before_validation :set_received_at, on: :create

  # Instance methods

  # Check if this is an inbound reply
  def reply?
    direction_inbound? && from_address.present?
  end

  # Check if email has attachments
  def has_attachments?
    attachments.attached?
  end

  # Get message ID from parsed headers
  def message_id
    parsed_data&.dig("message_id")
  end

  # Get the original email this is replying to
  def in_reply_to
    parsed_data&.dig("in_reply_to")
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
  # Preserves all content before Action Mailbox incineration
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
      body_text: extract_text_body(mail),
      body_html: mail.html_part&.body&.decoded,
      received_at: mail.date || Time.current,
      parsed_data: extract_headers(mail)
    )

    # Preserve attachments before incineration
    preserve_attachments!(email, mail)

    email.update_submission_reference!
    email
  end

  # Extract text body, handling multipart and plain emails
  def self.extract_text_body(mail)
    if mail.multipart?
      mail.text_part&.body&.decoded
    else
      mail.body&.decoded if mail.content_type&.start_with?("text/plain")
    end
  end

  # Extract important headers for reference
  def self.extract_headers(mail)
    {
      message_id: mail.message_id,
      in_reply_to: mail.in_reply_to,
      references: mail.references,
      reply_to: mail.reply_to&.first,
      return_path: mail.return_path,
      content_type: mail.content_type,
      x_mailer: mail.header["X-Mailer"]&.to_s,
      received_spf: mail.header["Received-SPF"]&.to_s
    }.compact
  end

  # Preserve attachments to Active Storage
  def self.preserve_attachments!(email, mail)
    return unless mail.attachments.any?

    mail.attachments.each do |attachment|
      # Skip inline images that are part of HTML body
      next if attachment.content_disposition&.include?("inline") && attachment.content_type&.start_with?("image/")

      email.attachments.attach(
        io: StringIO.new(attachment.body.decoded),
        filename: attachment.filename.presence || "attachment",
        content_type: attachment.content_type&.split(";")&.first || "application/octet-stream"
      )
    rescue => e
      Rails.logger.warn("[CaseEmail] Failed to preserve attachment #{attachment.filename}: #{e.message}")
    end
  end

  private

  def set_received_at
    self.received_at ||= Time.current
  end
end
