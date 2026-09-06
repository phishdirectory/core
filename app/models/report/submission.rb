# frozen_string_literal: true

class Report::Submission < ApplicationRecord
  self.table_name = "report_submissions"

  include AASM
  include SoftDeletable
  include EncodedIds::UuidIdentifiable

  set_public_id_prefix "rsb"

  has_paper_trail

  MAX_ATTEMPTS = 5

  # Associations
  belongs_to :case, class_name: "Report::Case", counter_cache: true
  belongs_to :abuse_contact, class_name: "Report::AbuseContact"
  belongs_to :depends_on_submission, class_name: "Report::Submission", optional: true

  has_many :dependent_submissions, class_name: "Report::Submission",
           foreign_key: :depends_on_submission_id,
           dependent: :nullify,
           inverse_of: :depends_on_submission

  has_many :emails, class_name: "Report::CaseEmail",
           foreign_key: :submission_id,
           dependent: :nullify,
           inverse_of: :submission

  # Enum
  enum :status, {
    pending: "pending",
    queued: "queued",
    sent: "sent",
    acknowledged: "acknowledged",
    resolved: "resolved",
    failed: "failed",
    skipped: "skipped"
  }, prefix: true

  # Validations
  validates :case_id, uniqueness: {
    scope: :abuse_contact_id,
    message: "already has a submission to this contact"
  }

  # Callbacks
  before_create :compute_payload_hash

  # Scopes
  scope :pending, -> { where(status: "pending") }
  scope :queued, -> { where(status: "queued") }
  scope :sent, -> { where(status: "sent") }
  scope :acknowledged, -> { where(status: "acknowledged") }
  scope :resolved, -> { where(status: "resolved") }
  scope :failed, -> { where(status: "failed") }
  scope :active, -> { where(status: %w[pending queued sent acknowledged]) }
  scope :terminal, -> { where(status: %w[resolved failed skipped]) }
  scope :retryable, -> { where(status: %w[pending queued]).where("attempts < ?", MAX_ATTEMPTS) }
  scope :ready_to_send, -> {
    pending.left_joins(:depends_on_submission)
           .where(depends_on_submission_id: nil)
           .or(
             pending.left_joins(:depends_on_submission)
                    .where(depends_on_submission: { status: %w[sent acknowledged resolved] })
           )
  }
  scope :by_priority, -> { joins(:abuse_contact).order("report_abuse_contacts.priority ASC") }

  # AASM State Machine (uses PostgreSQL enum, not Rails enum)
  aasm column: :status do
    state :pending, initial: true
    state :queued
    state :sent
    state :acknowledged
    state :resolved
    state :failed
    state :skipped

    event :enqueue do
      transitions from: :pending, to: :queued
      after { update!(queued_at: Time.current) }
    end

    event :mark_sent do
      transitions from: :queued, to: :sent
      after do
        update!(sent_at: Time.current, attempts: attempts + 1, last_error: nil)
        abuse_contact.record_submission_sent!
        self.case.update_activity!
      end
    end

    event :acknowledge do
      transitions from: :sent, to: :acknowledged
      after do
        update!(acknowledged_at: Time.current)
        abuse_contact.record_acknowledgment!
        self.case.update_activity!
      end
    end

    event :mark_resolved do
      transitions from: %i[sent acknowledged], to: :resolved
      after do
        update!(resolved_at: Time.current)
        self.case.update_activity!
        self.case.update_status_from_submissions!
      end
    end

    event :fail do
      transitions from: %i[pending queued sent], to: :failed
      after { self.case.update_activity! }
    end

    event :skip do
      transitions from: :pending, to: :skipped
      after { self.case.update_status_from_submissions! }
    end

    event :retry_submission do
      transitions from: :failed, to: :pending
      after do
        update!(
          attempts: 0,
          last_error: nil,
          next_retry_at: nil
        )
      end
    end
  end

  # Instance methods

  def retryable?
    (status_pending? || status_queued?) && attempts < max_attempts
  end

  def dependency_satisfied?
    depends_on_submission.nil? ||
      depends_on_submission.status_sent? ||
      depends_on_submission.status_acknowledged? ||
      depends_on_submission.status_resolved?
  end

  def record_attempt!(error: nil)
    update!(
      attempts: attempts + 1,
      last_attempt_at: Time.current,
      last_error: error,
      next_retry_at: retryable? ? retry_delay.from_now : nil
    )
  end

  def retry_delay
    # Exponential backoff: 1m, 5m, 15m, 1h, 4h
    delays = [ 1.minute, 5.minutes, 15.minutes, 1.hour, 4.hours ]
    delays[[ attempts, delays.length - 1 ].min]
  end

  def record_response!(status_code:, body:, headers: nil, reference: nil)
    update!(
      response_status_code: status_code,
      response_body: body&.truncate(50_000),
      response: headers || {},
      submission_reference: reference
    )
  end

  # Build payload for this submission
  def build_payload
    report_case = self.case

    {
      domain: report_case.domain_name,
      url: report_case.url_value,
      classification: report_case.verdict_snapshot&.classification,
      confidence: report_case.verdict_snapshot&.confidence_score,
      sources: report_case.verdict_snapshot&.sources || [],
      detected_at: report_case.verdict_snapshot&.created_at&.iso8601,
      case_reference: report_case.case_number,
      reporter: "phish.directory",
      reporter_email: report_case.email_address
    }.compact
  end

  private

  def compute_payload_hash
    return unless payload.present?

    self.payload_hash = Digest::SHA256.hexdigest(payload.to_json)
  end
end
