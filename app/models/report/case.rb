# frozen_string_literal: true

class Report::Case < ApplicationRecord
  self.table_name = "report_cases"

  include AASM
  include SoftDeletable
  include PublicIdentifiable
  include FlakeIdentifiable

  set_public_id_prefix "rpc"
  set_flake_prefix "case"
  set_flake_column :case_number

  has_paper_trail

  # Active Storage for manual review PDFs
  has_one_attached :manual_review_pdf

  # Associations
  belongs_to :reportable, polymorphic: true
  belongs_to :verdict_snapshot, class_name: "Verdict"

  has_many :submissions, class_name: "Report::Submission",
           foreign_key: :case_id,
           dependent: :destroy,
           inverse_of: :case,
           counter_cache: :submissions_count

  has_many :emails, class_name: "Report::CaseEmail",
           foreign_key: :case_id,
           dependent: :destroy,
           inverse_of: :case

  has_many :abuse_contacts, through: :submissions

  # Enum
  enum :status, {
    pending: "pending",
    submitting: "submitting",
    awaiting_response: "awaiting_response",
    partially_resolved: "partially_resolved",
    resolved: "resolved",
    escalated: "escalated"
  }, prefix: true

  # Validations
  validates :case_number, presence: true, uniqueness: true
  validates :confidence_at_creation, presence: true,
            numericality: { greater_than_or_equal_to: 0, less_than_or_equal_to: 1 }
  validates :reportable_type, inclusion: { in: %w[Phish::Domain Phish::Url] }

  # Scopes
  scope :active, -> { where(status: %w[pending submitting awaiting_response]) }
  scope :needs_attention, -> { where(status: %w[pending escalated]) }
  scope :needs_manual_review, -> { where(requires_manual_review: true) }
  scope :for_domain, ->(domain_id) { where(reportable_type: "Phish::Domain", reportable_id: domain_id) }
  scope :for_url, ->(url_id) { where(reportable_type: "Phish::Url", reportable_id: url_id) }
  scope :recent, -> { order(created_at: :desc) }

  # AASM State Machine
  aasm column: :status, enum: true do
    state :pending, initial: true
    state :submitting
    state :awaiting_response
    state :partially_resolved
    state :resolved
    state :escalated

    event :start_submitting do
      transitions from: :pending, to: :submitting
      after do
        update!(first_submitted_at: Time.current)
        update_activity!
      end
    end

    event :await_responses do
      transitions from: :submitting, to: :awaiting_response
      after { update_activity! }
    end

    event :partial_resolve do
      transitions from: %i[submitting awaiting_response], to: :partially_resolved
      after { update_activity! }
    end

    event :resolve do
      transitions from: %i[awaiting_response partially_resolved escalated], to: :resolved
      after do
        update!(resolved_at: Time.current)
        update_activity!
      end
    end

    event :escalate do
      transitions from: %i[pending submitting awaiting_response partially_resolved], to: :escalated
      after { update_activity! }
    end

    event :reopen do
      transitions from: %i[resolved escalated], to: :awaiting_response
      after { update_activity! }
    end
  end

  # Instance methods

  # Get the domain name (works for both Domain and URL reportables)
  def domain_name
    case reportable_type
    when "Phish::Domain"
      reportable&.domain
    when "Phish::Url"
      reportable&.domain
    end
  end

  # Get URL if reportable is a URL
  def url_value
    reportable_type == "Phish::Url" ? reportable&.url : nil
  end

  # Email address for CC'ing on reports (enables reply threading)
  def email_address
    "#{case_number}@cases.phish.directory"
  end

  # Update last_activity_at timestamp
  def update_activity!
    update!(last_activity_at: Time.current)
  end

  # Check if all submissions are resolved
  def all_submissions_resolved?
    submissions.where.not(status: %w[resolved skipped failed]).empty?
  end

  # Check if any submissions are still pending/queued
  def has_pending_submissions?
    submissions.where(status: %w[pending queued]).exists?
  end

  # Get submissions ready to be sent
  def ready_submissions
    submissions.pending.select(&:dependency_satisfied?)
  end

  # Update case status based on submissions
  def update_status_from_submissions!
    return if status_resolved? || status_escalated?

    if all_submissions_resolved?
      resolve! if may_resolve?
    elsif submissions.where(status: "resolved").exists?
      partial_resolve! if may_partial_resolve?
    elsif !has_pending_submissions? && submissions.where(status: "sent").exists?
      await_responses! if may_await_responses?
    end
  end

  # Mark for manual review
  def mark_for_manual_review!(reason = nil)
    update!(
      requires_manual_review: true,
      notes: [notes, "Manual review required: #{reason}"].compact.join("\n")
    )
  end
end
