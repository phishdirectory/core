# frozen_string_literal: true

class Phish::Email < ApplicationRecord
  include SoftDeletable
  include EncodedIds::UuidIdentifiable
  include Protectable
  include Classifiable

  self.table_name = "phish_emails"
  set_public_id_prefix "eml"

  # Associations
  belongs_to :verdict, optional: true
  belongs_to :marked_clean_by, class_name: "User", optional: true

  # Validations
  validates :email, presence: true, uniqueness: true
  validates :email, email_format: { message: "must be a valid email format" }
  validates :reputation_score, numericality: { greater_than_or_equal_to: 0, less_than_or_equal_to: 1 }, allow_nil: true

  # Normalizations
  normalizes :email, with: ->(email) { email.to_s.strip.downcase }

  # Callbacks
  before_validation :extract_domain, on: [:create, :update], if: :email_changed?

  # Scopes
  scope :checked, -> { where.not(last_checked_at: nil) }
  scope :unchecked, -> { where(last_checked_at: nil) }
  scope :stale, ->(threshold = 24.hours) { where("last_checked_at < ?", threshold.ago) }
  scope :needs_check, -> { unchecked.or(stale) }
  scope :with_verdict, -> { where.not(verdict_id: nil) }
  scope :phishing, -> { joins(:verdict).where(verdicts: { classification: "phishing" }) }
  scope :suspicious, -> { joins(:verdict).where(verdicts: { classification: "suspicious" }) }
  scope :clean, -> { joins(:verdict).where(verdicts: { classification: "clean" }) }

  # Usage tracking scopes
  scope :seen_recently, ->(threshold = 7.days) { where("last_seen_at > ?", threshold.ago) }
  scope :not_seen_recently, ->(threshold = 7.days) { where("last_seen_at IS NULL OR last_seen_at <= ?", threshold.ago) }

  # Email type scopes
  scope :disposable, -> { where(disposable: true) }
  scope :free_provider, -> { where(free_provider: true) }
  scope :deliverable, -> { where(deliverable: true) }
  scope :undeliverable, -> { where(deliverable: false) }
  scope :valid_mx, -> { where(valid_mx: true) }
  scope :for_domain, ->(domain) { where(domain: domain.downcase) }
  scope :high_reputation, -> { where("reputation_score >= ?", 0.7) }
  scope :low_reputation, -> { where("reputation_score < ?", 0.3) }

  # Delegations
  delegate :classification, :confidence_score, :phishing?, :suspicious?, :clean?, :dangerous?, :safe?,
           to: :verdict, allow_nil: true

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

  # Returns true if email has been checked before but verdict may need refreshing.
  # Uses a shorter threshold than needs_check? since this is for actively-queried emails.
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
  # Usage tracking
  # ===========================================

  def touch_last_seen!
    update!(last_seen_at: Time.current)
  end

  # ===========================================
  # Email metadata helpers
  # ===========================================

  def risky?
    disposable? || (reputation_score.present? && reputation_score < 0.3)
  end

  def trusted?
    !disposable? && deliverable? && valid_mx? && (reputation_score.nil? || reputation_score >= 0.7)
  end

  def update_metadata!(attrs)
    update!(attrs.slice(:disposable, :free_provider, :deliverable, :valid_mx, :reputation_score))
  end

  # ===========================================
  # Email parsing helpers
  # ===========================================

  def local_part
    email&.split("@")&.first
  end

  def domain_part
    domain || email&.split("@")&.last
  end

  # ===========================================
  # Class methods
  # ===========================================

  class << self
    def find_or_create_for_check(email_string)
      normalized = email_string.to_s.strip.downcase
      create_or_find_by!(email: normalized)
    end

    def normalize_email(email_string)
      email_string.to_s.strip.downcase
    end

    def valid_email?(email_string)
      return false if email_string.blank?

      # Basic email format check
      email_string.to_s.match?(/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/)
    end

    def extract_domain(email_string)
      email_string.to_s.strip.downcase.split("@").last
    end
  end

  private

  def extract_domain
    return if email.blank?

    self.domain = email.split("@").last
  end

  # Required by Protectable concern
  def protectable_value
    email
  end
end
