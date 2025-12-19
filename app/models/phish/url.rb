# frozen_string_literal: true

class Phish::Url < ApplicationRecord
  include SoftDeletable
  include PublicIdentifiable
  include Classifiable

  self.table_name = "phish_urls"
  set_public_id_prefix "url"

  # Associations
  belongs_to :verdict, optional: true

  # Validations
  validates :url, presence: true, uniqueness: true
  validates :url, format: {
    with: URI::DEFAULT_PARSER.make_regexp(%w[http https]),
    message: "must be a valid HTTP/HTTPS URL"
  }

  # Normalizations
  normalizes :url, with: ->(url) { url.strip }

  # Scopes
  scope :checked, -> { where.not(last_checked_at: nil) }
  scope :unchecked, -> { where(last_checked_at: nil) }
  scope :stale, ->(threshold = 24.hours) { where("last_checked_at < ?", threshold.ago) }
  scope :needs_check, -> { unchecked.or(stale) }
  scope :with_verdict, -> { where.not(verdict_id: nil) }
  scope :phishing, -> { joins(:verdict).where(verdicts: { classification: "phishing" }) }
  scope :suspicious, -> { joins(:verdict).where(verdicts: { classification: "suspicious" }) }
  scope :clean, -> { joins(:verdict).where(verdicts: { classification: "clean" }) }
  scope :seen_recently, ->(threshold = 7.days) { where("last_seen_at > ?", threshold.ago) }
  scope :not_seen_recently, ->(threshold = 7.days) { where("last_seen_at IS NULL OR last_seen_at <= ?", threshold.ago) }

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

  # Returns true if URL has been checked before but verdict may need refreshing.
  # Uses a shorter threshold than needs_check? since this is for actively-queried URLs.
  def needs_recheck?(threshold = 4.hours)
    checked? && stale?(threshold)
  end

  # ===========================================
  # URL parsing helpers
  # ===========================================

  def parsed_uri
    @parsed_uri ||= URI.parse(url)
  rescue URI::InvalidURIError
    nil
  end

  def domain
    parsed_uri&.host
  end

  def path
    parsed_uri&.path
  end

  def query_string
    parsed_uri&.query
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
  # Class methods
  # ===========================================

  class << self
    def find_or_create_for_check(url_string)
      find_or_create_by!(url: url_string.strip)
    end
  end
end
