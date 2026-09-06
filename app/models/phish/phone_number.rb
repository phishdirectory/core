# frozen_string_literal: true

class Phish::PhoneNumber < ApplicationRecord
  include SoftDeletable
  include EncodedIds::UuidIdentifiable
  include Protectable
  include Classifiable

  self.table_name = "phish_phone_numbers"
  set_public_id_prefix "phn"

  # Associations
  belongs_to :verdict, optional: true
  belongs_to :carrier, class_name: "Phish::Carrier", optional: true, counter_cache: :phone_numbers_count
  belongs_to :marked_clean_by, class_name: "User", optional: true

  # Validations
  validates :phone_number, presence: true, uniqueness: true
  validates :phone_number, format: {
    with: /\A\+[1-9]\d{1,14}\z/,
    message: "must be in E.164 format (e.g., +14155551234)"
  }

  PHONE_TYPES = %w[mobile voip landline toll_free unknown].freeze
  validates :phone_type, inclusion: { in: PHONE_TYPES }, allow_nil: true

  # Normalizations - parse and convert to E.164 format
  normalizes :phone_number, with: ->(num) {
    parsed = Phonelib.parse(num)
    parsed.e164.presence || num.to_s.gsub(/\s/, "")
  }

  # Callbacks
  before_validation :extract_country_code, on: [:create, :update], if: :phone_number_changed?

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

  # Phone type scopes
  scope :voip, -> { where(phone_type: "voip") }
  scope :mobile, -> { where(phone_type: "mobile") }
  scope :landline, -> { where(phone_type: "landline") }
  scope :toll_free, -> { where(phone_type: "toll_free") }
  scope :in_country, ->(code) { where(country_code: code) }

  # Carrier scopes
  scope :with_carrier, -> { where.not(carrier_id: nil) }
  scope :without_carrier, -> { where(carrier_id: nil) }

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

  # Returns true if phone number has been checked before but verdict may need refreshing.
  # Uses a shorter threshold than needs_check? since this is for actively-queried numbers.
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
  # Phone type helpers
  # ===========================================

  def voip?
    phone_type == "voip"
  end

  def mobile?
    phone_type == "mobile"
  end

  def landline?
    phone_type == "landline"
  end

  def toll_free?
    phone_type == "toll_free"
  end

  # ===========================================
  # Phone number parsing helpers
  # ===========================================

  def parsed_phone
    @parsed_phone ||= Phonelib.parse(phone_number)
  end

  def national_format
    parsed_phone.national
  end

  def international_format
    parsed_phone.international
  end

  def valid_phone?
    parsed_phone.valid?
  end

  # ===========================================
  # Class methods
  # ===========================================

  class << self
    def find_or_create_for_check(phone_string)
      normalized = normalize_phone_number(phone_string)
      create_or_find_by!(phone_number: normalized)
    end

    def normalize_phone_number(phone_string)
      parsed = Phonelib.parse(phone_string)
      parsed.e164.presence || phone_string.to_s.gsub(/\s/, "")
    end

    def valid_e164?(phone_string)
      phone_string.present? && phone_string.match?(/\A\+[1-9]\d{1,14}\z/)
    end
  end

  private

  def extract_country_code
    return if phone_number.blank?

    self.country_code ||= parsed_phone.country
  end

  # Required by Protectable concern
  def protectable_value
    phone_number
  end
end
