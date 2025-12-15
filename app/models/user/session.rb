# frozen_string_literal: true

class User::Session < ApplicationRecord
  self.table_name = "user_sessions"

  # Associations
  belongs_to :user
  belongs_to :impersonator, class_name: "User", foreign_key: :impersonated_by_id, optional: true

  # Lockbox encryption for session token
  has_encrypted :session_token
  blind_index :session_token

  # Geocoder integration for IP geolocation
  geocoded_by :ip do |session, results|
    if geo = results.first
      session.latitude = geo.latitude
      session.longitude = geo.longitude
    end
  end

  # Callbacks
  before_validation :generate_session_token, on: :create
  before_validation :set_expiration, on: :create
  after_validation :geocode, if: ->(s) { s.ip.present? && s.ip_changed? }

  # Validations
  validates :session_token, presence: true
  validates :expiration_at, presence: true

  # Scopes
  scope :active, -> { where(signed_out_at: nil).where("expiration_at > ?", Time.current) }
  scope :expired, -> { where("expiration_at <= ?", Time.current) }
  scope :signed_out, -> { where.not(signed_out_at: nil) }
  scope :impersonated, -> { where.not(impersonated_by_id: nil) }

  # ===========================================
  # Session state methods
  # ===========================================

  def active?
    signed_out_at.nil? && expiration_at > Time.current
  end

  def expired?
    expiration_at <= Time.current
  end

  def signed_out?
    signed_out_at.present?
  end

  def impersonated?
    impersonated_by_id.present?
  end

  # ===========================================
  # Session lifecycle methods
  # ===========================================

  def touch_last_seen!
    update!(last_seen_at: Time.current)
  end

  def extend_session!
    return false unless active?

    update!(expiration_at: user.session_duration_seconds.seconds.from_now)
  end

  def sign_out!
    update!(signed_out_at: Time.current)
  end

  # ===========================================
  # Class methods for authentication
  # ===========================================

  class << self
    def find_by_token(token)
      return nil if token.blank?

      find_by(session_token_bidx: blind_index_value(:session_token, token))
    end

    def authenticate(token)
      session = find_by_token(token)
      return nil unless session&.active?

      session.touch_last_seen!
      session
    end

    def create_for_user(user, ip: nil, device_info: nil, os_info: nil, timezone: nil, fingerprint: nil, impersonator: nil)
      create!(
        user: user,
        ip: ip,
        device_info: device_info,
        os_info: os_info,
        timezone: timezone,
        fingerprint: fingerprint,
        impersonated_by_id: impersonator&.id
      )
    end

    def cleanup_expired!
      expired.destroy_all
    end
  end

  private

  def generate_session_token
    self.session_token ||= SecureRandom.urlsafe_base64(32)
  end

  def set_expiration
    self.expiration_at ||= user.session_duration_seconds.seconds.from_now
  end
end
