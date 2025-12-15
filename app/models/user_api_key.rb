# frozen_string_literal: true

class UserApiKey < ApplicationRecord
  # API Key prefix for easy identification
  KEY_PREFIX = "pdat_"

  # Associations
  belongs_to :user

  # Callbacks
  before_validation :generate_key, on: :create

  # Validations
  validates :name, presence: true
  validates :key_digest, presence: true, uniqueness: true

  # Scopes
  scope :active, -> { where(active: true) }
  scope :inactive, -> { where(active: false) }
  scope :expired, -> { where("expires_at IS NOT NULL AND expires_at <= ?", Time.current) }
  scope :not_expired, -> { where("expires_at IS NULL OR expires_at > ?", Time.current) }
  scope :usable, -> { active.not_expired }

  # Virtual attribute to hold the plaintext key (only available at creation)
  attr_accessor :plaintext_key

  # ===========================================
  # Key state methods
  # ===========================================

  def expired?
    expires_at.present? && expires_at <= Time.current
  end

  def usable?
    active? && !expired?
  end

  # ===========================================
  # Key lifecycle methods
  # ===========================================

  def touch_last_used!
    update!(last_used_at: Time.current)
  end

  def revoke!
    update!(active: false)
  end

  def reactivate!
    update!(active: true)
  end

  # ===========================================
  # Class methods for authentication
  # ===========================================

  class << self
    def find_by_key(plaintext_key)
      return nil if plaintext_key.blank?

      digest = digest_key(plaintext_key)
      find_by(key_digest: digest)
    end

    def authenticate(plaintext_key)
      api_key = find_by_key(plaintext_key)
      return nil unless api_key&.usable?

      api_key.touch_last_used!
      api_key
    end

    def digest_key(plaintext_key)
      Digest::SHA256.hexdigest(plaintext_key)
    end
  end

  private

  def generate_key
    return if key_digest.present?

    # Generate a secure random key with prefix
    raw_key = SecureRandom.urlsafe_base64(32)
    self.plaintext_key = "#{KEY_PREFIX}#{raw_key}"
    self.key_digest = self.class.digest_key(plaintext_key)
  end
end
