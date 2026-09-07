# frozen_string_literal: true

class Service::Key < ApplicationRecord
  self.table_name = "service_keys"

  include AASM
  include SoftDeletable
  include EncodedIds::UuidIdentifiable

  set_public_id_prefix "sak"

  has_paper_trail

  # Associations
  belongs_to :service, counter_cache: :keys_count
  has_many :usages, class_name: "Service::KeyUsage", foreign_key: :key_id, dependent: :destroy
  has_many :api_requests, as: :authenticatable, dependent: :destroy

  # API key prefix-free by design: service keys are distinguished from user
  # keys (pdat_*) by the absence of a prefix.
  KEY_BYTES = 24

  # Callbacks
  before_validation :generate_credentials, on: :create

  # Validations
  validates :key_digest, presence: true, uniqueness: true

  # Holds the plaintext key for the one request in which it is created. It is
  # never stored, so this is the only chance to show it to anyone.
  attr_accessor :plaintext_key

  # State machine for key status (uses PostgreSQL enum, not Rails enum)
  aasm column: :status do
    state :active, initial: true
    state :deprecated
    state :revoked

    event :deprecate do
      transitions from: :active, to: :deprecated
    end

    event :revoke do
      transitions from: %i[active deprecated], to: :revoked
    end

    event :reactivate do
      transitions from: :deprecated, to: :active
    end
  end

  # ===========================================
  # Key state helpers
  # ===========================================

  def usable?
    active? && service.operational?
  end

  # ===========================================
  # Usage logging
  # ===========================================

  def log_usage(
    user: nil,
    request_path: nil,
    request_method: nil,
    ip_address: nil,
    user_agent: nil,
    request_headers: nil,
    request_body: nil,
    response_code: nil,
    response_body: nil,
    response_headers: nil,
    duration_ms: nil
  )
    usages.create!(
      user: user,
      request_path: request_path,
      request_method: request_method,
      ip_address: ip_address,
      user_agent: user_agent,
      request_headers: request_headers,
      request_body: request_body,
      requested_at: Time.current,
      response_code: response_code,
      response_body: response_body,
      response_headers: response_headers,
      duration_ms: duration_ms
    )
  end

  # ===========================================
  # Class methods
  # ===========================================

  class << self
    def find_by_key(plaintext_key)
      return nil if plaintext_key.blank?

      find_by(key_digest: digest_key(plaintext_key))
    end

    def authenticate(plaintext_key)
      key = find_by_key(plaintext_key)
      return nil unless key&.usable?

      key
    end

    def digest_key(plaintext_key)
      Digest::SHA256.hexdigest(plaintext_key)
    end
  end

  private

  def generate_credentials
    return if key_digest.present?

    self.plaintext_key = SecureRandom.hex(KEY_BYTES)
    self.key_digest = self.class.digest_key(plaintext_key)
    self.key_hint = plaintext_key.last(4)
  end
end
