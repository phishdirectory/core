# frozen_string_literal: true

class Service::Key < ApplicationRecord
  self.table_name = "service_keys"

  include AASM
  include SoftDeletable
  include PublicIdentifiable

  set_public_id_prefix "sak"

  has_paper_trail

  # Associations
  belongs_to :service, counter_cache: :keys_count
  has_many :usages, class_name: "Service::KeyUsage", foreign_key: :key_id, dependent: :destroy
  has_many :api_requests, as: :authenticatable, dependent: :destroy

  # Callbacks
  before_validation :generate_credentials, on: :create

  # Validations
  validates :api_key, presence: true, uniqueness: true
  validates :hash_key, presence: true

  # State machine for key status
  aasm column: :status, enum: true do
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
    def authenticate(api_key)
      key = find_by(api_key: api_key)
      return nil unless key&.usable?

      key
    end
  end

  private

  def generate_credentials
    self.api_key ||= SecureRandom.hex(24)   # 48 hex chars
    self.hash_key ||= SecureRandom.hex(32)  # 64 hex chars for encryption
  end
end
