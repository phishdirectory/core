# frozen_string_literal: true

class WebhookDelivery < ApplicationRecord
  MAX_ATTEMPTS = 5

  # Statuses
  STATUSES = %w[pending delivering delivered failed].freeze

  # Validations
  validates :url, presence: true
  validates :event, presence: true
  validates :status, presence: true, inclusion: { in: STATUSES }

  # Scopes
  scope :pending, -> { where(status: "pending") }
  scope :delivered, -> { where(status: "delivered") }
  scope :failed, -> { where(status: "failed") }
  scope :retryable, -> { where(status: %w[pending failed]).where("attempts < ?", MAX_ATTEMPTS) }

  # Callbacks
  before_validation :set_defaults, on: :create

  # ===========================================
  # Status helpers
  # ===========================================

  def pending?
    status == "pending"
  end

  def delivered?
    status == "delivered"
  end

  def failed?
    status == "failed"
  end

  def retryable?
    %w[pending failed].include?(status) && attempts < MAX_ATTEMPTS
  end

  # ===========================================
  # Delivery lifecycle
  # ===========================================

  def mark_delivering!
    update!(status: "delivering", last_attempt_at: Time.current)
  end

  def mark_delivered!(response_data = nil)
    update!(
      status: "delivered",
      attempts: attempts + 1,
      response: response_data
    )
  end

  def mark_failed!(response_data = nil)
    update!(
      status: "failed",
      attempts: attempts + 1,
      response: response_data
    )
  end

  def retry_later!
    return false unless retryable?

    DeliverWebhookJob.set(wait: retry_delay).perform_later(self)
    true
  end

  # ===========================================
  # Payload helpers
  # ===========================================

  def parsed_payload
    return {} if payload.blank?

    JSON.parse(payload)
  rescue JSON::ParserError
    {}
  end

  private

  def set_defaults
    self.status ||= "pending"
    self.attempts ||= 0
  end

  def retry_delay
    # Exponential backoff: 30s, 1m, 2m, 4m, 8m
    (30 * (2**attempts)).seconds
  end
end
