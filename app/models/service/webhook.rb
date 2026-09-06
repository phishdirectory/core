# frozen_string_literal: true

class Service::Webhook < ApplicationRecord
  self.table_name = "service_webhooks"

  include SoftDeletable
  include EncodedIds::UuidIdentifiable

  set_public_id_prefix "swh"

  has_paper_trail

  # Associations
  belongs_to :service

  # Callbacks
  before_validation :generate_secret, on: :create

  # Validations
  validates :url, presence: true, uniqueness: true
  validates :url, format: { with: URI::DEFAULT_PARSER.make_regexp(%w[http https]), message: "must be a valid HTTP/HTTPS URL" }
  validates :secret, presence: true

  # ===========================================
  # Signature generation
  # ===========================================

  def sign_payload(payload)
    payload_string = payload.is_a?(String) ? payload : payload.to_json
    OpenSSL::HMAC.hexdigest("SHA256", secret, payload_string)
  end

  def verify_signature(payload, signature)
    expected = sign_payload(payload)
    ActiveSupport::SecurityUtils.secure_compare(expected, signature)
  end

  # ===========================================
  # Delivery
  # ===========================================

  def deliver(event:, payload:)
    WebhookDelivery.create!(
      url: url,
      event: event,
      payload: payload.to_json,
      status: "pending"
    ).tap do |delivery|
      DeliverWebhookJob.perform_later(delivery, secret)
    end
  end

  private

  def generate_secret
    self.secret ||= SecureRandom.hex(32)
  end
end
