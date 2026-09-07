# frozen_string_literal: true

class Service::Webhook < ApplicationRecord
  self.table_name = "service_webhooks"

  include SoftDeletable
  include EncodedIds::UuidIdentifiable

  set_public_id_prefix "swh"

  # Every event this system can deliver. A webhook receives only the events it
  # subscribes to; without this a single registered endpoint received every
  # event for every service, including other users' email addresses.
  EVENTS = %w[
    user.created
    user.role_changed
    domain.verdict
    url.verdict
  ].freeze

  has_paper_trail

  # Associations
  belongs_to :service

  # Callbacks
  before_validation :generate_secret, on: :create
  before_validation :default_events, on: :create

  # Validations
  validates :url, presence: true, uniqueness: { conditions: -> { kept } }
  validates :url, format: { with: URI::DEFAULT_PARSER.make_regexp(%w[http https]), message: "must be a valid HTTP/HTTPS URL" }
  validates :secret, presence: true
  validate :events_are_known
  validate :url_is_not_internal

  # Scopes
  scope :subscribed_to, ->(event) { where("events @> ARRAY[?]::varchar[]", event) }

  def subscribed_to?(event)
    events.include?(event)
  end

  # ===========================================
  # Signature generation
  # ===========================================

  # The timestamp is part of the signed string, so a captured delivery stops
  # verifying once it falls outside the receiver's tolerance. Signing the body
  # alone left every delivery replayable forever.
  SIGNATURE_TOLERANCE = 5.minutes

  def sign_payload(payload, timestamp: Time.current.to_i)
    payload_string = payload.is_a?(String) ? payload : payload.to_json
    OpenSSL::HMAC.hexdigest("SHA256", secret, "#{timestamp}.#{payload_string}")
  end

  def verify_signature(payload, signature, timestamp:)
    return false if timestamp.blank?
    return false if (Time.current.to_i - timestamp.to_i).abs > SIGNATURE_TOLERANCE.to_i

    expected = sign_payload(payload, timestamp: timestamp)
    ActiveSupport::SecurityUtils.secure_compare(expected, signature.to_s)
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

  def default_events
    self.events = EVENTS if events.blank?
  end

  def events_are_known
    unknown = Array(events) - EVENTS
    return if unknown.empty?

    errors.add(:events, "contains unknown events: #{unknown.join(", ")}")
  end

  def url_is_not_internal
    return if url.blank?
    return unless WebhookAddressPolicy.obviously_internal?(url)

    errors.add(:url, "must be a public address")
  end
end
