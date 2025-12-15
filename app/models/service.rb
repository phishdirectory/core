# frozen_string_literal: true

class Service < ApplicationRecord
  include AASM

  has_paper_trail

  # Associations
  has_many :service_keys, class_name: "Service::Key", dependent: :destroy
  has_many :service_webhooks, class_name: "Service::Webhook", dependent: :destroy
  has_many :service_key_usages, through: :service_keys, source: :usages

  # Validations
  validates :name, presence: true, uniqueness: true

  # Counter cache for keys
  # Note: keys_count is managed by Service::Key callbacks

  # State machine for service status
  aasm column: :status, enum: true do
    state :active, initial: true
    state :suspended
    state :decommissioned

    event :suspend do
      transitions from: :active, to: :suspended
    end

    event :reactivate do
      transitions from: :suspended, to: :active
    end

    event :decommission do
      transitions from: %i[active suspended], to: :decommissioned
      after do
        service_keys.each(&:revoke!)
      end
    end
  end

  # ===========================================
  # Service state helpers
  # ===========================================

  def operational?
    active?
  end

  # ===========================================
  # Key management
  # ===========================================

  def generate_key!(notes: nil)
    service_keys.create!(notes: notes)
  end

  def active_keys
    service_keys.active
  end

  def primary_key
    active_keys.order(created_at: :asc).first
  end

  # ===========================================
  # Webhook management
  # ===========================================

  def register_webhook!(url:)
    service_webhooks.create!(url: url)
  end

  def active_webhooks
    service_webhooks
  end

  # ===========================================
  # Class methods for authentication
  # ===========================================

  class << self
    def find_by_api_key(api_key)
      key = Service::Key.find_by(api_key: api_key)
      key&.service
    end

    def authenticate(api_key)
      key = Service::Key.find_by(api_key: api_key)
      return nil unless key&.usable?

      key.service
    end
  end
end
