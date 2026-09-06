# frozen_string_literal: true

class Phish::Protection < ApplicationRecord
  include SoftDeletable
  include EncodedIds::UuidIdentifiable

  self.table_name = "phish_protections"
  set_public_id_prefix "prt"

  # Valid protectable types
  PROTECTABLE_TYPES = %w[Phish::Domain Phish::Url].freeze

  # Associations
  belongs_to :protected_by, class_name: "User"

  # Validations
  validates :protectable_type, presence: true, inclusion: { in: PROTECTABLE_TYPES }
  validates :protectable_value, presence: true
  validates :protectable_value, uniqueness: { scope: :protectable_type, case_sensitive: false }

  # Normalizations
  normalizes :protectable_value, with: ->(value) { value.strip.downcase }

  # Scopes
  scope :for_domains, -> { where(protectable_type: "Phish::Domain") }
  scope :for_urls, -> { where(protectable_type: "Phish::Url") }
  scope :by_user, ->(user) { where(protected_by: user) }
  scope :recent, -> { order(created_at: :desc) }

  # ===========================================
  # Class methods
  # ===========================================

  class << self
    def protected?(type, value)
      normalized_value = value.to_s.strip.downcase
      kept.exists?(protectable_type: type, protectable_value: normalized_value)
    end

    def protection_for(type, value)
      normalized_value = value.to_s.strip.downcase
      kept.find_by(protectable_type: type, protectable_value: normalized_value)
    end
  end
end
