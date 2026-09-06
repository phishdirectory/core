# frozen_string_literal: true

class Phish::Carrier < ApplicationRecord
  include SoftDeletable
  include EncodedIds::UuidIdentifiable

  self.table_name = "phish_carriers"
  set_public_id_prefix "car"

  # Associations
  has_many :phone_numbers, class_name: "Phish::PhoneNumber", foreign_key: :carrier_id, dependent: :nullify

  # Validations
  validates :name, presence: true, uniqueness: true

  CARRIER_TYPES = %w[mobile voip landline toll_free unknown].freeze
  validates :carrier_type, inclusion: { in: CARRIER_TYPES }, allow_nil: true

  # Normalizations
  normalizes :name, with: ->(name) { name.strip }

  # Scopes
  scope :by_phone_count, -> { order(phone_numbers_count: :desc) }
  scope :with_phone_numbers, -> { where("phone_numbers_count > 0") }
  scope :voip, -> { where(carrier_type: "voip") }
  scope :mobile, -> { where(carrier_type: "mobile") }
  scope :landline, -> { where(carrier_type: "landline") }
  scope :toll_free, -> { where(carrier_type: "toll_free") }
  scope :in_country, ->(code) { where(country_code: code) }

  # ===========================================
  # Class methods
  # ===========================================

  class << self
    # Find or create carrier by name
    # Uses upsert to handle race conditions atomically
    def find_or_create_by_name(carrier_name)
      return nil if carrier_name.blank?

      result = upsert(
        { name: carrier_name.strip },
        unique_by: :name,
        returning: [:id]
      )

      find(result.rows.first.first)
    end
  end

  # ===========================================
  # Instance methods
  # ===========================================

  def voip?
    carrier_type == "voip"
  end

  def mobile?
    carrier_type == "mobile"
  end

  def landline?
    carrier_type == "landline"
  end

  def toll_free?
    carrier_type == "toll_free"
  end
end
