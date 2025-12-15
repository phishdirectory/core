# frozen_string_literal: true

class Ahoy::Event < ApplicationRecord
  self.table_name = "ahoy_events"

  include Ahoy::QueryMethods

  # Associations
  belongs_to :visit, class_name: "Ahoy::Visit", optional: true
  belongs_to :user, optional: true

  # Scopes
  scope :with_user, -> { where.not(user_id: nil) }
  scope :anonymous, -> { where(user_id: nil) }
  scope :recent, ->(days = 30) { where("time > ?", days.days.ago) }
  scope :named, ->(name) { where(name: name) }

  # ===========================================
  # Property helpers
  # ===========================================

  def property(key)
    properties&.dig(key.to_s)
  end

  def has_property?(key)
    properties&.key?(key.to_s)
  end
end
