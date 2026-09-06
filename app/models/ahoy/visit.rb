# frozen_string_literal: true

class Ahoy::Visit < ApplicationRecord
  self.table_name = "ahoy_visits"

  # Associations
  belongs_to :user, optional: true
  has_many :events, class_name: "Ahoy::Event", dependent: :destroy

  # Scopes
  scope :with_user, -> { where.not(user_id: nil) }
  scope :anonymous, -> { where(user_id: nil) }
  scope :recent, ->(days = 30) { where("started_at > ?", days.days.ago) }
  scope :from_country, ->(country) { where(country: country) }
  scope :mobile, -> { where(device_type: "Mobile") }
  scope :desktop, -> { where(device_type: "Desktop") }
  scope :tablet, -> { where(device_type: "Tablet") }

  # ===========================================
  # Visit info helpers
  # ===========================================

  def anonymous?
    user_id.nil?
  end

  def mobile?
    device_type == "Mobile"
  end

  def desktop?
    device_type == "Desktop"
  end

  def tablet?
    device_type == "Tablet"
  end

  def has_location?
    latitude.present? && longitude.present?
  end

  def location_string
    [ city, region, country ].compact.join(", ")
  end

  # ===========================================
  # UTM helpers
  # ===========================================

  def has_utm?
    utm_source.present? || utm_medium.present? || utm_campaign.present?
  end

  def utm_params
    {
      source: utm_source,
      medium: utm_medium,
      term: utm_term,
      content: utm_content,
      campaign: utm_campaign
    }.compact
  end
end
