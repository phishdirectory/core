# frozen_string_literal: true

class Ahoy::Click < ApplicationRecord
  self.table_name = "ahoy_clicks"

  # Scopes
  scope :for_campaign, ->(campaign) { where(campaign: campaign) }
  scope :with_token, ->(token) { where(token: token) }
end
