# frozen_string_literal: true

# Rails session store model
# Used when config.session_store :active_record_store is enabled
class Session < ApplicationRecord
  # Scopes
  scope :stale, ->(threshold = 30.days) { where("updated_at < ?", threshold.ago) }

  # ===========================================
  # Class methods for session cleanup
  # ===========================================

  class << self
    def cleanup_stale!(threshold = 30.days)
      stale(threshold).destroy_all
    end
  end
end
