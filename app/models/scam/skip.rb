# frozen_string_literal: true

# Records when a user skips classifying an item.
# Used to move skipped items to the back of the classification queue.
class Scam::Skip < ApplicationRecord
  self.table_name = "scam_skips"

  # Associations
  belongs_to :classifiable, polymorphic: true
  belongs_to :user

  # Scopes
  scope :by_user, ->(user) { where(user: user) }
  scope :recent_first, -> { order(updated_at: :desc) }

  # Class method to record a skip (creates or updates timestamp)
  def self.record!(user:, classifiable:)
    skip = find_or_initialize_by(user: user, classifiable: classifiable)
    if skip.new_record?
      skip.save!
    else
      skip.touch
    end
    skip
  end
end
