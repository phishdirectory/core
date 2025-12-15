# frozen_string_literal: true

class Ahoy::Message < ApplicationRecord
  self.table_name = "ahoy_messages"

  # Lockbox encryption for email address
  has_encrypted :to
  blind_index :to

  # Associations (polymorphic user)
  belongs_to :user, polymorphic: true, optional: true

  # Scopes
  scope :recent, ->(days = 30) { where("sent_at > ?", days.days.ago) }
  scope :for_mailer, ->(mailer) { where(mailer: mailer) }
  scope :for_campaign, ->(campaign) { where(campaign: campaign) }

  # ===========================================
  # Query helpers
  # ===========================================

  def self.find_by_email(email)
    find_by(to_bidx: blind_index_value(:to, email))
  end

  def self.for_email(email)
    where(to_bidx: blind_index_value(:to, email))
  end
end
