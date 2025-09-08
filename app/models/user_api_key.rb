# frozen_string_literal: true

# == Schema Information
#
# Table name: user_api_keys
#
#  id           :bigint           not null, primary key
#  active       :boolean          default(TRUE), not null
#  expires_at   :datetime
#  key_digest   :string           not null
#  last_used_at :datetime
#  name         :string           not null
#  created_at   :datetime         not null
#  updated_at   :datetime         not null
#  user_id      :bigint           not null
#
# Indexes
#
#  index_user_api_keys_on_expires_at          (expires_at)
#  index_user_api_keys_on_key_digest          (key_digest) UNIQUE
#  index_user_api_keys_on_user_id             (user_id)
#  index_user_api_keys_on_user_id_and_active  (user_id,active)
#
# Foreign Keys
#
#  fk_rails_...  (user_id => users.id)
#
class UserApiKey < ApplicationRecord
  belongs_to :user

  validates :name, presence: true, length: { maximum: 100 }
  validates :key_digest, presence: true, uniqueness: true

  scope :active, -> { where(active: true) }
  scope :expired, -> { where("expires_at < ?", Time.current) }
  scope :api_valid, -> { active.where("expires_at IS NULL OR expires_at > ?", Time.current) }

  before_validation :generate_key_digest, on: :create

  attr_accessor :raw_key

  def self.generate_key
    # Generate a secure random key: 'pdat_' + base64 encoded random bytes
    "pdat_#{SecureRandom.urlsafe_base64(32)}"
  end

  def self.find_by_key(raw_key)
    return nil if raw_key.blank?

    # Hash the raw key to find the record
    digest = Digest::SHA256.hexdigest(raw_key)
    find_by(key_digest: digest)
  end

  def expired?
    expires_at && expires_at < Time.current
  end

  def api_valid?
    active? && !expired?
  end

  def touch_last_used!
    update!(last_used_at: Time.current)
  end

  def deactivate!
    update!(active: false)
  end

  def set_expiration(duration)
    self.expires_at = duration.from_now
  end

  private

  def generate_key_digest
    return if key_digest.present?

    @raw_key = self.class.generate_key
    self.key_digest = Digest::SHA256.hexdigest(@raw_key)
    self.active = true if active.nil?
  end

end
