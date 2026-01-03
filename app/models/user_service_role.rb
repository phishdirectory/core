# frozen_string_literal: true

class UserServiceRole < ApplicationRecord
  include SoftDeletable
  include PublicIdentifiable

  set_public_id_prefix "usr"

  # Associations
  belongs_to :user
  belongs_to :service
  belongs_to :granted_by, class_name: "User", optional: true

  has_paper_trail

  # Role configuration (matches User access_level enum)
  ROLES = %w[user trusted admin superadmin owner].freeze

  enum :role, ROLES.index_by(&:itself), scopes: false

  # Validations
  validates :user_id, uniqueness: { scope: :service_id, conditions: -> { kept } }
  validates :role, presence: true, inclusion: { in: ROLES }

  # Scopes
  scope :for_service, ->(service) { where(service: service) }
  scope :for_user, ->(user) { where(user: user) }
  scope :admins_and_above, -> { where(role: %w[admin superadmin owner]) }

  # Callbacks
  before_create :set_granted_at

  # ===========================================
  # Role checking methods
  # ===========================================

  def trusted?
    %w[trusted admin superadmin owner].include?(role)
  end

  def admin?
    %w[admin superadmin owner].include?(role)
  end

  def superadmin?
    %w[superadmin owner].include?(role)
  end

  def owner?
    role == "owner"
  end

  # ===========================================
  # Role modification methods
  # ===========================================

  def promote_to!(new_role, by: nil)
    update!(role: new_role, granted_by: by, granted_at: Time.current)
  end

  def demote_to!(new_role, by: nil)
    update!(role: new_role, granted_by: by, granted_at: Time.current)
  end

  def revoke!(by: nil)
    discard
  end

  private

  def set_granted_at
    self.granted_at ||= Time.current
  end
end
