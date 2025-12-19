# frozen_string_literal: true

# Records a user's scam category vote for a classifiable item (domain, URL, etc.)
# Each user can only vote once per item, but multiple users can vote on the same item.
class Scam::Classification < ApplicationRecord
  include PublicIdentifiable

  self.table_name = "scam_classifications"
  set_public_id_prefix "scl"

  # Associations
  belongs_to :classifiable, polymorphic: true
  belongs_to :user

  # Validations
  validates :scam_category, presence: true, inclusion: { in: Scam::CATEGORIES }
  validates :scam_subcategory, inclusion: { in: Scam::SUBCATEGORIES }, allow_nil: true
  validates :user_id, uniqueness: {
    scope: [ :classifiable_type, :classifiable_id ],
    message: "has already classified this item"
  }
  validate :scam_subcategory_matches_category

  # Scopes
  scope :by_category, ->(category) { where(scam_category: category) }
  scope :by_subcategory, ->(subcategory) { where(scam_subcategory: subcategory) }
  scope :recent, -> { order(created_at: :desc) }
  scope :by_user, ->(user) { where(user: user) }

  # Callbacks
  after_create :update_classifiable_consensus
  after_destroy :update_classifiable_consensus

  # ===========================================
  # Category helpers
  # ===========================================

  def category_name
    Scam.category_name(scam_category)
  end

  def subcategory_name
    scam_subcategory&.titleize
  end

  private

  def scam_subcategory_matches_category
    return if scam_subcategory.blank?

    unless Scam.valid_subcategory?(scam_category, scam_subcategory)
      errors.add(:scam_subcategory, "is not valid for the #{scam_category} category")
    end
  end

  def update_classifiable_consensus
    classifiable.recalculate_consensus! if classifiable.respond_to?(:recalculate_consensus!)
  end
end
