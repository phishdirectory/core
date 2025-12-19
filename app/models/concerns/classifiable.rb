# frozen_string_literal: true

# Concern for models that can be classified with scam categories by users.
# Provides scam classification voting, consensus tracking, and classification queue functionality.
#
# Models including this concern must:
# - Have a `verdict` association that responds to `dangerous?`
# - Have `scam_category`, `scam_subcategory`, and `marked_clean_at` columns
#
# Usage:
#   class Phish::Domain < ApplicationRecord
#     include Classifiable
#   end
#
module Classifiable
  extend ActiveSupport::Concern

  included do
    # Associations
    has_many :scam_classifications, as: :classifiable, class_name: "Scam::Classification", dependent: :destroy
    has_many :classifying_users, through: :scam_classifications, source: :user
    has_many :scam_skips, as: :classifiable, class_name: "Scam::Skip", dependent: :destroy

    # Scopes for classification queue
    scope :needs_classification, -> {
      joins(:verdict)
        .where(verdicts: { classification: %w[phishing suspicious] })
        .where(scam_category: nil)
        .where(marked_clean_at: nil)
    }

    scope :not_classified_by, ->(user) {
      where.not(id: Scam::Classification.where(classifiable: all, user: user).select(:classifiable_id))
    }

    # Order items by whether they've been skipped (unskipped first, then by skip time)
    scope :ordered_by_skip_for, ->(user) {
      skip_subquery = Scam::Skip.where(user: user)
        .where("scam_skips.classifiable_type = ? AND scam_skips.classifiable_id = #{table_name}.id", name)
        .select(:updated_at)
        .limit(1)

      order(
        Arel.sql("(#{skip_subquery.to_sql}) IS NOT NULL ASC"),
        Arel.sql("COALESCE((#{skip_subquery.to_sql}), '1970-01-01'::timestamp) ASC"),
        created_at: :asc
      )
    }

    scope :categorized, -> { where.not(scam_category: nil) }
    scope :uncategorized, -> { where(scam_category: nil) }
    scope :marked_clean, -> { where.not(marked_clean_at: nil) }
    scope :by_scam_category, ->(category) { where(scam_category: category) }
    scope :by_scam_subcategory, ->(subcategory) { where(scam_subcategory: subcategory) }

    # Validations
    validates :scam_category, inclusion: { in: Scam::CATEGORIES }, allow_nil: true
    validates :scam_subcategory, inclusion: { in: Scam::SUBCATEGORIES }, allow_nil: true
    validate :scam_subcategory_matches_category
  end

  # ===========================================
  # Classification status
  # ===========================================

  def classifiable?
    verdict&.dangerous?
  end

  def needs_classification?
    classifiable? && !categorized? && !marked_clean?
  end

  def categorized?
    scam_category.present?
  end

  def marked_clean?
    marked_clean_at.present?
  end

  def classified_by?(user)
    scam_classifications.exists?(user: user)
  end

  def classification_by(user)
    scam_classifications.find_by(user: user)
  end

  def classification_count
    scam_classifications.count
  end

  def skipped_by?(user)
    scam_skips.exists?(user: user)
  end

  def skip_by(user)
    scam_skips.find_by(user: user)
  end

  # Record that a user skipped this item (moves to back of their queue)
  def record_skip!(user)
    Scam::Skip.record!(user: user, classifiable: self)
  end

  # ===========================================
  # Scam category helpers
  # ===========================================

  def scam_category_name
    return nil unless scam_category

    Scam.category_name(scam_category)
  end

  def valid_subcategories
    return [] unless scam_category

    Scam.subcategories_for(scam_category)
  end

  # ===========================================
  # Classification actions
  # ===========================================

  # Add a user's classification vote
  def add_classification!(user:, category:, subcategory: nil, notes: nil)
    raise ArgumentError, "User has already classified this item" if classified_by?(user)
    raise ArgumentError, "Item is not classifiable (must be phishing or suspicious)" unless classifiable?
    raise ArgumentError, "Item has been marked as clean" if marked_clean?

    scam_classifications.create!(
      user: user,
      scam_category: category,
      scam_subcategory: subcategory,
      notes: notes
    )

    recalculate_consensus!
  end

  # Mark a suspicious item as clean (staff override)
  def mark_as_clean!(user:)
    raise ArgumentError, "Item is not suspicious" unless verdict&.suspicious?
    raise ArgumentError, "Item has already been marked clean" if marked_clean?

    update!(
      marked_clean_at: Time.current,
      marked_clean_by_id: user.id
    )
  end

  # Unmark a clean item (undo staff override)
  def unmark_clean!
    raise ArgumentError, "Item is not marked as clean" unless marked_clean?

    update!(
      marked_clean_at: nil,
      marked_clean_by_id: nil
    )
  end

  # Set the final scam category (consensus or manual override)
  def set_scam_category!(category, subcategory = nil)
    update!(scam_category: category, scam_subcategory: subcategory)
  end

  # Clear the scam classification
  def clear_scam_category!
    update!(scam_category: nil, scam_subcategory: nil)
  end

  # ===========================================
  # Consensus calculation
  # ===========================================

  # Recalculate consensus from all classifications
  def recalculate_consensus!
    return if scam_classifications.empty?

    # Find the most common category
    category_counts = scam_classifications.group(:scam_category).count
    consensus_category = category_counts.max_by { |_, count| count }&.first

    return unless consensus_category

    # Find the most common subcategory for that category
    subcategory_counts = scam_classifications
      .where(scam_category: consensus_category)
      .where.not(scam_subcategory: nil)
      .group(:scam_subcategory)
      .count
    consensus_subcategory = subcategory_counts.max_by { |_, count| count }&.first

    update!(
      scam_category: consensus_category,
      scam_subcategory: consensus_subcategory
    )
  end

  # Get the current consensus (most voted category)
  def classification_consensus
    return nil if scam_classifications.empty?

    scam_classifications.group(:scam_category).count.max_by { |_, v| v }&.first
  end

  # ===========================================
  # Class methods
  # ===========================================

  class_methods do
    # Get the classification queue for a user
    # Orders items that haven't been skipped first, then by skip time (oldest skips first)
    def classification_queue_for(user, limit: 10)
      needs_classification
        .not_classified_by(user)
        .includes(:verdict)
        .ordered_by_skip_for(user)
        .limit(limit)
    end
  end

  private

  def scam_subcategory_matches_category
    return if scam_subcategory.blank?

    if scam_category.blank?
      errors.add(:scam_subcategory, "requires a scam category to be set")
      return
    end

    unless Scam.valid_subcategory?(scam_category, scam_subcategory)
      errors.add(:scam_subcategory, "is not valid for the #{scam_category} category")
    end
  end
end
