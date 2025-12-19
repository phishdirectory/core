# frozen_string_literal: true

class Verdict < ApplicationRecord
  include PublicIdentifiable

  set_public_id_prefix "vrd"

  # Primary Classifications (threat level)
  CLASSIFICATIONS = %w[phishing suspicious clean unknown protected].freeze

  # Associations
  has_many :phish_domains, class_name: "Phish::Domain", dependent: :nullify
  has_many :phish_urls, class_name: "Phish::Url", dependent: :nullify
  has_many :phish_phone_numbers, class_name: "Phish::PhoneNumber", dependent: :nullify
  has_many :phish_emails, class_name: "Phish::Email", dependent: :nullify

  # Validations
  validates :classification, presence: true, inclusion: { in: CLASSIFICATIONS }
  validates :confidence_score, numericality: { greater_than_or_equal_to: 0, less_than_or_equal_to: 1 }, allow_nil: true

  # Scopes - Classification
  scope :phishing, -> { where(classification: "phishing") }
  scope :suspicious, -> { where(classification: "suspicious") }
  scope :clean, -> { where(classification: "clean") }
  scope :unknown, -> { where(classification: "unknown") }
  scope :protected_classification, -> { where(classification: "protected") }
  scope :high_confidence, -> { where("confidence_score >= ?", 0.8) }
  scope :low_confidence, -> { where("confidence_score < ?", 0.5) }
  scope :dangerous, -> { phishing.or(suspicious) }

  # ===========================================
  # Classification helpers
  # ===========================================

  def phishing?
    classification == "phishing"
  end

  def suspicious?
    classification == "suspicious"
  end

  def clean?
    classification == "clean"
  end

  def unknown?
    classification == "unknown"
  end

  def protected_classification?
    classification == "protected"
  end

  def dangerous?
    phishing? || suspicious?
  end

  def safe?
    clean? || protected_classification?
  end

  # ===========================================
  # Source helpers
  # ===========================================

  def sources_list
    sources || []
  end

  def add_source(source_name, result)
    self.sources ||= []
    self.sources << { name: source_name, result: result, checked_at: Time.current.iso8601 }
  end

  def flagged_by?(source_name)
    sources_list.any? { |s| s["name"] == source_name || s[:name] == source_name }
  end

  # ===========================================
  # Metadata helpers
  # ===========================================

  def metadata_hash
    metadata || {}
  end

  def set_metadata(key, value)
    self.metadata ||= {}
    self.metadata[key] = value
  end
end
