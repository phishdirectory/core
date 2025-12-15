# frozen_string_literal: true

class Verdict < ApplicationRecord
  # Classifications
  CLASSIFICATIONS = %w[phishing suspicious clean unknown].freeze

  # Associations
  has_many :phish_domains, class_name: "Phish::Domain", dependent: :nullify
  has_many :phish_urls, class_name: "Phish::Url", dependent: :nullify

  # Validations
  validates :classification, inclusion: { in: CLASSIFICATIONS }, allow_nil: true
  validates :confidence_score, numericality: { greater_than_or_equal_to: 0, less_than_or_equal_to: 1 }, allow_nil: true

  # Scopes
  scope :phishing, -> { where(classification: "phishing") }
  scope :suspicious, -> { where(classification: "suspicious") }
  scope :clean, -> { where(classification: "clean") }
  scope :unknown, -> { where(classification: "unknown") }
  scope :high_confidence, -> { where("confidence_score >= ?", 0.8) }
  scope :low_confidence, -> { where("confidence_score < ?", 0.5) }

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

  def dangerous?
    phishing? || suspicious?
  end

  def safe?
    clean?
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
