# frozen_string_literal: true

# One IOK ("Indicators of Kit") rule, synced from phish-report/IOK.
#
# The rules are Sigma rules that match against the content of a fetched page.
# Iok::SyncService writes these rows, Iok::RuleSet compiles them, and
# Phish::IokService evaluates them during a domain or URL check.
class Iok::Indicator < ApplicationRecord
  include SoftDeletable
  include EncodedIds::UuidIdentifiable

  self.table_name = "iok_indicators"
  set_public_id_prefix "iok"

  # Where the rule came from. Upstream rules are replaced wholesale by the sync
  # job; local ones live in db/iok/local and are ours to maintain.
  SOURCES = %w[upstream local].freeze

  validates :slug, presence: true, uniqueness: { conditions: -> { kept } }
  validates :title, presence: true
  validates :content_digest, presence: true
  validates :source, inclusion: { in: SOURCES }
  validates :severity, inclusion: { in: Iok::Severity::ALL }
  validates :severity_override, inclusion: { in: Iok::Severity::ALL }, allow_nil: true
  validate :detection_compiles

  normalizes :slug, with: ->(slug) { slug.to_s.strip.downcase }

  scope :enabled, -> { where(enabled: true) }
  scope :upstream, -> { where(source: "upstream") }
  scope :local, -> { where(source: "local") }
  scope :overridden, -> { where.not(severity_override: nil) }

  # What a match means, honouring an admin's correction over the value derived
  # from the rule's own metadata.
  def effective_severity
    severity_override.presence || severity
  end

  def severity_overridden?
    severity_override.present?
  end

  # An identification rule (which website builder a page uses, say) matching
  # tells us nothing about whether the page is malicious.
  def informational?
    effective_severity == Iok::Severity::INFORMATIONAL
  end
  scope :tagged, ->(tag) { where("tags @> ?", [ tag ].to_json) }
  scope :recently_synced, -> { order(synced_at: :desc) }

  # The compiled matcher for this indicator.
  # @return [Iok::Rule]
  def rule
    @rule ||= Iok::Rule.new(slug: slug, title: title, detection: detection)
  end

  # @return [Boolean] whether the detection block still compiles
  def valid_rule?
    rule
    true
  rescue Iok::Rule::InvalidRule
    false
  end

  def matches?(snapshot)
    rule.matches?(snapshot)
  end

  # Shape used in verdict details and API responses.
  def to_match_summary
    {
      id: public_id,
      slug: slug,
      title: title,
      tags: tags,
      source: source,
      severity: effective_severity,
      reference_urls: reference_urls
    }
  end

  private

  # A rule that does not compile can never fire, and storing one would move the
  # failure from sync time (where the job logs it) to check time (where it
  # would break an unrelated domain lookup).
  def detection_compiles
    Iok::Rule.new(slug: slug, title: title, detection: detection)
  rescue Iok::Rule::InvalidRule => e
    errors.add(:detection, e.message)
  end
end
