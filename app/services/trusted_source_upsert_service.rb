# frozen_string_literal: true

# Writes verdicts a trusted source supplied straight into the database.
#
# A trusted source is a service holding a service key flagged trusted_source.
# Those callers maintain their own curated lists, so their submissions skip
# Phish::AggregatorService entirely: what they send becomes the verdict.
#
# The service upserts. It creates the record when we have never seen the value,
# and it replaces the verdict on the record when we have. Nothing is deleted and
# nothing is duplicated, so a source can push the same feed as often as it likes.
#
#   TrustedSourceUpsertService.call(
#     type: "domain",
#     service: service,
#     entries: [ { "domain" => "evil.example", "classification" => "phishing" } ]
#   )
#
class TrustedSourceUpsertService
  # Classifications a trusted source may assign.
  #
  # "unknown" is excluded because it carries no information: accepting it would
  # only let a source overwrite a verdict we already trust with the absence of
  # one. "protected" is excluded because the protected list is an operator
  # decision, recorded in phish_protections, and it is not a source's to hand
  # out.
  CLASSIFICATIONS = %w[phishing suspicious clean].freeze

  # Confidence used when a source states a classification but not how sure it
  # is. A trusted source is taken at its word, so the default is certainty.
  DEFAULT_CONFIDENCE = 1.0

  # Ceiling on one submission, enforced by Api::V1::Source::EntriesController so
  # an oversized request gets a 400 rather than a timeout. Higher than the public
  # bulk endpoints, which stop at 100, because a source pushes whole feed deltas
  # rather than user queries. Still bounded: every entry is a separate write
  # inside one request.
  MAX_ENTRIES = 1_000

  # Ceiling on the free-form metadata stored per entry, in bytes of JSON.
  # Trusted means trusted to classify, not trusted to fill the verdicts table.
  MAX_METADATA_BYTES = 4_000

  # The record types a source may push, keyed by the type name the API uses.
  #
  # :attribute is both the column holding the value and the key an entry object
  # may carry it under. :protectable is the phish_protections type string, or
  # nil for record types the protected list does not cover.
  TYPES = {
    "domain" => {
      model: Phish::Domain,
      attribute: :domain,
      protectable: "Phish::Domain"
    },
    "url" => {
      model: Phish::Url,
      attribute: :url,
      protectable: "Phish::Url"
    },
    "email" => {
      model: Phish::Email,
      attribute: :email,
      protectable: nil
    },
    "phone_number" => {
      model: Phish::PhoneNumber,
      attribute: :phone_number,
      protectable: nil
    }
  }.freeze

  class UnknownType < ArgumentError; end

  # @param type [String] One of TYPES.keys
  # @param entries [Array] Strings, or objects carrying a value and a classification
  # @param service [Service] The submitting service, named on every verdict written
  # @param default_classification [String, nil] Applied to entries that state none
  # @param default_confidence [Float, nil] Applied to entries that state none
  def self.call(type:, entries:, service:, default_classification: nil, default_confidence: nil)
    new(
      type: type,
      entries: entries,
      service: service,
      default_classification: default_classification,
      default_confidence: default_confidence
    ).call
  end

  attr_reader :type, :entries, :service, :default_classification, :default_confidence

  def initialize(type:, entries:, service:, default_classification: nil, default_confidence: nil)
    @type = type.to_s
    raise UnknownType, "Unknown type: #{type}" unless TYPES.key?(@type)

    @entries = Array(entries)
    @service = service
    @default_classification = default_classification.presence
    @default_confidence = default_confidence
  end

  def call
    results = entries.map { |entry| process(entry) }

    {
      results: results,
      counts: results.group_by { |r| r[:status] }.transform_values(&:size),
      count: results.size
    }
  end

  # ===========================================
  # Type configuration
  # ===========================================

  def config
    TYPES.fetch(type)
  end

  def model
    config[:model]
  end

  def attribute
    config[:attribute]
  end

  private

  def process(entry)
    raw_value, classification, confidence, metadata = extract(entry)

    value = normalize(raw_value)
    return invalid(raw_value, "Missing or malformed value") if value.blank?
    return invalid(value, "Invalid #{type} format") unless valid_value?(value)
    return invalid(value, "Classification must be one of: #{CLASSIFICATIONS.join(", ")}") unless CLASSIFICATIONS.include?(classification)
    return invalid(value, "Confidence must be a number between 0 and 1") unless valid_confidence?(confidence)
    return invalid(value, "Metadata must be an object of at most #{MAX_METADATA_BYTES} bytes") if metadata == :invalid

    if (protection = protection_for(value))
      # The protected list is how an operator says "never flag this, whatever
      # anyone reports". A trusted source does not outrank that.
      return rejected(value, "Value is protected", protection_id: protection.public_id)
    end

    upsert(value, classification, confidence.to_f, metadata)
  rescue ActiveRecord::RecordInvalid => e
    invalid(raw_value, e.record.errors.full_messages.to_sentence.presence || e.message)
  end

  def upsert(value, classification, confidence, metadata)
    record = model.find_by(attribute => value)
    created = record.nil?
    record ||= model.find_or_create_by_natural_key!(attribute => value)

    # Deliberately does not touch last_seen_at. That column tracks values people
    # ask us about, and a feed push is not somebody asking.
    verdict = VerdictService.apply_trusted_source!(
      record,
      classification: classification,
      confidence: confidence,
      source: source_name,
      metadata: metadata
    )

    {
      value: value,
      status: created ? "created" : "updated",
      id: record.public_id,
      classification: verdict.classification,
      confidence: verdict.confidence_score,
      verdict_id: verdict.public_id
    }
  end

  # Reads one entry, which may be a bare value or an object stating its own
  # classification. A bare value falls back to the request-level defaults, so a
  # source pushing a single-classification feed does not repeat itself.
  def extract(entry)
    # A String answers to #[] as well, so the test has to be for a key lookup.
    return [ entry, default_classification, default_confidence_value, {} ] unless entry.respond_to?(:key?)

    value = entry[attribute.to_s] || entry[attribute] || entry["value"] || entry[:value]
    classification = (entry["classification"] || entry[:classification]).presence || default_classification
    confidence = entry["confidence"] || entry[:confidence]
    confidence = default_confidence_value if confidence.nil?

    [ value, classification&.to_s, confidence, sanitize_metadata(entry["metadata"] || entry[:metadata]) ]
  end

  def default_confidence_value
    default_confidence.nil? ? DEFAULT_CONFIDENCE : default_confidence
  end

  # Returns the metadata hash, {} when there is none, or :invalid when it is not
  # a hash or is too large to keep.
  def sanitize_metadata(metadata)
    return {} if metadata.blank?

    hash = metadata.respond_to?(:to_unsafe_h) ? metadata.to_unsafe_h : metadata
    return :invalid unless hash.is_a?(Hash)
    return :invalid if hash.to_json.bytesize > MAX_METADATA_BYTES

    hash.deep_stringify_keys
  end

  def valid_confidence?(confidence)
    Float(confidence).between?(0, 1)
  rescue ArgumentError, TypeError
    false
  end

  def protection_for(value)
    return nil if config[:protectable].nil?

    Phish::Protection.protection_for(config[:protectable], value)
  end

  # Named on every verdict this submission writes, so the audit trail says which
  # partner classified the record rather than only that a partner did.
  def source_name
    "service:#{service.name}"
  end

  def invalid(value, reason)
    { value: value.to_s, status: "invalid", reason: reason }
  end

  def rejected(value, reason, **extra)
    { value: value, status: "rejected", reason: reason }.merge(extra)
  end

  # ===========================================
  # Normalization and validation, per type
  # ===========================================

  def normalize(value)
    # Anything else is a nested object or array that a normalizer would either
    # choke on or silently turn into nonsense. Treat it as a missing value.
    return nil unless value.is_a?(String) || value.is_a?(Numeric)

    case type
    when "domain" then normalize_domain(value)
    when "url" then value.to_s.strip
    when "email" then Phish::Email.normalize_email(value)
    when "phone_number" then Phish::PhoneNumber.normalize_phone_number(value)
    end
  end

  # Matches Api::V1::Domain::DomainsController: a source may send a URL where we
  # want the host, and rejecting it outright would be unhelpful.
  def normalize_domain(value)
    domain = value.to_s.strip.downcase
    domain = domain.sub(%r{\Ahttps?://}, "")
    domain = domain.split("/").first.to_s
    domain.split(":").first.to_s
  end

  def valid_value?(value)
    case type
    when "domain" then value.match?(/\A[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}\z/i)
    when "url" then value.match?(/\A#{URI::DEFAULT_PARSER.make_regexp(%w[http https])}\z/)
    when "email" then Phish::Email.valid_email?(value)
    when "phone_number" then Phish::PhoneNumber.valid_e164?(value)
    end
  end
end
