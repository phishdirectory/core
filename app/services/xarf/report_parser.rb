# frozen_string_literal: true

module Xarf
  # Parses incoming XARF v4 reports and extracts relevant data
  #
  # Usage:
  #   parser = Xarf::ReportParser.new(json_string_or_hash)
  #   if parser.valid?
  #     result = parser.parse
  #     # result contains normalized data for creating/updating records
  #   else
  #     parser.errors # => ["Missing required field: report_id", ...]
  #   end
  #
  class ReportParser
    XARF_VERSION_PATTERN = /\A4\.\d+\.\d+\z/
    UUID_PATTERN = /\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/i

    REQUIRED_FIELDS = %w[
      xarf_version
      report_id
      timestamp
      reporter
      sender
      source_identifier
      category
      type
    ].freeze

    REQUIRED_CONTACT_FIELDS = %w[org contact domain].freeze

    attr_reader :raw_data, :errors

    def initialize(data)
      @errors = []
      @parsed = false
      @raw_data = normalize_input(data)
    end

    # Validate the XARF report structure
    #
    # @return [Boolean] true if valid
    def valid?
      validate unless @validated
      errors.empty?
    end

    # Check if report has been parsed
    #
    # @return [Boolean]
    def parsed?
      @parsed
    end

    # Parse the XARF report and extract relevant data
    #
    # @return [Hash] normalized data for record creation
    # @raise [InvalidReportError] if report is invalid
    def parse
      raise InvalidReportError, errors.join(", ") unless valid?

      @parsed = true

      {
        report_id: raw_data["report_id"],
        xarf_version: raw_data["xarf_version"],
        timestamp: parse_timestamp(raw_data["timestamp"]),
        category: raw_data["category"],
        type: raw_data["type"],
        source_identifier: raw_data["source_identifier"],
        reporter: parse_contact(raw_data["reporter"]),
        sender: parse_contact(raw_data["sender"]),
        classification: derive_classification,
        confidence: derive_confidence,
        urls: extract_urls,
        domains: extract_domains,
        ip_addresses: extract_ip_addresses,
        evidence: extract_evidence,
        metadata: extract_metadata,
        tags: raw_data["tags"] || [],
        raw: raw_data
      }
    end

    # Get the XARF category
    #
    # @return [String, nil]
    def category
      raw_data["category"]
    end

    # Get the XARF type
    #
    # @return [String, nil]
    def type
      raw_data["type"]
    end

    # Get the source identifier (IP, domain, etc.)
    #
    # @return [String, nil]
    def source_identifier
      raw_data["source_identifier"]
    end

    # Get URLs from the report
    #
    # @return [Array<String>]
    def urls
      extract_urls
    end

    # Get domains from the report
    #
    # @return [Array<String>]
    def domains
      extract_domains
    end

    class InvalidReportError < StandardError; end

    private

    def normalize_input(data)
      case data
      when String
        JSON.parse(data)
      when Hash
        data.deep_stringify_keys
      when ActionController::Parameters
        data.to_unsafe_h.deep_stringify_keys
      else
        {}
      end
    rescue JSON::ParserError
      @errors << "Invalid JSON format"
      {}
    end

    def validate
      @validated = true

      validate_required_fields
      validate_xarf_version
      validate_report_id
      validate_timestamp
      validate_category_and_type
      validate_contacts
    end

    def validate_required_fields
      REQUIRED_FIELDS.each do |field|
        if raw_data[field].blank?
          errors << "Missing required field: #{field}"
        end
      end
    end

    def validate_xarf_version
      version = raw_data["xarf_version"]
      return if version.blank? # Already caught by required fields

      unless version.match?(XARF_VERSION_PATTERN)
        errors << "Invalid xarf_version format: expected 4.x.x"
      end
    end

    def validate_report_id
      report_id = raw_data["report_id"]
      return if report_id.blank?

      unless report_id.match?(UUID_PATTERN)
        errors << "Invalid report_id format: expected UUID v4"
      end
    end

    def validate_timestamp
      timestamp = raw_data["timestamp"]
      return if timestamp.blank?

      Time.iso8601(timestamp)
    rescue ArgumentError
      errors << "Invalid timestamp format: expected ISO 8601"
    end

    def validate_category_and_type
      category = raw_data["category"]
      type = raw_data["type"]

      return if category.blank? || type.blank?

      unless CategoryMapper.valid_xarf_category?(category)
        errors << "Invalid category: #{category}"
      end

      unless CategoryMapper.valid_xarf_type?(type)
        errors << "Invalid type: #{type}"
      end

      expected_category = CategoryMapper.category_for_type(type)
      if expected_category && expected_category != category
        errors << "Type '#{type}' does not belong to category '#{category}'"
      end
    end

    def validate_contacts
      %w[reporter sender].each do |contact_type|
        contact = raw_data[contact_type]
        next if contact.blank?

        unless contact.is_a?(Hash)
          errors << "#{contact_type} must be an object"
          next
        end

        REQUIRED_CONTACT_FIELDS.each do |field|
          if contact[field].blank?
            errors << "Missing #{contact_type}.#{field}"
          end
        end
      end
    end

    def parse_timestamp(timestamp_str)
      return nil if timestamp_str.blank?
      Time.iso8601(timestamp_str)
    rescue ArgumentError
      nil
    end

    def parse_contact(contact)
      return nil if contact.blank?

      {
        organization: contact["org"],
        email: contact["contact"],
        domain: contact["domain"]
      }
    end

    def derive_classification
      CategoryMapper.from_xarf(raw_data["category"], raw_data["type"])
    end

    def derive_confidence
      base_confidence = CategoryMapper.confidence_for_type(raw_data["type"])

      # Adjust based on report confidence if provided
      if raw_data["confidence"].present?
        report_confidence = raw_data["confidence"].to_f.clamp(0.0, 1.0)
        # Weighted average: 70% type confidence, 30% report confidence
        (base_confidence * 0.7) + (report_confidence * 0.3)
      else
        base_confidence
      end
    end

    def extract_urls
      urls = []

      # Direct URL field
      urls << raw_data["url"] if raw_data["url"].present?

      # Redirect chain
      if raw_data["redirect_chain"].is_a?(Array)
        urls.concat(raw_data["redirect_chain"])
      end

      # Submission URL (for phishing)
      urls << raw_data["submission_url"] if raw_data["submission_url"].present?

      # From evidence items
      evidence_items = raw_data["evidence"] || []
      evidence_items.each do |item|
        if item["content_type"]&.include?("url") && item["payload"].present?
          decoded = decode_payload(item["payload"])
          urls << decoded if decoded.present? && decoded.match?(%r{\Ahttps?://})
        end
      end

      urls.compact.uniq
    end

    def extract_domains
      domains = []

      # From source_identifier if it's a domain
      source = raw_data["source_identifier"]
      if source.present? && !ip_address?(source)
        domains << normalize_domain(source)
      end

      # From cloned_site field (target of phishing)
      domains << raw_data["cloned_site"] if raw_data["cloned_site"].present?

      # From target_brand (might be a domain)
      target = raw_data["target_brand"]
      if target.present? && target.include?(".")
        domains << normalize_domain(target)
      end

      # Extract domains from URLs
      urls.each do |url|
        domain = extract_domain_from_url(url)
        domains << domain if domain.present?
      end

      domains.compact.uniq
    end

    def extract_ip_addresses
      ips = []

      source = raw_data["source_identifier"]
      ips << source if source.present? && ip_address?(source)

      # From evidence or additional fields
      if raw_data["additional_ip_addresses"].is_a?(Array)
        raw_data["additional_ip_addresses"].each do |ip|
          ips << ip if ip_address?(ip)
        end
      end

      ips.compact.uniq
    end

    def extract_evidence
      evidence_items = raw_data["evidence"] || []

      evidence_items.map do |item|
        {
          content_type: item["content_type"],
          description: item["description"],
          hashes: item["hashes"] || [],
          payload_size: item["payload"]&.length
        }
      end
    end

    def extract_metadata
      {
        target_brand: raw_data["target_brand"],
        cloned_site: raw_data["cloned_site"],
        phishing_kit: raw_data["phishing_kit"],
        credential_fields: raw_data["credential_fields"],
        lure_type: raw_data["lure_type"],
        detection_evasion: raw_data["detection_evasion"],
        reporter_reference_id: raw_data["reporter_reference_id"],
        priority: raw_data["priority"],
        legacy_xarf_version: raw_data["legacy_xarf_version"]
      }.compact
    end

    def decode_payload(payload)
      Base64.decode64(payload)
    rescue StandardError
      nil
    end

    def ip_address?(str)
      return false if str.blank?

      # IPv4
      return true if str.match?(/\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/)

      # IPv6 (simplified check)
      str.include?(":") && str.match?(/\A[0-9a-f:]+\z/i)
    end

    def normalize_domain(domain)
      domain = domain.to_s.strip.downcase
      domain = domain.sub(%r{\Ahttps?://}, "")
      domain = domain.split("/").first
      domain = domain.split(":").first
      domain
    end

    def extract_domain_from_url(url)
      uri = URI.parse(url)
      uri.host&.downcase
    rescue URI::InvalidURIError
      nil
    end
  end
end
