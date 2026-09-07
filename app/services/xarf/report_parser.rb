# frozen_string_literal: true

module Xarf
  # Parses incoming X-ARF reports and extracts relevant data.
  #
  # Accepts schema 3 of https://github.com/abusix/xarf, the same schema
  # Xarf::ReportGenerator emits.
  #
  # Usage:
  #   parser = Xarf::ReportParser.new(json_string_or_hash)
  #   if parser.valid?
  #     result = parser.parse
  #     # result contains normalized data for creating/updating records
  #   else
  #     parser.errors # => ["Missing required field: Version", ...]
  #   end
  #
  class ReportParser
    SUPPORTED_VERSIONS = %w[3].freeze

    REQUIRED_FIELDS = %w[Version ReporterInfo Disclosure Report].freeze
    REQUIRED_REPORT_FIELDS = %w[ReportClass ReportType Date].freeze

    # ReporterInfo requires these unless the reporter is a natural person.
    REQUIRED_REPORTER_FIELDS = %w[ReporterOrg ReporterOrgDomain ReporterOrgEmail].freeze

    attr_reader :raw_data, :errors

    def initialize(data)
      @errors = []
      @parsed = false
      @raw_data = normalize_input(data)
    end

    # Validate the X-ARF report structure
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

    # Parse the X-ARF report and extract relevant data
    #
    # @return [Hash] normalized data for record creation
    # @raise [InvalidReportError] if report is invalid
    def parse
      raise InvalidReportError, errors.join(", ") unless valid?

      @parsed = true

      {
        version: raw_data["Version"],
        timestamp: parse_timestamp(report["Date"]),
        report_class: report_class,
        report_type: report_type,
        report_subtype: report["ReportSubType"],
        case_id: report["ReporterCaseID"],
        severity: report["ReporterSeverity"],
        notes: report["ReporterNotes"],
        reporter: parse_reporter(raw_data["ReporterInfo"]),
        disclosure: raw_data["Disclosure"],
        classification: derive_classification,
        confidence: derive_confidence,
        urls: extract_urls,
        domains: extract_domains,
        ip_addresses: extract_ip_addresses,
        samples: extract_samples,
        metadata: extract_metadata,
        raw: raw_data
      }
    end

    # The Report object, which holds everything about the event itself
    #
    # @return [Hash]
    def report
      raw_data["Report"].is_a?(Hash) ? raw_data["Report"] : {}
    end

    # @return [String, nil]
    def report_class
      report["ReportClass"]
    end

    # @return [String, nil]
    def report_type
      report["ReportType"]
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
      validate_version
      validate_report
      validate_timestamp
      validate_class_and_type
      validate_reporter
    end

    def validate_required_fields
      REQUIRED_FIELDS.each do |field|
        # Disclosure is a boolean, so false is present but blank.
        next if field == "Disclosure" && [ true, false ].include?(raw_data[field])

        errors << "Missing required field: #{field}" if raw_data[field].blank?
      end
    end

    def validate_version
      version = raw_data["Version"]
      return if version.blank?

      unless SUPPORTED_VERSIONS.include?(version.to_s)
        errors << "Unsupported Version: expected one of #{SUPPORTED_VERSIONS.join(', ')}"
      end
    end

    def validate_report
      return errors << "Report must be an object" unless raw_data["Report"].is_a?(Hash)

      REQUIRED_REPORT_FIELDS.each do |field|
        errors << "Missing required field: Report.#{field}" if report[field].blank?
      end

      # A report is anchored to an origin by either an address or a URL.
      if report["SourceIp"].blank? && report["SourceUrl"].blank?
        errors << "Report requires either SourceIp or SourceUrl"
      end
    end

    def validate_timestamp
      timestamp = report["Date"]
      return if timestamp.blank?

      Time.iso8601(timestamp)
    rescue ArgumentError
      errors << "Invalid Report.Date format: expected ISO 8601"
    end

    def validate_class_and_type
      return if report_class.blank? || report_type.blank?

      unless CategoryMapper.valid_report_class?(report_class)
        errors << "Invalid ReportClass: #{report_class}"
      end

      unless CategoryMapper.valid_report_type?(report_type)
        errors << "Invalid ReportType: #{report_type}"
        return
      end

      unless CategoryMapper.type_in_class?(report_class, report_type)
        errors << "ReportType '#{report_type}' does not belong to ReportClass '#{report_class}'"
      end
    end

    def validate_reporter
      reporter = raw_data["ReporterInfo"]
      return if reporter.blank?

      return errors << "ReporterInfo must be an object" unless reporter.is_a?(Hash)

      # Contact details are optional when the reporter is a natural person.
      return if reporter["ReporterType"] == "Person"

      REQUIRED_REPORTER_FIELDS.each do |field|
        errors << "Missing ReporterInfo.#{field}" if reporter[field].blank?
      end
    end

    def parse_timestamp(timestamp_str)
      return nil if timestamp_str.blank?

      Time.iso8601(timestamp_str)
    rescue ArgumentError
      nil
    end

    def parse_reporter(reporter)
      return nil if reporter.blank?

      {
        type: reporter["ReporterType"],
        organization: reporter["ReporterOrg"],
        domain: reporter["ReporterOrgDomain"],
        email: reporter["ReporterOrgEmail"],
        contact_name: reporter["ReporterContactName"],
        contact_email: reporter["ReporterContactEmail"],
        contact_phone: reporter["ReporterContactPhone"]
      }.compact
    end

    def derive_classification
      CategoryMapper.from_xarf(report_class, report_type)
    end

    def derive_confidence
      CategoryMapper.confidence_for_type(report_type)
    end

    def extract_urls
      urls = []
      urls << report["SourceUrl"] if report["SourceUrl"].present?
      urls.compact.uniq
    end

    def extract_domains
      extract_urls.filter_map { |url| extract_domain_from_url(url) }.uniq
    end

    def extract_ip_addresses
      [ report["SourceIp"], report["DestinationIp"], report["AttackerIp"] ]
        .compact_blank
        .select { |address| ip_address?(address) }
        .uniq
    end

    def extract_samples
      Array(report["Samples"]).filter_map do |sample|
        next unless sample.is_a?(Hash)

        {
          content_type: sample["ContentType"],
          description: sample["Description"],
          base64_encoded: sample["Base64Encoded"],
          file_name: sample["FileName"],
          payload_size: sample["Payload"]&.length
        }.compact
      end
    end

    def extract_metadata
      {
        report_subtype: report["ReportSubType"],
        case_id: report["ReporterCaseID"],
        severity: report["ReporterSeverity"],
        ongoing: report["Ongoing"],
        threat_actor: report["ThreatActor"],
        source_port: report["SourcePort"],
        asn: report["ASN"],
        custom: report["Custom"]
      }.compact
    end

    def ip_address?(str)
      return false if str.blank?

      IPAddr.new(str.to_s)
      true
    rescue IPAddr::InvalidAddressError
      false
    end

    def extract_domain_from_url(url)
      URI.parse(url).host&.downcase
    rescue URI::InvalidURIError
      nil
    end
  end
end
