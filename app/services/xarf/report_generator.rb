# frozen_string_literal: true

module Xarf
  # Generates XARF v4 compliant reports from phish.directory data
  #
  # Usage:
  #   generator = Xarf::ReportGenerator.new
  #
  #   # Generate from a domain
  #   report = generator.generate_for_domain(domain)
  #
  #   # Generate from a URL
  #   report = generator.generate_for_url(url)
  #
  #   # Generate from a verdict
  #   report = generator.generate_for_verdict(verdict, source_type: :domain, source: domain)
  #
  #   # Get JSON
  #   report.to_json
  #
  class ReportGenerator
    XARF_VERSION = "4.0.0"

    DEFAULT_REPORTER = {
      org: "phish.directory",
      contact: "abuse@phish.directory",
      domain: "phish.directory"
    }.freeze

    attr_reader :reporter

    def initialize(reporter: nil)
      @reporter = reporter || DEFAULT_REPORTER
    end

    # Generate a XARF report for a Phish::Domain record
    #
    # @param domain [Phish::Domain] domain record
    # @param options [Hash] additional options
    # @return [Hash] XARF v4 compliant report
    def generate_for_domain(domain, **options)
      raise ArgumentError, "Domain required" if domain.nil?

      verdict = domain.verdict
      mapping = CategoryMapper.map_verdict(verdict)

      unless mapping[:reportable]
        return { error: "Domain classification not reportable via XARF" }
      end

      build_report(
        source_identifier: domain.domain,
        source_type: :domain,
        category: mapping[:category],
        type: mapping[:type],
        confidence: mapping[:confidence],
        verdict: verdict,
        record: domain,
        **options
      )
    end

    # Generate a XARF report for a Phish::Url record
    #
    # @param url [Phish::Url] URL record
    # @param options [Hash] additional options
    # @return [Hash] XARF v4 compliant report
    def generate_for_url(url, **options)
      raise ArgumentError, "URL required" if url.nil?

      verdict = url.verdict
      mapping = CategoryMapper.map_verdict(verdict)

      unless mapping[:reportable]
        return { error: "URL classification not reportable via XARF" }
      end

      build_report(
        source_identifier: url.domain || url.url,
        source_type: :url,
        category: mapping[:category],
        type: mapping[:type],
        confidence: mapping[:confidence],
        verdict: verdict,
        record: url,
        url: url.url,
        **options
      )
    end

    # Generate a XARF report for a Verdict with a specified source
    #
    # @param verdict [Verdict] verdict record
    # @param source_type [Symbol] :domain or :url
    # @param source [String] the source identifier
    # @param options [Hash] additional options
    # @return [Hash] XARF v4 compliant report
    def generate_for_verdict(verdict, source_type:, source:, **options)
      raise ArgumentError, "Verdict required" if verdict.nil?
      raise ArgumentError, "Source required" if source.blank?

      mapping = CategoryMapper.map_verdict(verdict)

      unless mapping[:reportable]
        return { error: "Verdict classification not reportable via XARF" }
      end

      build_report(
        source_identifier: source,
        source_type: source_type,
        category: mapping[:category],
        type: mapping[:type],
        confidence: mapping[:confidence],
        verdict: verdict,
        **options
      )
    end

    # Generate bulk XARF reports for multiple domains
    #
    # @param domains [Array<Phish::Domain>] array of domain records
    # @param options [Hash] additional options
    # @return [Array<Hash>] array of XARF reports
    def generate_bulk_for_domains(domains, **options)
      domains.filter_map do |domain|
        report = generate_for_domain(domain, **options)
        report unless report[:error]
      end
    end

    # Generate bulk XARF reports for multiple URLs
    #
    # @param urls [Array<Phish::Url>] array of URL records
    # @param options [Hash] additional options
    # @return [Array<Hash>] array of XARF reports
    def generate_bulk_for_urls(urls, **options)
      urls.filter_map do |url|
        report = generate_for_url(url, **options)
        report unless report[:error]
      end
    end

    # Export reports to NDJSON format (one JSON per line)
    #
    # @param reports [Array<Hash>] array of XARF reports
    # @return [String] NDJSON formatted string
    def to_ndjson(reports)
      reports.map { |r| r.to_json }.join("\n")
    end

    private

    def build_report(source_identifier:, source_type:, category:, type:, confidence:, verdict:, record: nil, **options)
      report = {
        xarf_version: XARF_VERSION,
        report_id: generate_uuid,
        timestamp: Time.current.iso8601,
        reporter: format_contact(reporter, include_type: true),
        sender: format_contact(reporter),
        source_identifier: source_identifier,
        category: category,
        type: type,
        severity: determine_severity(type, confidence),
        description: build_description(type, source_identifier, verdict)
      }

      # Add confidence if available
      report[:confidence] = confidence.round(2) if confidence

      # Add URL if provided
      report[:url] = options[:url] if options[:url].present?

      # Add type-specific fields
      add_phishing_fields(report, verdict, record, options) if type == "phishing"
      add_fraud_fields(report, verdict, record, options) if type == "fraud"

      # Add evidence (always include, even if empty array for spec compliance)
      evidence = build_evidence(verdict, record, options)
      report[:evidence] = evidence

      # Add tags
      tags = build_tags(verdict, record, source_type)
      report[:tags] = tags if tags.any?

      # Add optional fields
      add_optional_fields(report, verdict, record, options)

      report
    end

    def format_contact(contact, include_type: false)
      result = {
        org: contact[:org],
        contact: contact[:contact],
        domain: contact[:domain]
      }
      result[:type] = "automated" if include_type
      result
    end

    def build_description(type, source_identifier, verdict)
      confidence_text = if verdict&.confidence_score
                          "#{(verdict.confidence_score * 100).round}% confidence"
      else
                          "unconfirmed"
      end

      sources_count = verdict&.sources_list&.count || 0
      sources_text = sources_count > 0 ? "detected by #{sources_count} source#{'s' if sources_count > 1}" : ""

      case type
      when "phishing"
        base = "Phishing site identified at #{source_identifier}"
        [ base, confidence_text, sources_text ].reject(&:blank?).join(" - ")
      when "suspicious_registration"
        "Suspicious domain registration: #{source_identifier} - #{confidence_text}"
      when "malware"
        "Malware distribution identified at #{source_identifier} - #{confidence_text}"
      when "fraud"
        "Fraudulent activity identified at #{source_identifier} - #{confidence_text}"
      else
        "Abuse report for #{source_identifier} - #{confidence_text}"
      end
    end

    def generate_uuid
      SecureRandom.uuid
    end

    def determine_severity(type, confidence)
      # Severity based on type and confidence
      # critical: immediate threat requiring urgent action
      # high: significant threat
      # medium: moderate threat
      # low: minor or informational
      base_severity = case type
      when "phishing", "malware", "fraud"
                        confidence && confidence >= 0.8 ? "high" : "medium"
      when "suspicious_registration"
                        "medium"
      else
                        "low"
      end

      # Elevate to critical for high-confidence phishing/malware
      if %w[phishing malware].include?(type) && confidence && confidence >= 0.95
        "critical"
      else
        base_severity
      end
    end

    def add_phishing_fields(report, verdict, record, options)
      # Target brand from metadata or options
      target_brand = options[:target_brand] ||
                     verdict&.metadata_hash&.dig("target_brand")
      report[:target_brand] = target_brand if target_brand.present?

      # Cloned site
      cloned_site = options[:cloned_site] ||
                    verdict&.metadata_hash&.dig("cloned_site")
      report[:cloned_site] = cloned_site if cloned_site.present?

      # Credential fields if known
      credential_fields = options[:credential_fields] ||
                          verdict&.metadata_hash&.dig("credential_fields")
      report[:credential_fields] = credential_fields if credential_fields.present?

      # Phishing kit identification
      phishing_kit = options[:phishing_kit] ||
                     verdict&.metadata_hash&.dig("phishing_kit")
      report[:phishing_kit] = phishing_kit if phishing_kit.present?

      # Lure type
      lure_type = options[:lure_type] ||
                  verdict&.metadata_hash&.dig("lure_type")
      report[:lure_type] = lure_type if lure_type.present?
    end

    def add_fraud_fields(report, verdict, record, options)
      # Similar to phishing but with fraud-specific context
      target_brand = options[:target_brand] ||
                     verdict&.metadata_hash&.dig("target_brand")
      report[:target_brand] = target_brand if target_brand.present?
    end

    # Build evidence array for XARF report
    #
    # XARF Evidence can include (per spec):
    #   - Screenshots of phishing pages (image/png, image/jpeg)
    #   - Email headers and content (message/rfc822, text/plain)
    #   - HTTP response data (application/json, text/html)
    #   - DNS records (application/json)
    #   - WHOIS data (text/plain)
    #   - Malware samples (application/octet-stream) - with caution
    #   - Log files (text/plain, application/json)
    #   - API responses from detection services
    #
    # Each evidence item should have:
    #   - content_type: MIME type
    #   - payload: Base64-encoded content
    #   - description: Human-readable description
    #   - hashes: Array of integrity hashes (sha256:xxx, sha512:xxx, md5:xxx)
    #
    # TODO: Momento (screenshot capturing service) will provide:
    #   - Screenshots of phishing pages at time of detection
    #   - Visual evidence for XARF reports
    #
    def build_evidence(verdict, record, options)
      evidence = []

      # Add detection service responses as evidence
      # These are the raw results from services like VirusTotal, Google Safe Browsing, etc.
      if verdict&.sources_list&.any?
        sources_json = verdict.sources_list.to_json
        evidence << {
          type: "detection_results",
          description: "Detection service responses from #{verdict.sources_list.map { |s| s['name'] || s[:name] }.compact.join(', ')}",
          hash: Digest::SHA256.hexdigest(sources_json),
          hash_algorithm: "sha256"
        }
      end

      # Add verdict metadata as evidence if present
      if verdict&.metadata_hash&.any?
        metadata_json = verdict.metadata_hash.to_json
        evidence << {
          type: "metadata",
          description: "Additional detection metadata",
          hash: Digest::SHA256.hexdigest(metadata_json),
          hash_algorithm: "sha256"
        }
      end

      # Add screenshot if provided (from Momento or manual upload)
      if options[:screenshot].present?
        evidence << {
          type: "screenshot",
          description: "Screenshot of malicious content",
          hash: options[:screenshot_hash],
          hash_algorithm: "sha256"
        }.compact
      end

      # Add custom evidence items
      if options[:evidence].is_a?(Array)
        evidence.concat(options[:evidence])
      end

      evidence
    end

    def build_tags(verdict, record, source_type)
      tags = []

      # Add source type tag
      tags << "phishdirectory:source:#{source_type}"

      # Add classification tag
      if verdict&.classification
        tags << "phishdirectory:classification:#{verdict.classification}"
      end

      # Add confidence level tag
      if verdict&.confidence_score
        confidence_level = case verdict.confidence_score
        when 0.8..1.0 then "high"
        when 0.5...0.8 then "medium"
        else "low"
        end
        tags << "phishdirectory:confidence:#{confidence_level}"
      end

      # Add TLD tag for domains
      if record.respond_to?(:tld) && record.tld.present?
        tags << "phishdirectory:tld:#{record.tld.name}"
      end

      # Add source service tags
      verdict&.sources_list&.each do |source|
        source_name = source["name"] || source[:name]
        tags << "phishdirectory:detected_by:#{source_name}" if source_name
      end

      tags.uniq
    end

    def add_optional_fields(report, verdict, record, options)
      # Reporter reference ID (our internal ID)
      if record&.respond_to?(:public_id)
        report[:reporter_reference_id] = record.public_id
      elsif verdict&.respond_to?(:public_id)
        report[:reporter_reference_id] = verdict.public_id
      end

      # Priority based on confidence
      if verdict&.confidence_score
        report[:priority] = case verdict.confidence_score
        when 0.9..1.0 then "high"
        when 0.7...0.9 then "medium"
        else "low"
        end
      end

      # Custom fields from options
      if options[:reporter_custom_fields].is_a?(Hash)
        report[:reporter_custom_fields] = options[:reporter_custom_fields]
      end
    end
  end
end
