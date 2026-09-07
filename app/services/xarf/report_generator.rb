# frozen_string_literal: true

module Xarf
  # Generates X-ARF reports from phish.directory data.
  #
  # Output follows schema 3 of https://github.com/abusix/xarf, which is the
  # newest published schema. It is PascalCase and nests everything under
  # ReporterInfo and Report. Abuse desks with automated tooling validate
  # against it, so the same document serves the admin UI and the wire.
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
  #   # Generate the document that goes out as an email's xarf.json attachment
  #   report = generator.generate_for_submission(submission)
  #
  #   # Get JSON
  #   report.to_json
  #
  class ReportGenerator
    SCHEMA_VERSION = "3"

    DEFAULT_REPORTER = {
      org: "phish.directory",
      domain: "phish.directory",
      email: "reports@phish.directory",
      contact_name: "phish.directory Automated Reporting"
    }.freeze

    attr_reader :reporter

    def initialize(reporter: nil)
      @reporter = reporter || DEFAULT_REPORTER
    end

    # Generate an X-ARF report for a Phish::Domain record
    #
    # @param domain [Phish::Domain] domain record
    # @param options [Hash] additional options
    # @return [Hash] X-ARF schema 3 report
    def generate_for_domain(domain, **options)
      raise ArgumentError, "Domain required" if domain.nil?

      verdict = domain.verdict
      mapping = CategoryMapper.map_verdict(verdict)

      unless mapping[:reportable]
        return { error: "Domain classification not reportable via XARF" }
      end

      build_report(
        source_url: "https://#{domain.domain}",
        mapping: mapping,
        verdict: verdict,
        **options
      )
    end

    # Generate an X-ARF report for a Phish::Url record
    #
    # @param url [Phish::Url] URL record
    # @param options [Hash] additional options
    # @return [Hash] X-ARF schema 3 report
    def generate_for_url(url, **options)
      raise ArgumentError, "URL required" if url.nil?

      verdict = url.verdict
      mapping = CategoryMapper.map_verdict(verdict)

      unless mapping[:reportable]
        return { error: "URL classification not reportable via XARF" }
      end

      build_report(
        source_url: url.url,
        mapping: mapping,
        verdict: verdict,
        **options
      )
    end

    # Generate an X-ARF report for a Verdict with a specified source
    #
    # @param verdict [Verdict] verdict record
    # @param source_type [Symbol] :domain or :url
    # @param source [String] the source identifier
    # @param options [Hash] additional options
    # @return [Hash] X-ARF schema 3 report
    def generate_for_verdict(verdict, source_type:, source:, **options)
      raise ArgumentError, "Verdict required" if verdict.nil?
      raise ArgumentError, "Source required" if source.blank?

      mapping = CategoryMapper.map_verdict(verdict)

      unless mapping[:reportable]
        return { error: "Verdict classification not reportable via XARF" }
      end

      source_url = source_type.to_sym == :url ? source : "https://#{source}"

      build_report(source_url: source_url, mapping: mapping, verdict: verdict, **options)
    end

    # Generate the document that goes out as an abuse report's xarf.json.
    #
    # A submission carries case context the other entry points do not have: the
    # case number, the address replies thread back to, and the addresses the
    # domain resolved to when the case was opened.
    #
    # @param submission [Report::Submission] submission record
    # @param options [Hash] additional options
    # @return [Hash] X-ARF schema 3 report
    def generate_for_submission(submission, **options)
      raise ArgumentError, "Submission required" if submission.nil?

      report_case = submission.case
      payload = (submission.payload.presence || submission.build_payload).with_indifferent_access

      build_report(
        source_url: payload[:url].presence || "https://#{payload[:domain] || report_case.domain_name}",
        mapping: submission_mapping(payload),
        source_ip: case_source_ip(report_case),
        detected_at: payload[:detected_at],
        sources: payload[:sources],
        case_reference: payload[:case_reference] || report_case.case_number,
        # Replies to this address thread back onto the case.
        contact_email: report_case.email_address,
        **options
      )
    end

    # Generate bulk X-ARF reports for multiple domains
    #
    # @param domains [Array<Phish::Domain>] array of domain records
    # @param options [Hash] additional options
    # @return [Array<Hash>] array of X-ARF reports
    def generate_bulk_for_domains(domains, **options)
      domains.filter_map do |domain|
        report = generate_for_domain(domain, **options)
        report unless report[:error]
      end
    end

    # Generate bulk X-ARF reports for multiple URLs
    #
    # @param urls [Array<Phish::Url>] array of URL records
    # @param options [Hash] additional options
    # @return [Array<Hash>] array of X-ARF reports
    def generate_bulk_for_urls(urls, **options)
      urls.filter_map do |url|
        report = generate_for_url(url, **options)
        report unless report[:error]
      end
    end

    # Export reports to NDJSON format (one JSON per line)
    #
    # @param reports [Array<Hash>] array of X-ARF reports
    # @return [String] NDJSON formatted string
    def to_ndjson(reports)
      reports.map(&:to_json).join("\n")
    end

    private

    def build_report(source_url:, mapping:, verdict: nil, source_ip: nil, detected_at: nil,
                     sources: nil, case_reference: nil, contact_email: nil, **options)
      confidence = mapping[:confidence]
      source_names = format_sources(sources || verdict&.sources_list)

      {
        "Version" => SCHEMA_VERSION,
        "ReporterInfo" => reporter_info(contact_email),
        "Disclosure" => true,
        "Report" => {
          "ReportClass" => mapping[:report_class],
          "ReportType" => mapping[:report_type],
          "Date" => format_date(detected_at || verdict&.created_at),
          "SourceUrl" => source_url,
          "SourceIp" => normalize_ip(source_ip),
          "Ongoing" => true,
          "ReporterCaseID" => case_reference,
          "ReporterSeverity" => CategoryMapper.severity_for_confidence(confidence),
          "ReporterNotes" => notes(confidence, source_names, case_reference, contact_email),
          "Custom" => custom_fields(confidence, source_names, case_reference),
          "Samples" => options[:samples].presence
        }.compact
      }
    end

    # ReporterInfo forbids properties outside this set, so nothing else goes in.
    def reporter_info(contact_email)
      {
        "ReporterType" => "Org",
        "ReporterOrg" => reporter[:org],
        "ReporterOrgDomain" => reporter[:domain],
        "ReporterOrgEmail" => reporter[:email],
        "ReporterContactName" => reporter[:contact_name],
        "ReporterContactEmail" => contact_email || reporter[:email]
      }.compact
    end

    def submission_mapping(payload)
      mapping = CategoryMapper.to_xarf(payload[:classification]) ||
                CategoryMapper::CLASSIFICATION_TO_XARF["phishing"]

      mapping.merge(confidence: payload[:confidence].to_f)
    end

    # SourceIp only accepts an IP literal. Prefer IPv4: a report is more useful
    # to a host when it names the address most of the traffic reached.
    def case_source_ip(report_case)
      info = report_case.domain_info || {}

      Array(info["a_records"]).first || Array(info["aaaa_records"]).first
    end

    def normalize_ip(address)
      return nil if address.blank?

      IPAddr.new(address.to_s).to_s
    rescue IPAddr::InvalidAddressError
      nil
    end

    def format_date(timestamp)
      Time.parse(timestamp.to_s).utc.iso8601
    rescue ArgumentError, TypeError
      Time.current.utc.iso8601
    end

    def format_sources(sources)
      names = Array(sources).filter_map do |source|
        if source.is_a?(Hash)
          source["service"] || source[:service] || source["name"] || source[:name]
        else
          source.to_s.presence
        end
      end

      names.any? ? names.join(", ") : "phish.directory aggregated threat intelligence"
    end

    def notes(confidence, source_names, case_reference, contact_email)
      notes = "Phishing site detected by phish.directory with " \
              "#{confidence_percent(confidence)}% confidence. " \
              "Detection sources: #{source_names}."
      notes += " Case reference: #{case_reference}." if case_reference.present?
      notes += " Reply to #{contact_email} with any update on your investigation." if contact_email.present?
      notes
    end

    # Custom only accepts string and integer values.
    def custom_fields(confidence, source_names, case_reference)
      {
        "CaseReference" => case_reference,
        "Confidence" => confidence_percent(confidence),
        "DetectionSources" => source_names
      }.compact
    end

    def confidence_percent(confidence)
      (confidence.to_f * 100).round
    end
  end
end
