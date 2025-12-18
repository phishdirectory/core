# frozen_string_literal: true

module Report
  # Creates a report case when a phishing domain/URL is detected
  # with confidence above the configured threshold
  class CaseCreationService
    attr_reader :reportable, :verdict, :logger

    def initialize(reportable, verdict, logger: Rails.logger)
      @reportable = reportable
      @verdict = verdict
      @logger = logger
    end

    def create_case!
      return nil unless should_create_case?
      return nil if existing_open_case?

      Report::Case.transaction do
        # Create verdict snapshot for historical reference
        snapshot = create_verdict_snapshot

        # Fetch domain info (WHOIS/RDAP)
        domain_info = fetch_domain_info

        # Create the case
        report_case = Report::Case.create!(
          reportable: reportable,
          verdict_snapshot: snapshot,
          confidence_at_creation: verdict.confidence_score,
          domain_info: domain_info
        )

        log_info("Created case #{report_case.case_number} for #{domain_name}")

        # Create submissions to appropriate contacts
        create_submissions(report_case, domain_info)

        # Check if manual review needed (no contacts found)
        if report_case.submissions.empty?
          report_case.mark_for_manual_review!("No abuse contacts found")
          Report::GeneratePdfJob.perform_later(report_case.id)
          log_info("Case #{report_case.case_number} requires manual review - no contacts found")
        else
          Report::ProcessCaseJob.perform_later(report_case.id)
        end

        report_case
      end
    rescue StandardError => e
      log_error("Failed to create case", e)
      raise
    end

    private

    def should_create_case?
      return false unless verdict&.classification == "phishing"
      return false unless verdict.confidence_score >= confidence_threshold
      return false unless Flipper.enabled?(:auto_reporting)

      true
    end

    def confidence_threshold
      Rails.application.credentials.dig(:reporting, :confidence_threshold) || 0.8
    end

    def existing_open_case?
      Report::Case.active.exists?(
        reportable_type: reportable.class.name,
        reportable_id: reportable.id
      )
    end

    def domain_name
      case reportable
      when Phish::Domain
        reportable.domain
      when Phish::Url
        reportable.domain
      end
    end

    def create_verdict_snapshot
      # Create a copy of the verdict for historical reference
      Verdict.create!(
        classification: verdict.classification,
        confidence_score: verdict.confidence_score,
        sources: verdict.sources,
        metadata: (verdict.metadata || {}).merge(
          snapshot_of: verdict.id,
          snapshot_at: Time.current.iso8601
        )
      )
    end

    def fetch_domain_info
      lookup_service = Report::DomainLookupService.new(logger: logger)
      lookup = lookup_service.lookup(domain_name)

      lookup&.to_summary || {}
    rescue StandardError => e
      log_error("Failed to fetch domain info", e)
      {}
    end

    def create_submissions(report_case, domain_info)
      contacts = determine_abuse_contacts(domain_info)

      # Sort by priority and create with dependencies
      registrar_submission = nil

      contacts.sort_by(&:priority).each do |contact|
        # Hosting provider submissions depend on registrar being notified first
        depends_on = contact.contact_type_hosting? ? registrar_submission : nil

        submission = report_case.submissions.create!(
          abuse_contact: contact,
          payload: build_payload(report_case, contact),
          depends_on_submission: depends_on
        )

        registrar_submission = submission if contact.contact_type_registrar?

        log_info("Created submission to #{contact.name} for case #{report_case.case_number}")
      end
    end

    def determine_abuse_contacts(domain_info)
      contacts = []

      # Find contact from cached lookup
      lookup = Report::DomainLookup.for_domain(domain_name)

      if lookup
        contacts << lookup.matched_registrar_contact if lookup.matched_registrar_contact
        contacts << lookup.matched_hosting_contact if lookup.matched_hosting_contact
      end

      # Add security vendors that always receive reports
      contacts += Report::AbuseContact.always_report_to.to_a

      contacts.uniq
    end

    def build_payload(report_case, _contact)
      {
        domain: domain_name,
        url: reportable.is_a?(Phish::Url) ? reportable.url : nil,
        classification: verdict.classification,
        confidence: verdict.confidence_score,
        sources: verdict.sources,
        detected_at: verdict.created_at&.iso8601,
        case_reference: report_case.case_number,
        reporter: "phish.directory",
        reporter_email: report_case.email_address
      }.compact
    end

    def log_info(message)
      logger.info("[CaseCreation] #{message}")
    end

    def log_error(message, error)
      logger.error("[CaseCreation] #{message}: #{error.message}")
    end
  end
end
