# frozen_string_literal: true

module Report
  # Service for submitting abuse reports via API
  # Supports multiple API types (Google Safe Browsing, PhishTank, generic REST)
  class ApiSubmissionService < BaseService
    attr_reader :submission

    # Known API handlers
    API_HANDLERS = {
      "cleandns" => :submit_cleandns,
      "google_safe_browsing" => :submit_google_safe_browsing,
      "phishtank" => :submit_phishtank,
      "urlscan" => :submit_urlscan,
      "fishfish" => :submit_fishfish,
      "phish_report" => :submit_phish_report,
      "generic" => :submit_generic
    }.freeze

    def initialize(submission, logger: Rails.logger)
      super(logger: logger)
      @submission = submission
    end

    def submit!
      validate_submission!

      log_info("Submitting API report to #{abuse_contact.name}")

      # Determine which handler to use based on contact metadata or name
      handler = determine_handler
      success = send(handler)

      if success
        submission.mark_sent!
        log_info("Successfully submitted report to #{abuse_contact.name} for case #{report_case.case_number}")
      end

      success
    rescue ServiceError => e
      handle_error(e)
      false
    rescue StandardError => e
      handle_error(e)
      false
    end

    private

    def validate_submission!
      raise ArgumentError, "Submission is nil" unless submission
      raise ArgumentError, "Not an API contact" unless abuse_contact.contact_api?
      raise ArgumentError, "API endpoint is blank" if abuse_contact.api_endpoint.blank?
      raise ArgumentError, "Submission not in valid state" unless submission.status_pending? || submission.status_queued?
    end

    def report_case
      @report_case ||= submission.case
    end

    def abuse_contact
      @abuse_contact ||= submission.abuse_contact
    end

    # Get API key from contact or fall back to credentials
    def api_key_for(provider)
      # First check if contact has an API key set
      return abuse_contact.api_key if abuse_contact.api_key.present?

      # Fall back to credentials
      Rails.application.credentials.dig(provider, :api_key)
    end

    def payload
      @payload ||= submission.payload || submission.build_payload
    end

    def determine_handler
      # Check for specific API type in web_form_fields (we reuse this for API config)
      api_type = abuse_contact.web_form_fields&.dig("api_type")&.to_s&.downcase

      if api_type.present? && API_HANDLERS.key?(api_type)
        return API_HANDLERS[api_type]
      end

      # Try to detect from name
      name = abuse_contact.name.downcase
      return :submit_cleandns if name.include?("cleandns")
      return :submit_google_safe_browsing if name.include?("google") && name.include?("safe")
      return :submit_phishtank if name.include?("phishtank")
      return :submit_urlscan if name.include?("urlscan")
      return :submit_fishfish if name.include?("fishfish") || name.include?("yuri")
      return :submit_phish_report if name.include?("phish.report") || name.include?("phish report")

      # Default to generic
      :submit_generic
    end

    # =========================================
    # CleanDNS Trusted Reporter API
    # https://docs.cleandns.dev/
    # Uses full XARF format for abuse reports
    # =========================================
    def submit_cleandns
      api_key = api_key_for(:cleandns)
      raise ServiceError, "CleanDNS API key not configured" if api_key.blank?

      conn = connection(
        base_url: "https://api.cleandns.dev",
        headers: {
          "Content-Type" => "application/json",
          "Authorization" => api_key
        }
      )

      # Build XARF-compliant report
      xarf_report = build_cleandns_xarf_report

      response = conn.post("/v2/abuse/report", xarf_report)

      # Parse response to get report ID
      report_id = nil
      if response.is_a?(Hash)
        # Single report response
        if response["reports"]&.first&.dig("id")
          report_id = response["reports"].first["id"]
        elsif response["id"]
          report_id = response["id"]
        end

        # Check for errors
        if response["failure"]&.positive?
          error_msg = response["reports"]&.find { |r| r["error"] }&.dig("error")
          raise ServiceError, "CleanDNS rejected report: #{error_msg}" if error_msg
        end
      end

      submission.record_response!(
        status_code: 200,
        body: response.to_json,
        reference: report_id
      )

      log_info("CleanDNS report submitted with ID: #{report_id}")

      # Schedule status check for 24 hours from now
      Report::CheckCleandnsStatusJob.set(wait: 24.hours).perform_later(submission.id)

      true
    rescue Faraday::ClientError => e
      submission.record_response!(
        status_code: e.response[:status],
        body: e.response[:body].to_s
      )
      raise ServiceError, "CleanDNS API error: #{e.response[:status]}"
    end

    # Build XARF-compliant report for CleanDNS /v2/abuse/report endpoint
    # Based on: https://docs.cleandns.dev/
    def build_cleandns_xarf_report
      url_to_report = payload[:url] || "https://#{payload[:domain]}"
      confidence_pct = (payload[:confidence].to_f * 100).round

      # Build detection sources list for notes
      sources_list = if payload[:sources].present?
        payload[:sources].map { |s| s.is_a?(Hash) ? (s[:service] || s["service"]) : s.to_s }.join(", ")
      else
        "phish.directory aggregated threat intelligence"
      end

      {
        "Disclosure" => true,
        "Version" => 2,

        # Reporter information
        "ReporterInfo" => {
          "ReporterOrg" => "phish.directory",
          "ReporterOrgDomain" => "phish.directory",
          "ReporterContactName" => "phish.directory Automated Reporting",
          "ReporterContactEmail" => "reports@phish.directory"
        },

        # Report details
        "Report" => {
          "ReportClass" => "Content",
          "ReportType" => "Phishing",
          "ReporterNotes" => build_cleandns_notes(confidence_pct, sources_list),
          "Ongoing" => true,
          "Date" => format_cleandns_date(payload[:detected_at]),
          "ThreatActor" => payload[:domain],
          "SourceUrl" => url_to_report,

          # Custom fields for additional phish.directory context
          "Custom" => {
            "CaseReference" => payload[:case_reference],
            "Confidence" => confidence_pct,
            "DetectionSources" => sources_list
          }
        }
      }
    end

    def build_cleandns_notes(confidence_pct, sources_list)
      "Phishing site detected by phish.directory with #{confidence_pct}% confidence. " \
      "Detection sources: #{sources_list}. " \
      "Case reference: #{payload[:case_reference]}. " \
      "For case updates, contact #{report_case.email_address}."
    end

    def format_cleandns_date(date_string)
      # CleanDNS expects format: "2021-11-12 01:23:45"
      if date_string.present?
        Time.parse(date_string).strftime("%Y-%m-%d %H:%M:%S")
      else
        Time.current.strftime("%Y-%m-%d %H:%M:%S")
      end
    rescue ArgumentError
      Time.current.strftime("%Y-%m-%d %H:%M:%S")
    end

    # =========================================
    # Google Safe Browsing Submission
    # https://developers.google.com/safe-browsing/v4/submission-api
    # =========================================
    def submit_google_safe_browsing
      api_key = api_key_for(:google_safe_browsing)
      raise ServiceError, "Google Safe Browsing API key not configured" if api_key.blank?

      conn = connection(
        base_url: "https://safebrowsing.googleapis.com",
        headers: { "Content-Type" => "application/json" }
      )

      # Build threat entry
      url_to_report = payload[:url] || "https://#{payload[:domain]}"

      body = {
        submission: {
          uri: url_to_report
        }
      }

      response = conn.post("/v4/threatHits?key=#{api_key}", body)
      response_body = response.body

      submission.record_response!(
        status_code: response.status,
        body: response_body.to_json,
        reference: response_body.is_a?(Hash) ? response_body.dig("submissionId") : nil
      )

      true
    rescue Faraday::ClientError => e
      submission.record_response!(
        status_code: e.response[:status],
        body: e.response[:body].to_s
      )
      raise ServiceError, "Google Safe Browsing API error: #{e.response[:status]}"
    end

    # =========================================
    # PhishTank Submission
    # https://phishtank.org/api_info.php
    # =========================================
    def submit_phishtank
      api_key = api_key_for(:phishtank)
      raise ServiceError, "PhishTank API key not configured" if api_key.blank?

      conn = connection(
        base_url: "https://checkurl.phishtank.com",
        headers: { "Content-Type" => "application/x-www-form-urlencoded" }
      )

      url_to_report = payload[:url] || "https://#{payload[:domain]}"

      # PhishTank uses form-encoded data
      response = conn.post("/checkurl/") do |req|
        req.body = URI.encode_www_form(
          url: Base64.strict_encode64(url_to_report),
          format: "json",
          app_key: api_key
        )
      end

      submission.record_response!(
        status_code: 200,
        body: response.to_json,
        reference: response.dig("results", "phish_id")&.to_s
      )

      true
    rescue Faraday::ClientError => e
      submission.record_response!(
        status_code: e.response[:status],
        body: e.response[:body].to_s
      )
      raise ServiceError, "PhishTank API error: #{e.response[:status]}"
    end

    # =========================================
    # URLScan.io Submission
    # https://urlscan.io/docs/api/
    # =========================================
    def submit_urlscan
      api_key = api_key_for(:urlscan)
      raise ServiceError, "URLScan API key not configured" if api_key.blank?

      conn = connection(
        base_url: "https://urlscan.io",
        headers: {
          "Content-Type" => "application/json",
          "API-Key" => api_key
        }
      )

      url_to_report = payload[:url] || "https://#{payload[:domain]}"

      body = {
        url: url_to_report,
        visibility: "unlisted",
        tags: ["phishing", "phish.directory", report_case.case_number]
      }

      response = conn.post("/api/v1/scan/", body)

      submission.record_response!(
        status_code: 200,
        body: response.to_json,
        reference: response.dig("uuid")
      )

      true
    rescue Faraday::ClientError => e
      submission.record_response!(
        status_code: e.response[:status],
        body: e.response[:body].to_s
      )
      raise ServiceError, "URLScan API error: #{e.response[:status]}"
    end

    # =========================================
    # FishFish / Yuri Submission
    # https://yuri.bots.lostluma.dev/phish/report
    # Submits domains to FishFish via Lilly's yuri bot
    # =========================================
    def submit_fishfish
      # Yuri is the bot that submits to FishFish - check both credential keys
      api_key = api_key_for(:yuri) || api_key_for(:fishfish)
      raise ServiceError, "FishFish/Yuri API key not configured" if api_key.blank?

      conn = connection(
        base_url: "https://yuri.bots.lostluma.dev",
        headers: {
          "Content-Type" => "application/json",
          "Authorization" => api_key  # No Bearer prefix
        }
      )

      url_to_report = payload[:url] || payload[:domain]

      body = {
        url: url_to_report,
        reason: build_fishfish_reason
      }

      response = conn.post("/phish/report", body)

      accepted = response.is_a?(Hash) && response["accepted"]
      reason = response.is_a?(Hash) ? response["reason"] : response.to_s

      submission.record_response!(
        status_code: accepted ? 200 : 400,
        body: response.to_json,
        reference: nil
      )

      if accepted
        log_info("FishFish report accepted")
        true
      else
        # Not accepted but not an error - might be already known or protected
        log_info("FishFish report not accepted: #{reason}")
        true  # Still mark as sent since we successfully communicated
      end
    rescue Faraday::ClientError => e
      submission.record_response!(
        status_code: e.response[:status],
        body: e.response[:body].to_s
      )
      raise ServiceError, "FishFish API error: #{e.response[:status]}"
    end

    def build_fishfish_reason
      sources = payload[:sources]
      source_text = if sources.present?
        sources.map { |s| s.is_a?(Hash) ? (s[:service] || s["service"]) : s.to_s }.join(", ")
      else
        "phish.directory detection"
      end

      "Reported by phish.directory. " \
      "Confidence: #{(payload[:confidence].to_f * 100).round}%. " \
      "Sources: #{source_text}. " \
      "Case: #{payload[:case_reference]}"
    end

    # =========================================
    # Phish Report API
    # https://phish.report/api/v0
    # Creates takedown cases via phish.report
    # =========================================
    def submit_phish_report
      api_key = api_key_for(:phish_report)
      raise ServiceError, "Phish Report API key not configured" if api_key.blank?

      conn = connection(
        base_url: "https://phish.report",
        headers: {
          "Content-Type" => "application/json",
          "Authorization" => "Bearer #{api_key}"
        }
      )

      url_to_report = payload[:url] || "https://#{payload[:domain]}"

      body = {
        url: url_to_report,
        ignore_duplicates: true
      }

      response = conn.post("/api/v0/cases", body)
      response_body = response.body

      # Extract case ID from response
      case_id = response_body.is_a?(Hash) ? response_body["id"] : nil

      submission.record_response!(
        status_code: response.status,
        body: response_body.to_json,
        reference: case_id
      )

      log_info("Phish Report case created: #{case_id}")
      true
    rescue Faraday::ClientError => e
      submission.record_response!(
        status_code: e.response[:status],
        body: e.response[:body].to_s
      )
      raise ServiceError, "Phish Report API error: #{e.response[:status]}"
    end

    # =========================================
    # Generic REST API Submission
    # Uses configurable endpoint and payload mapping
    # =========================================
    def submit_generic
      endpoint = abuse_contact.api_endpoint
      api_key = abuse_contact.api_key

      # Parse URL parts
      uri = URI.parse(endpoint)
      base_url = "#{uri.scheme}://#{uri.host}"
      base_url += ":#{uri.port}" unless [80, 443].include?(uri.port)
      path = uri.path.presence || "/"

      # Build headers
      headers = { "Content-Type" => "application/json" }

      # Add API key - check config for where to put it
      auth_config = abuse_contact.web_form_fields&.dig("auth") || {}
      case auth_config["type"]
      when "header"
        headers[auth_config["header_name"] || "Authorization"] = api_key
      when "bearer"
        headers["Authorization"] = "Bearer #{api_key}"
      when "query"
        # Will be added to query params
      else
        # Default to Bearer token
        headers["Authorization"] = "Bearer #{api_key}"
      end

      conn = connection(base_url: base_url, headers: headers)

      # Build request body from payload
      body = build_generic_body

      response = conn.post(path, body)

      # Try to extract a reference from the response
      reference = extract_reference_from_response(response)

      submission.record_response!(
        status_code: 200,
        body: response.to_json,
        reference: reference
      )

      true
    rescue Faraday::ClientError => e
      submission.record_response!(
        status_code: e.response[:status],
        body: e.response[:body].to_s
      )
      raise ServiceError, "API error: #{e.response[:status]}"
    end

    def build_generic_body
      # Use custom mapping if provided, otherwise use standard payload
      mapping = abuse_contact.web_form_fields&.dig("payload_mapping")

      if mapping.present?
        mapping.transform_values do |key|
          payload[key.to_sym] || payload[key.to_s]
        end
      else
        {
          url: payload[:url] || "https://#{payload[:domain]}",
          domain: payload[:domain],
          source: "phish.directory",
          confidence: payload[:confidence],
          classification: payload[:classification],
          reference: payload[:case_reference],
          detected_at: payload[:detected_at]
        }.compact
      end
    end

    def extract_reference_from_response(response)
      return nil unless response.is_a?(Hash)

      # Common reference field names
      %w[id reference ticket_id submission_id uuid case_id].each do |key|
        value = response[key] || response[key.to_sym]
        return value.to_s if value.present?
      end

      nil
    end

    def handle_error(error)
      log_error("Failed to submit API report", error)

      submission.record_attempt!(error: error.message)

      if error.is_a?(RateLimitError)
        # Schedule retry after rate limit period
        submission.update!(next_retry_at: error.retry_after.seconds.from_now)
        log_info("Rate limited, will retry after #{error.retry_after}s")
      elsif submission.retryable?
        log_info("Submission will be retried (attempt #{submission.attempts}/#{submission.max_attempts})")
      else
        submission.fail!
        log_error("Submission failed permanently after #{submission.attempts} attempts", error)
      end
    end

    def log_error(message, error)
      logger.error("[ApiSubmission] #{message}: #{error.message}")
    end

    def log_info(message)
      logger.info("[ApiSubmission] #{message}")
    end

    # =========================================
    # CleanDNS Status Checking
    # https://docs.cleandns.dev/
    # =========================================
    class << self
      # Check status of a CleanDNS submission
      # Returns hash with :status, :tier, and :raw_response
      def check_cleandns_status(submission)
        return nil unless submission.submission_reference.present?

        api_key = cleandns_api_key(submission.abuse_contact)
        return nil if api_key.blank?

        conn = Faraday.new(url: "https://api.cleandns.dev") do |f|
          f.request :json
          f.response :json
          f.response :raise_error
          f.headers["Authorization"] = api_key
          f.headers["Content-Type"] = "application/json"
        end

        response = conn.get("/v2/abuse/status/#{submission.submission_reference}")

        {
          id: response.body["id"],
          tier: response.body["tier"],
          status: response.body["status"] || [],
          raw_response: response.body
        }
      rescue Faraday::Error => e
        Rails.logger.error("[ApiSubmission] CleanDNS status check failed: #{e.message}")
        nil
      end

      # Map CleanDNS status to our submission state
      def cleandns_status_to_state(status_info)
        return nil unless status_info

        statuses = status_info[:status]
        return nil if statuses.blank?

        # Check for resolved indicators
        resolved_keywords = ["Resolved", "Taken Down", "Suspended", "Removed"]
        if statuses.any? { |s| resolved_keywords.any? { |kw| s.to_s.include?(kw) } }
          return :resolved
        end

        # Check for acknowledged/in-progress indicators
        acknowledged_keywords = ["With Target", "Escalated", "Processing", "Forwarded"]
        if statuses.any? { |s| acknowledged_keywords.any? { |kw| s.to_s.include?(kw) } }
          return :acknowledged
        end

        nil
      end

      private

      def cleandns_api_key(abuse_contact)
        return abuse_contact.api_key if abuse_contact.api_key.present?

        Rails.application.credentials.dig(:cleandns, :api_key)
      end
    end
  end
end
