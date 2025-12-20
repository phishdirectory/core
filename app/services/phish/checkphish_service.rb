# frozen_string_literal: true

module Phish
  # CheckPhish API by Bolster
  # https://checkphish.bolster.ai/checkphish-api/
  #
  # Asynchronous API - submit URL for scan, then poll for results
  #
  # Rate Limits: Using conservative defaults (not documented)
  #
  class CheckphishService < BaseService
    BASE_URL = "https://developers.bolster.ai/api/"

    # Conservative rate limits (actual limits not documented)
    rate_limit :minute, requests: 60,  period: 1.minute
    rate_limit :daily,  requests: 500, period: 1.day

    # Dispositions returned by the API
    PHISHING_DISPOSITIONS = %w[phish].freeze
    SUSPICIOUS_DISPOSITIONS = %w[suspicious].freeze
    CLEAN_DISPOSITIONS = %w[clean].freeze

    def check_domain(domain)
      normalized = normalize_domain(domain)
      check_url("https://#{normalized}")
    end

    def check_url(url)
      normalized = normalize_url(url)
      log_info("Checking URL: #{normalized}")

      with_rate_limit do
        # Submit URL for scanning
        submit_response = submit_scan(normalized)
        job_id = submit_response["jobID"]

        return build_pending_result(normalized, job_id) unless job_id

        # Poll for result (with brief wait for quick scans)
        poll_for_result(normalized, job_id)
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    # Get scan status for a previously submitted job
    def get_scan_status(job_id)
      log_info("Fetching scan status: #{job_id}")

      with_rate_limit do
        response = fetch_scan_status(job_id)
        parse_scan_result(response)
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    private

    def credentials
      Rails.application.credentials.checkphish || {}
    end

    def api_key
      credentials[:api_key]
    end

    def api_connection
      raise AuthenticationError, "CheckPhish API key not configured" unless api_key

      connection(base_url: BASE_URL)
    end

    def submit_scan(url)
      conn = api_connection
      post(conn, "neo/scan", {
        apiKey: api_key,
        urlInfo: { url: url },
        scanType: "full"
      })
    end

    def fetch_scan_status(job_id)
      conn = api_connection
      post(conn, "neo/scan/status", {
        apiKey: api_key,
        jobID: job_id,
        insights: true
      })
    end

    def poll_for_result(url, job_id, max_attempts: 3, wait_time: 2)
      max_attempts.times do |attempt|
        response = fetch_scan_status(job_id)

        case response["status"]
        when "DONE"
          return parse_scan_result(response)
        when "PENDING", "IN_PROGRESS"
          # Still processing - wait briefly on early attempts
          if attempt < max_attempts - 1
            sleep(wait_time)
          else
            # Return pending result if not done after max attempts
            return build_pending_result(url, job_id)
          end
        else
          # Unknown status - return pending
          return build_pending_result(url, job_id, status: response["status"])
        end
      end

      build_pending_result(url, job_id)
    end

    def parse_scan_result(response)
      url = response["url"]
      disposition = response["disposition"]&.downcase
      brand = response["brand"]
      insights = response["insights"]

      verdict, confidence = determine_verdict(disposition)

      build_result(
        verdict: verdict,
        confidence: confidence,
        details: {
          url: url,
          job_id: response["job_id"] || response["jobID"],
          disposition: disposition,
          brand: brand,
          insights: insights,
          url_sha256: response["url_sha256"],
          resolved: response["resolved"],
          screenshot_path: response["screenshot_path"],
          source: "checkphish"
        }
      )
    end

    def determine_verdict(disposition)
      case disposition
      when *PHISHING_DISPOSITIONS
        [ "phishing", 0.95 ]
      when *CLEAN_DISPOSITIONS
        [ "clean", 0.85 ]
      when *SUSPICIOUS_DISPOSITIONS
        [ "suspicious", 0.7 ]
      else
        # Unknown disposition - treat as suspicious
        [ "suspicious", 0.5 ]
      end
    end

    def build_pending_result(url, job_id, status: "pending")
      build_result(
        verdict: "pending",
        confidence: 0.0,
        details: {
          url: url,
          job_id: job_id,
          status: status,
          source: "checkphish"
        }
      )
    end
  end
end
