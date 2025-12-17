# frozen_string_literal: true

module Phish
  # URLScan.io API
  # https://urlscan.io/docs/api/
  #
  # Rate Limits (varies by action, using conservative limits):
  #   Search:   120/min, 1000/hour, 1000/day
  #   Public:   60/min, 500/hour, 5000/day
  #   Unlisted: 60/min, 100/hour, 1000/day
  #   Retrieve: 120/min, 5000/hour, 10000/day
  #
  # Using unlisted for submissions as it has better privacy
  #
  class UrlscanService < BaseService
    BASE_URL = "https://urlscan.io/api/v1/"

    # Rate limits - using most restrictive across actions we use
    rate_limit :minute, requests: 60,   period: 1.minute
    rate_limit :hourly, requests: 100,  period: 1.hour    # unlisted is most restrictive
    rate_limit :daily,  requests: 1000, period: 1.day

    def check_domain(domain)
      normalized = normalize_domain(domain)
      check_url("https://#{normalized}")
    end

    def check_url(url)
      normalized = normalize_url(url)
      log_info("Checking URL: #{normalized}")

      with_rate_limit(action: :search) do
        # First, search for existing scans
        conn = authenticated_connection
        search_response = get(conn, "search/", { q: "page.url:\"#{normalized}\"", size: 1 })

        if search_response["results"].present?
          result = search_response["results"].first
          parse_search_result(result, normalized)
        else
          # No existing scan, submit for new scan
          submit_scan(normalized)
        end
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    def submit_scan(url)
      normalized = normalize_url(url)
      log_info("Submitting URL for scan: #{normalized}")

      with_rate_limit(action: :scan) do
        conn = authenticated_connection
        response = post(conn, "scan/", {
          url: normalized,
          visibility: "unlisted"
        })

        build_result(
          verdict: "pending",
          confidence: 0.0,
          details: {
            uuid: response["uuid"],
            result_url: response["result"],
            source: "urlscan",
            status: "submitted_for_scan"
          }
        )
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    def get_scan_result(uuid)
      log_info("Fetching scan result: #{uuid}")

      with_rate_limit(action: :retrieve) do
        conn = authenticated_connection
        response = get(conn, "result/#{uuid}/")
        parse_scan_result(response)
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    private

    def credentials
      Rails.application.credentials.urlscan || {}
    end

    def authenticated_connection
      api_key = credentials[:api_key]
      headers = api_key ? { "API-Key" => api_key } : {}

      connection(
        base_url: BASE_URL,
        headers: headers
      )
    end

    def parse_search_result(result, url)
      # Check for malicious verdicts in the scan
      verdicts = result.dig("verdicts", "overall") || {}

      if verdicts["malicious"]
        build_result(
          verdict: "phishing",
          confidence: verdicts["score"].to_f / 100.0,
          details: {
            url: url,
            scan_id: result["_id"],
            result_url: result["result"],
            categories: verdicts["categories"],
            source: "urlscan"
          }
        )
      else
        build_result(
          verdict: "clean",
          confidence: 0.7,
          details: {
            url: url,
            scan_id: result["_id"],
            result_url: result["result"],
            source: "urlscan"
          }
        )
      end
    end

    def parse_scan_result(response)
      verdicts = response.dig("verdicts", "overall") || {}
      url = response.dig("page", "url")

      if verdicts["malicious"]
        build_result(
          verdict: "phishing",
          confidence: verdicts["score"].to_f / 100.0,
          details: {
            url: url,
            scan_id: response.dig("task", "uuid"),
            categories: verdicts["categories"],
            brands: verdicts["brands"],
            source: "urlscan"
          }
        )
      else
        build_result(
          verdict: "clean",
          confidence: 0.8,
          details: {
            url: url,
            scan_id: response.dig("task", "uuid"),
            source: "urlscan"
          }
        )
      end
    end
  end
end
