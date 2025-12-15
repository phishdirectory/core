# frozen_string_literal: true

module Phish
  # URLScan.io API
  # https://urlscan.io/docs/api/
  class UrlscanService < BaseService
    BASE_URL = "https://urlscan.io/api/v1/"

    def check_domain(domain)
      normalized = normalize_domain(domain)
      check_url("https://#{normalized}")
    end

    def check_url(url)
      normalized = normalize_url(url)
      log_info("Checking URL: #{normalized}")

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

    def submit_scan(url)
      normalized = normalize_url(url)
      log_info("Submitting URL for scan: #{normalized}")

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

    def get_scan_result(uuid)
      log_info("Fetching scan result: #{uuid}")

      conn = authenticated_connection
      response = get(conn, "result/#{uuid}/")

      parse_scan_result(response)
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
