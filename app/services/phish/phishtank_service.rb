# frozen_string_literal: true

module Phish
  # PhishTank API
  # https://www.phishtank.com/api_info.php
  class PhishtankService < BaseService
    BASE_URL = "https://checkurl.phishtank.com"

    def check_domain(domain)
      # PhishTank works with URLs, construct a basic URL
      normalized = normalize_domain(domain)
      check_url("https://#{normalized}")
    end

    def check_url(url)
      normalized = normalize_url(url)
      log_info("Checking URL: #{normalized}")

      api_key = credentials[:api_key]

      params = {
        url: Base64.strict_encode64(normalized),
        format: "json",
        app_key: api_key
      }.compact

      conn = connection(base_url: BASE_URL, timeout: 45)
      response = post(conn, "/checkurl/", params)

      parse_response(response, normalized)
    end

    private

    def credentials
      Rails.application.credentials.phishtank || {}
    end

    def parse_response(response, url)
      results = response["results"]

      if results["in_database"]
        if results["valid"]
          build_result(
            verdict: "phishing",
            confidence: 0.95,
            details: {
              url: url,
              phish_id: results["phish_id"],
              phish_detail_page: results["phish_detail_page"],
              verified: results["verified"],
              verified_at: results["verified_at"],
              source: "phishtank"
            }
          )
        else
          # In database but marked as not valid (false positive)
          build_result(
            verdict: "clean",
            confidence: 0.7,
            details: {
              url: url,
              in_database: true,
              marked_invalid: true,
              source: "phishtank"
            }
          )
        end
      else
        build_result(
          verdict: "unknown",
          confidence: 0.0,
          details: {
            url: url,
            in_database: false,
            source: "phishtank"
          }
        )
      end
    end
  end
end
