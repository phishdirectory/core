# frozen_string_literal: true

module Phish
  # Walshy's Phishing Detection API
  # https://api.walshy.dev/
  #
  # Rate Limits:
  #   No documented limits, using conservative defaults
  #   to be a good API citizen
  #
  class WalshyService < BaseService
    BASE_URL = "https://api.walshy.dev"

    # Conservative rate limits (no documented limits)
    rate_limit :minute, requests: 30,  period: 1.minute
    rate_limit :hourly, requests: 500, period: 1.hour

    def check_domain(domain)
      normalized = normalize_domain(domain)
      log_info("Checking domain: #{normalized}")

      with_rate_limit do
        conn = connection(base_url: BASE_URL)
        response = post(conn, "/check", { domain: normalized })

        build_result(
          verdict: response["badDomain"] ? "phishing" : "clean",
          confidence: response["badDomain"] ? 0.9 : 0.8,
          details: {
            bad_domain: response["badDomain"],
            detection: response["detection"],
            source: "walshy"
          }
        )
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    def check_url(url)
      # Walshy API works on domains, extract domain from URL
      normalized = normalize_url(url)
      uri = URI.parse(normalized)
      check_domain(uri.host)
    end
  end
end
