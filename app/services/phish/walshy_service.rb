# frozen_string_literal: true

module Phish
  # Walshy's Phishing Detection API
  # https://api.walshy.dev/
  class WalshyService < BaseService
    BASE_URL = "https://api.walshy.dev"

    def check_domain(domain)
      normalized = normalize_domain(domain)
      log_info("Checking domain: #{normalized}")

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

    def check_url(url)
      # Walshy API works on domains, extract domain from URL
      normalized = normalize_url(url)
      uri = URI.parse(normalized)
      check_domain(uri.host)
    end
  end
end
