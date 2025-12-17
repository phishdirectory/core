# frozen_string_literal: true

module Phish
  # Google Safe Browsing API v4
  # https://developers.google.com/safe-browsing/v4
  #
  # Rate Limits:
  #   - 10,000 URLs per day (Lookup API)
  #   - Supports batch requests up to 500 URLs
  #
  # Note: Update API (local database) has different/no limits
  #
  class GoogleSafeBrowsingService < BaseService
    BASE_URL = "https://safebrowsing.googleapis.com/v4/"

    # Rate limits - Google is generous but we add conservative limits
    rate_limit :minute, requests: 100,   period: 1.minute
    rate_limit :daily,  requests: 10000, period: 1.day

    THREAT_TYPES = %w[
      MALWARE
      SOCIAL_ENGINEERING
      UNWANTED_SOFTWARE
      POTENTIALLY_HARMFUL_APPLICATION
    ].freeze

    PLATFORM_TYPES = %w[ANY_PLATFORM].freeze

    THREAT_ENTRY_TYPES = %w[URL].freeze

    def check_domain(domain)
      normalized = normalize_domain(domain)
      check_url("https://#{normalized}")
    end

    def check_url(url)
      normalized = normalize_url(url)
      log_info("Checking URL: #{normalized}")

      with_rate_limit do
        api_key = credentials[:api_key]
        raise AuthenticationError, "Google Safe Browsing API key not configured" unless api_key

        conn = connection(base_url: BASE_URL)
        response = post(conn, "threatMatches:find?key=#{api_key}", threat_request(normalized))

        if response["matches"].present?
          build_result(
            verdict: "phishing",
            confidence: 0.95,
            details: {
              matches: response["matches"].map { |m| parse_match(m) },
              source: "google_safe_browsing"
            }
          )
        else
          build_result(
            verdict: "clean",
            confidence: 0.9,
            details: {
              source: "google_safe_browsing"
            }
          )
        end
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    def check_urls_bulk(urls)
      normalized_urls = urls.map { |url| normalize_url(url) }
      log_info("Bulk checking #{normalized_urls.size} URLs")

      with_rate_limit do
        api_key = credentials[:api_key]
        raise AuthenticationError, "Google Safe Browsing API key not configured" unless api_key

        conn = connection(base_url: BASE_URL)
        response = post(conn, "threatMatches:find?key=#{api_key}", threat_request(*normalized_urls))

        matches_by_url = (response["matches"] || []).group_by { |m| m.dig("threat", "url") }

        normalized_urls.map do |url|
          if matches_by_url[url].present?
            build_result(
              verdict: "phishing",
              confidence: 0.95,
              details: {
                url: url,
                matches: matches_by_url[url].map { |m| parse_match(m) },
                source: "google_safe_browsing"
              }
            )
          else
            build_result(
              verdict: "clean",
              confidence: 0.9,
              details: {
                url: url,
                source: "google_safe_browsing"
              }
            )
          end
        end
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    private

    def credentials
      Rails.application.credentials.google_safe_browsing || {}
    end

    def threat_request(*urls)
      {
        client: {
          clientId: "phish-directory",
          clientVersion: ENV.fetch("RELEASE_VERSION", "1.0.0")
        },
        threatInfo: {
          threatTypes: THREAT_TYPES,
          platformTypes: PLATFORM_TYPES,
          threatEntryTypes: THREAT_ENTRY_TYPES,
          threatEntries: urls.map { |url| { url: url } }
        }
      }
    end

    def parse_match(match)
      {
        threat_type: match["threatType"],
        platform_type: match["platformType"],
        url: match.dig("threat", "url")
      }
    end
  end
end
