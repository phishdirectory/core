# frozen_string_literal: true

module Phish
  # EmailRep.io API
  # https://emailrep.io/docs
  #
  # Rate Limits (Free Tier):
  #   - 10 queries per day
  #   - 250 queries per month
  #
  # Response includes:
  #   - reputation: high/medium/low/none
  #   - suspicious: boolean
  #   - details: domain info, profiles, blacklists, breach data
  #
  class EmailrepService < BaseService
    BASE_URL = "https://emailrep.io"

    # Rate limits for Free tier (very conservative)
    rate_limit :daily,   requests: 10,  period: 1.day
    rate_limit :monthly, requests: 250, period: 30.days

    REPUTATION_SCORES = {
      "high" => 0.9,
      "medium" => 0.6,
      "low" => 0.3,
      "none" => 0.1
    }.freeze

    def check_email(email)
      normalized = normalize_email(email)
      log_info("Checking email: #{normalized}")

      with_rate_limit do
        conn = connection(
          base_url: BASE_URL,
          headers: build_headers
        )
        response = get(conn, "/#{normalized}")
        parse_response(response, normalized)
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    # This service doesn't support domain/URL checks
    def check_domain(_domain)
      nil
    end

    def check_url(_url)
      nil
    end

    private

    def credentials
      Rails.application.credentials.emailrep || {}
    end

    def build_headers
      headers = {}
      api_key = credentials[:api_key]
      headers["Key"] = api_key if api_key.present?
      headers
    end

    def normalize_email(email)
      email.to_s.strip.downcase
    end

    def parse_response(response, email)
      response = ensure_hash_response(response)

      reputation = response["reputation"] || "none"
      suspicious = response["suspicious"] == true
      details = response["details"] || {}

      # Determine verdict based on reputation and suspicious flag
      verdict = if suspicious || reputation == "none"
        "suspicious"
      elsif details["blacklisted"] == true || details["malicious_activity"] == true
        "phishing"
      elsif reputation == "low"
        "suspicious"
      else
        "clean"
      end

      # Calculate confidence from reputation score
      base_confidence = REPUTATION_SCORES[reputation] || 0.5

      # Adjust confidence based on additional factors
      confidence = base_confidence
      confidence -= 0.2 if suspicious
      confidence -= 0.2 if details["blacklisted"]
      confidence -= 0.1 if details["spam"]
      confidence += 0.1 if details["profiles"]&.any?
      confidence = confidence.clamp(0.0, 1.0)

      build_result(
        verdict: verdict,
        confidence: confidence.round(2),
        details: {
          email: email,
          reputation: reputation,
          suspicious: suspicious,
          disposable: details["disposable"],
          free_provider: details["free_provider"],
          deliverable: details["deliverable"],
          valid_mx: !details["invalid_mx"],
          domain_exists: details["domain_exists"],
          profiles: details["profiles"],
          blacklisted: details["blacklisted"],
          malicious_activity: details["malicious_activity"],
          credentials_leaked: details["credentials_leaked"],
          data_breach: details["data_breach"],
          spam: details["spam"],
          source: "emailrep"
        }
      )
    end

    def ensure_hash_response(response)
      return response if response.is_a?(Hash)

      begin
        JSON.parse(response.to_s)
      rescue JSON::ParserError
        log_error("Failed to parse response as JSON", StandardError.new(response.to_s.truncate(200)))
        {}
      end
    end
  end
end
