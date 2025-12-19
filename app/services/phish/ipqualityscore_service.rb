# frozen_string_literal: true

module Phish
  # IPQualityScore Email Validation API
  # https://www.ipqualityscore.com/documentation/email-validation-api/overview
  #
  # Rate Limits vary by plan, using conservative defaults
  #
  # Response includes:
  #   - valid: boolean
  #   - disposable: boolean
  #   - fraud_score: 0-100
  #   - recent_abuse: boolean
  #   - leaked: boolean
  #
  class IpqualityscoreService < BaseService
    BASE_URL = "https://ipqualityscore.com/api/json/email"

    # Conservative rate limits (adjust based on plan)
    rate_limit :minute, requests: 60,   period: 1.minute
    rate_limit :daily,  requests: 5000, period: 1.day

    # Fraud score thresholds
    HIGH_RISK_THRESHOLD = 85
    MEDIUM_RISK_THRESHOLD = 75
    SUSPICIOUS_THRESHOLD = 50

    def check_email(email)
      normalized = normalize_email(email)
      log_info("Checking email: #{normalized}")

      api_key = credentials[:api_key]
      raise AuthenticationError, "IPQualityScore API key not configured" unless api_key

      with_rate_limit do
        conn = connection(base_url: BASE_URL)
        response = get(conn, "/#{api_key}/#{CGI.escape(normalized)}", request_params)
        parse_response(response, normalized)
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    # This service doesn't support domain/URL checks (use their separate APIs)
    def check_domain(_domain)
      nil
    end

    def check_url(_url)
      nil
    end

    private

    def credentials
      Rails.application.credentials.ipqualityscore || {}
    end

    def request_params
      {
        fast: false,           # Full lookup
        timeout: 7,            # Timeout in seconds
        suggest_domain: false, # Don't suggest corrections
        strictness: 1,         # Medium strictness (0-2)
        abuse_strictness: 1    # Medium abuse strictness (0-2)
      }
    end

    def normalize_email(email)
      email.to_s.strip.downcase
    end

    def parse_response(response, email)
      response = ensure_hash_response(response)

      # Check for API errors
      if response["success"] == false
        log_error("API error: #{response['message']}", StandardError.new(response.to_json))
        return build_result(
          verdict: "unknown",
          confidence: 0.0,
          details: { email: email, error: response["message"], source: "ipqualityscore" }
        )
      end

      fraud_score = response["fraud_score"].to_i
      valid = response["valid"] == true
      disposable = response["disposable"] == true
      recent_abuse = response["recent_abuse"] == true
      leaked = response["leaked"] == true
      honeypot = response["honeypot"] == true
      spam_trap = response["spam_trap_score"]&.to_s == "high"

      # Determine verdict based on fraud score and flags
      verdict = if fraud_score >= HIGH_RISK_THRESHOLD || honeypot || spam_trap
        "phishing"
      elsif fraud_score >= MEDIUM_RISK_THRESHOLD || recent_abuse || (disposable && leaked)
        "phishing"
      elsif fraud_score >= SUSPICIOUS_THRESHOLD || disposable || leaked
        "suspicious"
      elsif !valid
        "suspicious"
      else
        "clean"
      end

      # Calculate confidence (inverse of fraud_score normalized)
      # High fraud = low confidence in being clean
      base_confidence = if verdict == "clean"
        (100 - fraud_score) / 100.0
      else
        fraud_score / 100.0
      end

      # Boost confidence for strong signals
      confidence = base_confidence
      confidence += 0.1 if honeypot || spam_trap
      confidence += 0.1 if recent_abuse
      confidence -= 0.1 if response["catch_all"] == true # Catch-all reduces certainty
      confidence = confidence.clamp(0.0, 1.0)

      build_result(
        verdict: verdict,
        confidence: confidence.round(2),
        details: {
          email: email,
          fraud_score: fraud_score,
          valid: valid,
          disposable: disposable,
          free_provider: response["free_email"],
          deliverable: response["deliverability"] == "high",
          valid_mx: response["valid_mx"],
          recent_abuse: recent_abuse,
          leaked: leaked,
          honeypot: honeypot,
          spam_trap_score: response["spam_trap_score"],
          catch_all: response["catch_all"],
          generic: response["generic"],
          common: response["common"],
          dns_valid: response["dns_valid"],
          smtp_score: response["smtp_score"],
          overall_score: response["overall_score"],
          first_seen: response["first_seen"],
          domain_age: response.dig("domain_age", "human"),
          suggested_domain: response["suggested_domain"],
          source: "ipqualityscore"
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
