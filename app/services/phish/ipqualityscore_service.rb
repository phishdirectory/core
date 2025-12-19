# frozen_string_literal: true

module Phish
  # IPQualityScore API
  # https://www.ipqualityscore.com/documentation/malicious-url-scanner-api/overview
  # https://www.ipqualityscore.com/documentation/email-validation-api/overview
  #
  # Rate Limits vary by plan, using conservative defaults
  #
  # URL/Domain Response includes:
  #   - unsafe: boolean
  #   - risk_score: 0-100
  #   - phishing: boolean
  #   - malware: boolean
  #   - suspicious: boolean
  #
  # Email Response includes:
  #   - valid: boolean
  #   - disposable: boolean
  #   - fraud_score: 0-100
  #   - recent_abuse: boolean
  #   - leaked: boolean
  #
  class IpqualityscoreService < BaseService
    EMAIL_BASE_URL = "https://ipqualityscore.com/api/json/email"
    URL_BASE_URL = "https://ipqualityscore.com/api/json/url"

    # Conservative rate limits (adjust based on plan)
    rate_limit :minute, requests: 60,   period: 1.minute
    rate_limit :daily,  requests: 5000, period: 1.day

    # Fraud/risk score thresholds
    HIGH_RISK_THRESHOLD = 85
    MEDIUM_RISK_THRESHOLD = 75
    SUSPICIOUS_THRESHOLD = 50

    # ===========================================
    # Domain Checking
    # ===========================================

    def check_domain(domain)
      normalized = normalize_domain(domain)
      log_info("Checking domain: #{normalized}")

      api_key = credentials[:api_key]
      raise AuthenticationError, "IPQualityScore API key not configured" unless api_key

      with_rate_limit do
        conn = connection(base_url: URL_BASE_URL)
        response = get(conn, "#{api_key}/#{CGI.escape(normalized)}", url_request_params)
        parse_url_response(response, domain: normalized)
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    # ===========================================
    # URL Checking
    # ===========================================

    def check_url(url)
      normalized = normalize_url(url)
      log_info("Checking URL: #{normalized}")

      api_key = credentials[:api_key]
      raise AuthenticationError, "IPQualityScore API key not configured" unless api_key

      with_rate_limit do
        conn = connection(base_url: URL_BASE_URL)
        response = get(conn, "#{api_key}/#{CGI.escape(normalized)}", url_request_params)
        parse_url_response(response, url: normalized)
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    # ===========================================
    # Email Checking
    # ===========================================

    def check_email(email)
      normalized = normalize_email(email)
      log_info("Checking email: #{normalized}")

      api_key = credentials[:api_key]
      raise AuthenticationError, "IPQualityScore API key not configured" unless api_key

      with_rate_limit do
        conn = connection(base_url: EMAIL_BASE_URL)
        response = get(conn, "#{api_key}/#{CGI.escape(normalized)}", email_request_params)
        parse_email_response(response, normalized)
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    # ===========================================
    # Phone Number Checking
    # ===========================================

    PHONE_BASE_URL = "https://ipqualityscore.com/api/json/phone"

    def check_phone(phone_number)
      normalized = normalize_phone(phone_number)
      log_info("Checking phone: #{normalized}")

      api_key = credentials[:api_key]
      raise AuthenticationError, "IPQualityScore API key not configured" unless api_key

      with_rate_limit do
        conn = connection(base_url: PHONE_BASE_URL)
        response = get(conn, "#{api_key}/#{CGI.escape(normalized)}", phone_request_params)
        parse_phone_response(response, normalized)
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    private

    def credentials
      Rails.application.credentials.ipqualityscore || {}
    end

    # ===========================================
    # Request Parameters
    # ===========================================

    def url_request_params
      {
        strictness: 1,         # Medium strictness (0-2)
        fast: false,           # Full lookup for better accuracy
        timeout: 7
      }
    end

    def email_request_params
      {
        fast: false,           # Full lookup
        timeout: 7,            # Timeout in seconds
        suggest_domain: false, # Don't suggest corrections
        strictness: 1,         # Medium strictness (0-2)
        abuse_strictness: 1    # Medium abuse strictness (0-2)
      }
    end

    def phone_request_params
      {
        strictness: 1,         # Medium strictness (0-2)
        country: []            # Auto-detect country
      }
    end

    # ===========================================
    # Normalization
    # ===========================================

    def normalize_email(email)
      email.to_s.strip.downcase
    end

    def normalize_phone(phone)
      # Strip everything except + and digits, then ensure E.164 format
      cleaned = phone.to_s.gsub(/[^\d+]/, "")
      cleaned.start_with?("+") ? cleaned : "+#{cleaned}"
    end

    # ===========================================
    # Response Parsing - URL/Domain
    # ===========================================

    def parse_url_response(response, domain: nil, url: nil)
      response = ensure_hash_response(response)
      target = url || domain

      # Check for API errors
      if response["success"] == false
        log_error("API error: #{response['message']}", StandardError.new(response.to_json))
        return build_result(
          verdict: "unknown",
          confidence: 0.0,
          details: { domain: domain, url: url, error: response["message"], source: "ipqualityscore" }
        )
      end

      risk_score = response["risk_score"].to_i
      is_phishing = response["phishing"] == true
      is_malware = response["malware"] == true
      is_suspicious = response["suspicious"] == true
      is_unsafe = response["unsafe"] == true
      is_parking = response["parking"] == true
      is_spamming = response["spamming"] == true

      # Determine verdict based on risk score and flags
      verdict = if is_phishing || is_malware || risk_score >= HIGH_RISK_THRESHOLD
        "phishing"
      elsif is_unsafe || is_spamming || risk_score >= MEDIUM_RISK_THRESHOLD
        "phishing"
      elsif is_suspicious || is_parking || risk_score >= SUSPICIOUS_THRESHOLD
        "suspicious"
      else
        "clean"
      end

      # Calculate confidence based on risk score
      base_confidence = if verdict == "clean"
        (100 - risk_score) / 100.0
      else
        risk_score / 100.0
      end

      # Boost confidence for strong signals
      confidence = base_confidence
      confidence += 0.15 if is_phishing || is_malware
      confidence += 0.1 if is_unsafe
      confidence -= 0.1 if is_parking # Parked domains are less certain
      confidence = confidence.clamp(0.0, 1.0)

      build_result(
        verdict: verdict,
        confidence: confidence.round(2),
        details: {
          domain: domain,
          url: url,
          risk_score: risk_score,
          phishing: is_phishing,
          malware: is_malware,
          suspicious: is_suspicious,
          unsafe: is_unsafe,
          parking: is_parking,
          spamming: is_spamming,
          adult: response["adult"],
          category: response["category"],
          dns_valid: response["dns_valid"],
          domain_rank: response["domain_rank"],
          domain_age: response.dig("domain_age", "human"),
          page_size: response["page_size"],
          redirected: response["redirected"],
          final_url: response["final_url"],
          server: response["server"],
          content_type: response["content_type"],
          source: "ipqualityscore"
        }
      )
    end

    # ===========================================
    # Response Parsing - Email
    # ===========================================

    def parse_email_response(response, email)
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

      # Map deliverability string to boolean
      deliverability = response["deliverability"]
      deliverable = case deliverability
      when "high" then true
      when "medium" then true
      when "low" then false
      else nil
      end

      build_result(
        verdict: verdict,
        confidence: confidence.round(2),
        details: {
          email: email,
          fraud_score: fraud_score,
          valid: valid,
          disposable: disposable,
          free_provider: response["free_email"],
          free_email: response["free_email"],
          deliverable: deliverable,
          deliverability: deliverability,
          valid_mx: response["dns_valid"],  # IPQS uses dns_valid for MX validation
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
          first_seen: response.dig("first_seen", "human"),
          domain_age: response.dig("domain_age", "human"),
          suggested_domain: response["suggested_domain"],
          source: "ipqualityscore"
        }
      )
    end

    # ===========================================
    # Response Parsing - Phone
    # ===========================================

    def parse_phone_response(response, phone_number)
      response = ensure_hash_response(response)

      # Check for API errors
      if response["success"] == false
        log_error("API error: #{response['message']}", StandardError.new(response.to_json))
        return build_result(
          verdict: "unknown",
          confidence: 0.0,
          details: { phone_number: phone_number, error: response["message"], source: "ipqualityscore" }
        )
      end

      fraud_score = response["fraud_score"].to_i
      valid = response["valid"] == true
      active = response["active"] == true
      risky = response["risky"] == true
      recent_abuse = response["recent_abuse"] == true
      voip = response["VOIP"] == true || response["voip"] == true
      prepaid = response["prepaid"] == true
      leaked = response["leaked"] == true
      spammer = response["spammer"] == true

      # Determine verdict based on fraud score and flags
      verdict = if fraud_score >= HIGH_RISK_THRESHOLD || spammer
        "phishing"
      elsif fraud_score >= MEDIUM_RISK_THRESHOLD || recent_abuse || (voip && risky)
        "phishing"
      elsif fraud_score >= SUSPICIOUS_THRESHOLD || risky || leaked
        "suspicious"
      elsif !valid || !active
        "suspicious"
      else
        "clean"
      end

      # Calculate confidence
      base_confidence = if verdict == "clean"
        (100 - fraud_score) / 100.0
      else
        fraud_score / 100.0
      end

      # Boost confidence for strong signals
      confidence = base_confidence
      confidence += 0.15 if spammer
      confidence += 0.1 if recent_abuse
      confidence -= 0.1 if voip && !risky # VOIP alone reduces certainty
      confidence = confidence.clamp(0.0, 1.0)

      build_result(
        verdict: verdict,
        confidence: confidence.round(2),
        details: {
          phone_number: phone_number,
          fraud_score: fraud_score,
          valid: valid,
          active: active,
          risky: risky,
          voip: voip,
          prepaid: prepaid,
          recent_abuse: recent_abuse,
          leaked: leaked,
          spammer: spammer,
          carrier: response["carrier"],
          line_type: response["line_type"],
          country: response["country"],
          region: response["region"],
          city: response["city"],
          zip_code: response["zip_code"],
          timezone: response["timezone"],
          do_not_call: response["do_not_call"],
          formatted: response["formatted"],
          local_format: response["local_format"],
          source: "ipqualityscore"
        }
      )
    end

    # ===========================================
    # Utilities
    # ===========================================

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
