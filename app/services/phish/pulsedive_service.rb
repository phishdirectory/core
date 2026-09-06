# frozen_string_literal: true

module Phish
  # Pulsedive Threat Intelligence API
  # https://pulsedive.com/api/
  #
  # Rate Limits (Free Plan):
  #   - 500 requests per month
  #   - 100 bulk scans per month
  #   - 100 bulk submissions per month
  #
  # Risk Levels: none, low, medium, high, critical, unknown, retired
  #
  # Due to strict rate limits, this service uses aggressive caching
  # and should be used sparingly (on-demand rather than every check)
  #
  class PulsediveService < BaseService
    BASE_URL = "https://pulsedive.com/api/"

    # Conservative rate limits (500/month ≈ 16/day)
    rate_limit :daily, requests: 15, period: 1.day
    rate_limit :monthly, requests: 450, period: 30.days

    # Cache TTL - cache for 7 days given strict rate limits
    CACHE_TTL = 7.days

    # Risk level mappings to verdicts
    RISK_VERDICTS = {
      "critical" => "phishing",
      "high" => "phishing",
      "medium" => "suspicious",
      "low" => "clean",
      "none" => "clean",
      "unknown" => "unknown",
      "retired" => "unknown"
    }.freeze

    # Confidence scores by risk level
    RISK_CONFIDENCE = {
      "critical" => 0.95,
      "high" => 0.85,
      "medium" => 0.65,
      "low" => 0.70,
      "none" => 0.80,
      "unknown" => 0.0,
      "retired" => 0.0
    }.freeze

    def check_domain(domain)
      normalized = normalize_domain(domain)
      log_info("Checking domain: #{normalized}")

      # Check cache first (aggressive caching due to rate limits)
      cached = read_cache(normalized, :domain)
      return cached if cached

      with_rate_limit do
        response = query_indicator(normalized)
        result = if response.nil?
                   build_not_found_result(normalized, :domain)
        else
                   parse_indicator_response(response, normalized, :domain)
        end
        write_cache(normalized, :domain, result)
        result
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    def check_url(url)
      normalized = normalize_url(url)
      log_info("Checking URL: #{normalized}")

      # Check cache first
      cached = read_cache(normalized, :url)
      return cached if cached

      with_rate_limit do
        response = query_indicator(normalized)
        result = if response.nil?
                   build_not_found_result(normalized, :url)
        else
                   parse_indicator_response(response, normalized, :url)
        end
        write_cache(normalized, :url, result)
        result
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    # Get detailed indicator info including properties and links
    def get_indicator_details(iid)
      log_info("Getting indicator details for iid: #{iid}")

      with_rate_limit do
        conn = authenticated_connection
        response = get(conn, "info.php", { iid: iid, get: "links,properties" })
        ensure_hash_response(response)
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    private

    def credentials
      Rails.application.credentials.pulsedive || {}
    end

    def authenticated_connection
      api_key = credentials[:api_key]
      raise AuthenticationError, "Pulsedive API key not configured" unless api_key

      connection(base_url: BASE_URL)
    end

    def query_indicator(indicator)
      api_key = credentials[:api_key]
      raise AuthenticationError, "Pulsedive API key not configured" unless api_key

      conn = connection(base_url: BASE_URL)
      response = get(conn, "info.php", { indicator: indicator, key: api_key })
      ensure_hash_response(response)
    end

    # Override to handle 404 as "not found" rather than error
    def handle_client_error(error)
      status = error.response[:status]
      return nil if status == 404 # Indicator not in Pulsedive database

      super
    end

    def build_not_found_result(indicator, type)
      log_info("Indicator not found in Pulsedive: #{indicator}")
      build_result(
        verdict: "unknown",
        confidence: 0.0,
        details: {
          "#{type}": indicator,
          not_found: true,
          source: "pulsedive"
        }
      )
    end

    def parse_indicator_response(response, indicator, type)
      # Handle not found case
      if response["error"]
        log_info("Indicator not found in Pulsedive: #{indicator}")
        return build_result(
          verdict: "unknown",
          confidence: 0.0,
          details: {
            "#{type}": indicator,
            error: response["error"],
            source: "pulsedive"
          }
        )
      end

      risk = response["risk"]&.downcase || "unknown"
      verdict = RISK_VERDICTS[risk] || "unknown"
      confidence = RISK_CONFIDENCE[risk] || 0.0

      build_result(
        verdict: verdict,
        confidence: confidence,
        details: {
          "#{type}": indicator,
          iid: response["iid"],
          risk: risk,
          risk_recommended: response["risk_recommended"],
          indicator_type: response["type"],
          manualrisk: response["manualrisk"],
          retired: response["retired"],
          stamp_added: response["stamp_added"],
          stamp_updated: response["stamp_updated"],
          stamp_seen: response["stamp_seen"],
          stamp_probed: response["stamp_probed"],
          stamp_retired: response["stamp_retired"],
          threats: response["threats"],
          feeds: response["feeds"],
          riskfactors: response["riskfactors"],
          source: "pulsedive"
        }
      )
    end

    # Cache helpers - aggressive caching due to strict rate limits
    def cache_key(indicator, type)
      "pulsedive:#{type}:#{Digest::SHA256.hexdigest(indicator.to_s)}"
    end

    def read_cache(indicator, type)
      Rails.cache.read(cache_key(indicator, type))
    end

    def write_cache(indicator, type, result)
      Rails.cache.write(cache_key(indicator, type), result, expires_in: CACHE_TTL)
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
