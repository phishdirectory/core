# frozen_string_literal: true

module Phish
  # FishFish Phishing Detection API
  # https://api.fishfish.gg/v1
  #
  # FishFish maintains a curated list of known phishing domains.
  # This service checks domains against their database and syncs
  # the full list periodically for local caching.
  #
  class FishFishService < BaseService
    BASE_URL = "https://api.fishfish.gg/v1"

    # Rate limits per their documentation (be conservative)
    rate_limit :minute, requests: 60, period: 1.minute
    rate_limit :hourly, requests: 1000, period: 1.hour

    # Session token cache (valid for 1 hour per docs)
    SESSION_TOKEN_CACHE_KEY = "fishfish:session_token"
    SESSION_TOKEN_TTL = 55.minutes # Refresh 5 min before expiry

    def check_domain(domain)
      normalized = normalize_domain(domain)
      log_info("Checking domain against FishFish: #{normalized}")

      # First check local cache if available
      cached_result = check_local_cache(normalized)
      return cached_result if cached_result

      # Fall back to API
      with_rate_limit do
        token = get_session_token
        return nil unless token

        conn = authenticated_connection(token)
        response = get(conn, "/domains/#{normalized}")

        if response && response["domain"]
          build_result(
            verdict: "phishing",
            confidence: category_confidence(response["category"]),
            details: {
              category: response["category"],
              added: response["added"],
              source: "fishfish"
            }
          )
        else
          # Not on the list - don't report clean, let other services decide
          nil
        end
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    rescue Faraday::ResourceNotFound
      # Domain not in FishFish database - don't report, let other services decide
      nil
    end

    def check_url(url)
      normalized = normalize_url(url)
      uri = URI.parse(normalized)
      check_domain(uri.host)
    end

    # Sync the full FishFish domain list to local cache
    # Called by FishFishSyncJob
    def sync_domain_list
      log_info("Syncing FishFish domain list...")

      token = get_session_token
      raise ServiceError, "Could not obtain FishFish session token" unless token

      conn = authenticated_connection(token)

      # Get full domain list
      response = get(conn, "/domains?full=true")

      unless response.is_a?(Array)
        log_error("Unexpected response format from FishFish", StandardError.new(response.inspect))
        return { success: false, error: "Unexpected response format" }
      end

      # Cache each domain
      cached = 0
      response.each do |domain_data|
        domain = domain_data["domain"]
        next unless domain

        cache_domain(domain, domain_data)
        cached += 1
      end

      log_info("Synced #{cached} domains from FishFish")

      { success: true, count: cached }
    end

    private

    def check_local_cache(domain)
      data = Rails.cache.read(cache_key_for(domain))
      return nil unless data

      build_result(
        verdict: "phishing",
        confidence: category_confidence(data["category"]),
        details: {
          category: data["category"],
          added: data["added"],
          source: "fishfish",
          cached: true
        }
      )
    end

    def cache_domain(domain, data)
      Rails.cache.write(
        cache_key_for(domain),
        data,
        expires_in: 1.week # Cache for 1 week, sync weekly
      )
    end

    def cache_key_for(domain)
      "fishfish:domain:#{domain.downcase}"
    end

    def category_confidence(category)
      # FishFish is a highly trusted source with curated data
      # Categories: safe, suspicious, malware, phishing
      case category&.downcase
      when "phishing"
        0.99  # Very high confidence - FishFish is curated
      when "malware"
        0.99
      when "suspicious"
        0.85
      else
        0.95
      end
    end

    def get_session_token
      # Check cache first
      cached = Rails.cache.read(SESSION_TOKEN_CACHE_KEY)
      return cached if cached

      # Get new session token
      api_key = credentials[:api_key]
      unless api_key
        log_error("FishFish API key not configured", StandardError.new("missing credentials"))
        return nil
      end

      conn = Faraday.new(url: BASE_URL) do |f|
        f.request :json
        f.response :json, content_type: /\bjson$/
        f.headers["Authorization"] = api_key
        f.headers["User-Agent"] = user_agent
      end

      response = conn.post("/users/@me/tokens")

      if response.success? && response.body["token"]
        token = response.body["token"]
        Rails.cache.write(SESSION_TOKEN_CACHE_KEY, token, expires_in: SESSION_TOKEN_TTL)
        token
      else
        log_error("Failed to get FishFish session token", StandardError.new(response.body.to_s))
        nil
      end
    rescue Faraday::Error => e
      log_error("FishFish token request failed", e)
      nil
    end

    def authenticated_connection(token)
      Faraday.new(url: BASE_URL) do |f|
        f.request :json
        f.response :json, content_type: /\bjson$/
        f.headers["Authorization"] = token
        f.headers["User-Agent"] = user_agent
        f.adapter Faraday.default_adapter
      end
    end

    def credentials
      Rails.application.credentials.fishfish || {}
    end
  end
end
