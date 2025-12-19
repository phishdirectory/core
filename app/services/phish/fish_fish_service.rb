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

    def check_domain(domain)
      normalized = normalize_domain(domain)
      log_info("Checking domain against FishFish: #{normalized}")

      # First check local cache if available
      cached_result = check_local_cache(normalized)
      return cached_result if cached_result

      # FishFish API is unauthenticated for reads
      with_rate_limit do
        conn = public_connection
        response = get(conn, "domains/#{normalized}")

        if response && response["name"]
          build_result(
            verdict: "phishing",
            confidence: category_confidence(response["category"]),
            details: {
              domain: response["name"],
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

    # Sync the full FishFish domain list to local cache and database
    # Called by FishFishSyncJob
    # Uses unauthenticated endpoint - no API key needed
    def sync_domain_list
      log_info("Syncing FishFish domain list...")

      conn = public_connection

      # Get full domain list (unauthenticated, returns domain names only)
      response = get(conn, "domains")

      unless response.is_a?(Array)
        log_error("Unexpected response format from FishFish", StandardError.new(response.inspect))
        return { success: false, error: "Unexpected response format" }
      end

      # Track domains in the new list for cache invalidation
      new_domains = Set.new

      # Cache and import each domain
      cached = 0
      imported = 0
      response.each do |domain|
        next unless domain.is_a?(String)

        normalized = domain.downcase
        new_domains.add(normalized)
        cache_domain(normalized, { "domain" => normalized, "category" => "phishing" })
        cached += 1

        # Import domain to database and schedule verdict check
        if import_domain(normalized)
          imported += 1
        end
      end

      # Invalidate cache entries for domains no longer in the list
      invalidated = invalidate_stale_cache(new_domains)

      log_info("Synced #{cached} domains from FishFish (#{imported} new imports, #{invalidated} cache entries invalidated)")

      { success: true, count: cached, imported: imported, invalidated: invalidated }
    end

    # Invalidate cache for a specific domain
    # Call this when a domain's verdict changes
    def invalidate_cache(domain)
      Rails.cache.delete(cache_key_for(domain.downcase))
    end

    private

    def public_connection
      Faraday.new(url: BASE_URL) do |f|
        f.request :json
        f.response :json, content_type: /\bjson$/
        f.headers["User-Agent"] = user_agent
        f.adapter Faraday.default_adapter
      end
    end

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
        expires_in: 48.hours # Reduced from 1 week for fresher data
      )
    end

    def cache_key_for(domain)
      "fishfish:domain:#{domain.downcase}"
    end

    # Track all cached domains in a set for invalidation
    CACHED_DOMAINS_KEY = "fishfish:cached_domains"

    def invalidate_stale_cache(current_domains)
      # Get previously cached domains
      previous_domains = Rails.cache.read(CACHED_DOMAINS_KEY) || Set.new

      # Find domains that were removed from the list
      stale_domains = previous_domains - current_domains

      # Invalidate each stale domain
      stale_domains.each do |domain|
        Rails.cache.delete(cache_key_for(domain))
      end

      # Update the tracked domains set
      Rails.cache.write(CACHED_DOMAINS_KEY, current_domains, expires_in: 1.week)

      stale_domains.size
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

    def import_domain(domain)
      normalized = domain.downcase
      existing = Phish::Domain.find_by(domain: normalized)

      if existing
        # Schedule check for existing domains that don't have a verdict yet
        if existing.verdict.nil?
          PhishDomainCheckJob.perform_later(existing.id)
          return true
        end
        return false
      end

      record = Phish::Domain.create(domain: normalized)
      if record.persisted?
        PhishDomainCheckJob.perform_later(record.id)
        true
      else
        false
      end
    end

  end
end
