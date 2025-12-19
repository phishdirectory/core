# frozen_string_literal: true

module Phish
  # Sinking Yachts Phishing Domain Feed
  # https://phish.sinking.yachts/docs
  #
  # A curated, real-time phishing domain database. Uses polling
  # of the /v2/recent endpoint for incremental updates every 10 minutes.
  #
  class SinkingYachtsService < BaseService
    BASE_URL = "https://phish.sinking.yachts"

    # Conservative rate limits for HTTP API
    rate_limit :minute, requests: 30, period: 1.minute
    rate_limit :daily, requests: 1000, period: 1.day

    def check_domain(domain)
      normalized = normalize_domain(domain)
      log_info("Checking domain against Sinking Yachts: #{normalized}")

      # Check local cache first
      cached_result = check_local_cache(normalized)
      return cached_result if cached_result

      # Check API
      with_rate_limit do
        conn = connection_with_identity
        response = get(conn, "/v2/check/#{normalized}")

        if response == true
          cache_domain(normalized)
          build_result(
            verdict: "phishing",
            confidence: 0.95,
            details: { source: "sinking_yachts", cached: false }
          )
        else
          nil # Not in database, let other services decide
        end
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    rescue Faraday::ResourceNotFound
      nil # Domain not in database
    end

    def check_url(url)
      normalized = normalize_url(url)
      uri = URI.parse(normalized)
      check_domain(uri.host)
    end

    # Full sync via HTTP (called once on initial setup or as fallback)
    def sync_all
      log_info("Syncing full Sinking Yachts domain list...")

      with_rate_limit do
        conn = connection_with_identity
        response = get(conn, "/v2/all")
        process_full_list(response)
      end
    rescue RateLimitable::RateLimitExceeded => e
      { success: false, error: "Rate limited", retry_after: e.retry_after }
    rescue Faraday::Error => e
      log_error("Failed to sync full list", e)
      { success: false, error: e.message }
    end

    # Sync recent changes via HTTP polling
    def sync_recent(seconds: 600)
      log_info("Syncing Sinking Yachts changes from last #{seconds}s...")

      with_rate_limit do
        conn = connection_with_identity
        response = get(conn, "/v2/recent/#{seconds}")
        process_changes(response)
      end
    rescue RateLimitable::RateLimitExceeded => e
      { success: false, error: "Rate limited", retry_after: e.retry_after }
    rescue Faraday::Error => e
      log_error("Failed to sync recent changes", e)
      { success: false, error: e.message }
    end

    private

    def connection_with_identity
      identity = Rails.application.credentials.dig(:sinking_yachts, :identity) || "phish.directory"

      Faraday.new(url: BASE_URL) do |f|
        f.request :json
        f.response :json, content_type: /\bjson$/
        f.headers["User-Agent"] = user_agent
        f.headers["X-Identity"] = identity
        f.adapter Faraday.default_adapter
      end
    end

    def process_changes(changes)
      return { success: false, error: "Invalid response" } unless changes.is_a?(Array)

      added = 0
      removed = 0

      changes.each do |change|
        domains = change["domains"] || []
        case change["type"]
        when "add"
          domains.each do |domain|
            cache_domain(domain)
            import_domain(domain)
            added += 1
          end
        when "delete"
          domains.each do |domain|
            uncache_domain(domain)
            removed += 1
          end
        end
      end

      log_info("Sinking Yachts sync: #{added} added, #{removed} removed")
      { success: true, added: added, removed: removed }
    end

    def process_full_list(domains)
      return { success: false, error: "Invalid response" } unless domains.is_a?(Array)

      # Clear old cache entries
      Rails.cache.delete_matched("sinking_yachts:domain:*")

      imported = 0
      domains.each do |domain|
        cache_domain(domain)
        import_domain(domain)
        imported += 1
      end

      log_info("Sinking Yachts full sync: #{imported} domains")
      { success: true, count: imported }
    end

    def import_domain(domain)
      normalized = domain.downcase
      existing = Phish::Domain.find_by(domain: normalized)

      if existing
        # Schedule check for existing domains that don't have a verdict yet
        if existing.verdict.nil?
          PhishDomainCheckJob.perform_later(existing.id)
        end
        return
      end

      record = Phish::Domain.create(domain: normalized)
      PhishDomainCheckJob.perform_later(record.id) if record.persisted?
    end

    def check_local_cache(domain)
      return nil unless Rails.cache.exist?(cache_key_for(domain))

      build_result(
        verdict: "phishing",
        confidence: 0.95,
        details: { source: "sinking_yachts", cached: true }
      )
    end

    def cache_domain(domain)
      Rails.cache.write(cache_key_for(domain), true, expires_in: 1.week)
    end

    def uncache_domain(domain)
      Rails.cache.delete(cache_key_for(domain))
    end

    def cache_key_for(domain)
      "sinking_yachts:domain:#{domain.downcase}"
    end
  end
end
