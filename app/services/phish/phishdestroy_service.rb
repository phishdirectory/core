# frozen_string_literal: true

module Phish
  # PhishDestroy Destroylist Feed
  # https://github.com/phishdestroy/destroylist
  #
  # The destroylist provides a JSON array of phishing domains
  # curated and updated in real-time by PhishDestroy.
  #
  class PhishdestroyService < BaseService
    FEED_URL = "https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.json"

    # Conservative rate limits (simple file fetch)
    rate_limit :minute, requests: 10, period: 1.minute
    rate_limit :daily, requests: 100, period: 1.day

    def check_domain(domain)
      normalized = normalize_domain(domain)
      log_info("Checking domain against PhishDestroy: #{normalized}")

      cached_result = check_local_cache(normalized)
      return cached_result if cached_result

      nil # PhishDestroy is feed-based, not API-based
    end

    def check_url(url)
      normalized = normalize_url(url)
      log_info("Checking URL against PhishDestroy: #{normalized}")

      cached_result = check_local_url_cache(normalized)
      return cached_result if cached_result

      nil # Feed-based, not API-based
    end

    # Sync the full feed (called by PhishdestroySync Job)
    def sync_feed
      log_info("Syncing PhishDestroy feed...")

      with_rate_limit do
        conn = Faraday.new do |f|
          f.headers["User-Agent"] = user_agent
          f.adapter Faraday.default_adapter
        end

        response = conn.get(FEED_URL)
        unless response.success?
          return { success: false, error: "Failed to fetch feed: #{response.status}" }
        end

        process_feed(response.body)
      end
    rescue RateLimitable::RateLimitExceeded => e
      { success: false, error: "Rate limited", retry_after: e.retry_after }
    rescue Faraday::Error => e
      log_error("Failed to fetch PhishDestroy feed", e)
      { success: false, error: e.message }
    end

    private

    def process_feed(body)
      # Parse JSON array of domains
      domains = JSON.parse(body)
      unless domains.is_a?(Array)
        return { success: false, error: "Invalid feed format: expected array" }
      end

      imported_domains = 0
      domains_seen = Set.new

      domains.each do |domain|
        # Skip if not a string or already processed
        next unless domain.is_a?(String)
        domain = domain.strip.downcase
        next if domain.blank? || domains_seen.include?(domain)

        domains_seen.add(domain)

        # Remove protocol if present
        domain = domain.sub(%r{\Ahttps?://}, "")
        domain = domain.split("/").first
        domain = domain.split(":").first

        # Cache and import domain
        cache_domain(domain)
        import_domain(domain)
        imported_domains += 1
      end

      log_info("PhishDestroy sync: #{imported_domains} domains")
      { success: true, domains: imported_domains }
    rescue JSON::ParserError => e
      log_error("Failed to parse PhishDestroy feed JSON", e)
      { success: false, error: "Invalid JSON: #{e.message}" }
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
      return nil unless Rails.cache.exist?(domain_cache_key(domain))

      build_result(
        verdict: "phishing",
        confidence: 0.95,
        details: { source: "phishdestroy", cached: true }
      )
    end

    def check_local_url_cache(url)
      return nil unless Rails.cache.exist?(url_cache_key(url))

      build_result(
        verdict: "phishing",
        confidence: 0.95,
        details: { source: "phishdestroy", cached: true, url: url }
      )
    end

    def cache_domain(domain)
      Rails.cache.write(domain_cache_key(domain), true, expires_in: 24.hours)
    end

    def cache_url(url)
      Rails.cache.write(url_cache_key(url), true, expires_in: 24.hours)
    end

    def domain_cache_key(domain)
      "phishdestroy:domain:#{domain.downcase}"
    end

    def url_cache_key(url)
      "phishdestroy:url:#{Digest::SHA256.hexdigest(url.downcase)}"
    end
  end
end
