# frozen_string_literal: true

module Phish
  # OpenPhish Community Phishing Feed
  # https://openphish.com/phishing_feeds.html
  #
  # The community feed provides a text file of phishing URLs
  # updated every 12 hours.
  #
  class OpenphishService < BaseService
    FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"

    # Conservative rate limits (simple file fetch)
    rate_limit :minute, requests: 10, period: 1.minute
    rate_limit :daily, requests: 100, period: 1.day

    def check_domain(domain)
      normalized = normalize_domain(domain)
      log_info("Checking domain against OpenPhish: #{normalized}")

      cached_result = check_local_cache(normalized)
      return cached_result if cached_result

      nil # OpenPhish is feed-based, not API-based
    end

    def check_url(url)
      normalized = normalize_url(url)
      log_info("Checking URL against OpenPhish: #{normalized}")

      cached_result = check_local_url_cache(normalized)
      return cached_result if cached_result

      nil # Feed-based, not API-based
    end

    # Sync the full feed (called by OpenphishSyncJob)
    def sync_feed
      log_info("Syncing OpenPhish feed...")

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
      log_error("Failed to fetch OpenPhish feed", e)
      { success: false, error: e.message }
    end

    private

    def process_feed(body)
      urls = body.split("\n").map(&:strip).reject(&:blank?)

      imported_urls = 0
      imported_domains = 0
      domains_seen = Set.new

      urls.each do |url|
        next unless url.start_with?("http")

        # Cache the URL
        cache_url(url)
        imported_urls += 1

        # Extract and cache domain
        begin
          uri = URI.parse(url)
          domain = uri.host&.downcase
          next unless domain && !domains_seen.include?(domain)

          domains_seen.add(domain)
          cache_domain(domain)
          import_domain(domain)
          imported_domains += 1
        rescue URI::InvalidURIError
          next
        end
      end

      log_info("OpenPhish sync: #{imported_urls} URLs, #{imported_domains} domains")
      { success: true, urls: imported_urls, domains: imported_domains }
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
        confidence: 0.90,
        details: { source: "openphish", cached: true }
      )
    end

    def check_local_url_cache(url)
      return nil unless Rails.cache.exist?(url_cache_key(url))

      build_result(
        verdict: "phishing",
        confidence: 0.90,
        details: { source: "openphish", cached: true, url: url }
      )
    end

    def cache_domain(domain)
      Rails.cache.write(domain_cache_key(domain), true, expires_in: 24.hours)
    end

    def cache_url(url)
      Rails.cache.write(url_cache_key(url), true, expires_in: 24.hours)
    end

    def domain_cache_key(domain)
      "openphish:domain:#{domain.downcase}"
    end

    def url_cache_key(url)
      "openphish:url:#{Digest::SHA256.hexdigest(url.downcase)}"
    end
  end
end
