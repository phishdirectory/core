# frozen_string_literal: true

module Phish
  # Reddit Phishing Feed Scraper
  # Extracts domains/URLs from scam-related subreddits
  #
  # Uses public Reddit JSON endpoints (no API key required)
  #
  class RedditService < BaseService
    BASE_URL = "https://www.reddit.com"

    # Subreddits to monitor for phishing reports
    SUBREDDITS = %w[DIYscambaiting Scams phishing scambait].freeze

    # Domains to ignore (Reddit infrastructure, common links)
    SAFE_DOMAINS = %w[
      reddit.com www.reddit.com old.reddit.com
      redd.it i.redd.it v.redd.it
      imgur.com i.imgur.com
      youtube.com youtu.be www.youtube.com
      twitter.com x.com www.twitter.com
      google.com www.google.com goo.gl
      bit.ly tinyurl.com t.co
      facebook.com www.facebook.com
      instagram.com www.instagram.com
      linkedin.com www.linkedin.com
      wikipedia.org en.wikipedia.org
      github.com
      discord.com discord.gg
      pastebin.com
    ].freeze

    # Rate limits (be respectful of Reddit)
    rate_limit :minute, requests: 60, period: 1.minute
    rate_limit :daily, requests: 1000, period: 1.day

    def check_domain(_domain)
      # Reddit is feed-only, no domain checking
      nil
    end

    def check_url(_url)
      # Reddit is feed-only, no URL checking
      nil
    end

    # Sync posts from configured subreddits
    # @param hours [Integer] Look back this many hours (default: 6)
    def sync_subreddits(hours: 6)
      log_info("Syncing Reddit posts from last #{hours} hours...")

      total_domains = Set.new
      total_posts = 0
      errors = []

      SUBREDDITS.each do |subreddit|
        result = sync_subreddit(subreddit, hours: hours)
        if result[:success]
          total_domains.merge(result[:domains])
          total_posts += result[:posts]
        else
          errors << "r/#{subreddit}: #{result[:error]}"
        end
      end

      import_domains(total_domains)

      log_info("Reddit sync: #{total_posts} posts, #{total_domains.size} domains")
      {
        success: errors.empty?,
        posts: total_posts,
        domains: total_domains.size,
        errors: errors.presence
      }
    end

    private

    def sync_subreddit(subreddit, hours:)
      with_rate_limit do
        conn = reddit_connection
        response = get(conn, "/r/#{subreddit}/new.json?limit=100")

        return { success: false, error: "Invalid response" } unless response.is_a?(Hash)

        posts = response.dig("data", "children") || []
        cutoff = hours.hours.ago.to_i

        domains = Set.new
        processed = 0

        posts.each do |post|
          data = post["data"]
          created = data["created_utc"].to_i
          next if created < cutoff

          # Extract domains from title and selftext
          text = "#{data['title']} #{data['selftext']}"
          extracted = extract_domains(text)
          domains.merge(extracted)
          processed += 1
        end

        { success: true, posts: processed, domains: domains }
      end
    rescue RateLimitable::RateLimitExceeded => e
      { success: false, error: "Rate limited", retry_after: e.retry_after }
    rescue Faraday::Error => e
      log_error("Failed to fetch r/#{subreddit}", e)
      { success: false, error: e.message }
    end

    def reddit_connection
      Faraday.new(url: BASE_URL) do |f|
        f.response :json, content_type: /\bjson$/
        f.headers["User-Agent"] = "#{user_agent} (phishing research)"
        f.adapter Faraday.default_adapter
      end
    end

    def extract_domains(text)
      domains = Set.new

      # Extract URLs and domains using various patterns
      # Full URLs (http/https)
      text.scan(%r{https?://(?:www\.)?([\w\-]+(?:\.[\w\-]+)+)(?:/[^\s\[\]()]*)?}i) do |match|
        add_domain(domains, match[0])
      end

      # Obfuscated URLs (hxxp/hxxps)
      text.scan(%r{hxxps?://(?:www\.)?([\w\-]+(?:\.[\w\-]+)+)}i) do |match|
        add_domain(domains, match[0])
      end

      # Domain patterns with [.] obfuscation
      text.scan(/([\w\-]+(?:\[?\.\]?[\w\-]+)+\[?\.\]?(?:com|net|org|io|co|xyz|info|biz|ru|cn|top|site|online|club|shop|app|dev|me|uk|de|fr|jp|ca|au|in|br))/i) do |match|
        domain = match[0].to_s
        # Clean up obfuscation
        domain = domain.gsub(/\[?\.\]?/, ".")
        add_domain(domains, domain)
      end

      domains
    end

    def add_domain(domains, domain)
      return unless domain

      domain = domain.to_s.downcase
      domain = domain.gsub(/\.+/, ".") # Collapse multiple dots
      domain = domain.chomp(".")       # Remove trailing dot

      return if domain.blank?
      return if SAFE_DOMAINS.include?(domain)
      return unless valid_domain?(domain)

      domains.add(domain)
    end

    def valid_domain?(domain)
      # Basic validation
      return false if domain.length < 4 || domain.length > 253
      return false unless domain.include?(".")
      return false if domain.match?(/\s/)
      return false if domain.match?(/^[\d.]+$/) # IP addresses

      # Must have valid TLD (use public_suffix gem)
      PublicSuffix.valid?(domain, default_rule: nil)
    rescue
      false
    end

    def import_domains(domains)
      domains.each do |domain|
        # Only import truly new domains to save resources on nightly syncs
        next if Phish::Domain.exists?(domain: domain.downcase)

        # Cache with note that it's from Reddit (user-reported)
        Rails.cache.write(
          "reddit:domain:#{domain.downcase}",
          { reported_at: Time.current },
          expires_in: 12.hours
        )

        record = Phish::Domain.create(domain: domain.downcase)
        PhishDomainCheckJob.perform_later(record.id) if record.persisted?
      end
    end
  end
end
