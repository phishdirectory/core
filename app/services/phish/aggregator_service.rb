# frozen_string_literal: true

module Phish
  # Aggregates results from multiple phishing detection services
  # and produces a combined verdict
  class AggregatorService < BaseService
    # Default services to check (can be configured)
    # Note: Reddit is excluded - it's feed-only with no check_domain/check_url API
    DEFAULT_SERVICES = %i[
      walshy
      google_safe_browsing
      virustotal
      fish_fish
      sinking_yachts
      openphish
    ].freeze

    attr_reader :services

    def initialize(services: DEFAULT_SERVICES, logger: Rails.logger)
      super(logger: logger)
      @services = services.map { |s| instantiate_service(s) }.compact
    end

    # Check a domain against all configured services
    # @param domain [String] The domain to check
    # @param record [Phish::Domain, nil] Optional record for scheduling retries
    # @return [Hash] Aggregated result
    def check_domain(domain, record: nil)
      normalized = normalize_domain(domain)
      log_info("Aggregating checks for domain: #{normalized}")

      # Check if domain is protected before running any services
      if (protection = Phish::Protection.protection_for("Phish::Domain", normalized))
        log_info("Domain #{normalized} is protected, skipping checks")
        return build_protected_result(domain: normalized, protection: protection)
      end

      results, rate_limited = collect_service_results(:check_domain, normalized)

      # Schedule retry jobs for rate-limited services
      schedule_retries(rate_limited, record_type: "domain", record: record)

      aggregate_results(results, domain: normalized, rate_limited_services: rate_limited)
    end

    # Check a URL against all configured services
    # @param url [String] The URL to check
    # @param record [Phish::Url, nil] Optional record for scheduling retries
    # @return [Hash] Aggregated result
    def check_url(url, record: nil)
      normalized = normalize_url(url)
      log_info("Aggregating checks for URL: #{normalized}")

      # Check if URL is protected before running any services
      if (protection = Phish::Protection.protection_for("Phish::Url", normalized))
        log_info("URL #{normalized} is protected, skipping checks")
        return build_protected_result(url: normalized, protection: protection)
      end

      results, rate_limited = collect_service_results(:check_url, normalized)

      # Schedule retry jobs for rate-limited services
      schedule_retries(rate_limited, record_type: "url", record: record)

      aggregate_results(results, url: normalized, rate_limited_services: rate_limited)
    end

    # Check rate limit status for all services
    def services_rate_limit_status
      services.each_with_object({}) do |service, status|
        status[service.service_name] = {
          available: service.rate_limit_available?,
          limits: service.rate_limit_status
        }
      end
    end

    private

    # Schedule retry jobs for rate-limited services
    def schedule_retries(rate_limited, record_type:, record:)
      return if rate_limited.empty? || record.nil?

      rate_limited.each do |info|
        wait_time = [(info[:retry_after] || 60).to_i, 5].max.seconds

        PhishServiceRetryJob
          .set(wait: wait_time)
          .perform_later(
            record_type: record_type,
            record_id: record.id,
            service_name: info[:service]
          )

        log_info("Scheduled retry for #{info[:service]} in #{wait_time.to_i}s")
      end
    end

    # Collect results from all services, tracking rate-limited ones
    def collect_service_results(method, *args)
      results = []
      rate_limited = []

      services.each do |service|
        result = service.public_send(method, *args)
        results << result if result
      rescue RateLimitError => e
        rate_limited << {
          service: service.service_name,
          retry_after: e.retry_after
        }
        log_info("Service #{service.service_name} rate limited, retry after #{e.retry_after}s")
      rescue ServiceError => e
        log_error("Service #{service.service_name} failed", e)
      end

      [results, rate_limited]
    end

    def instantiate_service(name)
      klass = case name.to_sym
      when :walshy then WalshyService
      when :google_safe_browsing then GoogleSafeBrowsingService
      when :virustotal then VirustotalService
      when :urlscan then UrlscanService
      when :fish_fish then FishFishService
      when :sinking_yachts then SinkingYachtsService
      when :openphish then OpenphishService
      else
        log_info("Unknown service: #{name}")
        return nil
      end

      klass.new(logger: logger)
    end

    def aggregate_results(results, rate_limited_services: [], **context)
      # Include rate limited info in context
      context[:rate_limited_services] = rate_limited_services if rate_limited_services.any?

      return build_unknown_result(context) if results.empty?

      # Check for authoritative sources first
      # FishFish maintains a curated list with high standards for inclusion -
      # if a domain is in their list, it's confirmed phishing
      authoritative_result = check_authoritative_sources(results)
      if authoritative_result
        service_results = results.map do |r|
          { service: r[:service], verdict: r[:verdict], confidence: r[:confidence] }
        end
        return build_result(
          verdict: authoritative_result[:verdict],
          confidence: authoritative_result[:confidence],
          details: context.merge(
            service_results: service_results,
            services_checked: results.size,
            authoritative_source: authoritative_result[:service],
            reason: "Authoritative source detection"
          )
        )
      end

      # Calculate weighted scores
      phishing_score = 0.0
      clean_score = 0.0
      total_weight = 0.0
      service_results = []

      results.each do |result|
        next unless result[:confidence] && result[:confidence] >= min_confidence

        weight = service_weight(result[:service])
        confidence = result[:confidence]
        weighted_confidence = confidence * weight

        case result[:verdict]
        when "phishing"
          phishing_score += weighted_confidence
        when "clean"
          clean_score += weighted_confidence
        end

        total_weight += weight
        service_results << {
          service: result[:service],
          verdict: result[:verdict],
          confidence: confidence
        }
      end

      # Determine final verdict
      if total_weight.zero?
        build_unknown_result(context.merge(service_results: service_results))
      else
        normalized_phishing = phishing_score / total_weight
        normalized_clean = clean_score / total_weight

        if normalized_phishing > normalized_clean && normalized_phishing >= min_confidence
          build_result(
            verdict: "phishing",
            confidence: normalized_phishing.round(2),
            details: context.merge(
              service_results: service_results,
              services_checked: results.size,
              phishing_score: normalized_phishing.round(2),
              clean_score: normalized_clean.round(2)
            )
          )
        elsif normalized_clean > normalized_phishing && normalized_clean >= min_confidence
          build_result(
            verdict: "clean",
            confidence: normalized_clean.round(2),
            details: context.merge(
              service_results: service_results,
              services_checked: results.size,
              phishing_score: normalized_phishing.round(2),
              clean_score: normalized_clean.round(2)
            )
          )
        else
          build_result(
            verdict: "suspicious",
            confidence: [normalized_phishing, normalized_clean].max.round(2),
            details: context.merge(
              service_results: service_results,
              services_checked: results.size,
              phishing_score: normalized_phishing.round(2),
              clean_score: normalized_clean.round(2)
            )
          )
        end
      end
    end

    def build_unknown_result(context)
      build_result(
        verdict: "unknown",
        confidence: 0.0,
        details: context.merge(
          services_checked: 0,
          reason: "No services returned results"
        )
      )
    end

    def build_protected_result(protection:, **context)
      build_result(
        verdict: "protected",
        confidence: 1.0,
        details: context.merge(
          services_checked: 0,
          reason: protection.reason || "Domain is on protected list",
          protected_by: protection.protected_by&.public_id,
          protected_at: protection.created_at.iso8601
        )
      )
    end

    # Authoritative sources that override weighted scoring when they detect phishing
    # These are curated lists with high standards for inclusion
    AUTHORITATIVE_SOURCES = %w[fish_fish sinking_yachts].freeze

    # Check if any authoritative source flagged as phishing
    # Returns the result if found, nil otherwise
    def check_authoritative_sources(results)
      results.find do |result|
        AUTHORITATIVE_SOURCES.include?(result[:service]) &&
          result[:verdict] == "phishing" &&
          result[:confidence] && result[:confidence] >= 0.9
      end
    end

    # Scoring configuration from encrypted credentials
    def scoring_config
      @scoring_config ||= Rails.application.credentials.scoring || {}
    end

    def service_weight(service_name)
      weights = scoring_config[:weights] || {}
      weights[service_name.to_sym] || default_weight
    end

    def min_confidence
      scoring_config[:min_confidence] || default_min_confidence
    end

    def default_weight
      scoring_config[:default_weight] || 1.0
    end

    # Fallback for development/test when credentials not configured
    def default_min_confidence
      0.3
    end
  end
end
