# frozen_string_literal: true

module Phish
  # Aggregates results from multiple phishing detection services
  # and produces a combined verdict
  class AggregatorService < BaseService
    # Default services to check (can be configured)
    DEFAULT_SERVICES = %i[
      walshy
      google_safe_browsing
      virustotal
    ].freeze

    attr_reader :services

    def initialize(services: DEFAULT_SERVICES, logger: Rails.logger)
      super(logger: logger)
      @services = services.map { |s| instantiate_service(s) }.compact
    end

    def check_domain(domain)
      normalized = normalize_domain(domain)
      log_info("Aggregating checks for domain: #{normalized}")

      results = services.map do |service|
        begin
          service.check_domain(normalized)
        rescue ServiceError => e
          log_error("Service #{service.service_name} failed", e)
          nil
        end
      end.compact

      aggregate_results(results, domain: normalized)
    end

    def check_url(url)
      normalized = normalize_url(url)
      log_info("Aggregating checks for URL: #{normalized}")

      results = services.map do |service|
        begin
          service.check_url(normalized)
        rescue ServiceError => e
          log_error("Service #{service.service_name} failed", e)
          nil
        end
      end.compact

      aggregate_results(results, url: normalized)
    end

    private

    def instantiate_service(name)
      klass = case name.to_sym
      when :walshy then WalshyService
      when :google_safe_browsing then GoogleSafeBrowsingService
      when :virustotal then VirustotalService
      when :urlscan then UrlscanService
      else
        log_info("Unknown service: #{name}")
        return nil
      end

      klass.new(logger: logger)
    end

    def aggregate_results(results, **context)
      return build_unknown_result(context) if results.empty?

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
