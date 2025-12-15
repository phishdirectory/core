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

    # Weights for different services (higher = more trusted)
    SERVICE_WEIGHTS = {
      google_safe_browsing: 1.5,
      virustotal: 1.3,
      phishtank: 1.2,
      urlscan: 1.0,
      walshy: 1.0
    }.freeze

    # Minimum confidence to consider a verdict
    MIN_CONFIDENCE = 0.3

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
      when :phishtank then PhishtankService
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
        next unless result[:confidence] && result[:confidence] >= MIN_CONFIDENCE

        weight = SERVICE_WEIGHTS[result[:service].to_sym] || 1.0
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

        if normalized_phishing > normalized_clean && normalized_phishing >= MIN_CONFIDENCE
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
        elsif normalized_clean > normalized_phishing && normalized_clean >= MIN_CONFIDENCE
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
  end
end
