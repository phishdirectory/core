# frozen_string_literal: true

module Phish
  # Base class for aggregator services that combine results from multiple
  # phishing/fraud detection services.
  #
  # Subclasses should:
  #   - Define DEFAULT_SERVICES and SERVICE_WEIGHTS constants
  #   - Implement #check_target(target) calling collect_service_results
  #   - Implement #build_service(service_name) to instantiate services
  #   - Implement #extract_metadata(results) for target-specific metadata
  #   - Implement #protected?(target) to check protection status
  #
  class BaseAggregatorService < BaseService
    def initialize(services: self.class::DEFAULT_SERVICES, logger: Rails.logger)
      super(logger: logger)
      @services = services
    end

    protected

    # Collects results from all configured services for the given target.
    # Returns { results: [...], rate_limited: {...} }
    def collect_service_results(target, check_method:)
      results = []
      rate_limited = {}

      @services.each do |service_name|
        service = build_service(service_name)
        next unless service

        begin
          result = service.public_send(check_method, target)
          results << result.merge(service_name: service_name) if result
        rescue RateLimitError => e
          log_info("Service #{service_name} rate limited: #{e.message}")
          rate_limited[service_name] = { retry_after: e.retry_after }
        rescue AuthenticationError => e
          log_error("Service #{service_name} auth error", e)
          # Skip this service, don't fail the whole request
        rescue ServiceError => e
          log_error("Service #{service_name} error", e)
          # Skip this service, don't fail the whole request
        end
      end

      { results: results, rate_limited: rate_limited }
    end

    # Calculates the final verdict from service results using weighted scoring.
    def calculate_verdict(results)
      return { verdict: "unknown", confidence: 0.0 } if results.empty?

      # Tally weighted votes for each verdict
      verdict_scores = Hash.new(0.0)
      total_weight = 0.0

      results.each do |result|
        service_name = result[:service_name] || result[:service]&.to_sym
        weight = service_weights[service_name] || 1.0
        confidence = result[:confidence] || 0.5
        verdict = result[:verdict]

        next if verdict.blank? || verdict == "pending"

        weighted_score = weight * confidence
        verdict_scores[verdict] += weighted_score
        total_weight += weight
      end

      return { verdict: "unknown", confidence: 0.0 } if total_weight.zero?

      # Normalize scores
      verdict_scores.transform_values! { |v| v / total_weight }

      # Determine final verdict
      # Priority: phishing > suspicious > clean > unknown
      final_verdict, final_confidence = determine_final_verdict(verdict_scores)

      { verdict: final_verdict, confidence: final_confidence.round(2) }
    end

    # Build a protected result for the given target.
    def build_protected_result(target, target_key:, source:)
      build_result(
        verdict: "protected",
        confidence: 1.0,
        details: {
          target_key => target,
          protected: true,
          source: source
        }
      )
    end

    # Must be implemented by subclass
    def build_service(_service_name)
      raise NotImplementedError, "Subclass must implement #build_service"
    end

    # Must be implemented by subclass
    def extract_metadata(_results)
      raise NotImplementedError, "Subclass must implement #extract_metadata"
    end

    private

    def service_weights
      self.class::SERVICE_WEIGHTS
    end

    def determine_final_verdict(verdict_scores)
      if verdict_scores["phishing"] >= 0.5
        ["phishing", verdict_scores["phishing"]]
      elsif verdict_scores["suspicious"] >= 0.4
        ["suspicious", verdict_scores["suspicious"]]
      elsif verdict_scores["clean"] >= 0.5
        ["clean", verdict_scores["clean"]]
      elsif verdict_scores["phishing"] > 0 || verdict_scores["suspicious"] > 0
        # Any phishing/suspicious signal with lower confidence
        if verdict_scores["phishing"] >= verdict_scores["suspicious"]
          ["suspicious", [verdict_scores["phishing"], verdict_scores["suspicious"]].max]
        else
          ["suspicious", verdict_scores["suspicious"]]
        end
      else
        max_verdict = verdict_scores.max_by { |_, v| v }
        [max_verdict&.first || "unknown", max_verdict&.last || 0.0]
      end
    end
  end
end
