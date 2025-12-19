# frozen_string_literal: true

module Phish
  # Aggregates results from multiple email reputation services
  #
  # Services checked:
  #   - EmailRep.io (reputation, suspicious flags, breach data) - DISABLED pending API key
  #   - IPQualityScore (fraud score, abuse detection)
  #
  # Scoring uses weighted confidence from each service.
  #
  class EmailAggregatorService < BaseService
    # NOTE: emailrep temporarily disabled while waiting for API key
    # Re-enable by adding :emailrep back to this array
    DEFAULT_SERVICES = %i[ipqualityscore].freeze

    SERVICE_WEIGHTS = {
      emailrep: 1.0,
      ipqualityscore: 1.2  # Slightly higher weight for more comprehensive data
    }.freeze

    def initialize(services: DEFAULT_SERVICES, logger: Rails.logger)
      super(logger: logger)
      @services = services
    end

    def check_email(email)
      normalized = email.to_s.strip.downcase
      log_info("Aggregating email check for: #{normalized}")

      # Check if email is protected
      if Phish::Protection.protected?("Phish::Email", normalized)
        return build_protected_result(normalized)
      end

      results = collect_service_results(normalized)
      rate_limited_services = results[:rate_limited]
      service_results = results[:results]

      # If all services were rate limited, raise error
      if service_results.empty? && rate_limited_services.any?
        retry_after = rate_limited_services.values.map { |r| r[:retry_after] || 60 }.min
        raise RateLimitError.new("All email services rate limited", retry_after: retry_after)
      end

      # Calculate aggregated verdict
      verdict_result = calculate_verdict(service_results)

      # Extract metadata from services
      metadata = extract_metadata(service_results)

      build_result(
        verdict: verdict_result[:verdict],
        confidence: verdict_result[:confidence],
        details: {
          email: normalized,
          services_checked: service_results.size,
          rate_limited_services: rate_limited_services.keys,
          metadata: metadata,
          sources: service_results,
          source: "email_aggregator"
        }
      )
    end

    # Email aggregator doesn't support domain/URL checks
    def check_domain(_domain)
      nil
    end

    def check_url(_url)
      nil
    end

    private

    def collect_service_results(email)
      results = []
      rate_limited = {}

      @services.each do |service_name|
        service = build_service(service_name)
        next unless service

        begin
          result = service.check_email(email)
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

    def build_service(service_name)
      case service_name
      when :emailrep
        EmailrepService.new(logger: logger)
      when :ipqualityscore
        IpqualityscoreService.new(logger: logger)
      else
        log_error("Unknown service: #{service_name}", StandardError.new)
        nil
      end
    end

    def calculate_verdict(results)
      return { verdict: "unknown", confidence: 0.0 } if results.empty?

      # Tally weighted votes for each verdict
      verdict_scores = Hash.new(0.0)
      total_weight = 0.0

      results.each do |result|
        service_name = result[:service_name] || result[:service]&.to_sym
        weight = SERVICE_WEIGHTS[service_name] || 1.0
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
      final_verdict, final_confidence = if verdict_scores["phishing"] >= 0.5
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

      { verdict: final_verdict, confidence: final_confidence.round(2) }
    end

    def extract_metadata(results)
      # Merge metadata from all services, preferring non-nil values
      metadata = {
        disposable: nil,
        free_provider: nil,
        deliverable: nil,
        valid_mx: nil,
        leaked: nil,
        fraud_score: nil,
        reputation: nil
      }

      results.each do |result|
        details = result[:details] || {}

        metadata[:disposable] ||= details[:disposable]
        metadata[:free_provider] ||= details[:free_provider] || details[:free_email]
        metadata[:deliverable] ||= details[:deliverable]
        metadata[:valid_mx] ||= details[:valid_mx]
        metadata[:leaked] ||= details[:leaked] || details[:credentials_leaked] || details[:data_breach]
        metadata[:fraud_score] ||= details[:fraud_score]
        metadata[:reputation] ||= details[:reputation]
      end

      metadata.compact
    end

    def build_protected_result(email)
      build_result(
        verdict: "protected",
        confidence: 1.0,
        details: {
          email: email,
          protected: true,
          source: "email_aggregator"
        }
      )
    end
  end
end
