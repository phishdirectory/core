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
  class EmailAggregatorService < BaseAggregatorService
    # NOTE: emailrep temporarily disabled while waiting for API key
    # Re-enable by adding :emailrep back to this array
    DEFAULT_SERVICES = %i[ipqualityscore].freeze

    SERVICE_WEIGHTS = {
      emailrep: 1.0,
      ipqualityscore: 1.2  # Slightly higher weight for more comprehensive data
    }.freeze

    def check_email(email)
      normalized = email.to_s.strip.downcase
      log_info("Aggregating email check for: #{normalized}")

      # Check if email is protected
      if Phish::Protection.protected?("Phish::Email", normalized)
        return build_protected_result(normalized, target_key: :email, source: "email_aggregator")
      end

      results = collect_service_results(normalized, check_method: :check_email)
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

    protected

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

        # Calculate reputation from fraud_score (invert: 0 fraud = 1.0 reputation)
        # or from overall_score (normalize: 4 = 1.0, 1 = 0.25)
        metadata[:reputation] ||= if details[:fraud_score].present?
          (100 - details[:fraud_score].to_i) / 100.0
        elsif details[:overall_score].present?
          details[:overall_score].to_f / 4.0
        end
      end

      metadata.compact
    end
  end
end
