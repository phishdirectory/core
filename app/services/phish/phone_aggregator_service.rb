# frozen_string_literal: true

module Phish
  # Aggregates results from multiple phone number reputation services
  #
  # Services checked:
  #   - IPQualityScore (fraud score, abuse detection, carrier info)
  #
  # Scoring uses weighted confidence from each service.
  #
  class PhoneAggregatorService < BaseAggregatorService
    DEFAULT_SERVICES = %i[ipqualityscore].freeze

    SERVICE_WEIGHTS = {
      ipqualityscore: 1.0
    }.freeze

    def check_phone(phone_number)
      normalized = normalize_phone(phone_number)
      log_info("Aggregating phone check for: #{normalized}")

      # Check if phone is protected
      if Phish::Protection.protected?("Phish::PhoneNumber", normalized)
        return build_protected_result(normalized, target_key: :phone_number, source: "phone_aggregator")
      end

      results = collect_service_results(normalized, check_method: :check_phone)
      rate_limited_services = results[:rate_limited]
      service_results = results[:results]

      # If all services were rate limited, raise error
      if service_results.empty? && rate_limited_services.any?
        retry_after = rate_limited_services.values.map { |r| r[:retry_after] || 60 }.min
        raise RateLimitError.new("All phone services rate limited", retry_after: retry_after)
      end

      # Calculate aggregated verdict
      verdict_result = calculate_verdict(service_results)

      # Extract metadata from services
      metadata = extract_metadata(service_results)

      build_result(
        verdict: verdict_result[:verdict],
        confidence: verdict_result[:confidence],
        details: {
          phone_number: normalized,
          services_checked: service_results.size,
          rate_limited_services: rate_limited_services.keys,
          metadata: metadata,
          sources: service_results,
          source: "phone_aggregator"
        }
      )
    end

    # Phone aggregator doesn't support domain/URL/email checks
    def check_domain(_domain)
      nil
    end

    def check_url(_url)
      nil
    end

    def check_email(_email)
      nil
    end

    protected

    def build_service(service_name)
      case service_name
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
        phone_type: nil,
        line_type: nil,
        carrier: nil,
        country_code: nil,
        voip: nil,
        prepaid: nil,
        active: nil,
        fraud_score: nil
      }

      results.each do |result|
        details = result[:details] || {}

        metadata[:phone_type] ||= details[:line_type]
        metadata[:line_type] ||= details[:line_type]
        metadata[:carrier] ||= details[:carrier]
        metadata[:country_code] ||= details[:country]
        metadata[:voip] ||= details[:voip]
        metadata[:prepaid] ||= details[:prepaid]
        metadata[:active] ||= details[:active]
        metadata[:fraud_score] ||= details[:fraud_score]
      end

      metadata.compact
    end

    private

    def normalize_phone(phone)
      # Strip everything except + and digits, then ensure E.164 format
      cleaned = phone.to_s.gsub(/[^\d+]/, "")
      cleaned.start_with?("+") ? cleaned : "+#{cleaned}"
    end
  end
end
