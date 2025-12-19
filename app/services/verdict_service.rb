# frozen_string_literal: true

class VerdictService
  class << self
    # Updates or creates a verdict for a domain/URL record atomically.
    #
    # @param record [Phish::Domain, Phish::Url] The domain or URL record
    # @param result [Hash] The aggregator service result with :verdict, :confidence, :details
    # @return [Verdict] The created/updated verdict
    def update_verdict!(record, result)
      ActiveRecord::Base.transaction do
        verdict = record.verdict || record.build_verdict
        verdict.assign_attributes(
          classification: result[:verdict],
          confidence_score: result[:confidence],
          sources: result[:details]&.dig(:service_results) || [],
          metadata: result[:details] || {}
        )
        verdict.save!

        record.update!(verdict: verdict, last_checked_at: Time.current)

        verdict
      end
    end

    # Runs a phishing check on a domain and updates its verdict.
    #
    # @param domain [Phish::Domain] The domain record to check
    # @return [Hash] The aggregator service result
    def check_domain!(domain)
      service = Phish::AggregatorService.new
      result = service.check_domain(domain.domain)

      update_verdict!(domain, result)

      result
    end

    # Runs a phishing check on a URL and updates its verdict.
    #
    # @param url [Phish::Url] The URL record to check
    # @return [Hash] The aggregator service result
    def check_url!(url)
      service = Phish::AggregatorService.new
      result = service.check_url(url.url)

      update_verdict!(url, result)

      result
    end
  end
end
