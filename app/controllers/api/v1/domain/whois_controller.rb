# frozen_string_literal: true

module Api
  module V1
    module Domain
      class WhoisController < BaseController
        # GET/POST /api/v1/domain/whois
        def check
          domain = params[:domain]&.strip&.downcase

          if domain.blank?
            return render json: { error: "Missing required parameter: domain" }, status: :bad_request
          end

          # Normalize domain (remove protocol, path, etc.)
          normalized_domain = normalize_domain(domain)

          # Validate domain format
          unless valid_domain?(normalized_domain)
            return render json: { error: "Invalid domain format" }, status: :bad_request
          end

          # Perform lookup
          service = Phish::DomainExpiryService.new
          result = service.lookup(normalized_domain)

          render json: result
        rescue Phish::DomainExpiryService::DomainNotFoundError => e
          render json: {
            domain: normalized_domain,
            error: "Domain registration information not found",
            queried_at: Time.current.iso8601
          }, status: :not_found
        rescue Phish::BaseService::RateLimitError => e
          response.headers["Retry-After"] = e.retry_after.to_s if e.retry_after
          render json: {
            error: "Rate limit exceeded",
            retry_after: e.retry_after
          }, status: :too_many_requests
        rescue Phish::BaseService::ServiceError => e
          render json: { error: e.message }, status: :service_unavailable
        end

        # GET/POST /api/v1/domain/whois/bulk
        def bulk
          domains = Array(params[:domains]).map { |d| d&.strip&.downcase }.compact.uniq

          if domains.empty?
            return render json: { error: "Missing required parameter: domains" }, status: :bad_request
          end

          if domains.size > 100
            return render json: { error: "Maximum 100 domains per request" }, status: :bad_request
          end

          # Normalize all domains first
          normalized_domains = domains.map { |d| normalize_domain(d) }

          # Validate all domains before lookup
          invalid_domains = normalized_domains.reject { |d| valid_domain?(d) }
          if invalid_domains.any?
            return render json: {
              error: "Invalid domain format",
              invalid_domains: invalid_domains.first(10)
            }, status: :bad_request
          end

          # Perform bulk lookup
          service = Phish::DomainExpiryService.new
          lookup_result = service.bulk_lookup(normalized_domains)

          # Build response in original order
          results = normalized_domains.map do |domain|
            lookup_result[:results][domain] || { domain: domain, error: "Lookup failed" }
          end

          render json: {
            results: results,
            count: results.size,
            errors: lookup_result[:errors]
          }
        rescue Phish::BaseService::RateLimitError => e
          response.headers["Retry-After"] = e.retry_after.to_s if e.retry_after
          render json: {
            error: "Rate limit exceeded",
            retry_after: e.retry_after
          }, status: :too_many_requests
        end

        private

        def normalize_domain(domain)
          # Remove protocol
          domain = domain.sub(%r{\Ahttps?://}, "")
          # Remove path and query string
          domain = domain.split("/").first
          # Remove port
          domain = domain.split(":").first
          domain
        end

        # Matches Phish::Domain validation regex
        def valid_domain?(domain)
          domain.present? && domain.match?(/\A[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}\z/i)
        end
      end
    end
  end
end
