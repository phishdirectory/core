# frozen_string_literal: true

module Api
  module V1
    module Domain
      class DomainsController < BaseController
        # GET/POST /api/v1/domain/check
        def check
          domain = params[:domain]&.strip&.downcase

          if domain.blank?
            return render json: { error: "Missing required parameter: domain" }, status: :bad_request
          end

          # Normalize domain (remove protocol, path, etc.)
          normalized_domain = normalize_domain(domain)

          # Find or create the domain record
          phish_domain = Phish::Domain.find_or_create_by(domain: normalized_domain)

          # Track that this domain was queried
          phish_domain.touch_last_seen!

          # Check if we need to refresh the verdict
          if phish_domain.needs_recheck?
            # Queue background check
            # PhishDomainCheckJob.perform_later(phish_domain.id)
          end

          render json: serialize_domain(phish_domain)
        end

        # GET/POST /api/v1/domain/bulk
        def bulk
          domains = Array(params[:domains]).map { |d| d&.strip&.downcase }.compact.uniq

          if domains.empty?
            return render json: { error: "Missing required parameter: domains" }, status: :bad_request
          end

          if domains.size > 100
            return render json: { error: "Maximum 100 domains per request" }, status: :bad_request
          end

          results = domains.map do |domain|
            normalized = normalize_domain(domain)
            phish_domain = Phish::Domain.find_or_create_by(domain: normalized)
            phish_domain.touch_last_seen!
            serialize_domain(phish_domain)
          end

          render json: {
            results: results,
            count: results.size
          }
        end

        private

        def serialize_domain(phish_domain)
          {
            id: phish_domain.public_id,
            domain: phish_domain.domain,
            verdict: phish_domain.verdict&.verdict || "unknown",
            confidence: phish_domain.verdict&.confidence,
            verdict_id: phish_domain.verdict&.public_id,
            last_checked: phish_domain.last_checked_at&.iso8601,
            created_at: phish_domain.created_at.iso8601
          }
        end

        def normalize_domain(domain)
          # Remove protocol
          domain = domain.sub(%r{\Ahttps?://}, "")
          # Remove path and query string
          domain = domain.split("/").first
          # Remove port
          domain = domain.split(":").first
          # Remove www prefix (optional, based on requirements)
          # domain = domain.sub(/\Awww\./, "")
          domain
        end
      end
    end
  end
end
