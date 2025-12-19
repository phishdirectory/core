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

          # Validate domain format before database access
          unless valid_domain?(normalized_domain)
            return render json: { error: "Invalid domain format" }, status: :bad_request
          end

          # Find or create the domain record (create_or_find_by handles race conditions)
          phish_domain = Phish::Domain.create_or_find_by!(domain: normalized_domain)

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

          # Normalize all domains first
          normalized_domains = domains.map { |d| normalize_domain(d) }

          # Validate all domains before database access
          invalid_domains = normalized_domains.reject { |d| valid_domain?(d) }
          if invalid_domains.any?
            return render json: {
              error: "Invalid domain format",
              invalid_domains: invalid_domains.first(10)
            }, status: :bad_request
          end

          # Find existing domains
          existing = Phish::Domain.where(domain: normalized_domains).index_by(&:domain)

          # Create missing domains (create_or_find_by! handles race conditions)
          missing_domains = normalized_domains - existing.keys
          missing_domains.each do |domain|
            existing[domain] = Phish::Domain.create_or_find_by!(domain: domain)
          end

          # Update last_seen_at for all domains in bulk
          Phish::Domain.where(domain: normalized_domains).update_all(last_seen_at: Time.current)

          # Reload all domains with verdict eager loading to avoid N+1
          phish_domains = Phish::Domain.includes(:verdict).where(domain: normalized_domains).index_by(&:domain)

          # Serialize in original order
          results = normalized_domains.map { |d| serialize_domain(phish_domains[d]) }

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

        # Matches Phish::Domain validation regex
        def valid_domain?(domain)
          domain.present? && domain.match?(/\A[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}\z/i)
        end
      end
    end
  end
end
