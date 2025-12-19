# frozen_string_literal: true

module Api
  module V1
    module Url
      class UrlsController < BaseController
        # GET/POST /api/v1/url/check
        def check
          url = params[:url]&.strip

          if url.blank?
            return render json: { error: "Missing required parameter: url" }, status: :bad_request
          end

          # Normalize URL
          normalized_url = normalize_url(url)

          # Validate URL format before database access
          unless valid_url?(normalized_url)
            return render json: { error: "Invalid URL format" }, status: :bad_request
          end

          # Find or create the URL record
          phish_url = Phish::Url.find_or_create_by(url: normalized_url)

          # Check if we need to refresh the verdict
          if phish_url.needs_recheck?
            # Queue background check
            # PhishUrlCheckJob.perform_later(phish_url.id)
          end

          render json: serialize_url(phish_url)
        end

        # GET/POST /api/v1/url/bulk
        def bulk
          urls = Array(params[:urls]).map { |u| u&.strip }.compact.uniq

          if urls.empty?
            return render json: { error: "Missing required parameter: urls" }, status: :bad_request
          end

          if urls.size > 100
            return render json: { error: "Maximum 100 URLs per request" }, status: :bad_request
          end

          # Normalize all URLs first
          normalized_urls = urls.map { |u| normalize_url(u) }

          # Validate all URLs before database access
          invalid_urls = normalized_urls.reject { |u| valid_url?(u) }
          if invalid_urls.any?
            return render json: {
              error: "Invalid URL format",
              invalid_urls: invalid_urls.first(10)
            }, status: :bad_request
          end

          # Find existing URLs
          existing = Phish::Url.where(url: normalized_urls).index_by(&:url)

          # Create missing URLs
          missing_urls = normalized_urls - existing.keys
          missing_urls.each do |url|
            existing[url] = Phish::Url.create!(url: url)
          end

          # Reload all URLs with verdict eager loading to avoid N+1
          phish_urls = Phish::Url.includes(:verdict).where(url: normalized_urls).index_by(&:url)

          # Serialize in original order
          results = normalized_urls.map { |u| serialize_url(phish_urls[u]) }

          render json: {
            results: results,
            count: results.size
          }
        end

        private

        def serialize_url(phish_url)
          verdict = phish_url.verdict
          {
            id: phish_url.public_id,
            url: phish_url.url,
            domain: phish_url.domain,
            verdict: verdict&.classification || "unknown",
            confidence: verdict&.confidence_score,
            scam_category: phish_url.scam_category,
            scam_subcategory: phish_url.scam_subcategory,
            verdict_id: verdict&.public_id,
            last_checked: phish_url.last_checked_at&.iso8601,
            created_at: phish_url.created_at.iso8601
          }
        end

        def normalize_url(url)
          # Add protocol if missing
          url = "https://#{url}" unless url.match?(%r{\Ahttps?://})
          # Parse and reconstruct to normalize
          uri = URI.parse(url)
          # Downcase host
          uri.host = uri.host&.downcase
          uri.to_s
        rescue URI::InvalidURIError
          url
        end

        # Matches Phish::Url validation (valid HTTP/HTTPS URL)
        def valid_url?(url)
          return false if url.blank?

          uri = URI.parse(url)
          uri.is_a?(URI::HTTP) && uri.host.present?
        rescue URI::InvalidURIError
          false
        end
      end
    end
  end
end
