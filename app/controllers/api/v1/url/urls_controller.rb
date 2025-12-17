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

          # Find or create the URL record
          phish_url = Phish::Url.find_or_create_by(url: normalized_url)

          # Check if we need to refresh the verdict
          if phish_url.needs_recheck?
            # Queue background check
            # PhishUrlCheckJob.perform_later(phish_url.id)
          end

          log_service_usage(response_code: 200)

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

          results = urls.map do |url|
            normalized = normalize_url(url)
            phish_url = Phish::Url.find_or_create_by(url: normalized)
            serialize_url(phish_url)
          end

          log_service_usage(response_code: 200)

          render json: {
            results: results,
            count: results.size
          }
        end

        private

        def serialize_url(phish_url)
          {
            id: phish_url.public_id,
            url: phish_url.url,
            domain: phish_url.domain,
            verdict: phish_url.verdict&.verdict || "unknown",
            confidence: phish_url.verdict&.confidence,
            verdict_id: phish_url.verdict&.public_id,
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
      end
    end
  end
end
